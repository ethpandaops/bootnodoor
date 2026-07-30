package bootnode

import (
	"context"
	"fmt"
	"math"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	"github.com/ethpandaops/bootnodoor/db"
	"github.com/ethpandaops/bootnodoor/discv4"
	v4node "github.com/ethpandaops/bootnodoor/discv4/node"
	"github.com/ethpandaops/bootnodoor/discv5"
	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	v5protocol "github.com/ethpandaops/bootnodoor/discv5/protocol"
	"github.com/ethpandaops/bootnodoor/enode"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/nodes"
	"github.com/ethpandaops/bootnodoor/services"
	"github.com/ethpandaops/bootnodoor/transport"
	"github.com/sirupsen/logrus"
)

// Service is the universal bootnode service.
//
// It provides:
//   - Dual protocol support (discv4 + discv5)
//   - Dual layer support (EL + CL)
//   - Separate routing tables for each layer
//   - Fork-aware filtering
type Service struct {
	// Configuration
	config *Config

	// Discovery identities (1 when a single key serves both layers, 2 when
	// separate EL and CL keys are supplied). Aliases below point at the primary.
	identities []*identity

	// Local node (primary identity: EL if present, else the sole identity)
	localNode *v5node.Node

	// Network components
	discv4Service *discv4.Service // May be nil if discv4 disabled
	discv5Service *discv5.Service // primary identity's discv5 (may be nil)

	// ENR management (primary identity; its fork filters classify all peers)
	enrManager *ENRManager

	// IP discovery
	ipDiscovery *services.IPDiscovery

	// Node databases (layer-specific)
	elNodeDB *nodes.NodeDB // May be nil if EL disabled
	clNodeDB *nodes.NodeDB // May be nil if CL disabled

	// Routing tables (layer-specific)
	elTable *nodes.FlatTable // May be nil if EL disabled
	clTable *nodes.FlatTable // May be nil if CL disabled

	// Discovery services (ping is per-identity; see identity.pingService)
	elLookupService *services.LookupService // EL lookup service (may be nil if EL disabled)
	clLookupService *services.LookupService // CL lookup service (may be nil if CL disabled)

	// ENR request tracking (prevents duplicate requests)
	pendingENRRequestsV4 sync.Map // map[node.ID]time.Time

	// v5ProbeSem bounds concurrent v5 capability probes
	v5ProbeSem chan struct{}

	// v5ProbesInFlight keeps one probe per node in flight
	v5ProbesInFlight sync.Map // map[[32]byte]struct{}

	// Lifecycle
	ctx       context.Context
	cancel    context.CancelFunc
	startTime time.Time
	mu        sync.RWMutex
	running   bool
}

// New creates a new universal bootnode service.
//
// Example:
//
//	config := bootnode.DefaultConfig()
//	config.PrivateKey = privKey
//	config.Database = db
//	config.ELConfig = elConfig
//	config.CLConfig = clConfig
//
//	service, err := bootnode.New(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer service.Stop()
func New(cfg *Config) (*Service, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	cfg.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create context
	ctx, cancel := context.WithCancel(context.Background())

	s := &Service{
		config:     cfg,
		ctx:        ctx,
		cancel:     cancel,
		v5ProbeSem: make(chan struct{}, maxConcurrentV5Probes),
	}

	// Resolve discovery identities (one shared, or separate EL/CL keys).
	s.identities = resolveIdentities(cfg)

	// Create one UDP transport per distinct bind port. Identities sharing a port
	// share a socket and are demultiplexed by their node ID at decode time.
	transports := make(map[uint16]*transport.UDPTransport)
	closeTransports := func() {
		for _, t := range transports {
			t.Close()
		}
	}

	// Everything created below hangs off s.ctx (NodeDB queue processors,
	// protocol-handler cleanup goroutines), so cancelling tears it all down.
	ok := false
	defer func() {
		if !ok {
			cancel()
			closeTransports()
		}
	}()

	for _, id := range s.identities {
		if transports[id.bindPort] == nil {
			// JoinHostPort so an IPv6 bind addr becomes [::]:port, not :::port.
			listenAddr := net.JoinHostPort(cfg.BindIP.String(), fmt.Sprintf("%d", id.bindPort))
			t, terr := transport.NewUDPTransport(&transport.Config{ListenAddr: listenAddr, Logger: cfg.Logger})
			if terr != nil {
				return nil, fmt.Errorf("failed to create UDP transport on port %d: %w", id.bindPort, terr)
			}
			cfg.Logger.WithField("address", listenAddr).Info("listening for discovery")
			transports[id.bindPort] = t
		}
		id.transport = transports[id.bindPort]
	}

	for _, id := range s.identities {
		storedENR, lerr := s.loadStoredENR(id.storeKey)
		if lerr != nil {
			cfg.Logger.WithError(lerr).Debug("no stored ENR, will create new one")
		}

		localNode, nerr := createLocalNode(cfg, id.key, id.enrIP, id.enrIP6, id.enrPort, storedENR)
		if nerr != nil {
			return nil, fmt.Errorf("failed to create local node: %w", nerr)
		}
		id.localNode = localNode

		if serr := s.storeENR(id.storeKey, localNode.Record()); serr != nil {
			cfg.Logger.WithError(serr).Warn("failed to store initial ENR")
		}

		id.enrManager = NewENRManager(cfg, id.key, localNode, id.servesEL, id.servesCL)
		headBlock, headTime := StaticHead()
		changed, uerr := id.enrManager.UpdateENR(headBlock, headTime)
		switch {
		case uerr != nil:
			cfg.Logger.WithError(uerr).Warn("failed to update ENR with eth/eth2 fields")
		case changed:
			if serr := s.storeENR(id.storeKey, localNode.Record()); serr != nil {
				cfg.Logger.WithError(serr).Warn("failed to store updated ENR")
			}
		}
	}

	// Aliases for the code paths that operate on a single representative identity.
	primary := s.primaryIdentity()
	s.localNode = primary.localNode
	s.enrManager = primary.enrManager

	// Create IP discovery service. Leaving it nil when disabled is the whole
	// enforcement: onPongReceived already returns early on a nil service, so no
	// peer report can reach consensus and rewrite the ENR.
	if cfg.EnableIPDiscovery {
		s.ipDiscovery = services.NewIPDiscovery(services.IPDiscoveryConfig{
			MinReports:     5, // Require 5 reports
			MinDistinctIPs: 3, // From at least 3 distinct IPs
			Logger:         cfg.Logger,
			OnConsensusReached: func(ip net.IP, port uint16, isIPv6 bool) {
				s.updateENRWithDiscoveredIP(ip, port, isIPv6)
			},
		})
	}

	// Create node databases for enabled layers
	var err error
	if cfg.HasEL() {
		s.elNodeDB = nodes.NewNodeDB(ctx, cfg.Database, db.LayerEL, cfg.Logger)
	}
	if cfg.HasCL() {
		s.clNodeDB = nodes.NewNodeDB(ctx, cfg.Database, db.LayerCL, cfg.Logger)
	}

	// Create routing tables for enabled layers, each keyed by its identity's node
	// ID (peers compute FINDNODE distances relative to the ID they dialed).
	if cfg.HasEL() {
		s.elTable, err = s.createTable(s.elIdentity().localNode.ID(), s.elNodeDB, "EL")
		if err != nil {
			return nil, fmt.Errorf("failed to create EL table: %w", err)
		}
	}
	if cfg.HasCL() {
		s.clTable, err = s.createTable(s.clIdentity().localNode.ID(), s.clNodeDB, "CL")
		if err != nil {
			return nil, fmt.Errorf("failed to create CL table: %w", err)
		}
	}

	// Create a discv5 service per identity (registered on its transport).
	if cfg.EnableDiscv5 {
		for _, id := range s.identities {
			if ierr := s.initDiscv5(id); ierr != nil {
				return nil, fmt.Errorf("failed to initialize discv5: %w", ierr)
			}
		}
		s.discv5Service = primary.discv5Service
	}

	// Create the discv4 service (EL-only) on the EL identity.
	if cfg.EnableDiscv4 {
		if ierr := s.initDiscv4(s.elIdentity()); ierr != nil {
			return nil, fmt.Errorf("failed to initialize discv4: %w", ierr)
		}
	}

	// Create a ping service per identity. discv4 is attached to the EL identity
	// only, so CL pings go out over discv5 under the CL node ID.
	for _, id := range s.identities {
		var v4 *discv4.Service
		if id.servesEL {
			v4 = s.discv4Service
		}
		var v5h *v5protocol.Handler
		if id.discv5Service != nil {
			v5h = id.discv5Service.Handler()
		}
		id.pingService = services.NewPingService(v5h, v4, cfg.Logger.WithField("service", "ping"))
	}

	// Create lookup services for enabled layers
	if cfg.HasEL() && s.elTable != nil {
		s.elLookupService = services.NewLookupService(services.Config{
			LocalIDs:      s.localIDs(),
			NodeDB:        s.elNodeDB,
			Table:         s.elTable,
			V5Handler:     s.getV5Handler(),
			V4Service:     s.getV4Service(),
			Database:      cfg.Database,
			Layer:         db.LayerEL,
			Alpha:         3,
			LookupTimeout: 30 * time.Second,
			OnNodeFound:   s.admitELLookupNode,
			Logger:        cfg.Logger.WithField("service", "el-lookup"),
		})
	}

	if cfg.HasCL() && s.clTable != nil {
		clID := s.clIdentity()
		// CL discovery runs under the CL identity's discv5 handler. discv4 is
		// EL-only, so only attach it when one shared identity serves both layers.
		var clV5Handler *v5protocol.Handler
		if clID.discv5Service != nil {
			clV5Handler = clID.discv5Service.Handler()
		}
		var clV4Service *discv4.Service
		if clID.servesEL {
			clV4Service = s.getV4Service()
		}
		s.clLookupService = services.NewLookupService(services.Config{
			LocalIDs:      s.localIDs(),
			NodeDB:        s.clNodeDB,
			Table:         s.clTable,
			V5Handler:     clV5Handler,
			V4Service:     clV4Service,
			Database:      cfg.Database,
			Layer:         db.LayerCL,
			Alpha:         3,
			LookupTimeout: 30 * time.Second,
			OnNodeFound:   s.admitCLLookupNode,
			Logger:        cfg.Logger.WithField("service", "cl-lookup"),
		})
	}

	ok = true

	return s, nil
}

// initDiscv5 initializes the discv5 service for one identity.
func (s *Service) initDiscv5(id *identity) error {
	discv5Config := discv5.DefaultConfig()
	discv5Config.LocalNode = id.localNode
	discv5Config.Context = s.ctx
	discv5Config.PrivateKey = id.key
	discv5Config.SessionLifetime = s.config.SessionLifetime
	discv5Config.MaxSessions = s.config.MaxSessions
	discv5Config.Logger = s.config.Logger

	// FINDNODE is scoped to the layers this identity serves.
	discv5Config.OnHandshakeComplete = s.onHandshakeComplete
	discv5Config.OnNodeUpdate = s.onNodeUpdate
	discv5Config.OnNodeSeen = s.onNodeSeen
	discv5Config.OnFindNode = func(msg *v5protocol.FindNode, sourceNode *v5node.Node, requester *net.UDPAddr) []*v5node.Node {
		return s.onFindNodeV5(id, msg, sourceNode, requester)
	}
	discv5Config.OnTalkReq = nil // No TALKREQ support
	discv5Config.OnPongReceived = func(remoteID v5node.ID, sourceIP net.IP, reportedIP net.IP, reportedPort uint16) {
		s.onPongReceived(remoteID[:], sourceIP, reportedIP, reportedPort)
	}

	// Create service
	service, err := discv5.New(discv5Config, id.transport)
	if err != nil {
		return err
	}

	id.discv5Service = service
	return nil
}

// initDiscv4 initializes the discv4 service (EL-only) on the EL identity.
func (s *Service) initDiscv4(id *identity) error {
	discv4Config := discv4.DefaultConfig()
	discv4Config.PrivateKey = id.key
	discv4Config.LocalENR = id.localNode.Record()

	// Set callbacks
	discv4Config.OnFindnode = func(from *v4node.Node, target []byte, requester *net.UDPAddr) []*v4node.Node {
		return s.onFindNodeV4(from, target, requester)
	}
	discv4Config.OnNodeSeen = func(n *v4node.Node, timestamp time.Time) {
		s.onNodeSeenV4(n, timestamp)
	}
	discv4Config.OnPongReceived = func(from *v4node.Node, provenAddr *net.UDPAddr, ip net.IP, port uint16) {
		s.onPongReceived(from.IDBytes(), provenAddr.IP, ip, port)
	}
	// OnENRRequest: discv4 service handles this internally using LocalENR from config
	// No callback needed - it will automatically respond with the ENR

	// Create service
	service, err := discv4.New(discv4Config, id.transport)
	if err != nil {
		return err
	}

	s.discv4Service = service
	return nil
}

// createTable creates a routing table for a layer.
func (s *Service) createTable(localID [32]byte, nodeDB *nodes.NodeDB, layerName string) (*nodes.FlatTable, error) {
	tableConfig := nodes.FlatTableConfig{
		LocalID:             localID,
		DB:                  nodeDB,
		MaxActiveNodes:      s.config.MaxActiveNodes,
		MaxNodesPerIP:       s.config.MaxNodesPerIP,
		PingInterval:        s.config.PingInterval,
		PingRate:            200,
		MaxNodeAge:          s.config.MaxNodeAge,
		MaxFailures:         s.config.MaxFailures,
		SweepPercent:        10,
		NodeChangedCallback: nil,
		Logger:              s.config.Logger.WithField("layer", layerName),
	}

	table, err := nodes.NewFlatTable(tableConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s table: %w", layerName, err)
	}

	return table, nil
}

func (s *Service) elIdentity() *identity {
	for _, id := range s.identities {
		if id.servesEL {
			return id
		}
	}
	return nil
}

func (s *Service) clIdentity() *identity {
	for _, id := range s.identities {
		if id.servesCL {
			return id
		}
	}
	return nil
}

// singleSocket reports whether every identity shares one socket, in which case
// an externally-observed port from IP discovery is unambiguous.
func (s *Service) singleSocket() bool {
	if len(s.identities) == 0 {
		return true
	}
	for _, id := range s.identities {
		if id.bindPort != s.identities[0].bindPort {
			return false
		}
	}
	return true
}

// primaryIdentity returns the representative identity: EL if present, else CL.
func (s *Service) primaryIdentity() *identity {
	if id := s.elIdentity(); id != nil {
		return id
	}
	return s.clIdentity()
}

func (s *Service) elPing() *services.PingService {
	if id := s.elIdentity(); id != nil {
		return id.pingService
	}
	return nil
}

func (s *Service) clPing() *services.PingService {
	if id := s.clIdentity(); id != nil {
		return id.pingService
	}
	return nil
}

// Start starts the bootnode service.
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service already running")
	}

	s.startTime = time.Now()

	// Load initial nodes from databases
	if s.elTable != nil {
		if err := s.elTable.LoadInitialNodesFromDB(); err != nil {
			return fmt.Errorf("failed to load EL nodes: %w", err)
		}
	}
	if s.clTable != nil {
		if err := s.clTable.LoadInitialNodesFromDB(); err != nil {
			return fmt.Errorf("failed to load CL nodes: %w", err)
		}
	}

	// Start protocol services (one discv5 service per identity)
	for _, id := range s.identities {
		if id.discv5Service != nil {
			if err := id.discv5Service.Start(); err != nil {
				return fmt.Errorf("failed to start discv5: %w", err)
			}
		}
	}
	if s.discv4Service != nil {
		if err := s.discv4Service.Start(); err != nil {
			return fmt.Errorf("failed to start discv4: %w", err)
		}
	}

	// Start maintenance loops
	go s.maintenanceLoop()

	// Connect to bootnodes
	go s.connectBootnodes()

	s.running = true
	s.config.Logger.Info("bootnode service started")

	return nil
}

// Stop stops the bootnode service.
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return fmt.Errorf("service not running")
	}
	s.running = false
	s.mu.Unlock()

	// Stop protocol services (one discv5 service per identity)
	for _, id := range s.identities {
		if id.discv5Service != nil {
			id.discv5Service.Stop()
		}
	}
	if s.discv4Service != nil {
		s.discv4Service.Stop()
	}

	// Close transports (identities may share one socket, so dedupe)
	closed := make(map[*transport.UDPTransport]bool)
	for _, id := range s.identities {
		if id.transport != nil && !closed[id.transport] {
			id.transport.Close()
			closed[id.transport] = true
		}
	}

	// Cancel context to stop background tasks
	s.cancel()

	// Close databases
	if s.elNodeDB != nil {
		s.elNodeDB.Close()
	}
	if s.clNodeDB != nil {
		s.clNodeDB.Close()
	}

	s.config.Logger.Info("bootnode service stopped")
	return nil
}

// maintenanceLoop runs periodic maintenance tasks.
func (s *Service) maintenanceLoop() {
	tableMaintenance := time.NewTicker(5 * time.Minute)
	alivenessCheck := time.NewTicker(s.config.PingInterval)
	randomWalk := time.NewTicker(30 * time.Second)
	supportCheck := time.NewTicker(30 * time.Minute)     // Check protocol support every 30 minutes
	badNodesCleanup := time.NewTicker(24 * time.Hour)    // Cleanup bad nodes once per day
	enrRequestCleanup := time.NewTicker(1 * time.Minute) // Cleanup stale ENR requests every minute

	// Fork fields are re-published on a timer armed for the next boundary rather
	// than polled: peers see the transition immediately and re-request our record,
	// so a free-running tick left us advertising the previous fork for up to its
	// full period. forkReconcile is the backstop for a missing schedule, a clock
	// jump, or a boundary that passed while we were starting.
	forkRefresh := time.NewTimer(s.nextForkRefreshDelay())
	forkReconcile := time.NewTicker(1 * time.Minute)

	defer tableMaintenance.Stop()
	defer alivenessCheck.Stop()
	defer randomWalk.Stop()
	defer supportCheck.Stop()
	defer badNodesCleanup.Stop()
	defer enrRequestCleanup.Stop()
	defer forkRefresh.Stop()
	defer forkReconcile.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return

		case <-tableMaintenance.C:
			s.performTableMaintenance()

		case <-alivenessCheck.C:
			s.performAlivenessCheck()

		case <-randomWalk.C:
			s.performRandomWalk()

		case <-supportCheck.C:
			s.performProtocolSupportCheck()

		case <-badNodesCleanup.C:
			s.performBadNodesCleanup()

		case <-enrRequestCleanup.C:
			s.cleanupStaleENRRequests()

		case <-forkRefresh.C:
			s.refreshForkENR()
			forkRefresh.Reset(s.nextForkRefreshDelay())

		case <-forkReconcile.C:
			// Refresh before recomputing: if a boundary was missed, this is what
			// corrects the record, and the delay must be measured from now.
			s.refreshForkENR()
			if !forkRefresh.Stop() {
				select {
				case <-forkRefresh.C:
				default:
				}
			}
			forkRefresh.Reset(s.nextForkRefreshDelay())
		}
	}
}

// forkRefreshLead re-publishes just after a boundary, once the new fork is what
// the clock reports.
const forkRefreshLead = 500 * time.Millisecond

// maxForkRefreshDelay caps the wait so a schedule that yields no future boundary
// still reaches refreshForkENR at the old cadence.
const maxForkRefreshDelay = time.Minute

// forkSettleWindow is how long after a boundary the refresh keeps polling.
//
// A boundary that has just passed is skipped by nextForkBoundary, so arming for
// the following one leaves a full maxForkRefreshDelay hole: a fire landing on the
// boundary before the digest is computable finds no change and does not look
// again for a minute. A devnet BPO transition took 75s that way. Polling until
// the change appears bounds the lag to forkSettlePoll instead.
const forkSettleWindow = 90 * time.Second

// forkSettlePoll is the retry interval inside forkSettleWindow.
const forkSettlePoll = time.Second

// nextForkRefreshDelay returns how long to wait before the next refresh attempt.
func (s *Service) nextForkRefreshDelay() time.Duration {
	now := time.Now()

	if last, ok := s.lastForkBoundary(now); ok && now.Sub(last) < forkSettleWindow {
		return forkSettlePoll
	}

	next, ok := s.nextForkBoundary(now)
	if !ok {
		return maxForkRefreshDelay
	}

	delay := next.Sub(now) + forkRefreshLead
	if delay < time.Millisecond {
		delay = time.Millisecond
	}
	if delay > maxForkRefreshDelay {
		delay = maxForkRefreshDelay
	}
	return delay
}

// forkOffsetSeconds returns seconds from genesis to an epoch, reporting false if
// any step would overflow. Each multiplication is checked before it happens: a
// placeholder epoch or an absurd slot length would otherwise wrap, and dividing
// by an already-wrapped product panics.
func forkOffsetSeconds(epoch, slotsPerEpoch, secondsPerSlot uint64) (uint64, bool) {
	if slotsPerEpoch == 0 || secondsPerSlot == 0 {
		return 0, false
	}
	if slotsPerEpoch > math.MaxUint64/secondsPerSlot {
		return 0, false
	}
	epochSeconds := slotsPerEpoch * secondsPerSlot
	if epoch > math.MaxUint64/epochSeconds {
		return 0, false
	}
	return epoch * epochSeconds, true
}

// nextForkBoundary returns the earliest CL or EL fork activation after now.
func (s *Service) nextForkBoundary(now time.Time) (time.Time, bool) {
	var next time.Time
	found := false

	s.eachForkBoundary(func(t time.Time) {
		if !t.After(now) {
			return
		}
		if !found || t.Before(next) {
			next = t
			found = true
		}
	})

	return next, found
}

// lastForkBoundary returns the most recent CL or EL fork activation at or before
// now, so a refresh can keep polling until the transition is observable.
func (s *Service) lastForkBoundary(now time.Time) (time.Time, bool) {
	var last time.Time
	found := false

	s.eachForkBoundary(func(t time.Time) {
		if t.After(now) {
			return
		}
		if !found || t.After(last) {
			last = t
			found = true
		}
	})

	return last, found
}

// eachForkBoundary calls fn with every scheduled fork activation time.
func (s *Service) eachForkBoundary(consider func(time.Time)) {
	if cfg := s.config.CLConfig; cfg != nil {
		genesis := cfg.GetGenesisTime()
		slotsPerEpoch := cfg.GetSlotsPerEpoch()
		secondsPerSlot := cfg.SecondsPerSlot
		if genesis > 0 && slotsPerEpoch > 0 && secondsPerSlot > 0 {
			for _, epoch := range cfg.ForkEpochs() {
				offset, ok := forkOffsetSeconds(epoch, slotsPerEpoch, secondsPerSlot)
				// Bound offset first: MaxInt64-offset is unsigned arithmetic and
				// would wrap for an offset past MaxInt64, letting the guard pass.
				if !ok || offset > math.MaxInt64 || genesis > math.MaxInt64-offset {
					continue
				}
				consider(time.Unix(int64(genesis+offset), 0))
			}
		}
	}

	if s.enrManager != nil {
		if filter := s.enrManager.GetELFilter(); filter != nil {
			for _, fork := range filter.GetAllForkIDsWithNames() {
				// Block-numbered forks have no wall clock; only timestamps do.
				if fork.IsTime && fork.Activation <= math.MaxInt64 {
					consider(time.Unix(int64(fork.Activation), 0))
				}
			}
		}
	}
}

// localIDs returns the node IDs of every discovery identity, so discovery can
// exclude our own records from candidate sets.
func (s *Service) localIDs() [][32]byte {
	ids := make([][32]byte, 0, len(s.identities))
	for _, id := range s.identities {
		if id.localNode != nil {
			ids = append(ids, id.localNode.ID())
		}
	}
	return ids
}

// refreshForkENR re-publishes the eth/eth2 ENR fields when a fork activates
// while running. Nothing else refreshes them, so without this a long-lived
// bootnode keeps advertising a stale fork id past every scheduled transition.
// UpdateENR is a no-op when nothing changed, so the sequence number only moves
// at real transitions.
func (s *Service) refreshForkENR() {
	s.mu.Lock()
	defer s.mu.Unlock()

	headBlock, headTime := StaticHead()

	for _, id := range s.identities {
		if id.localNode == nil || id.enrManager == nil {
			continue
		}
		// Advance the CL accept set first so the recomputed eth2 field carries
		// the new digest.
		if clFilter := id.enrManager.GetCLFilter(); clFilter != nil {
			clFilter.Update()
		}

		changed, err := id.enrManager.UpdateENR(headBlock, headTime)
		if err != nil {
			s.config.Logger.WithError(err).Error("failed to refresh fork fields in ENR")
			continue
		}
		if !changed {
			continue
		}

		s.publishENR(id)
		s.config.Logger.WithField("seq", id.localNode.Record().Seq()).Info("fork transition: re-published ENR fork fields")
	}
}

// publishENR persists an identity's current record and pushes it to every
// service that caches a copy. The discv4 handler answers ENRRESPONSE from its
// own copy, so skipping it would keep serving a stale record. Callers must
// hold s.mu.
func (s *Service) publishENR(id *identity) {
	record := id.localNode.Record()

	if err := s.storeENR(id.storeKey, record); err != nil {
		s.config.Logger.WithError(err).Warn("failed to store updated ENR")
	}
	if id.servesEL && s.discv4Service != nil {
		s.discv4Service.SetLocalENR(record)
	}
}

// performTableMaintenance performs routing table maintenance.
func (s *Service) performTableMaintenance() {
	if s.elTable != nil {
		s.elTable.PerformSweep()
	}
	if s.clTable != nil {
		s.clTable.PerformSweep()
	}
}

// performAlivenessCheck checks node aliveness by pinging a sample of nodes.
func (s *Service) performAlivenessCheck() {
	// Ping a sample from each table
	const sampleSize = 10 // Ping 10 nodes per table per check

	// Ping EL nodes
	if s.elTable != nil && s.elPing() != nil {
		elNodes := s.elTable.GetActiveNodes()
		if len(elNodes) > sampleSize {
			// Shuffle and take sample
			perm := make([]int, len(elNodes))
			for i := range perm {
				perm[i] = i
			}
			for i := range perm {
				j := i + int(time.Now().UnixNano())%(len(perm)-i)
				perm[i], perm[j] = perm[j], perm[i]
			}
			sample := make([]*nodes.Node, sampleSize)
			for i := 0; i < sampleSize; i++ {
				sample[i] = elNodes[perm[i]]
			}
			elNodes = sample
		}

		s.config.Logger.WithField("count", len(elNodes)).WithField("layer", "EL").Debug("pinging nodes")
		s.elPing().PingMultiple(elNodes)
	}

	// Ping CL nodes
	if s.clTable != nil && s.clPing() != nil {
		clNodes := s.clTable.GetActiveNodes()
		if len(clNodes) > sampleSize {
			// Shuffle and take sample
			perm := make([]int, len(clNodes))
			for i := range perm {
				perm[i] = i
			}
			for i := range perm {
				j := i + int(time.Now().UnixNano())%(len(perm)-i)
				perm[i], perm[j] = perm[j], perm[i]
			}
			sample := make([]*nodes.Node, sampleSize)
			for i := 0; i < sampleSize; i++ {
				sample[i] = clNodes[perm[i]]
			}
			clNodes = sample
		}

		s.config.Logger.WithField("count", len(clNodes)).WithField("layer", "CL").Debug("pinging nodes")
		s.clPing().PingMultiple(clNodes)
	}
}

// performRandomWalk performs random walk for discovery.
func (s *Service) performRandomWalk() {
	// Perform random walks for each layer
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	// EL random walk
	if s.elLookupService != nil {
		s.config.Logger.WithField("layer", "EL").Debug("starting random walk")
		nodes, err := s.elLookupService.RandomWalk(ctx)
		if err != nil {
			s.config.Logger.WithError(err).WithField("layer", "EL").Debug("random walk failed")
		} else {
			s.config.Logger.WithField("layer", "EL").WithField("discovered", len(nodes)).Debug("random walk complete")
		}
	}

	// CL random walk
	if s.clLookupService != nil {
		s.config.Logger.WithField("layer", "CL").Debug("starting random walk")
		nodes, err := s.clLookupService.RandomWalk(ctx)
		if err != nil {
			s.config.Logger.WithError(err).WithField("layer", "CL").Debug("random walk failed")
		} else {
			s.config.Logger.WithField("layer", "CL").WithField("discovered", len(nodes)).Debug("random walk complete")
		}
	}
}

// performProtocolSupportCheck checks protocol support for a sample of nodes.
//
// This runs less frequently than aliveness checks (every 30 minutes vs every 30 seconds)
// and tests BOTH v4 and v5 to determine which protocols nodes actually support.
//
// Note: Only checks EL nodes. CL nodes only support discv5, so checking for v4 is wasteful.
func (s *Service) performProtocolSupportCheck() {
	// Sample nodes from each table
	const sampleSize = 10 // Check 10 nodes per table per check

	// Check EL nodes only
	// CL nodes only support discv5, so there's no point in checking for v4 support
	if s.elTable != nil && s.elNodeDB != nil && s.elPing() != nil {
		elNodes := s.elTable.GetRandomActiveNodes(sampleSize)
		if len(elNodes) > 0 {
			s.config.Logger.WithField("count", len(elNodes)).WithField("layer", "EL").Debug("checking protocol support")
			s.elPing().CheckProtocolSupportMultiple(elNodes)

			// Queue protocol support updates for all checked nodes (SetV4/SetV5 already marked them dirty)
			for _, n := range elNodes {
				if err := s.elNodeDB.QueueUpdate(n); err != nil {
					s.config.Logger.WithError(err).WithField("nodeID", n.PeerID()).Debug("failed to queue node for protocol support update")
				}
			}
		}
	}
}

// performBadNodesCleanup removes old entries from the bad nodes table.
// This runs once per day to prevent unbounded growth of the bad nodes list.
func (s *Service) performBadNodesCleanup() {
	if s.config.Database == nil {
		return
	}

	s.config.Logger.Debug("cleaning up old bad nodes")

	// Clean up bad nodes older than 7 days (default recheck interval)
	deletedCount, err := s.config.Database.CleanupOldBadNodes(0)
	if err != nil {
		s.config.Logger.WithError(err).Warn("failed to cleanup old bad nodes")
		return
	}

	if deletedCount > 0 {
		s.config.Logger.WithField("deleted", deletedCount).Info("cleaned up old bad nodes")
	}

	// Log bad nodes statistics
	counts, err := s.config.Database.GetBadNodesCount()
	if err != nil {
		s.config.Logger.WithError(err).Debug("failed to get bad nodes count")
		return
	}

	if len(counts) > 0 {
		s.config.Logger.WithField("counts", counts).Info("bad nodes statistics")
	}
}

// cleanupStaleENRRequests removes stale ENR requests from the pending map.
// This prevents memory leaks from hung or failed requests.
func (s *Service) cleanupStaleENRRequests() {
	now := time.Now()
	staleThreshold := 60 * time.Second // Consider requests stale after 60 seconds
	cleanedCount := 0

	s.pendingENRRequestsV4.Range(func(key, value interface{}) bool {
		if timestamp, ok := value.(time.Time); ok {
			// Delete only the entry we just judged stale: a fresh claim may have
			// replaced it between the Range read and here.
			if now.Sub(timestamp) > staleThreshold && s.pendingENRRequestsV4.CompareAndDelete(key, value) {
				cleanedCount++
			}
		}
		return true // continue iteration
	})

	if cleanedCount > 0 {
		s.config.Logger.WithField("cleaned", cleanedCount).Debug("cleaned up stale ENR requests")
	}
}

// connectBootnodes connects to initial bootnodes.
func (s *Service) connectBootnodes() {
	// Connect to EL bootnodes
	if s.config.HasEL() && len(s.config.ELBootnodes) > 0 {
		s.connectELBootnodes()
	}

	// Connect to CL bootnodes
	if s.config.HasCL() && len(s.config.CLBootnodes) > 0 {
		s.connectCLBootnodes()
	}
}

// connectELBootnodes connects to EL bootnodes (supports both ENR and enode).
func (s *Service) connectELBootnodes() {
	s.config.Logger.WithField("count", len(s.config.ELBootnodes)).Info("connecting to EL bootnodes")

	for _, bootnode := range s.config.ELBootnodes {
		// Try parsing as ENR first
		if record, err := enr.DecodeBase64(bootnode); err == nil {
			s.connectELBootnodeENR(record)
			continue
		}

		// Try parsing as enode
		if enodeURL, err := enode.Parse(bootnode); err == nil {
			s.connectELBootnodeEnode(enodeURL)
			continue
		}

		s.config.Logger.WithField("bootnode", bootnode).Warn("invalid bootnode format")
	}
}

// connectELBootnodeENR connects to an EL bootnode via ENR.
func (s *Service) connectELBootnodeENR(record *enr.Record) {
	// Convert to v5 node; this also rejects records missing an IP or UDP port.
	v5, err := v5node.New(record)
	if err != nil {
		s.config.Logger.WithError(err).Warn("failed to create v5 node from ENR")
		return
	}

	// Filter by fork ID before adding. Serve-all must not drop a configured seed:
	// rejecting the only seed leaves the table empty, so discovery never starts.
	if !s.config.ServeAll && s.enrManager != nil {
		isEL, forkID := s.enrManager.AdmitELNode(record)
		if !isEL {
			s.config.Logger.WithFields(logrus.Fields{
				"nodeID": fmt.Sprintf("%x", v5.ID().Bytes()[:8]),
				"eth":    forkID,
			}).Warn("bootnode ENR has invalid fork ID, skipping")
			return
		}
	}

	genericNode := nodes.NewFromV5(v5, s.elNodeDB)
	s.addBootnodeToTable(s.elTable, s.elNodeDB, genericNode, s.config.Logger.WithField("layer", "EL"))
}

// connectELBootnodeEnode connects to an EL bootnode via enode URL.
//
// This requires performing an ENR request via discv4 first.
func (s *Service) connectELBootnodeEnode(enodeURL *enode.Enode) {
	if s.discv4Service == nil {
		s.config.Logger.Warn("discv4 disabled, cannot connect to enode bootnode")
		return
	}

	// Create v4 node from enode
	v4Node, err := v4node.FromEnode(enodeURL)
	if err != nil {
		s.config.Logger.WithError(err).Warn("failed to create v4 node from enode")
		return
	}

	nodeID := v4Node.ID()

	// Never dial ourselves: our own enode in the bootnode list would otherwise
	// race our handshake challenges against our own identity.
	if slices.Contains(s.localIDs(), [32]byte(nodeID)) {
		s.config.Logger.WithField("enode", enodeURL).Debug("skipping bootnode: it is our own identity")
		return
	}

	// Request ENR from the node
	s.config.Logger.WithField("enode", enodeURL).Debug("requesting ENR from enode bootnode")
	enrRecord, err := s.discv4Service.RequestENR(v4Node)
	if err != nil {
		s.config.Logger.WithError(err).Warn("failed to request ENR from enode bootnode, skipping")
		return
	}

	// Set the ENR on the node
	v4Node.SetENR(enrRecord)

	// Filter by fork ID before adding
	if !s.config.ServeAll && s.enrManager != nil {
		isEL, forkID := s.enrManager.AdmitELNode(enrRecord)
		if !isEL {
			s.config.Logger.WithFields(logrus.Fields{
				"nodeID": fmt.Sprintf("%x", nodeID[:8]),
				"eth":    forkID,
			}).Warn("enode bootnode has invalid fork ID, skipping")
			return
		}
	}

	// Create generic node and add to table
	genericNode := nodes.NewFromV4(v4Node, s.elNodeDB)

	// Track successful ENR exchange
	genericNode.IncrementSuccess()

	s.addBootnodeToTable(s.elTable, s.elNodeDB, genericNode,
		s.config.Logger.WithField("layer", "EL").WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])))
}

// connectCLBootnodes connects to CL bootnodes (ENR only).
func (s *Service) connectCLBootnodes() {
	s.config.Logger.WithField("count", len(s.config.CLBootnodes)).Info("connecting to CL bootnodes")

	for _, bootnode := range s.config.CLBootnodes {
		record, err := enr.DecodeBase64(bootnode)
		if err != nil {
			s.config.Logger.WithField("bootnode", bootnode).WithError(err).Warn("invalid ENR")
			continue
		}

		// Convert to v5 node; this also rejects records missing an IP or UDP port.
		v5, err := v5node.New(record)
		if err != nil {
			s.config.Logger.WithError(err).Warn("failed to create v5 node from ENR")
			continue
		}

		nodeID := v5.ID()

		// Filter by fork digest before adding
		if !s.config.ServeAll && s.enrManager != nil && !s.enrManager.AdmitCLNode(record) {
			s.config.Logger.WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Warn("CL bootnode ENR has invalid fork digest, skipping")
			continue
		}

		genericNode := nodes.NewFromV5(v5, s.clNodeDB)
		s.addBootnodeToTable(s.clTable, s.clNodeDB, genericNode,
			s.config.Logger.WithField("layer", "CL").WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])))
	}
}

// addBootnodeToTable admits a configured bootnode to a routing table and
// persists it.
func (s *Service) addBootnodeToTable(table *nodes.FlatTable, nodeDB *nodes.NodeDB, n *nodes.Node, logger logrus.FieldLogger) {
	if table == nil {
		return
	}
	if !table.Add(n) {
		logger.Debug("bootnode not admitted to table, not persisting")
		return
	}
	logger.Info("added bootnode to table")

	if nodeDB != nil {
		n.MarkDirty(nodes.DirtyFull)
		if err := nodeDB.QueueUpdate(n); err != nil {
			logger.WithError(err).Debug("failed to queue bootnode for database update")
		}
	}
}

// loadStoredENR loads the stored ENR from database.
func (s *Service) loadStoredENR(key string) (*enr.Record, error) {
	data, err := s.config.Database.GetState(key)
	if err != nil {
		return nil, err
	}

	return enr.Load(data)
}

// storeENR stores an identity's ENR to the database under its state key.
func (s *Service) storeENR(key string, record *enr.Record) error {
	data, err := record.EncodeRLPBytes()
	if err != nil {
		return err
	}

	return s.config.Database.SetState(nil, key, data)
}

// Callbacks for discv5

func (s *Service) onHandshakeComplete(n *v5node.Node, incoming bool) {
	s.checkAndAddNode(n)
}

func (s *Service) onNodeUpdate(n *v5node.Node) {
	s.checkAndAddNode(n)
}

func (s *Service) onNodeSeen(n *v5node.Node, timestamp time.Time) {
	// Determine layer and update appropriate database
	if s.enrManager != nil {
		nodeID := n.ID()

		// Both layers, independently, as checkAndAddNode admits them: a dual-layer
		// record becomes two node objects with their own last-seen, so refreshing
		// only one lets the other age out while the peer is actively talking.
		var isEL, isCL bool
		if s.config.ServeAll {
			isEL = s.elTable != nil
			isCL = s.clTable != nil
		} else {
			isEL, _ = s.enrManager.ClassifyELNode(n.Record())
			isCL = s.enrManager.ClassifyCLNode(n.Record())
		}

		if isEL && s.elTable != nil && s.elNodeDB != nil {
			if genericNode := s.elTable.Get(nodeID); genericNode != nil {
				genericNode.SetLastSeen(timestamp) // This marks it dirty
				// Get falls back to the DB, so Add re-admits demoted nodes
				s.elTable.Add(genericNode)
				s.elNodeDB.QueueUpdate(genericNode)
			}
		}
		if isCL && s.clTable != nil && s.clNodeDB != nil {
			if genericNode := s.clTable.Get(nodeID); genericNode != nil {
				genericNode.SetLastSeen(timestamp) // This marks it dirty
				s.clTable.Add(genericNode)
				s.clNodeDB.QueueUpdate(genericNode)
			}
		}
	}
}

func (s *Service) onFindNodeV5(id *identity, msg *v5protocol.FindNode, sourceNode *v5node.Node, requester *net.UDPAddr) []*v5node.Node {
	// Distances are relative to the node ID the peer dialed.
	var allNodes []*nodes.Node
	localID := id.localNode.ID()

	serveEL := id.servesEL
	serveCL := id.servesCL

	// A shared identity serves both layers under one ID, so classify a known
	// requester by its ENR and serve only its layer(s); an unclassifiable known
	// peer gets nothing, an unknown one (no ENR yet) falls through to both.
	// Serve-all skips this: every requester gets nodes from every served layer.
	if !s.config.ServeAll && id.servesEL && id.servesCL && sourceNode != nil && s.enrManager != nil {
		sourceRecord := sourceNode.Record()
		serveEL, _ = s.enrManager.ClassifyELNode(sourceRecord)
		serveCL = s.enrManager.ClassifyCLNode(sourceRecord)
	}

	if serveEL && s.elTable != nil {
		allNodes = append(allNodes, s.elTable.GetNodesByDistance(localID, msg.Distances, 8)...)
	}
	if serveCL && s.clTable != nil {
		allNodes = append(allNodes, s.clTable.GetNodesByDistance(localID, msg.Distances, 8)...)
	}

	// Filter nodes based on protocol support (only return v5-capable nodes)
	// and apply LAN-aware filtering
	filteredNodes := s.filterNodesForRequester(allNodes, requester, true)

	// Convert to v5 nodes
	v5Nodes := make([]*v5node.Node, 0, len(filteredNodes))
	for _, n := range filteredNodes {
		if v5 := n.V5(); v5 != nil {
			v5Nodes = append(v5Nodes, v5)
		}
	}

	return v5Nodes
}

// Callbacks for discv4

func (s *Service) onNodeSeenV4(n *v4node.Node, timestamp time.Time) {
	// Check if node is already in table
	if s.elTable != nil && s.elNodeDB != nil {
		// Look up the generic node from the table
		if genericNode := s.elTable.Get(n.ID()); genericNode != nil {
			genericNode.SetLastSeen(timestamp) // This marks it dirty
			s.elNodeDB.QueueUpdate(genericNode)

			// A known node still needs its record re-checked. PONG triggers an
			// ENR refresh on the handler's node, but nothing propagates that to
			// the table, so without this the table serves the peer's pre-fork
			// record for the rest of its lifetime.
			if rec := n.ENR(); rec != nil && rec.Seq() > genericNode.Record().Seq() {
				s.checkAndAddNodeV4(n)
			}
			return
		}

		// Node doesn't exist yet
		// For discv4, we need to request the ENR before we can filter/add the node
		// Check if the node has an ENR already (from ENRRESPONSE)
		if n.ENR() != nil {
			// We have the ENR, try to add it
			s.checkAndAddNodeV4(n)
		} else {
			// No ENR yet, request it
			// The node will be added when we receive the ENRRESPONSE
			s.requestENRV4(n)
		}
	}
}

func (s *Service) onFindNodeV4(from *v4node.Node, target []byte, requester *net.UDPAddr) []*v4node.Node {
	// Only return EL nodes for discv4 requests
	if s.elTable == nil {
		return nil
	}

	// Convert target to [32]byte
	var targetID [32]byte
	copy(targetID[:], target)

	// For v4, we find closest nodes to the target
	allNodes := s.elTable.FindClosestNodes(targetID, 16)

	// Filter for v4 support and LAN-aware filtering
	filteredNodes := s.filterNodesForRequester(allNodes, requester, false)

	// Convert to v4 nodes
	v4Nodes := make([]*v4node.Node, 0, len(filteredNodes))
	for _, n := range filteredNodes {
		if v4 := n.V4(); v4 != nil {
			v4Nodes = append(v4Nodes, v4)
		}
	}

	return v4Nodes
}

// requestENRV4 sends an ENRREQUEST to a discv4 node and tries to add it.
// This runs in a goroutine to avoid blocking the packet handler.
func (s *Service) requestENRV4(n *v4node.Node) {
	if s.discv4Service == nil {
		return
	}

	nodeID := n.ID()
	now := time.Now()

	// Claim the slot atomically: a Load followed by a Store lets two callers both
	// through, and takeover of an entry older than 30s has to stay possible, so a
	// bare LoadOrStore is not enough either.
	for {
		val, loaded := s.pendingENRRequestsV4.LoadOrStore(nodeID, now)
		if !loaded {
			break
		}
		timestamp, ok := val.(time.Time)
		if ok && time.Since(timestamp) < 30*time.Second {
			return
		}
		if s.pendingENRRequestsV4.CompareAndSwap(nodeID, val, now) {
			break
		}
	}

	// Run in goroutine to avoid blocking packet handling
	go func() {
		// Release only our own claim: an unconditional delete would drop the entry
		// of whoever took over after our 30s window expired.
		defer s.pendingENRRequestsV4.CompareAndDelete(nodeID, now)

		// IMPORTANT: Some clients (like reth) require bidirectional bonding before responding to ENRRequest.
		// Bidirectional bonding means:
		// 1. They ping us, we pong them (already done when we received their PING)
		// 2. We ping them, they pong us (RequestENR will do this if not bonded)
		//
		// RequestENR() automatically checks bond status and will ping the node if needed,
		// then waits for their PONG before sending the ENRRequest.
		enrRecord, err := s.discv4Service.RequestENR(n)
		if err != nil {
			s.config.Logger.WithFields(logrus.Fields{
				"nodeID": fmt.Sprintf("%x", n.IDBytes()[:8]),
				"error":  err,
			}).Debug("Failed to request ENR from discv4 node")
			return
		}

		s.config.Logger.WithFields(logrus.Fields{
			"nodeID": fmt.Sprintf("%x", n.IDBytes()[:8]),
			"addr":   n.Addr().String(),
			"enrSeq": enrRecord.Seq(),
		}).Debug("Received ENR from discv4 node")

		// Node now has the ENR, try to add it
		s.checkAndAddNodeV4(n)
	}()
}

// admitELLookupNode decides admission of a lookup-discovered node to the EL
// table.
func (s *Service) admitELLookupNode(n *nodes.Node) services.AdmissionResult {
	if !s.config.ServeAll && n.Record() != nil && s.enrManager != nil {
		isEL, forkID := s.enrManager.AdmitELNode(n.Record())
		if !isEL {
			// A record with no eth entry is a consensus node, not an
			// execution node on the wrong fork.
			if !n.Record().Has("eth") {
				s.markBadNode(n, db.LayerEL, "not_el")
				return services.AdmissionRejectedLayer
			}
			s.config.Logger.WithFields(logrus.Fields{
				"peerID": n.PeerID(),
				"eth":    forkID.String(),
			}).Debug("EL lookup admission rejected: incompatible fork id")
			s.markBadNode(n, db.LayerEL, "invalid_fork_id")
			return services.AdmissionRejectedFilter
		}
	}

	result := s.admitToTable(n, s.elTable, db.LayerEL)

	// After admission, and off this goroutine: each probe waits a request timeout,
	// so probing a 16-node NEIGHBORS response inline stalled the lookup and the
	// whole maintenance loop for over a minute. Resolving the table entry rather
	// than reusing n also means the result lands on the object the table kept.
	if result == services.AdmissionAccepted && n.HasV4() && !n.HasV5() {
		s.scheduleV5Probe(n.ID())
	}

	return result
}

// admitCLLookupNode decides admission of a lookup-discovered node to the CL
// table.
func (s *Service) admitCLLookupNode(n *nodes.Node) services.AdmissionResult {
	if !s.config.ServeAll && n.Record() != nil && s.enrManager != nil {
		if !s.enrManager.AdmitCLNode(n.Record()) {
			// No eth2 entry means an execution node, not a consensus
			// node on the wrong digest; keep the two distinguishable.
			if !n.Record().Has("eth2") {
				s.markBadNode(n, db.LayerCL, "not_cl")
				return services.AdmissionRejectedLayer
			}
			s.markBadNode(n, db.LayerCL, "invalid_fork_digest")
			return services.AdmissionRejectedFilter
		}
	}

	return s.admitToTable(n, s.clTable, db.LayerCL)
}

// markBadNode records a rejected node so it is not retried on restart.
func (s *Service) markBadNode(n *nodes.Node, layer db.NodeLayer, reason string) {
	if err := s.config.Database.StoreBadNode(n.IDBytes(), layer, reason); err != nil {
		s.config.Logger.WithError(err).Debug("failed to store bad node")
	}
}

// admitToTable pools an accepted node and clears any prior bad-node record.
func (s *Service) admitToTable(n *nodes.Node, table *nodes.FlatTable, layer db.NodeLayer) services.AdmissionResult {
	if !table.Add(n) {
		return services.AdmissionRejectedPool
	}
	if err := s.config.Database.RemoveBadNode(n.IDBytes(), layer); err != nil {
		s.config.Logger.WithError(err).Debug("failed to remove from bad nodes")
	}
	return services.AdmissionAccepted
}

// probeV5Support pings a v4-discovered node over discv5 and, on success,
// attaches v5 support so lookups prefer the richer protocol.
// maxConcurrentV5Probes bounds the probes in flight so a large NEIGHBORS response
// cannot spawn one goroutine per node.
const maxConcurrentV5Probes = 8

// scheduleV5Probe runs a v5 probe for an admitted node without blocking the
// caller. Dropping the probe when saturated is fine: the node stays v4-only and
// the next lookup that rediscovers it tries again.
//
// The table entry decides, not the wrapper the caller happened to hold: after a
// merge the entry may already know v5, and re-probing it on every rediscovery
// would occupy the slots that genuinely v4-only nodes need.
func (s *Service) scheduleV5Probe(id [32]byte) {
	if s.elTable == nil {
		return
	}
	entry := s.elTable.Get(id)
	if entry == nil || entry.HasV5() {
		return
	}
	if _, inFlight := s.v5ProbesInFlight.LoadOrStore(id, struct{}{}); inFlight {
		return
	}

	select {
	case s.v5ProbeSem <- struct{}{}:
	default:
		s.v5ProbesInFlight.Delete(id)
		return
	}

	go func() {
		defer func() {
			<-s.v5ProbeSem
			s.v5ProbesInFlight.Delete(id)
		}()
		s.probeV5Support(id, entry)
	}()
}

// probeV5Support pings a v4-discovered node over discv5 and records the result on
// whichever wrapper the table holds when the answer arrives — the entry can be
// swept or replaced during the round trip, and writing to a detached object would
// silently lose the capability.
func (s *Service) probeV5Support(id [32]byte, n *nodes.Node) {
	handler := s.getV5Handler()
	if handler == nil {
		return
	}
	record := n.Record()
	if record == nil {
		return
	}
	probedSeq := record.Seq()
	v5Node, err := nodes.NewV5NodeFromRecord(record)
	if err != nil {
		return
	}

	start := time.Now()
	respChan, err := handler.SendPing(v5Node)
	if err != nil {
		return
	}
	var resp *v5protocol.Response
	select {
	case resp = <-respChan:
	case <-s.ctx.Done():
		return
	}
	if resp == nil || resp.Error != nil {
		return
	}

	// Re-resolve: this is the first moment the result can be applied, and the
	// entry may have been swept or replaced while the ping was outstanding.
	// SetV5AtSeq then discards the result if the peer moved on from the record we
	// probed, rather than pinning v5 traffic to the address we happened to test.
	target := s.elTable.Get(id)
	if target == nil {
		return
	}
	n = target

	if !n.SetV5AtSeq(v5Node, probedSeq) {
		return
	}
	s.config.Logger.WithFields(logrus.Fields{
		"peerID": n.PeerID(),
		"addr":   n.Addr(),
		"rtt":    time.Since(start),
	}).Debug("discovered v5 support on v4-discovered node")

	// Queue protocol support update (SetV5 already marked it dirty)
	if s.elNodeDB != nil {
		if err := s.elNodeDB.QueueUpdate(n); err != nil {
			s.config.Logger.WithError(err).Debug("failed to queue node for protocol support update")
		}
	}
}

// checkAndAddNodeV4 adds a discv4 node to the EL table after filtering.
func (s *Service) checkAndAddNodeV4(n *v4node.Node) bool {
	// Ensure we have an ENR for filtering
	if n.ENR() == nil {
		s.config.Logger.WithFields(logrus.Fields{
			"nodeID": fmt.Sprintf("%x", n.IDBytes()[:8]),
		}).Debug("Cannot add discv4 node without ENR")
		return false
	}

	// discv4 nodes go to EL table
	if s.elTable == nil {
		return false
	}

	// A node already in the table still needs its record re-checked: Add()
	// installs a newer ENR, which is how a peer's post-fork eth entry reaches
	// the table. Returning early here left the pre-fork record in place and
	// served it to every FINDNODE querier.
	alreadyKnown := s.elTable.Get(n.ID()) != nil

	// Filter the node using ENR manager (EL-only for discv4)
	if !s.config.ServeAll && s.enrManager != nil {
		filter, forkID := s.enrManager.AdmitELNode(n.ENR())
		if !filter {
			s.config.Logger.WithFields(logrus.Fields{
				"nodeID": fmt.Sprintf("%x", n.IDBytes()[:8]),
				"remote": n.Addr().String(),
				"eth":    forkID,
			}).Debug("Discv4 node filtered out (wrong fork or not EL)")
			return false
		}
	}

	// Create generic node from v4 node
	genericNode := nodes.NewFromV4(n, s.elNodeDB)

	// Try to add to table
	if s.elTable.Add(genericNode) {
		if !alreadyKnown {
			s.config.Logger.WithFields(logrus.Fields{
				"nodeID": fmt.Sprintf("%x", n.IDBytes()[:8]),
				"addr":   n.Addr().String(),
			}).Debug("Added discv4 node to EL table")
		}
		return true
	}

	return false
}

// checkAndAddNode performs admission checks and adds node to appropriate table.
func (s *Service) checkAndAddNode(n *v5node.Node) bool {
	if s.enrManager == nil {
		return false
	}

	// Serve-all skips the filters rather than overriding their results: calling
	// them would move admission counters for decisions never made.
	var isEL, isCL bool
	if s.config.ServeAll {
		isEL = s.elTable != nil
		isCL = s.clTable != nil
	} else {
		isEL, _ = s.enrManager.AdmitELNode(n.Record())
		isCL = s.enrManager.AdmitCLNode(n.Record())
	}

	// Add to appropriate table(s)
	added := false
	if isEL && s.elTable != nil {
		genericNode := nodes.NewFromV5(n, s.elNodeDB)
		if s.elTable.Add(genericNode) {
			added = true
		}
	}
	if isCL && s.clTable != nil {
		genericNode := nodes.NewFromV5(n, s.clNodeDB)
		if s.clTable.Add(genericNode) {
			added = true
		}
	}

	return added
}

// filterNodesForRequester applies LAN-aware and protocol filtering. It is the
// single funnel for both protocols' FINDNODE responses, so it also enforces
// that a response never repeats a node ID — a node can sit in both tables (any
// dual-stack peer, and every peer under serve-all).
func (s *Service) filterNodesForRequester(nodeList []*nodes.Node, requester *net.UDPAddr, needsV5 bool) []*nodes.Node {
	requesterIsLAN := v5node.IsLANAddress(requester.IP)

	filtered := make([]*nodes.Node, 0, len(nodeList))
	for _, n := range nodeList {
		// Check protocol support
		if needsV5 && !n.HasV5() {
			continue
		}
		if !needsV5 && !n.HasV4() {
			continue
		}

		// Apply LAN-aware filtering
		nodeIP := n.Record().IP()
		if nodeIP == nil {
			nodeIP = n.Record().IP6()
		}
		if nodeIP == nil {
			continue
		}

		// WAN requesters only get WAN nodes
		if !requesterIsLAN && v5node.IsLANAddress(nodeIP) {
			continue
		}

		id := n.ID()
		if slices.ContainsFunc(filtered, func(kept *nodes.Node) bool { return kept.ID() == id }) {
			continue
		}

		filtered = append(filtered, n)
	}

	return filtered
}

// LocalNode returns the primary identity's local node.
func (s *Service) LocalNode() *v5node.Node {
	return s.localNode
}

// StartTime returns when the service started running.
func (s *Service) StartTime() time.Time {
	return s.startTime
}

// ELLocalNode returns the EL identity's local node (nil if EL disabled).
func (s *Service) ELLocalNode() *v5node.Node {
	if id := s.elIdentity(); id != nil {
		return id.localNode
	}
	return nil
}

// CLLocalNode returns the CL identity's local node (nil if CL disabled).
func (s *Service) CLLocalNode() *v5node.Node {
	if id := s.clIdentity(); id != nil {
		return id.localNode
	}
	return nil
}

// HasSeparateIdentities reports whether EL and CL run under distinct node IDs.
func (s *Service) HasSeparateIdentities() bool {
	return s.elIdentity() != nil && s.clIdentity() != nil && s.elIdentity() != s.clIdentity()
}

// strippedENR returns the base64 ENR for the given identity's node with the named
// fields removed and the record re-signed by that identity's key. The live
// sequence number is kept deliberately: a peer seeded from this record keeps it
// (discv5 only adopts a strictly-higher seq), so the stripped fields stay absent
// for that peer rather than being overwritten by the next live update.
func (s *Service) strippedENR(node *v5node.Node, drop ...string) (string, error) {
	if node == nil {
		return "", fmt.Errorf("nil node")
	}
	for _, id := range s.identities {
		if id.localNode != node {
			continue
		}
		rec, err := node.Record().Clone()
		if err != nil {
			return "", err
		}
		for _, key := range drop {
			rec.Delete(key)
		}
		if err := rec.Sign(id.key); err != nil {
			return "", err
		}
		return rec.EncodeBase64()
	}
	return "", fmt.Errorf("no identity for node")
}

// GenericENR returns the base64 ENR for the given identity's node with the fork
// fields (eth/eth2) removed. This is the record to commit to static bootnode
// lists, which omit fork filtering so the bootnode is accepted regardless of the
// client's fork state; the bootnode still advertises the full fork-filtered ENR
// for live discovery.
func (s *Service) GenericENR(node *v5node.Node) (string, error) {
	return s.strippedENR(node, "eth", "eth2")
}

// ELENR returns the EL identity's ENR with the CL-only eth2 field removed — the
// record to hand to EL clients, some of which reject an ENR carrying eth2. In
// shared-key mode this strips eth2 from the combined record; with separate keys
// the EL record already omits eth2, so the strip is a no-op. Empty if EL is
// disabled.
func (s *Service) ELENR() (string, error) {
	node := s.ELLocalNode()
	if node == nil {
		return "", fmt.Errorf("EL not enabled")
	}
	return s.strippedENR(node, "eth2")
}

// CLENR returns the CL identity's ENR with the EL-only eth field removed. Empty
// if CL is disabled. See ELENR for the shared- vs separate-key behavior.
func (s *Service) CLENR() (string, error) {
	node := s.CLLocalNode()
	if node == nil {
		return "", fmt.Errorf("CL not enabled")
	}
	return s.strippedENR(node, "eth")
}

// ELTable returns the EL routing table (may be nil if EL disabled).
func (s *Service) ELTable() *nodes.FlatTable {
	return s.elTable
}

// CLTable returns the CL routing table (may be nil if CL disabled).
func (s *Service) CLTable() *nodes.FlatTable {
	return s.clTable
}

// ELNodeDB returns the EL node database (may be nil if EL disabled).
func (s *Service) ELNodeDB() *nodes.NodeDB {
	return s.elNodeDB
}

// CLNodeDB returns the CL node database (may be nil if CL disabled).
func (s *Service) CLNodeDB() *nodes.NodeDB {
	return s.clNodeDB
}

// ELConfig returns the EL chain configuration (may be nil if EL disabled).
func (s *Service) ELConfig() *elconfig.ChainConfig {
	if s.config == nil {
		return nil
	}
	return s.config.ELConfig
}

// CLConfig returns the CL beacon chain configuration (may be nil if CL disabled).
func (s *Service) CLConfig() *clconfig.Config {
	if s.config == nil {
		return nil
	}
	return s.config.CLConfig
}

// ENRManager returns the ENR manager.
func (s *Service) ENRManager() *ENRManager {
	return s.enrManager
}

// getV5Handler returns the discv5 protocol handler (may be nil).
func (s *Service) getV5Handler() *v5protocol.Handler {
	if s.discv5Service != nil {
		return s.discv5Service.Handler()
	}
	return nil
}

// getV4Service returns the discv4 service (may be nil).
func (s *Service) getV4Service() *discv4.Service {
	return s.discv4Service
}

// onPongReceived handles PONG responses from both discv4 and discv5.
// It reports the external IP/port to the IP discovery service.
func (s *Service) onPongReceived(remoteID []byte, sourceIP net.IP, reportedIP net.IP, reportedPort uint16) {
	if s.ipDiscovery == nil {
		return
	}

	// Split sockets observe different external ports, which would split the
	// IP-discovery vote across IP:port buckets and prevent consensus. Bucket
	// them under one port instead; the per-identity advertised port is applied
	// in updateENRWithDiscoveredIP, which ignores the discovered port when
	// identities don't share a socket.
	port := reportedPort
	if !s.singleSocket() {
		port = s.primaryIdentity().enrPort
	}

	// The full ID, not a prefix: this keys the distinct-reporter threshold, so a
	// truncated key would let two peers count as one.
	s.ipDiscovery.ReportIP(reportedIP, port, fmt.Sprintf("%x", remoteID), sourceIP)
}

// updateENRWithDiscoveredIP updates every identity's ENR with the discovered IP.
func (s *Service) updateENRWithDiscoveredIP(ip net.IP, port uint16, isIPv6 bool) {
	// An explicitly configured address is authoritative (see Config.ENRIPProvided),
	// so peer reports must not move it. reconcileStoredENR already honours this at
	// startup; without the same check here a configured address is overwritten
	// while running and only restored on restart.
	if isIPv6 && s.config.ENRIP6Provided {
		return
	}
	if !isIPv6 && s.config.ENRIPProvided {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// The discovered port can only be attributed to a layer when all identities
	// share one socket; otherwise each keeps its configured port.
	sharedSocket := s.singleSocket()

	for _, id := range s.identities {
		if id.localNode == nil {
			continue
		}

		advPort := id.enrPort
		if sharedSocket {
			advPort = port
		}

		current := id.localNode.Record()
		var err error
		if isIPv6 {
			if curIP := current.IP6(); curIP != nil && curIP.Equal(ip) && current.UDP6() == advPort {
				continue
			}
			err = id.enrManager.UpdateENRWithIP6(ip, advPort)
		} else {
			if curIP := current.IP(); curIP != nil && curIP.Equal(ip) && current.UDP() == advPort {
				continue
			}
			err = id.enrManager.UpdateENRWithIP(ip, advPort)
		}
		if err != nil {
			s.config.Logger.WithError(err).Error("failed to update ENR with discovered IP")
			continue
		}

		s.config.Logger.WithFields(map[string]interface{}{
			"ip":     ip.String(),
			"port":   advPort,
			"isIPv6": isIPv6,
		}).Info("IP discovery: consensus reached, updated ENR")

		s.publishENR(id)
	}
}
