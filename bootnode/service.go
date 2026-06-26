package bootnode

import (
	"context"
	"fmt"
	"net"
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
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
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
	for _, id := range s.identities {
		if transports[id.bindPort] == nil {
			listenAddr := fmt.Sprintf("%s:%d", cfg.BindIP.String(), id.bindPort)
			t, terr := transport.NewUDPTransport(&transport.Config{ListenAddr: listenAddr, Logger: cfg.Logger})
			if terr != nil {
				closeTransports()
				return nil, fmt.Errorf("failed to create UDP transport on port %d: %w", id.bindPort, terr)
			}
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
			closeTransports()
			return nil, fmt.Errorf("failed to create local node: %w", nerr)
		}
		id.localNode = localNode

		if serr := s.storeENR(id.storeKey, localNode.Record()); serr != nil {
			cfg.Logger.WithError(serr).Warn("failed to store initial ENR")
		}

		id.enrManager = NewENRManager(cfg, id.key, localNode, id.servesEL, id.servesCL)
		if uerr := id.enrManager.UpdateENR(0, 0); uerr != nil {
			cfg.Logger.WithError(uerr).Warn("failed to update ENR with eth/eth2 fields")
		} else if serr := s.storeENR(id.storeKey, localNode.Record()); serr != nil {
			cfg.Logger.WithError(serr).Warn("failed to store updated ENR")
		}
	}

	// Aliases for the code paths that operate on a single representative identity.
	primary := s.primaryIdentity()
	s.localNode = primary.localNode
	s.enrManager = primary.enrManager

	// Create IP discovery service
	ipDiscoveryCfg := services.IPDiscoveryConfig{
		MinReports:     5, // Require 5 reports
		MinDistinctIPs: 3, // From at least 3 distinct IPs
		Logger:         cfg.Logger,
		OnConsensusReached: func(ip net.IP, port uint16, isIPv6 bool) {
			s.updateENRWithDiscoveredIP(ip, port, isIPv6)
		},
	}
	s.ipDiscovery = services.NewIPDiscovery(ipDiscoveryCfg)

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
			closeTransports()
			return nil, fmt.Errorf("failed to create EL table: %w", err)
		}
	}
	if cfg.HasCL() {
		s.clTable, err = s.createTable(s.clIdentity().localNode.ID(), s.clNodeDB, "CL")
		if err != nil {
			closeTransports()
			return nil, fmt.Errorf("failed to create CL table: %w", err)
		}
	}

	// Create a discv5 service per identity (registered on its transport).
	if cfg.EnableDiscv5 {
		for _, id := range s.identities {
			if ierr := s.initDiscv5(id); ierr != nil {
				closeTransports()
				return nil, fmt.Errorf("failed to initialize discv5: %w", ierr)
			}
		}
		s.discv5Service = primary.discv5Service
	}

	// Create the discv4 service (EL-only) on the EL identity.
	if cfg.EnableDiscv4 {
		if ierr := s.initDiscv4(s.elIdentity()); ierr != nil {
			for _, id := range s.identities {
				if id.discv5Service != nil {
					id.discv5Service.Stop()
				}
			}
			closeTransports()
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
		localNode := nodes.NewFromV5(s.localNode, s.elNodeDB)
		s.elLookupService = services.NewLookupService(services.Config{
			LocalNode:     localNode,
			NodeDB:        s.elNodeDB,
			Table:         s.elTable,
			V5Handler:     s.getV5Handler(),
			V4Service:     s.getV4Service(),
			Database:      cfg.Database,
			Layer:         db.LayerEL,
			Alpha:         3,
			LookupTimeout: 30 * time.Second,
			OnNodeFound: func(n *nodes.Node) bool {
				// Filter by fork ID before adding to table
				if n.Record() != nil && s.enrManager != nil {
					if isEL, _ := s.enrManager.FilterELNode(n.Record()); !isEL {
						// Mark as bad node
						if err := cfg.Database.StoreBadNode(n.IDBytes(), db.LayerEL, "invalid_fork_id"); err != nil {
							cfg.Logger.WithError(err).Debug("failed to store bad node")
						}
						return false
					}
				}

				// If node was discovered via v4 (only has v4 support), immediately test for v5 support
				if n.HasV4() && !n.HasV5() && s.getV5Handler() != nil {
					record := n.Record()
					if record != nil {
						// Try to create v5 node from ENR
						v5Node, err := nodes.NewV5NodeFromRecord(record)
						if err == nil && s.getV5Handler() != nil {
							// Ping on v5 to test support
							start := time.Now()
							respChan, err := s.getV5Handler().SendPing(v5Node)
							if err == nil {
								resp := <-respChan
								rtt := time.Since(start)
								if resp.Error == nil {
									// v5 ping succeeded - add v5 support
									n.SetV5(v5Node)
									cfg.Logger.WithFields(logrus.Fields{
										"peerID": n.PeerID(),
										"addr":   n.Addr(),
										"rtt":    rtt,
									}).Debug("discovered v5 support on v4-discovered node")

									// Queue protocol support update (SetV5 already marked it dirty)
									if s.elNodeDB != nil {
										if err := s.elNodeDB.QueueUpdate(n); err != nil {
											cfg.Logger.WithError(err).Debug("failed to queue node for protocol support update")
										}
									}
								}
							}
						}
					}
				}

				// Attempt to add to EL table
				added := s.elTable.Add(n)
				if added {
					// Remove from bad nodes list if it was previously bad
					if err := cfg.Database.RemoveBadNode(n.IDBytes(), db.LayerEL); err != nil {
						cfg.Logger.WithError(err).Debug("failed to remove from bad nodes")
					}
				}
				return added
			},
			Logger: cfg.Logger.WithField("service", "el-lookup"),
		})
	}

	if cfg.HasCL() && s.clTable != nil {
		clID := s.clIdentity()
		localNode := nodes.NewFromV5(clID.localNode, s.clNodeDB)
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
			LocalNode:     localNode,
			NodeDB:        s.clNodeDB,
			Table:         s.clTable,
			V5Handler:     clV5Handler,
			V4Service:     clV4Service,
			Database:      cfg.Database,
			Layer:         db.LayerCL,
			Alpha:         3,
			LookupTimeout: 30 * time.Second,
			OnNodeFound: func(n *nodes.Node) bool {
				// Filter by fork digest before adding to table
				if n.Record() != nil && s.enrManager != nil {
					if !s.enrManager.FilterCLNode(n.Record()) {
						// Mark as bad node
						if err := cfg.Database.StoreBadNode(n.IDBytes(), db.LayerCL, "invalid_fork_digest"); err != nil {
							cfg.Logger.WithError(err).Debug("failed to store bad node")
						}
						return false
					}
				}
				// Attempt to add to CL table
				added := s.clTable.Add(n)
				if added {
					// Remove from bad nodes list if it was previously bad
					if err := cfg.Database.RemoveBadNode(n.IDBytes(), db.LayerCL); err != nil {
						cfg.Logger.WithError(err).Debug("failed to remove from bad nodes")
					}
				}
				return added
			},
			Logger: cfg.Logger.WithField("service", "cl-lookup"),
		})
	}

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
	discv4Config.OnPongReceived = func(from *v4node.Node, ip net.IP, port uint16) {
		sourceIP := from.Addr().IP
		s.onPongReceived(from.IDBytes(), sourceIP, ip, port)
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

	defer tableMaintenance.Stop()
	defer alivenessCheck.Stop()
	defer randomWalk.Stop()
	defer supportCheck.Stop()
	defer badNodesCleanup.Stop()
	defer enrRequestCleanup.Stop()

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
		}
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
			if now.Sub(timestamp) > staleThreshold {
				s.pendingENRRequestsV4.Delete(key)
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
	// Convert to v5 node
	v5, err := v5node.New(record)
	if err != nil {
		s.config.Logger.WithError(err).Warn("failed to create v5 node from ENR")
		return
	}

	// Verify ENR has required fields (IP and port)
	if record.IP() == nil && record.IP6() == nil {
		s.config.Logger.Warn("bootnode ENR missing IP address, skipping")
		return
	}
	if record.UDP() == 0 {
		s.config.Logger.Warn("bootnode ENR missing UDP port, skipping")
		return
	}

	// Filter by fork ID before adding
	if s.enrManager != nil {
		if isEL, forkID := s.enrManager.FilterELNode(record); !isEL {
			s.config.Logger.WithFields(logrus.Fields{
				"nodeID": fmt.Sprintf("%x", v5.ID().Bytes()[:8]),
				"eth":    forkID,
			}).Warn("bootnode ENR has invalid fork ID, skipping")
			return
		}
	}

	// Create generic node and add to table
	genericNode := nodes.NewFromV5(v5, s.elNodeDB)
	if s.elTable != nil {
		s.config.Logger.Info("added ENR bootnode to table")
		s.elTable.Add(genericNode)

		// Persist to database
		if s.elNodeDB != nil {
			genericNode.MarkDirty(nodes.DirtyFull)
			if err := s.elNodeDB.QueueUpdate(genericNode); err != nil {
				s.config.Logger.WithError(err).Debug("failed to queue bootnode for database update")
			}
		}
	}
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
	if s.enrManager != nil {
		if isEL, forkID := s.enrManager.FilterELNode(enrRecord); !isEL {
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

	if s.elTable != nil {
		s.config.Logger.WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Info("added enode bootnode to table")
		s.elTable.Add(genericNode)

		// Persist to database
		if s.elNodeDB != nil {
			genericNode.MarkDirty(nodes.DirtyFull)
			if err := s.elNodeDB.QueueUpdate(genericNode); err != nil {
				s.config.Logger.WithError(err).Debug("failed to queue bootnode for database update")
			}
		}
	}
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

		// Convert to v5 node to get node ID
		v5, err := v5node.New(record)
		if err != nil {
			s.config.Logger.WithError(err).Warn("failed to create v5 node from ENR")
			continue
		}

		nodeID := v5.ID()

		// Verify ENR has required fields (IP and port)
		if record.IP() == nil && record.IP6() == nil {
			s.config.Logger.WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Warn("CL bootnode ENR missing IP address, skipping")
			continue
		}
		if record.UDP() == 0 {
			s.config.Logger.WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Warn("CL bootnode ENR missing UDP port, skipping")
			continue
		}

		// Filter by fork digest before adding
		if s.enrManager != nil && !s.enrManager.FilterCLNode(record) {
			s.config.Logger.WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Warn("CL bootnode ENR has invalid fork digest, skipping")
			continue
		}

		// Create generic node and add to table
		genericNode := nodes.NewFromV5(v5, s.clNodeDB)
		if s.clTable != nil {
			s.config.Logger.WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Info("added CL ENR bootnode to table")
			s.clTable.Add(genericNode)

			// Persist to database
			if s.clNodeDB != nil {
				genericNode.MarkDirty(nodes.DirtyFull)
				if err := s.clNodeDB.QueueUpdate(genericNode); err != nil {
					s.config.Logger.WithError(err).Debug("failed to queue bootnode for database update")
				}
			}
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
	data, err := record.EncodeRLP()
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

		if isEL, _ := s.enrManager.FilterELNode(n.Record()); isEL && s.elTable != nil && s.elNodeDB != nil {
			// Look up the generic node from the table
			if genericNode := s.elTable.Get(nodeID); genericNode != nil {
				genericNode.SetLastSeen(timestamp) // This marks it dirty
				s.elNodeDB.QueueUpdate(genericNode)
			}
		} else if s.enrManager.FilterCLNode(n.Record()) && s.clTable != nil && s.clNodeDB != nil {
			// Look up the generic node from the table
			if genericNode := s.clTable.Get(nodeID); genericNode != nil {
				genericNode.SetLastSeen(timestamp) // This marks it dirty
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
	if id.servesEL && id.servesCL && sourceNode != nil && s.enrManager != nil {
		sourceRecord := sourceNode.Record()
		serveEL, _ = s.enrManager.FilterELNode(sourceRecord)
		serveCL = s.enrManager.FilterCLNode(sourceRecord)
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
			// Node exists, just update last seen
			genericNode.SetLastSeen(timestamp) // This marks it dirty
			s.elNodeDB.QueueUpdate(genericNode)
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

	// Check if we already have a recent pending ENR request for this node
	if val, exists := s.pendingENRRequestsV4.Load(nodeID); exists {
		if timestamp, ok := val.(time.Time); ok {
			// If request is less than 30 seconds old, skip (still pending)
			if time.Since(timestamp) < 30*time.Second {
				return
			}
			// Request is stale (>30s), replace it
		}
	}

	// Mark as pending with current timestamp
	s.pendingENRRequestsV4.Store(nodeID, now)

	// Run in goroutine to avoid blocking packet handling
	go func() {
		// Remove from pending when done
		defer s.pendingENRRequestsV4.Delete(nodeID)

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

	// Check if node already exists in table
	if existingNode := s.elTable.Get(n.ID()); existingNode != nil {
		s.config.Logger.WithFields(logrus.Fields{
			"nodeID": fmt.Sprintf("%x", n.IDBytes()[:8]),
		}).Debug("Discv4 node already in EL table, skipping add")
		return false
	}

	// Filter the node using ENR manager (EL-only for discv4)
	if s.enrManager != nil {
		filter, forkID := s.enrManager.FilterELNode(n.ENR())
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
		s.config.Logger.WithFields(logrus.Fields{
			"nodeID": fmt.Sprintf("%x", n.IDBytes()[:8]),
			"addr":   n.Addr().String(),
		}).Info("Added discv4 node to EL table")
		return true
	}

	return false
}

// checkAndAddNode performs admission checks and adds node to appropriate table.
func (s *Service) checkAndAddNode(n *v5node.Node) bool {
	// Determine layer
	isEL, _ := s.enrManager.FilterELNode(n.Record())
	isCL := s.enrManager.FilterCLNode(n.Record())

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

// filterNodesForRequester applies LAN-aware and protocol filtering.
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

		filtered = append(filtered, n)
	}

	return filtered
}

// LocalNode returns the primary identity's local node.
func (s *Service) LocalNode() *v5node.Node {
	return s.localNode
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

	// Report to IP discovery service with source IP
	reporterIDStr := fmt.Sprintf("%x", remoteID[:8])
	s.ipDiscovery.ReportIP(reportedIP, reportedPort, reporterIDStr, sourceIP)
}

// updateENRWithDiscoveredIP updates every identity's ENR with the discovered IP.
func (s *Service) updateENRWithDiscoveredIP(ip net.IP, port uint16, isIPv6 bool) {
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

		if err := s.storeENR(id.storeKey, id.localNode.Record()); err != nil {
			s.config.Logger.WithError(err).Warn("failed to store updated ENR")
		}

		// Keep the discv4 service's ENR in sync (EL identity only).
		if id.servesEL && s.discv4Service != nil {
			s.discv4Service.SetLocalENR(id.localNode.Record())
		}
	}
}
