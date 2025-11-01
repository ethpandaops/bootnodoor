package bootnode

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pk910/bootoor/beacon-bootnode/config"
	"github.com/pk910/bootoor/beacon-bootnode/discover"
	"github.com/pk910/bootoor/beacon-bootnode/nodedb"
	"github.com/pk910/bootoor/beacon-bootnode/table"
	"github.com/pk910/bootoor/discv5"
	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/pk910/bootoor/discv5/protocol"
	"github.com/sirupsen/logrus"
)

// Service is the beacon chain bootnode service.
//
// It wraps the generic discv5 library with beacon chain specific features:
//   - Fork digest filtering
//   - Node database and persistence
//   - Routing table with IP limits
//   - Discovery and ping services
type Service struct {
	// config is the bootnode configuration
	config *Config

	// discv5Service is the underlying discv5 service
	discv5Service *discv5.Service

	// forkFilter handles fork digest filtering
	forkFilter *config.ForkDigestFilter

	// nodeDB stores discovered nodes
	nodeDB *nodedb.NodeDB

	// table is the routing table
	table *table.FlatTable

	// lookup performs node discovery
	lookup *discover.LookupService

	// ping handles liveness checks
	ping *discover.PingService

	// ipDiscovery handles automatic IP detection from PONG responses (optional)
	ipDiscovery *discv5.IPDiscovery

	// startTime records when the service started
	startTime time.Time

	// Lifecycle management
	running   bool
	mu        sync.RWMutex
	ctx       context.Context
	cancelCtx context.CancelFunc
}

// New creates a new beacon bootnode service.
//
// Example:
//
//	config := bootnode.DefaultConfig()
//	config.PrivateKey = privKey
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

	// Set defaults
	if cfg.Logger == nil {
		cfg.Logger = logrus.New()
	}

	if cfg.NodeDB == nil {
		return nil, fmt.Errorf("NodeDB is required")
	}

	if cfg.GracePeriod <= 0 {
		cfg.GracePeriod = 60 * time.Minute
	}

	// Create fork digest filter
	forkFilter := config.NewForkDigestFilter(cfg.CLConfig, cfg.GracePeriod)
	forkFilter.SetLogger(cfg.Logger)

	// Create routing table first (before discv5 service)
	// We need it for callbacks
	// Derive local ID from private key
	localPubKey := &cfg.PrivateKey.PublicKey
	localID := node.PubkeyToID(localPubKey)

	flatTableConfig := table.FlatTableConfig{
		LocalID:             localID,
		DB:                  cfg.NodeDB,
		MaxActiveNodes:      500, // Cap at 500 active nodes (1000 hard limit)
		MaxNodesPerIP:       cfg.MaxNodesPerIP,
		PingInterval:        cfg.PingInterval,
		PingRate:            200, // pings per minute
		MaxNodeAge:          cfg.MaxNodeAge,
		MaxFailures:         cfg.MaxFailures,
		SweepPercent:        10,  // Rotate 10% of active nodes
		NodeChangedCallback: nil, // DB updates are queued automatically
		Logger:              cfg.Logger,
	}
	routingTable, err := table.NewFlatTable(flatTableConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create flat table: %w", err)
	}

	// Create service
	s := &Service{
		config:     cfg,
		forkFilter: forkFilter,
		nodeDB:     cfg.NodeDB,
		table:      routingTable,
	}

	// Create context for graceful shutdown
	s.ctx, s.cancelCtx = context.WithCancel(context.Background())

	// Load stored ENR if available (discv5 will create new one if nil)
	storedENR := s.loadStoredENR()

	// Create discv5 service configuration with callbacks
	discv5Config := discv5.DefaultConfig()
	discv5Config.LocalENR = storedENR
	discv5Config.Context = s.ctx
	discv5Config.PrivateKey = cfg.PrivateKey
	discv5Config.BindIP = cfg.BindIP
	discv5Config.BindPort = cfg.BindPort
	discv5Config.ENRIP = cfg.ENRIP
	discv5Config.ENRIP6 = cfg.ENRIP6
	discv5Config.ENRPort = cfg.ENRPort
	discv5Config.ETH2Data = forkFilter.ComputeEth2Field()
	discv5Config.SessionLifetime = cfg.SessionLifetime
	discv5Config.MaxSessions = cfg.MaxSessions
	discv5Config.Logger = cfg.Logger

	// Set callbacks for protocol events
	discv5Config.OnHandshakeComplete = func(n *node.Node, incoming bool) {
		// Check and add node through service (handles all admission checks)
		s.CheckAndAddNode(n)
	}

	discv5Config.OnNodeUpdate = func(n *node.Node) {
		// Check and add/update node through service (handles all checks)
		s.CheckAndAddNode(n)
	}

	discv5Config.OnNodeSeen = func(n *node.Node, timestamp time.Time) {
		// Queue last_seen timestamp update for persistence
		if err := s.nodeDB.UpdateLastSeen(n.ID(), timestamp); err != nil {
			s.config.Logger.WithError(err).WithField("nodeID", n.ID()).Debug("failed to queue last_seen update")
		}
	}

	discv5Config.OnFindNode = func(msg *protocol.FindNode, requester *net.UDPAddr) []*node.Node {
		// Serve FINDNODE requests from routing table with score-weighted random selection
		nodes := routingTable.GetNodesByDistance(localID, msg.Distances, 16)

		// Apply LAN-aware filtering
		return s.filterNodesForRequester(nodes, requester)
	}

	// OnTalkReq can be nil for now (no TALKREQ support)
	discv5Config.OnTalkReq = nil

	// Set up IP discovery if enabled
	if cfg.EnableIPDiscovery {
		// Create IP discovery service with callback for consensus
		ipDiscoveryConfig := discv5.IPDiscoveryConfig{
			MinReports:        5,
			MajorityThreshold: 0.75,
			ReportExpiry:      30 * time.Minute,
			RecentWindow:      5 * time.Minute,
			OnConsensusReached: func(ip net.IP, port uint16, isIPv6 bool) {
				s.handleIPConsensus(ip, port, isIPv6)
			},
			Logger: cfg.Logger,
		}
		s.ipDiscovery = discv5.NewIPDiscovery(ipDiscoveryConfig)

		// Wire up OnPongReceived callback to feed IP:Port to discovery service
		discv5Config.OnPongReceived = func(remoteNodeID node.ID, reportedIP net.IP, reportedPort uint16) {
			if s.ipDiscovery != nil {
				s.ipDiscovery.ReportIP(reportedIP, reportedPort, remoteNodeID.String())
			}
		}

		cfg.Logger.Info("IP discovery enabled - will detect public IP:Port from PONG responses")
	}

	// Create the discv5 service
	s.discv5Service, err = discv5.New(discv5Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create discv5 service: %w", err)
	}

	// Store the ENR (either newly created or updated from stored)
	localENR := s.discv5Service.LocalNode().Record()
	if err := s.storeENR(localENR); err != nil {
		cfg.Logger.WithError(err).Warn("failed to store initial ENR")
	}

	// Create lookup service
	lookupConfig := discover.Config{
		LocalNode: s.discv5Service.LocalNode(),
		Table:     routingTable,
		Handler:   s.discv5Service.Handler(),
		OnNodeFound: func(n *node.Node) bool {
			// Use CheckAndAddNode to handle all admission checks
			return s.CheckAndAddNode(n)
		},
		Logger: cfg.Logger,
	}
	s.lookup = discover.NewLookupService(lookupConfig)

	// Create ping service
	s.ping = discover.NewPingService(s.discv5Service.Handler(), cfg.Logger)

	return s, nil
}

// Start starts the bootnode service.
//
// This starts all background tasks:
//   - Discv5 protocol handler
//   - Fork digest periodic updates
//   - Node discovery and maintenance
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service is already running")
	}

	// Record start time
	s.startTime = time.Now()

	// Load initial nodes from DB
	if err := s.table.LoadInitialNodesFromDB(); err != nil {
		return fmt.Errorf("failed to load initial nodes from DB: %w", err)
	}

	// Start discv5 service
	if err := s.discv5Service.Start(); err != nil {
		return fmt.Errorf("failed to start discv5 service: %w", err)
	}

	// Start background tasks
	go s.maintenanceLoop()

	// Start periodic fork digest updates
	go s.forkDigestUpdateLoop()

	// Connect to boot nodes
	if len(s.config.BootNodes) > 0 {
		go s.connectBootNodes()
	}

	s.running = true

	return nil
}

// Stop stops the bootnode service.
//
// This gracefully shuts down all components by cancelling the context.
// Background tasks are context-aware and will exit promptly.
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return fmt.Errorf("service is not running")
	}
	s.running = false
	s.mu.Unlock()

	// Stop discv5 service
	if err := s.discv5Service.Stop(); err != nil {
		s.config.Logger.WithError(err).Error("failed to stop discv5 service")
	}

	// Signal stop to background tasks via context cancellation
	s.cancelCtx()

	// Give goroutines a brief moment to exit gracefully
	time.Sleep(100 * time.Millisecond)

	// Close node database
	if err := s.nodeDB.Close(); err != nil {
		s.config.Logger.WithError(err).Error("failed to close node database")
	}

	return nil
}

// maintenanceLoop runs periodic maintenance tasks.
func (s *Service) maintenanceLoop() {
	// Tickers for periodic tasks
	tableMaintenance := time.NewTicker(5 * time.Minute)
	alivenessCheck := time.NewTicker(s.config.PingInterval)
	randomWalk := time.NewTicker(30 * time.Second)

	defer tableMaintenance.Stop()
	defer alivenessCheck.Stop()
	defer randomWalk.Stop()

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
		}
	}
}

// performTableMaintenance performs routing table maintenance.
func (s *Service) performTableMaintenance() {
	// Perform active/inactive node sweep
	s.table.PerformSweep()
}

// performAlivenessCheck checks node aliveness with PINGs.
func (s *Service) performAlivenessCheck() {
	nodes := s.table.GetNodesNeedingPing()
	if len(nodes) == 0 {
		return
	}

	s.config.Logger.WithField("count", len(nodes)).Debug("performing aliveness check")

	// Ping nodes in parallel
	results := s.ping.PingMultiple(nodes)

	// Update node statistics and queue DB updates
	for nodeID, success := range results {
		n := s.table.Get(nodeID)
		if n == nil {
			continue
		}

		if success {
			n.SetLastSeen(time.Now())
			n.ResetFailureCount()
		} else {
			n.IncrementFailureCount()
		}

		// Queue full node update to persist stats changes
		if err := s.nodeDB.UpdateNodeFull(n); err != nil {
			s.config.Logger.WithError(err).WithField("nodeID", nodeID).Warn("failed to queue node update after ping")
		}
	}
}

// performRandomWalk performs a random walk for network exploration.
func (s *Service) performRandomWalk() {
	// Check if we're shutting down
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	// Only perform random walk if table is not full enough
	if s.table.NumBucketsFilled() >= 100 {
		return
	}

	s.config.Logger.Debug("performing random walk")

	_, err := s.lookup.RandomWalk(s.ctx)
	if err != nil {
		s.config.Logger.WithError(err).Debug("random walk failed")
	}
}

// connectBootNodes connects to boot nodes on startup.
func (s *Service) connectBootNodes() {
	s.config.Logger.WithField("count", len(s.config.BootNodes)).Info("connecting to boot nodes")

	for _, bootNode := range s.config.BootNodes {
		s.config.Logger.WithFields(logrus.Fields{
			"peerID": bootNode.PeerID(),
			"addr":   bootNode.Addr(),
		}).Info("attempting to connect to boot node")

		// Add to routing table
		added := s.table.Add(bootNode)
		s.config.Logger.WithFields(logrus.Fields{
			"peerID": bootNode.PeerID(),
			"added":  added,
		}).Debug("boot node add to table result")

		// Ping the boot node
		success, rtt, err := s.ping.Ping(bootNode)
		if err != nil {
			s.config.Logger.WithFields(logrus.Fields{
				"peerID": bootNode.PeerID(),
				"error":  err,
			}).Warn("failed to ping boot node")
			continue
		}

		s.config.Logger.WithFields(logrus.Fields{
			"peerID":  bootNode.PeerID(),
			"success": success,
			"rtt":     rtt,
		}).Info("boot node ping result")

		if !success {
			continue
		}

		// Update node stats and add to active pool
		now := time.Now()
		bootNode.SetLastSeen(now)
		bootNode.ResetFailureCount()

		// Queue last_seen update
		if err := s.nodeDB.UpdateLastSeen(bootNode.ID(), now); err != nil {
			s.config.Logger.WithError(err).Warn("failed to queue last_seen update for boot node")
		}

		// Perform lookup using boot node
		_, err = s.lookup.Lookup(s.ctx, bootNode.ID(), 16)
		if err != nil {
			s.config.Logger.WithField("peerID", bootNode.PeerID()).WithError(err).Debug("boot node lookup failed")
		}
	}
}

// forkDigestUpdateLoop periodically updates the fork digest.
func (s *Service) forkDigestUpdateLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Update immediately on start
	s.updateForkScoringInfo()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.forkFilter.Update()
			s.updateForkScoringInfo()
		}
	}
}

// updateForkScoringInfo updates the table's fork scoring information.
func (s *Service) updateForkScoringInfo() {
	// Get fork scoring info from filter
	filterInfo := s.forkFilter.GetForkScoringInfo()

	// Convert to node.ForkScoringInfo
	nodeInfo := &node.ForkScoringInfo{
		CurrentForkDigest:  [4]byte(filterInfo.CurrentForkDigest),
		PreviousForkDigest: [4]byte(filterInfo.PreviousForkDigest),
		GenesisForkDigest:  [4]byte(filterInfo.GenesisForkDigest),
		GracePeriodEnd:     filterInfo.GracePeriodEnd,
	}

	// Update table
	s.table.SetForkScoringInfo(nodeInfo)
}

// LocalNode returns the local node information.
func (s *Service) LocalNode() *node.Node {
	return s.discv5Service.LocalNode()
}

// Table returns the routing table.
func (s *Service) Table() *table.FlatTable {
	return s.table
}

// NodeDB returns the node database.
func (s *Service) NodeDB() *nodedb.NodeDB {
	return s.nodeDB
}

// Discv5Service returns the underlying discv5 service.
func (s *Service) Discv5Service() *discv5.Service {
	return s.discv5Service
}

// ForkFilter returns the fork digest filter.
func (s *Service) ForkFilter() *config.ForkDigestFilter {
	return s.forkFilter
}

// Lookup performs a node lookup for the target ID.
func (s *Service) Lookup(ctx context.Context, target node.ID) ([]*node.Node, error) {
	return s.lookup.Lookup(ctx, target, 16)
}

// LookupWithFilter performs a lookup with an ENR filter.
func (s *Service) LookupWithFilter(ctx context.Context, target node.ID, k int, filter enr.ENRFilter) ([]*node.Node, error) {
	return s.lookup.LookupWithFilter(ctx, target, k, filter)
}

// RandomWalk performs a random walk to discover new nodes.
func (s *Service) RandomWalk(ctx context.Context) ([]*node.Node, error) {
	return s.lookup.RandomWalk(ctx)
}

// Ping sends a PING to a node and waits for PONG.
func (s *Service) Ping(n *node.Node) (bool, time.Duration, error) {
	return s.ping.Ping(n)
}

// PingMultiple sends PINGs to multiple nodes in parallel.
func (s *Service) PingMultiple(nodes []*node.Node) map[node.ID]bool {
	return s.ping.PingMultiple(nodes)
}

// CheckAndAddNode performs all admission checks and adds node to table if it passes.
//
// This method handles:
//   - Admission filter validation (fork digest)
//   - DB existence check for updates
//   - IP limit validation
//   - Ping-before-add for new nodes when pool is full
//   - Adding to routing table if all checks pass
func (s *Service) CheckAndAddNode(n *node.Node) bool {
	if n == nil {
		return false
	}

	// Check admission filter
	if s.forkFilter != nil && !s.forkFilter.Filter(n.Record()) {
		s.config.Logger.WithField("peerID", n.PeerID()).Debug("rejected node due to admission filter")
		return false
	}

	nodeID := n.ID()

	// Check if node exists in DB
	exists, seq := s.nodeDB.NodeExists(nodeID)
	if exists {
		// Existing node - just update if newer seq
		if n.Record().Seq() > seq {
			return s.table.Add(n)
		}
		return true
	}

	// New node - check IP limits globally
	if !s.table.CanAddNodeByIP(n) {
		s.config.Logger.WithField("peerID", n.PeerID()).WithField("ip", n.IP()).Debug("rejected node due to IP limit")
		return false
	}

	// Initialize stats for new node
	n.SetFirstSeen(time.Now())

	// Check if pool has space (max 500 active nodes)
	poolFull := s.table.ActiveSize() >= 500

	if poolFull {
		// Pool is full - ping node first
		s.config.Logger.WithField("peerID", n.PeerID()).WithField("addr", n.Addr()).Debug("active pool full, pinging new node before adding")

		success, rtt, err := s.ping.Ping(n)
		if err != nil || !success {
			s.config.Logger.WithField("peerID", n.PeerID()).WithError(err).Debug("ping failed, adding as inactive")
			// Ping failed - add as inactive only
			return s.nodeDB.UpdateNodeENR(n) == nil
		}

		// Ping successful - update stats and add to table
		s.config.Logger.WithField("peerID", n.PeerID()).WithField("rtt", rtt).Info("ping successful, adding new node")
		now := time.Now()
		n.SetLastSeen(now)
		n.ResetFailureCount() // This also increments success count

		// Queue last_seen update
		if err := s.nodeDB.UpdateLastSeen(n.ID(), now); err != nil {
			s.config.Logger.WithError(err).Warn("failed to queue last_seen update")
		}

		// Add to table (will go to active even if over capacity, sweep handles cleanup)
		return s.table.Add(n)
	}

	// Pool has space - add directly
	return s.table.Add(n)
}

// GetActiveNodes returns the active nodes from the routing table.
// Only active nodes are returned (inactive nodes in DB are not shown).
func (s *Service) GetActiveNodes() []*node.Node {
	return s.table.GetActiveNodes()
}

// GetStats returns service statistics for display.
func (s *Service) GetStats() ServiceStats {
	s.mu.RLock()
	uptime := time.Since(s.startTime)
	s.mu.RUnlock()

	// Get handler stats from disc v5 service
	handlerStats := s.discv5Service.Handler().GetStats()
	sessionStats := s.discv5Service.Sessions().GetStats()

	// Get active/inactive node counts
	activeNodes := s.table.ActiveSize()
	totalNodes := s.nodeDB.Count()
	inactiveNodes := totalNodes - activeNodes

	return ServiceStats{
		PeerID:        s.LocalNode().PeerID(),
		BindAddress:   fmt.Sprintf("%s:%d", s.config.BindIP, s.config.BindPort),
		Uptime:        uptime,
		TableSize:     s.table.Size(),
		BucketsFilled: s.table.NumBucketsFilled(),
		ActiveNodes:   activeNodes,
		InactiveNodes: inactiveNodes,
		TableStats:    s.table.GetStats(),
		LookupStats:   s.lookup.GetStats(),
		PingStats:     s.ping.GetStats(),
		SessionStats: SessionStats{
			Total:   sessionStats.Total,
			Active:  sessionStats.Active,
			Expired: sessionStats.Expired,
		},
		HandlerStats: HandlerStats{
			PacketsReceived:   handlerStats.PacketsReceived,
			PacketsSent:       handlerStats.PacketsSent,
			InvalidPackets:    handlerStats.InvalidPackets,
			FilteredResponses: handlerStats.FilteredResponses,
			FindNodeReceived:  handlerStats.FindNodeReceived,
			PendingHandshakes: handlerStats.PendingHandshakes,
			PendingChallenges: handlerStats.PendingChallenges,
		},
		ForkFilter: &config.ForkFilterStats{
			NetworkName:     s.forkFilter.GetNetworkName(),
			CurrentFork:     s.forkFilter.GetCurrentFork(),
			CurrentDigest:   s.forkFilter.GetCurrentDigest(),
			GracePeriod:     s.forkFilter.GetGracePeriod(),
			OldDigests:      s.forkFilter.GetOldDigests(),
			AcceptedCurrent: s.forkFilter.GetAcceptedCurrent(),
			AcceptedOld:     s.forkFilter.GetAcceptedOld(),
			RejectedInvalid: s.forkFilter.GetRejectedInvalid(),
			RejectedExpired: s.forkFilter.GetRejectedExpired(),
			TotalChecks:     s.forkFilter.GetTotalChecks(),
		},
	}
}

// SessionStats contains session-related statistics.
type SessionStats struct {
	Total   int
	Active  int
	Expired int
}

// HandlerStats contains protocol handler statistics.
type HandlerStats struct {
	PacketsReceived   int
	PacketsSent       int
	InvalidPackets    int
	FilteredResponses int
	FindNodeReceived  int
	PendingHandshakes int
	PendingChallenges int
}

// ServiceStats contains statistics about the bootnode service.
type ServiceStats struct {
	PeerID        string
	BindAddress   string
	Uptime        time.Duration
	TableSize     int
	BucketsFilled int // Deprecated for FlatTable
	ActiveNodes   int
	InactiveNodes int
	TableStats    table.TableStats
	LookupStats   discover.LookupStats
	PingStats     discover.PingStats
	SessionStats  SessionStats
	HandlerStats  HandlerStats
	ForkFilter    *config.ForkFilterStats
}

// ForkFilterStatsProvider interface implementation for webui

func (s *Service) GetCurrentFork() string {
	return s.forkFilter.GetCurrentFork()
}

func (s *Service) GetCurrentDigest() string {
	return s.forkFilter.GetCurrentDigest()
}

func (s *Service) GetGracePeriod() string {
	return s.forkFilter.GetGracePeriod()
}

func (s *Service) GetOldDigests() map[string]time.Duration {
	return s.forkFilter.GetOldDigests()
}

func (s *Service) GetAcceptedCurrent() int {
	return s.forkFilter.GetAcceptedCurrent()
}

func (s *Service) GetAcceptedOld() int {
	return s.forkFilter.GetAcceptedOld()
}

func (s *Service) GetRejectedInvalid() int {
	return s.forkFilter.GetRejectedInvalid()
}

func (s *Service) GetRejectedExpired() int {
	return s.forkFilter.GetRejectedExpired()
}

func (s *Service) GetTotalChecks() int {
	return s.forkFilter.GetTotalChecks()
}

func (s *Service) GetNetworkName() string {
	return s.forkFilter.GetNetworkName()
}

// filterNodesForRequester applies LAN-aware filtering to nodes based on requester address.
//
// LAN requesters receive all nodes (LAN and WAN).
// WAN requesters only receive WAN nodes (prevents leaking private network topology).
func (s *Service) filterNodesForRequester(nodes []*node.Node, requester *net.UDPAddr) []*node.Node {
	requesterIsLAN := node.IsLANAddress(requester.IP)
	if requesterIsLAN {
		// LAN requesters get all nodes
		return nodes
	}

	// WAN requesters only get WAN nodes
	filtered := make([]*node.Node, 0, len(nodes))
	for _, n := range nodes {
		nodeIP := n.Record().IP()
		if nodeIP == nil {
			nodeIP = n.Record().IP6()
		}
		if nodeIP == nil {
			// No IP in ENR, skip
			continue
		}

		// Only include WAN nodes for WAN requesters
		if !node.IsLANAddress(nodeIP) {
			filtered = append(filtered, n)
		}
	}

	return filtered
}

// loadStoredENR loads the stored ENR from the database.
// Returns nil if no ENR is stored or if loading fails.
func (s *Service) loadStoredENR() *enr.Record {
	data, err := s.nodeDB.LoadLocalENR()
	if err != nil {
		s.config.Logger.Debug("no stored ENR found (this is normal on first run)")
		return nil
	}

	storedENR, err := enr.Load(data)
	if err != nil {
		s.config.Logger.WithError(err).Warn("failed to decode stored ENR, starting fresh")
		return nil
	}

	s.config.Logger.WithFields(logrus.Fields{
		"seq": storedENR.Seq(),
		"enr": storedENR.String(),
	}).Debug("loaded stored ENR from database")

	return storedENR
}

// storeENR stores the ENR in the database for persistence across restarts.
func (s *Service) storeENR(record *enr.Record) error {
	data, err := record.EncodeRLP()
	if err != nil {
		return fmt.Errorf("failed to encode ENR: %w", err)
	}

	if err := s.nodeDB.StoreLocalENR(data); err != nil {
		return fmt.Errorf("failed to store ENR: %w", err)
	}

	s.config.Logger.WithField("seq", record.Seq()).Debug("stored ENR to database")
	return nil
}

// handleIPConsensus is called when IP discovery reaches consensus on a public IP:Port.
// It updates the local node's ENR with the discovered IP address and port.
func (s *Service) handleIPConsensus(ip net.IP, port uint16, isIPv6 bool) {
	defer func() {
		if r := recover(); r != nil {
			s.config.Logger.WithField("panic", r).Error("panic in handleIPConsensus")
		}
	}()

	familyName := "IPv4"
	if isIPv6 {
		familyName = "IPv6"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	localNode := s.discv5Service.LocalNode()
	currentRecord := localNode.Record()

	// Check if IP and port have actually changed (avoid unnecessary updates)
	var currentIP net.IP
	if isIPv6 {
		currentIP = currentRecord.IP6()
	} else {
		currentIP = currentRecord.IP()
	}
	currentPort := currentRecord.UDP()

	// Check if address actually changed
	if currentIP != nil && currentIP.Equal(ip) && currentPort == port {
		return
	}

	s.config.Logger.WithFields(logrus.Fields{
		"family":      familyName,
		"newAddr":     fmt.Sprintf("%s:%d", ip.String(), port),
		"currentIP":   currentIP,
		"currentPort": currentPort,
		"oldSeq":      currentRecord.Seq(),
	}).Info("local ip:port updated, updating ENR")

	// Clone the current ENR to preserve all fields
	newRecord, err := currentRecord.Clone()
	if err != nil {
		s.config.Logger.WithError(err).Error("failed to clone ENR")
		return
	}

	// Update the IP field with discovered value
	if isIPv6 {
		newRecord.Set("ip6", ip)
	} else {
		newRecord.Set("ip", ip.To4())
	}

	// Update the UDP port with discovered value
	newRecord.Set("udp", port)

	// Increment sequence number
	newRecord.SetSeq(currentRecord.Seq() + 1)

	// Re-sign the record
	if err := newRecord.Sign(s.config.PrivateKey); err != nil {
		s.config.Logger.WithError(err).Error("failed to sign updated ENR")
		return
	}

	// Update local node's ENR
	if updated := localNode.UpdateENR(newRecord); updated {
		// Store the updated ENR for persistence
		if err := s.storeENR(newRecord); err != nil {
			s.config.Logger.WithError(err).Warn("failed to store updated ENR")
		}
	} else {
		s.config.Logger.Warn("failed to update local ENR (sequence number issue)")
	}
}
