package bootnode

import (
	"context"
	"fmt"
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
	nodeDB nodedb.DB

	// table is the routing table
	table *table.Table

	// lookup performs node discovery
	lookup *discover.LookupService

	// ping handles liveness checks
	ping *discover.PingService

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
		cfg.NodeDB = nodedb.NewMemoryDB(cfg.Logger)
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

	tableConfig := table.Config{
		LocalID:         localID,
		MaxNodesPerIP:   cfg.MaxNodesPerIP,
		AdmissionFilter: forkFilter.Filter(), // Fork digest filtering at admission
		PingInterval:    cfg.PingInterval,
		MaxNodeAge:      cfg.MaxNodeAge,
		MaxFailures:     cfg.MaxFailures,
		DB:              cfg.NodeDB,
		Logger:          cfg.Logger,
		NodeChangedCallback: func(n *node.Node) {
			// Persist node to database in background
			go func() {
				if err := cfg.NodeDB.Store(n); err != nil {
					cfg.Logger.WithError(err).WithField("peerID", n.PeerID()).Warn("failed to persist node to database")
				}
			}()
		},
	}
	routingTable := table.NewTable(tableConfig)

	// Create discv5 service configuration with callbacks
	discv5Config := discv5.DefaultConfig()
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

	// Set response filter (admission filter is applied at table level)
	discv5Config.ResponseFilter = protocol.ChainResponseFilters(
		protocol.LANAwareResponseFilter(),
		forkFilter.ResponseFilter(),
	)

	// Set callbacks for protocol events
	discv5Config.OnHandshakeComplete = func(n *node.Node, incoming bool) {
		// Add node to routing table after handshake
		routingTable.Add(n)
	}

	discv5Config.OnNodeUpdate = func(n *node.Node) {
		// Update node in routing table when ENR is updated
		routingTable.Add(n)
	}

	discv5Config.OnFindNode = func(msg *protocol.FindNode) []*node.Node {
		// Serve FINDNODE requests from routing table
		if len(msg.Distances) == 1 && msg.Distances[0] == 256 {
			// Special case: return all nodes
			return routingTable.FindClosestNodes(localID, 16)
		}

		// Find nodes at requested distances
		var collectedNodes []*node.Node
		for _, distance := range msg.Distances {
			// Validate distance is in valid range (0-255)
			if distance >= 256 {
				continue
			}

			// Get nodes from the bucket at this distance
			bucketNodes := routingTable.GetBucketNodes(int(distance))
			collectedNodes = append(collectedNodes, bucketNodes...)

			// Limit total nodes to 16 (standard Kademlia bucket size)
			if len(collectedNodes) >= 16 {
				collectedNodes = collectedNodes[:16]
				break
			}
		}
		return collectedNodes
	}

	// OnTalkReq can be nil for now (no TALKREQ support)
	discv5Config.OnTalkReq = nil

	// Create the discv5 service (minimal, no table/nodedb)
	discv5Service, err := discv5.New(discv5Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create discv5 service: %w", err)
	}

	s := &Service{
		config:        cfg,
		discv5Service: discv5Service,
		forkFilter:    forkFilter,
		nodeDB:        cfg.NodeDB,
		table:         routingTable,
	}

	// Create context for graceful shutdown
	s.ctx, s.cancelCtx = context.WithCancel(context.Background())

	// Create lookup service
	lookupConfig := discover.Config{
		LocalNode: discv5Service.LocalNode(),
		Table:     routingTable,
		Handler:   discv5Service.Handler(),
		Logger:    cfg.Logger,
	}
	s.lookup = discover.NewLookupService(lookupConfig)

	// Create ping service
	s.ping = discover.NewPingService(discv5Service.Handler(), cfg.Logger)

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

	// Restore nodes from database
	s.restoreNodesFromDB()

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

	// Signal stop to background tasks via context cancellation
	s.cancelCtx()

	// Give goroutines a brief moment to exit gracefully
	time.Sleep(100 * time.Millisecond)

	// Stop discv5 service
	if err := s.discv5Service.Stop(); err != nil {
		s.config.Logger.WithError(err).Error("failed to stop discv5 service")
	}

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
	// Remove stale nodes
	removed := s.table.RemoveStaleNodes()
	if removed > 0 {
		s.config.Logger.WithField("count", removed).Info("removed stale nodes")
	}

	// Cleanup expired rejection log entries
	rejectionCleaned := s.table.CleanupRejectionLog()
	if rejectionCleaned > 0 {
		s.config.Logger.WithField("count", rejectionCleaned).Debug("cleaned up rejection log entries")
	}
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

	// Update node statistics
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

// restoreNodesFromDB restores nodes from the database to the routing table.
func (s *Service) restoreNodesFromDB() {
	nodes := s.nodeDB.List()
	if len(nodes) == 0 {
		s.config.Logger.Info("no nodes to restore from database")
		return
	}

	s.config.Logger.WithField("count", len(nodes)).Info("restoring nodes from database")

	restored := 0
	for _, n := range nodes {
		// Add to routing table (will trigger admission filter and IP limits)
		if s.table.Add(n) {
			restored++
		}
	}

	s.config.Logger.WithFields(logrus.Fields{
		"total":    len(nodes),
		"restored": restored,
	}).Info("finished restoring nodes from database")
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

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.forkFilter.Update()
		}
	}
}

// LocalNode returns the local node information.
func (s *Service) LocalNode() *node.Node {
	return s.discv5Service.LocalNode()
}

// Table returns the routing table.
func (s *Service) Table() *table.Table {
	return s.table
}

// NodeDB returns the node database.
func (s *Service) NodeDB() nodedb.DB {
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

// BucketInfo contains information about a routing table bucket.
type BucketInfo struct {
	Index    int
	Distance string
	Nodes    []BucketNodeInfo
}

// BucketNodeInfo contains node information for display.
type BucketNodeInfo struct {
	PeerID       string
	IP           string
	Port         int
	FirstSeen    time.Time
	LastSeen     time.Time
	SuccessCount int
	FailureCount int
	IsAlive      bool
	Score        int
	ForkDigest   string
	HasForkData  bool
	ENRSeq       uint64
	ENR          string
}

// GetBuckets returns information about all routing table buckets.
func (s *Service) GetBuckets() []BucketInfo {
	buckets := make([]BucketInfo, 0, 256)

	for i := 0; i < 256; i++ {
		nodes := s.table.GetBucketNodes(i)
		if len(nodes) == 0 {
			continue
		}

		bucketInfo := BucketInfo{
			Index:    i,
			Distance: fmt.Sprintf("2^%d", i),
			Nodes:    make([]BucketNodeInfo, 0, len(nodes)),
		}

		for _, n := range nodes {
			nodeInfo := BucketNodeInfo{
				PeerID:       n.PeerID(),
				IP:           n.IP().String(),
				Port:         int(n.UDPPort()),
				FirstSeen:    n.FirstSeen(),
				LastSeen:     n.LastSeen(),
				SuccessCount: n.SuccessCount(),
				FailureCount: n.FailureCount(),
				IsAlive:      n.FailureCount() < 3,
				Score:        n.SuccessCount() - n.FailureCount(),
				ENRSeq:       n.Record().Seq(),
			}

			// Extract eth2 fork digest if available
			if eth2Data, ok := n.Record().Eth2(); ok {
				nodeInfo.ForkDigest = fmt.Sprintf("%x", eth2Data.ForkDigest)
				nodeInfo.HasForkData = true
			}

			// Get ENR string
			if enrStr, err := n.Record().EncodeBase64(); err == nil {
				nodeInfo.ENR = enrStr
			}

			bucketInfo.Nodes = append(bucketInfo.Nodes, nodeInfo)
		}

		buckets = append(buckets, bucketInfo)
	}

	return buckets
}

// GetStats returns service statistics for display.
func (s *Service) GetStats() ServiceStats {
	s.mu.RLock()
	uptime := time.Since(s.startTime)
	s.mu.RUnlock()

	// Get handler stats from disc v5 service
	handlerStats := s.discv5Service.Handler().GetStats()
	sessionStats := s.discv5Service.Sessions().GetStats()

	return ServiceStats{
		PeerID:        s.LocalNode().PeerID(),
		BindAddress:   fmt.Sprintf("%s:%d", s.config.BindIP, s.config.BindPort),
		Uptime:        uptime,
		TableSize:     s.table.Size(),
		BucketsFilled: s.table.NumBucketsFilled(),
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
	BucketsFilled int
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
