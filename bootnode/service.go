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

	// Local node (shared across protocols)
	localNode *v5node.Node

	// Network components
	transport     *transport.UDPTransport
	discv4Service *discv4.Service // May be nil if discv4 disabled
	discv5Service *discv5.Service // May be nil if discv5 disabled

	// ENR management
	enrManager *ENRManager

	// IP discovery
	ipDiscovery *services.IPDiscovery

	// Node databases (layer-specific)
	elNodeDB *nodes.NodeDB // May be nil if EL disabled
	clNodeDB *nodes.NodeDB // May be nil if CL disabled

	// Routing tables (layer-specific)
	elTable *nodes.FlatTable // May be nil if EL disabled
	clTable *nodes.FlatTable // May be nil if CL disabled

	// Discovery services
	pingService     *services.PingService   // Handles PING/PONG for aliveness checks
	elLookupService *services.LookupService // EL lookup service (may be nil if EL disabled)
	clLookupService *services.LookupService // CL lookup service (may be nil if CL disabled)

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

	// Create UDP transport (shared by both protocols)
	listenAddr := fmt.Sprintf("%s:%d", cfg.BindIP.String(), cfg.BindPort)
	transportConfig := &transport.Config{
		ListenAddr: listenAddr,
		Logger:     cfg.Logger,
	}
	udpTransport, err := transport.NewUDPTransport(transportConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP transport: %w", err)
	}
	s.transport = udpTransport

	// Load stored ENR
	storedENR, err := s.loadStoredENR()
	if err != nil {
		cfg.Logger.WithError(err).Debug("no stored ENR, will create new one")
	}

	// Create local node (shared across both protocols)
	localNode, err := createLocalNode(cfg, storedENR)
	if err != nil {
		udpTransport.Close()
		return nil, fmt.Errorf("failed to create local node: %w", err)
	}
	s.localNode = localNode

	// Store the ENR
	if err := s.storeENR(localNode.Record()); err != nil {
		cfg.Logger.WithError(err).Warn("failed to store initial ENR")
	}

	// Create ENR manager and update ENR with eth/eth2 fields
	s.enrManager = NewENRManager(cfg, localNode)
	if err := s.enrManager.UpdateENR(0, 0); err != nil {
		cfg.Logger.WithError(err).Warn("failed to update ENR with eth/eth2 fields")
	} else {
		// Store updated ENR with eth/eth2 fields
		if err := s.storeENR(localNode.Record()); err != nil {
			cfg.Logger.WithError(err).Warn("failed to store updated ENR")
		}
	}

	// Create IP discovery service
	ipDiscoveryCfg := services.IPDiscoveryConfig{
		MinReports:     5, // Require 5 reports
		MinDistinctIPs: 3, // From at least 3 distinct IPs
		Logger:         cfg.Logger,
		OnConsensusReached: func(ip net.IP, port uint16, isIPv6 bool) {
			// Update local node's ENR with discovered IP
			s.updateENRWithDiscoveredIP(ip, port, isIPv6)
		},
	}
	s.ipDiscovery = services.NewIPDiscovery(ipDiscoveryCfg)

	// Create discv5 service (if enabled) - pass the local node
	if cfg.EnableDiscv5 {
		if err := s.initDiscv5(udpTransport, localNode); err != nil {
			udpTransport.Close()
			return nil, fmt.Errorf("failed to initialize discv5: %w", err)
		}
	}

	// Create discv4 service (if enabled) - pass the local node's ENR
	if cfg.EnableDiscv4 {
		if err := s.initDiscv4(udpTransport, localNode.Record()); err != nil {
			if s.discv5Service != nil {
				s.discv5Service.Stop()
			}
			udpTransport.Close()
			return nil, fmt.Errorf("failed to initialize discv4: %w", err)
		}
	}

	// Create node databases for enabled layers
	if cfg.HasEL() {
		s.elNodeDB = nodes.NewNodeDB(ctx, cfg.Database, db.LayerEL, cfg.Logger)
	}
	if cfg.HasCL() {
		s.clNodeDB = nodes.NewNodeDB(ctx, cfg.Database, db.LayerCL, cfg.Logger)
	}

	// Create routing tables for enabled layers
	localID := localNode.ID()
	if cfg.HasEL() {
		s.elTable, err = s.createTable(localID, s.elNodeDB, "EL")
		if err != nil {
			return nil, fmt.Errorf("failed to create EL table: %w", err)
		}
	}
	if cfg.HasCL() {
		s.clTable, err = s.createTable(localID, s.clNodeDB, "CL")
		if err != nil {
			return nil, fmt.Errorf("failed to create CL table: %w", err)
		}
	}

	// Create ping service (shared across protocols)
	s.pingService = services.NewPingService(
		s.getV5Handler(),
		s.getV4Service(),
		cfg.Logger.WithField("service", "ping"),
	)

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
					if !s.enrManager.FilterELNode(n.Record()) {
						// Mark as bad node
						if err := cfg.Database.StoreBadNode(n.IDBytes(), db.LayerEL, "invalid_fork_id"); err != nil {
							cfg.Logger.WithError(err).Debug("failed to store bad node")
						}
						return false
					}
				}

				// If node was discovered via v4 (only has v4 support), immediately test for v5 support
				if n.HasV4() && !n.HasV5() && s.pingService != nil {
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
		localNode := nodes.NewFromV5(s.localNode, s.clNodeDB)
		s.clLookupService = services.NewLookupService(services.Config{
			LocalNode:     localNode,
			NodeDB:        s.clNodeDB,
			Table:         s.clTable,
			V5Handler:     s.getV5Handler(),
			V4Service:     s.getV4Service(),
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

// initDiscv5 initializes the discv5 service.
func (s *Service) initDiscv5(udpTransport *transport.UDPTransport, localNode *v5node.Node) error {
	discv5Config := discv5.DefaultConfig()
	discv5Config.LocalNode = localNode // Pass the pre-created local node
	discv5Config.Context = s.ctx
	discv5Config.PrivateKey = s.config.PrivateKey
	discv5Config.SessionLifetime = s.config.SessionLifetime
	discv5Config.MaxSessions = s.config.MaxSessions
	discv5Config.Logger = s.config.Logger

	// Set callbacks
	discv5Config.OnHandshakeComplete = s.onHandshakeComplete
	discv5Config.OnNodeUpdate = s.onNodeUpdate
	discv5Config.OnNodeSeen = s.onNodeSeen
	discv5Config.OnFindNode = s.onFindNodeV5
	discv5Config.OnTalkReq = nil // No TALKREQ support
	discv5Config.OnPongReceived = func(remoteID v5node.ID, sourceIP net.IP, reportedIP net.IP, reportedPort uint16) {
		s.onPongReceived(remoteID[:], sourceIP, reportedIP, reportedPort)
	}

	// Create service
	service, err := discv5.New(discv5Config, udpTransport)
	if err != nil {
		return err
	}

	s.discv5Service = service
	return nil
}

// initDiscv4 initializes the discv4 service.
func (s *Service) initDiscv4(udpTransport *transport.UDPTransport, localENR *enr.Record) error {
	discv4Config := discv4.DefaultConfig()
	discv4Config.PrivateKey = s.config.PrivateKey
	discv4Config.LocalENR = localENR

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
	service, err := discv4.New(discv4Config, udpTransport)
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

// getLocalID returns the local node ID.
func (s *Service) getLocalID() [32]byte {
	return s.localNode.ID()
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

	// Start protocol services
	if s.discv5Service != nil {
		if err := s.discv5Service.Start(); err != nil {
			return fmt.Errorf("failed to start discv5: %w", err)
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

	// Stop protocol services
	if s.discv5Service != nil {
		s.discv5Service.Stop()
	}
	if s.discv4Service != nil {
		s.discv4Service.Stop()
	}

	// Close transport
	if s.transport != nil {
		s.transport.Close()
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
	supportCheck := time.NewTicker(30 * time.Minute)  // Check protocol support every 30 minutes
	badNodesCleanup := time.NewTicker(24 * time.Hour) // Cleanup bad nodes once per day

	defer tableMaintenance.Stop()
	defer alivenessCheck.Stop()
	defer randomWalk.Stop()
	defer supportCheck.Stop()
	defer badNodesCleanup.Stop()

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
	if s.pingService == nil {
		return
	}

	// Ping a sample from each table
	const sampleSize = 10 // Ping 10 nodes per table per check

	// Ping EL nodes
	if s.elTable != nil {
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
		s.pingService.PingMultiple(elNodes)
	}

	// Ping CL nodes
	if s.clTable != nil {
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
		s.pingService.PingMultiple(clNodes)
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
	if s.pingService == nil {
		return
	}

	// Sample nodes from each table
	const sampleSize = 10 // Check 10 nodes per table per check

	// Check EL nodes only
	// CL nodes only support discv5, so there's no point in checking for v4 support
	if s.elTable != nil && s.elNodeDB != nil {
		elNodes := s.elTable.GetRandomActiveNodes(sampleSize)
		if len(elNodes) > 0 {
			s.config.Logger.WithField("count", len(elNodes)).WithField("layer", "EL").Debug("checking protocol support")
			s.pingService.CheckProtocolSupportMultiple(elNodes)

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
	if s.enrManager != nil && !s.enrManager.FilterELNode(record) {
		s.config.Logger.Warn("bootnode ENR has invalid fork ID, skipping")
		return
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
	if s.enrManager != nil && !s.enrManager.FilterELNode(enrRecord) {
		s.config.Logger.WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Warn("enode bootnode has invalid fork ID, skipping")
		return
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
func (s *Service) loadStoredENR() (*enr.Record, error) {
	data, err := s.config.Database.LoadLocalENR()
	if err != nil {
		return nil, err
	}

	return enr.Load(data)
}

// storeENR stores the ENR to database.
func (s *Service) storeENR(record *enr.Record) error {
	data, err := record.EncodeRLP()
	if err != nil {
		return err
	}

	return s.config.Database.StoreLocalENR(data)
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

		if s.enrManager.FilterELNode(n.Record()) && s.elTable != nil && s.elNodeDB != nil {
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

func (s *Service) onFindNodeV5(msg *v5protocol.FindNode, sourceNode *v5node.Node, requester *net.UDPAddr) []*v5node.Node {
	// Determine which table to serve from based on source node's layer
	// If source node is unknown, serve from both tables
	var allNodes []*nodes.Node
	localID := s.getLocalID()

	if sourceNode != nil && s.enrManager != nil {
		// Check source node's layer
		sourceRecord := sourceNode.Record()
		isEL := s.enrManager.FilterELNode(sourceRecord)
		isCL := s.enrManager.FilterCLNode(sourceRecord)

		// Serve from appropriate table(s)
		if isEL && s.elTable != nil {
			elNodes := s.elTable.GetNodesByDistance(localID, msg.Distances, 8)
			allNodes = append(allNodes, elNodes...)
			s.config.Logger.WithField("sourceNodeID", sourceNode.ID().String()[:16]+"...").Debug("serving EL nodes to EL source")
		}
		if isCL && s.clTable != nil {
			clNodes := s.clTable.GetNodesByDistance(localID, msg.Distances, 8)
			allNodes = append(allNodes, clNodes...)
			s.config.Logger.WithField("sourceNodeID", sourceNode.ID().String()[:16]+"...").Debug("serving CL nodes to CL source")
		}
	} else {
		// Source unknown or no ENR manager - serve from both tables
		if s.elTable != nil {
			elNodes := s.elTable.GetNodesByDistance(localID, msg.Distances, 8)
			allNodes = append(allNodes, elNodes...)
		}
		if s.clTable != nil {
			clNodes := s.clTable.GetNodesByDistance(localID, msg.Distances, 8)
			allNodes = append(allNodes, clNodes...)
		}
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
	// Update last seen in EL database (discv4 is EL-only)
	if s.elTable != nil && s.elNodeDB != nil {
		// Look up the generic node from the table
		if genericNode := s.elTable.Get(n.ID()); genericNode != nil {
			genericNode.SetLastSeen(timestamp) // This marks it dirty
			s.elNodeDB.QueueUpdate(genericNode)
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

// checkAndAddNode performs admission checks and adds node to appropriate table.
func (s *Service) checkAndAddNode(n *v5node.Node) bool {
	// Determine layer
	isEL := s.enrManager.FilterELNode(n.Record())
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

// LocalNode returns the local node.
func (s *Service) LocalNode() *v5node.Node {
	return s.localNode
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

// updateENRWithDiscoveredIP updates the local ENR with the discovered external IP.
func (s *Service) updateENRWithDiscoveredIP(ip net.IP, port uint16, isIPv6 bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.localNode == nil {
		return
	}

	// Get current ENR
	currentENR := s.localNode.Record()

	// Check if IP/port has actually changed
	currentIP := currentENR.IP()
	currentPort := currentENR.UDP()
	if currentIP != nil && currentIP.Equal(ip) && currentPort == port {
		s.config.Logger.Debug("IP discovery: no change in external IP")
		return
	}

	s.config.Logger.WithFields(map[string]interface{}{
		"ip":     ip.String(),
		"port":   port,
		"isIPv6": isIPv6,
	}).Info("IP discovery: consensus reached, updating ENR")

	// Update the ENR with the new IP/port
	// The ENR manager will handle signing and incrementing the sequence number
	var err error
	if isIPv6 {
		err = s.enrManager.UpdateENRWithIP6(ip, port)
	} else {
		err = s.enrManager.UpdateENRWithIP(ip, port)
	}

	if err != nil {
		s.config.Logger.WithError(err).Error("failed to update ENR with discovered IP")
		return
	}

	// Store the updated ENR
	if err := s.storeENR(s.localNode.Record()); err != nil {
		s.config.Logger.WithError(err).Warn("failed to store updated ENR")
	}

	// Update discv4 service's local ENR if enabled
	if s.discv4Service != nil {
		s.discv4Service.SetLocalENR(s.localNode.Record())
	}
}
