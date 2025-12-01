package nodes

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethpandaops/bootnodoor/db"
	discv5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/stats"
	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
)

// NodeDB wraps the Database and provides node storage with async updates.
// It operates on either el or cl table based on the layer configuration.
type NodeDB struct {
	db     *db.Database
	logger logrus.FieldLogger
	ctx    context.Context
	layer  db.NodeLayer // Which table to operate on (el or cl)

	// Update queue for async DB writes - queues nodes by reference
	updateQueue     chan *Node
	updateQueueSet  map[[32]byte]*Node // Tracks pending updates by nodeID
	updateQueueLock sync.Mutex

	// Stats tracking
	stats     NodeDBStats
	statsLock sync.RWMutex

	wg sync.WaitGroup
}

// NodeDBStats contains statistics about database operations.
type NodeDBStats struct {
	QueueSize        int   // Current number of pending updates in queue
	ProcessedUpdates int64 // Total updates processed
	MergedUpdates    int64 // Total updates merged with existing pending
	FailedUpdates    int64 // Total updates that failed
	Transactions     int64 // Total database transactions executed
	TotalQueries     int64 // Total database queries executed
	OpenConnections  int   // Current number of open DB connections
}

// NewNodeDB creates a new node database wrapper for the specified layer.
// layer should be either db.LayerEL or db.LayerCL.
func NewNodeDB(ctx context.Context, database *db.Database, layer db.NodeLayer, logger logrus.FieldLogger) *NodeDB {
	ndb := &NodeDB{
		db:             database,
		logger:         logger,
		ctx:            ctx,
		layer:          layer,
		updateQueue:    make(chan *Node, 1000),
		updateQueueSet: make(map[[32]byte]*Node),
	}

	// Start update queue processor
	ndb.wg.Add(1)
	go ndb.processUpdateQueue()

	return ndb
}

// QueueUpdate queues a node for database update.
// The node's dirty flags determine what gets updated.
func (ndb *NodeDB) QueueUpdate(n *Node) error {
	if n == nil {
		return fmt.Errorf("cannot queue nil node")
	}

	nodeID := n.ID()

	ndb.updateQueueLock.Lock()
	defer ndb.updateQueueLock.Unlock()

	// Check if there's already a pending update for this node
	if _, ok := ndb.updateQueueSet[nodeID]; ok {
		// Node already queued - dirty flags will accumulate automatically
		// since we're storing the same node reference
		ndb.statsLock.Lock()
		ndb.stats.MergedUpdates++
		ndb.statsLock.Unlock()
		return nil
	}

	// Add to queue set
	ndb.updateQueueSet[nodeID] = n

	// Send to queue (non-blocking)
	select {
	case ndb.updateQueue <- n:
		ndb.logger.WithFields(logrus.Fields{
			"nodeID":      fmt.Sprintf("%x", nodeID[:8]),
			"dirtyFields": n.GetDirtyFlags(),
			"queueSize":   len(ndb.updateQueue),
		}).Debug("queued node for update")
		return nil
	default:
		// Queue full, remove from set
		delete(ndb.updateQueueSet, nodeID)

		ndb.logger.WithFields(logrus.Fields{
			"nodeID": fmt.Sprintf("%x", nodeID[:8]),
		}).Warn("update queue full, dropping update")

		// Track failed update
		ndb.statsLock.Lock()
		ndb.stats.FailedUpdates++
		ndb.statsLock.Unlock()

		return fmt.Errorf("update queue full")
	}
}

// processUpdateQueue processes the async update queue in batches of 50.
func (ndb *NodeDB) processUpdateQueue() {
	defer ndb.wg.Done()

	batch := make([]*Node, 0, 50)
	ticker := time.NewTicker(1000 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ndb.ctx.Done():
			// Process remaining batch
			if len(batch) > 0 {
				ndb.batchUpdate(batch)
			}
			return

		case node := <-ndb.updateQueue:
			batch = append(batch, node)

			// Process when batch reaches 50 items
			if len(batch) >= 50 {
				ndb.batchUpdate(batch)
				batch = batch[:0]
				time.Sleep(10 * time.Millisecond) // Avoid hammering DB
			}

		case <-ticker.C:
			// Process any pending items
			if len(batch) > 0 {
				ndb.batchUpdate(batch)
				batch = batch[:0]
			}
		}
	}
}

// batchUpdate performs a batch update of nodes.
func (ndb *NodeDB) batchUpdate(nodes []*Node) {
	if len(nodes) == 0 {
		return
	}

	ndb.logger.WithFields(logrus.Fields{
		"count": len(nodes),
		"layer": ndb.layer,
	}).Debug("processing batch update")

	err := ndb.db.RunDBTransaction(func(tx *sqlx.Tx) error {
		for _, node := range nodes {
			dirtyFlags := node.GetDirtyFlags()
			nodeID := node.ID()

			ndb.logger.WithFields(logrus.Fields{
				"nodeID":      fmt.Sprintf("%x", nodeID[:8]),
				"dirtyFields": dirtyFlags,
			}).Debug("processing node in batch")

			// Handle full upsert (initial add)
			if dirtyFlags&DirtyFull != 0 {
				ndb.logger.WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Debug("full upsert")
				if err := ndb.upsertNodeTx(tx, node); err != nil {
					ndb.logger.WithError(err).WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Error("failed to upsert node in batch")
					continue
				}
				// Full upsert covers everything, clear all dirty flags
				node.ClearDirtyFlags()
				continue
			}

			// Handle ENR update (seq+enr+ip)
			if dirtyFlags&DirtyENR != 0 {
				ndb.logger.WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Debug("updating ENR")
				if err := ndb.updateNodeENRTx(tx, node); err != nil {
					ndb.logger.WithError(err).WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Error("failed to update ENR in batch")
				}
			}

			// Handle stats update
			if dirtyFlags&DirtyStats != 0 {
				ndb.logger.WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Debug("updating stats")
				if err := ndb.updateNodeStatsTx(tx, node); err != nil {
					ndb.logger.WithError(err).WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Error("failed to update stats in batch")
				}
			}

			// Handle last_active update
			if dirtyFlags&DirtyLastActive != 0 {
				lastActive := node.LastActive()
				if !lastActive.IsZero() {
					if err := ndb.db.UpdateNodeLastActive(tx, ndb.layer, nodeID[:], lastActive.Unix()); err != nil {
						ndb.logger.WithError(err).WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Error("failed to update last_active in batch")
					}
				}
			}

			// Handle last_seen update
			if dirtyFlags&DirtyLastSeen != 0 {
				lastSeen := node.LastSeen()
				if !lastSeen.IsZero() {
					if err := ndb.db.UpdateNodeLastSeen(tx, ndb.layer, nodeID[:], lastSeen.Unix()); err != nil {
						ndb.logger.WithError(err).WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Error("failed to update last_seen in batch")
					}
				}
			}

			// Handle protocol support update
			if dirtyFlags&DirtyProtocol != 0 {
				if err := ndb.updateNodeProtocolSupportTx(tx, nodeID, node.HasV4(), node.HasV5()); err != nil {
					ndb.logger.WithError(err).WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Error("failed to update protocol support in batch")
				}
			}

			// Clear dirty flags after successful update
			node.ClearDirtyFlags()
		}
		return nil
	})

	if err != nil {
		ndb.logger.WithError(err).Error("failed to commit batch transaction")
	} else {
		ndb.logger.WithFields(logrus.Fields{
			"count": len(nodes),
			"layer": ndb.layer,
		}).Debug("batch update committed successfully")
	}

	// Remove nodes from queue set
	ndb.updateQueueLock.Lock()
	for _, node := range nodes {
		delete(ndb.updateQueueSet, node.ID())
	}
	ndb.updateQueueLock.Unlock()

	// Track processed updates
	ndb.statsLock.Lock()
	ndb.stats.ProcessedUpdates += int64(len(nodes))
	ndb.statsLock.Unlock()
}

// updateNodeENRTx updates only ENR info within a transaction.
func (ndb *NodeDB) updateNodeENRTx(tx *sqlx.Tx, n *Node) error {
	nodeID := n.ID()
	ip := n.Addr().IP
	var ipv4, ipv6 []byte

	if ip.To4() != nil {
		ipv4 = ip.To4()
	} else {
		ipv6 = ip.To16()
	}

	port := n.Addr().Port
	seq := n.ENR().Seq()

	// Extract fork digest based on layer
	var forkDigest []byte
	if ndb.layer == db.LayerEL {
		// EL: use 'eth' field fork digest
		// The eth field is RLP-encoded as [[ForkHash, ForkNext]] - a list of fork IDs
		var forkList []struct {
			Hash []byte
			Next uint64
		}
		if err := n.ENR().Get("eth", &forkList); err == nil && len(forkList) > 0 {
			// Use the first (current) fork ID
			forkData := forkList[0]
			// Validate hash is 4 bytes
			if len(forkData.Hash) == 4 {
				forkDigest = forkData.Hash
			}
		}
	} else {
		// CL: use 'eth2' field fork digest
		if eth2, ok := n.ENR().Eth2(); ok {
			forkDigest = eth2.ForkDigest[:]
		}
	}

	enrBytes, err := n.ENR().EncodeRLP()
	if err != nil {
		return fmt.Errorf("failed to encode ENR: %w", err)
	}

	return ndb.db.UpdateNodeENR(tx, ndb.layer, nodeID[:], ipv4, ipv6, port, seq, forkDigest, enrBytes, n.HasV4(), n.HasV5())
}

// updateNodeStatsTx updates only packet stats within a transaction.
func (ndb *NodeDB) updateNodeStatsTx(tx *sqlx.Tx, n *Node) error {
	nodeID := n.ID()
	query := "UPDATE nodes SET success_count = ?, failure_count = ?, avg_rtt = ? WHERE nodeid = ? AND layer = ?"
	_, err := tx.Exec(query, n.SuccessCount(), n.FailureCount(), int(n.AvgRTT().Milliseconds()), nodeID[:], string(ndb.layer))
	return err
}

// updateNodeProtocolSupportTx updates only the has_v4/has_v5 flags within a transaction.
func (ndb *NodeDB) updateNodeProtocolSupportTx(tx *sqlx.Tx, id [32]byte, hasV4, hasV5 bool) error {
	query := "UPDATE nodes SET has_v4 = ?, has_v5 = ? WHERE nodeid = ? AND layer = ?"
	_, err := tx.Exec(query, hasV4, hasV5, id[:], string(ndb.layer))
	return err
}

// upsertNodeTx upserts a node within a transaction (full insert/update).
func (ndb *NodeDB) upsertNodeTx(tx *sqlx.Tx, n *Node) error {
	nodeID := n.ID()
	ip := n.Addr().IP
	var ipv4, ipv6 []byte

	if ip.To4() != nil {
		ipv4 = ip.To4()
	} else {
		ipv6 = ip.To16()
	}

	port := n.Addr().Port
	seq := n.ENR().Seq()

	enrBytes, err := n.ENR().EncodeRLP()
	if err != nil {
		return fmt.Errorf("failed to encode ENR: %w", err)
	}

	stats := n.GetStats()
	firstSeen := stats.FirstSeen.Unix()

	lastSeen := sql.NullInt64{}
	if !stats.LastSeen.IsZero() {
		lastSeen.Valid = true
		lastSeen.Int64 = stats.LastSeen.Unix()
	}

	// Extract fork digest based on layer
	var forkDigest []byte
	if ndb.layer == db.LayerEL {
		// EL: use 'eth' field fork digest
		// The eth field is RLP-encoded as [[ForkHash, ForkNext]] - a list of fork IDs
		var forkList []struct {
			Hash []byte
			Next uint64
		}
		if err := n.ENR().Get("eth", &forkList); err == nil && len(forkList) > 0 {
			// Use the first (current) fork ID
			forkData := forkList[0]
			// Validate hash is 4 bytes
			if len(forkData.Hash) == 4 {
				forkDigest = forkData.Hash
			}
		}
	} else {
		// CL: use 'eth2' field fork digest
		if eth2, ok := n.ENR().Eth2(); ok {
			forkDigest = eth2.ForkDigest[:]
		}
	}

	node := &db.Node{
		NodeID:       nodeID[:],
		Layer:        string(ndb.layer),
		IP:           ipv4,
		IPv6:         ipv6,
		Port:         port,
		Seq:          seq,
		ForkDigest:   forkDigest,
		FirstSeen:    firstSeen,
		LastSeen:     lastSeen,
		LastActive:   sql.NullInt64{}, // Updated separately
		ENR:          enrBytes,
		HasV4:        n.HasV4(),
		HasV5:        n.HasV5(),
		SuccessCount: stats.SuccessCount,
		FailureCount: stats.FailureCount,
		AvgRTT:       int(stats.AvgRTT.Milliseconds()),
	}

	ndb.logger.WithFields(logrus.Fields{
		"nodeID": fmt.Sprintf("%x", nodeID[:8]),
		"peerID": n.PeerID(),
		"layer":  ndb.layer,
		"hasV4":  n.HasV4(),
		"hasV5":  n.HasV5(),
	}).Debug("upserting node to database")

	err = ndb.db.UpsertNode(tx, node)
	if err != nil {
		ndb.logger.WithError(err).WithField("nodeID", fmt.Sprintf("%x", nodeID[:8])).Error("failed to upsert node")
	}
	return err
}

// Load retrieves a node by ID.
func (ndb *NodeDB) Load(id [32]byte) (*Node, error) {
	dbNode, err := ndb.db.GetNode(ndb.layer, id[:])
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("node not found")
	}
	if err != nil {
		return nil, err
	}

	return ndb.buildNodeFromDB(dbNode)
}

// buildNodeFromDB creates a Node from database record.
func (ndb *NodeDB) buildNodeFromDB(dbNode *db.Node) (*Node, error) {
	// Decode ENR
	enrRecord := &enr.Record{}
	if err := enrRecord.DecodeRLPBytes(dbNode.ENR); err != nil {
		return nil, fmt.Errorf("failed to decode ENR: %w", err)
	}

	// Create discv5 node from ENR record
	v5Node, err := discv5node.New(enrRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to create node from ENR: %w", err)
	}

	// Extract public key
	pubKey := v5Node.PublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("ENR has no public key")
	}

	// Build address
	ip := enrRecord.IP()
	if ip == nil {
		return nil, fmt.Errorf("ENR has no IP")
	}
	port := enrRecord.UDP()
	addr := &net.UDPAddr{
		IP:   ip,
		Port: int(port),
	}

	// Create base node WITHOUT protocol-specific nodes initially
	// Create shared stats from database values
	nodeStats := stats.NewSharedStats(time.Unix(dbNode.FirstSeen, 0))
	nodeStats.SetSuccessCount(dbNode.SuccessCount)
	nodeStats.SetFailureCount(dbNode.FailureCount)
	if dbNode.AvgRTT > 0 {
		nodeStats.UpdateRTT(time.Duration(dbNode.AvgRTT) * time.Millisecond)
	}
	if dbNode.LastSeen.Valid {
		nodeStats.SetLastSeen(time.Unix(dbNode.LastSeen.Int64, 0))
	}

	// We'll add v4/v5 based on database flags
	n := &Node{
		nodedb:    ndb,
		id:        discv5node.PubkeyToID(pubKey),
		pubKey:    pubKey,
		enr:       enrRecord,
		addr:      addr,
		nodeStats: nodeStats,
	}

	// Only set v5 node if marked as having v5 support
	if dbNode.HasV5 {
		n.SetV5(v5Node)
	}

	// Only create v4 node if marked as having v4 support
	if dbNode.HasV4 {
		v4Node, err := NewV4NodeFromRecord(enrRecord, addr)
		if err != nil {
			ndb.logger.WithError(err).Debug("failed to create v4 node from DB record")
		} else {
			n.SetV4(v4Node)
		}
	}

	return n, nil
}

// LoadAll loads all nodes for this layer.
func (ndb *NodeDB) LoadAll() ([]*Node, error) {
	dbNodes, err := ndb.db.GetAllNodes()
	if err != nil {
		return nil, err
	}

	// Filter by layer
	filteredNodes := make([]*db.Node, 0)
	for _, dbNode := range dbNodes {
		if dbNode.Layer == string(ndb.layer) {
			filteredNodes = append(filteredNodes, dbNode)
		}
	}
	dbNodes = filteredNodes

	nodes := make([]*Node, 0, len(dbNodes))
	for _, dbNode := range dbNodes {
		node, err := ndb.buildNodeFromDB(dbNode)
		if err != nil {
			ndb.logger.WithError(err).WithField("nodeID", fmt.Sprintf("%x", dbNode.NodeID[:8])).Warn("failed to build node from DB")
			continue
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// LoadRandom loads a random sample of nodes (up to limit).
func (ndb *NodeDB) LoadRandom(limit int) ([]*Node, error) {
	dbNodes, err := ndb.db.GetRandomNodes(ndb.layer, limit)
	if err != nil {
		return nil, err
	}

	nodes := make([]*Node, 0, len(dbNodes))
	for _, dbNode := range dbNodes {
		node, err := ndb.buildNodeFromDB(dbNode)
		if err != nil {
			ndb.logger.WithError(err).WithField("nodeID", fmt.Sprintf("%x", dbNode.NodeID[:8])).Warn("failed to build node from DB")
			continue
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// Close stops the update queue processor and waits for pending updates.
func (ndb *NodeDB) Close() {
	// Wait for queue processor to finish
	ndb.wg.Wait()
}

// GetStats returns current database statistics.
func (ndb *NodeDB) GetStats() NodeDBStats {
	ndb.statsLock.RLock()
	stats := ndb.stats
	ndb.statsLock.RUnlock()

	// Get current queue size
	ndb.updateQueueLock.Lock()
	stats.QueueSize = len(ndb.updateQueueSet)
	ndb.updateQueueLock.Unlock()

	// Get database stats
	dbStats := ndb.db.GetStats()
	stats.Transactions = dbStats.Transactions
	stats.TotalQueries = dbStats.TotalQueries
	stats.OpenConnections = dbStats.OpenConnections

	return stats
}

// List loads all nodes (alias for LoadAll).
func (ndb *NodeDB) List() []*Node {
	nodes, _ := ndb.LoadAll()
	return nodes
}

// Count returns the total number of nodes in the database.
func (ndb *NodeDB) Count() int {
	count, err := ndb.db.CountNodes(ndb.layer)
	if err != nil {
		ndb.logger.WithError(err).Warn("failed to count nodes")
		return 0
	}
	return count
}

// LoadRandomNodes loads a random sample of nodes (alias for LoadRandom).
func (ndb *NodeDB) LoadRandomNodes(limit int) []*Node {
	nodes, _ := ndb.LoadRandom(limit)
	return nodes
}

// LoadInactiveNodes loads inactive nodes (not seen recently).
func (ndb *NodeDB) LoadInactiveNodes(limit int) []*Node {
	dbNodes, err := ndb.db.GetInactiveNodes(ndb.layer, limit)
	if err != nil {
		ndb.logger.WithError(err).Warn("failed to load inactive nodes")
		return nil
	}

	nodes := make([]*Node, 0, len(dbNodes))
	for _, dbNode := range dbNodes {
		node, err := ndb.buildNodeFromDB(dbNode)
		if err != nil {
			ndb.logger.WithError(err).WithField("nodeID", fmt.Sprintf("%x", dbNode.NodeID[:8])).Warn("failed to build node from DB")
			continue
		}
		nodes = append(nodes, node)
	}

	return nodes
}
