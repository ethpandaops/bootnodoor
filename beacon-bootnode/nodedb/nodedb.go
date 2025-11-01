package nodedb

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/pk910/bootoor/beacon-bootnode/db"
	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/sirupsen/logrus"
)

// updateType represents the type of update to perform
type updateType uint8

const (
	updateTypeENR        updateType = iota // Update seq+enr+ip only (preserve stats & timestamps)
	updateTypeFull                         // Full update including stats (after ping/stats change)
	updateTypeLastActive                   // Update last_active timestamp only
	updateTypeLastSeen                     // Update last_seen timestamp only
)

// nodeUpdate represents a pending database update for a node.
type nodeUpdate struct {
	nodeID     node.ID
	updateType updateType
	node       *node.Node // For ENR and full updates
	active     bool       // For last_active updates
	timestamp  time.Time  // For last_seen updates
}

// NodeDB wraps the Database and provides node storage with async updates.
type NodeDB struct {
	db     *db.Database
	logger logrus.FieldLogger
	ctx    context.Context

	// Update queue for async DB writes (50 per batch with sleep)
	updateQueue     chan nodeUpdate
	updateQueueSet  map[node.ID]*nodeUpdate // Tracks pending updates, can merge
	updateQueueLock sync.Mutex

	wg sync.WaitGroup
}

// NewNodeDB creates a new node database wrapper.
func NewNodeDB(ctx context.Context, database *db.Database, logger logrus.FieldLogger) *NodeDB {
	ndb := &NodeDB{
		db:             database,
		logger:         logger,
		ctx:            ctx,
		updateQueue:    make(chan nodeUpdate, 1000),
		updateQueueSet: make(map[node.ID]*nodeUpdate),
	}

	// Start update queue processor
	ndb.wg.Add(1)
	go ndb.processUpdateQueue()

	return ndb
}

// UpdateNodeENR queues an ENR update (seq+enr+ip only, preserves stats & timestamps).
// Use this when receiving nodes from discovery (FINDNODE responses).
func (ndb *NodeDB) UpdateNodeENR(n *node.Node) error {
	if n == nil {
		return fmt.Errorf("cannot update nil node")
	}

	update := nodeUpdate{
		nodeID:     n.ID(),
		updateType: updateTypeENR,
		node:       n,
	}

	return ndb.queueUpdate(update)
}

// UpdateNodeFull queues a full node update including stats.
// Use this after pinging or when stats have changed.
func (ndb *NodeDB) UpdateNodeFull(n *node.Node) error {
	if n == nil {
		return fmt.Errorf("cannot update nil node")
	}

	update := nodeUpdate{
		nodeID:     n.ID(),
		updateType: updateTypeFull,
		node:       n,
	}

	return ndb.queueUpdate(update)
}

// UpdateLastActive queues a last_active timestamp update.
func (ndb *NodeDB) UpdateLastActive(id node.ID, active bool) error {
	update := nodeUpdate{
		nodeID:     id,
		updateType: updateTypeLastActive,
		active:     active,
	}

	return ndb.queueUpdate(update)
}

// UpdateLastSeen queues a last_seen timestamp update.
func (ndb *NodeDB) UpdateLastSeen(id node.ID, timestamp time.Time) error {
	update := nodeUpdate{
		nodeID:     id,
		updateType: updateTypeLastSeen,
		timestamp:  timestamp,
	}

	return ndb.queueUpdate(update)
}

// queueUpdate queues an update, merging with existing pending updates if possible.
func (ndb *NodeDB) queueUpdate(update nodeUpdate) error {
	ndb.updateQueueLock.Lock()
	defer ndb.updateQueueLock.Unlock()

	// Check if there's already a pending update for this node
	if existing, ok := ndb.updateQueueSet[update.nodeID]; ok {
		// Merge updates based on priority:
		// updateTypeFull > updateTypeENR > updateTypeLastActive/updateTypeLastSeen

		if update.updateType == updateTypeFull {
			// Full update takes precedence over everything
			existing.updateType = updateTypeFull
			existing.node = update.node
		} else if existing.updateType == updateTypeFull {
			// Don't downgrade from full update
			return nil
		} else if update.updateType == updateTypeENR {
			// ENR update takes precedence over timestamp updates
			if existing.updateType != updateTypeENR {
				existing.updateType = updateTypeENR
				existing.node = update.node
			}
		} else if existing.updateType == updateTypeENR {
			// Don't downgrade from ENR update
			return nil
		} else {
			// Merge timestamp updates
			if update.updateType == updateTypeLastActive {
				existing.active = update.active
			} else if update.updateType == updateTypeLastSeen {
				existing.timestamp = update.timestamp
			}
		}
		return nil
	}

	// Add to queue set
	ndb.updateQueueSet[update.nodeID] = &update

	// Send to queue (non-blocking)
	select {
	case ndb.updateQueue <- update:
		return nil
	default:
		// Queue full, remove from set
		delete(ndb.updateQueueSet, update.nodeID)
		return fmt.Errorf("update queue full")
	}
}

// processUpdateQueue processes the async update queue in batches of 50.
func (ndb *NodeDB) processUpdateQueue() {
	defer ndb.wg.Done()

	batch := make([]nodeUpdate, 0, 50)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ndb.ctx.Done():
			// Process remaining batch
			if len(batch) > 0 {
				ndb.batchUpdate(batch)
			}
			return

		case update := <-ndb.updateQueue:
			batch = append(batch, update)

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

// batchUpdate performs a batch update of node updates.
func (ndb *NodeDB) batchUpdate(updates []nodeUpdate) {
	if len(updates) == 0 {
		return
	}

	err := ndb.db.RunDBTransaction(func(tx *sqlx.Tx) error {
		for _, update := range updates {
			var err error
			switch update.updateType {
			case updateTypeENR:
				err = ndb.updateNodeENRTx(tx, update.node)
			case updateTypeFull:
				err = ndb.upsertNodeTx(tx, update.node)
			case updateTypeLastActive:
				err = ndb.db.UpdateNodeLastActive(tx, update.nodeID[:], update.active)
			case updateTypeLastSeen:
				err = ndb.updateNodeLastSeenTx(tx, update.nodeID, update.timestamp)
			}

			if err != nil {
				ndb.logger.WithError(err).WithField("nodeID", update.nodeID).Error("failed to update node in batch")
			}
		}
		return nil
	})

	if err != nil {
		ndb.logger.WithError(err).Error("failed to commit batch transaction")
	}

	// Remove updates from queue set
	ndb.updateQueueLock.Lock()
	for _, update := range updates {
		delete(ndb.updateQueueSet, update.nodeID)
	}
	ndb.updateQueueLock.Unlock()
}

// updateNodeENRTx updates only ENR info (seq+enr+ip) within a transaction, preserving stats.
func (ndb *NodeDB) updateNodeENRTx(tx *sqlx.Tx, n *node.Node) error {
	nodeID := n.ID()
	ip := n.IP()
	var ipv4, ipv6 []byte

	if ip.To4() != nil {
		ipv4 = ip.To4()
	} else {
		ipv6 = ip.To16()
	}

	port := int(n.UDPPort())
	seq := n.Record().Seq()

	var forkDigest []byte
	if eth2, ok := n.Record().Eth2(); ok {
		forkDigest = eth2.ForkDigest[:]
	}

	enrBytes, err := n.Record().EncodeRLP()
	if err != nil {
		return fmt.Errorf("failed to encode ENR: %w", err)
	}

	return ndb.db.UpdateNodeENR(tx, nodeID[:], ipv4, ipv6, port, seq, forkDigest, enrBytes)
}

// updateNodeLastSeenTx updates only the last_seen timestamp within a transaction.
func (ndb *NodeDB) updateNodeLastSeenTx(tx *sqlx.Tx, id node.ID, timestamp time.Time) error {
	return ndb.db.UpdateNodeLastSeen(tx, id[:], timestamp.Unix())
}

// upsertNodeTx upserts a node within a transaction.
func (ndb *NodeDB) upsertNodeTx(tx *sqlx.Tx, n *node.Node) error {
	nodeID := n.ID()
	ip := n.IP()
	var ipv4, ipv6 []byte

	if ip.To4() != nil {
		ipv4 = ip.To4()
	} else {
		ipv6 = ip.To16()
	}

	port := int(n.UDPPort())
	seq := n.Record().Seq()

	var forkDigest []byte
	if eth2, ok := n.Record().Eth2(); ok {
		forkDigest = eth2.ForkDigest[:]
	}

	enrBytes, err := n.Record().EncodeRLP()
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

	// Note: last_active is not set here - it's managed separately via UpdateLastActive()
	// State is implicit based on membership in the active set, not stored in the node.
	dbNode := &db.Node{
		NodeID:       nodeID[:],
		IP:           ipv4,
		IPv6:         ipv6,
		Port:         port,
		Seq:          seq,
		ForkDigest:   forkDigest,
		FirstSeen:    firstSeen,
		LastSeen:     lastSeen,
		LastActive:   sql.NullInt64{}, // NULL by default, updated via UpdateLastActive()
		ENR:          enrBytes,
		SuccessCount: stats.SuccessCount,
		FailureCount: stats.FailureCount,
		AvgRTT:       int(stats.AvgRTT.Milliseconds()),
	}

	return ndb.db.UpsertNode(tx, dbNode)
}

// Load retrieves a node by ID.
func (ndb *NodeDB) Load(id node.ID) (*node.Node, error) {
	dbNode, err := ndb.db.GetNode(id[:])
	if err == sql.ErrNoRows {
		return nil, node.ErrNodeNotFound
	}
	if err != nil {
		return nil, err
	}

	return ndb.buildNodeFromDB(dbNode)
}

// NodeExists checks if a node exists in the database.
func (ndb *NodeDB) NodeExists(id node.ID) (bool, uint64) {
	exists, seq, err := ndb.db.NodeExists(id[:])
	if err != nil {
		return false, 0
	}
	return exists, seq
}

// buildNodeFromDB constructs a node from database row data.
func (ndb *NodeDB) buildNodeFromDB(dbNode *db.Node) (*node.Node, error) {
	// Decode ENR
	var record enr.Record
	if err := record.DecodeRLPBytes(dbNode.ENR); err != nil {
		return nil, fmt.Errorf("failed to decode ENR: %w", err)
	}

	// Create node from ENR
	n, err := node.New(&record)
	if err != nil {
		return nil, fmt.Errorf("failed to create node: %w", err)
	}

	// Restore statistics
	n.SetFirstSeen(time.Unix(dbNode.FirstSeen, 0))
	if dbNode.LastSeen.Valid {
		n.SetLastSeen(time.Unix(dbNode.LastSeen.Int64, 0))
	}
	n.SetSuccessCount(dbNode.SuccessCount)
	n.SetFailureCount(dbNode.FailureCount)

	// Note: State is implicit based on membership in active set, not stored in node
	return n, nil
}

// Delete removes a node from the database.
func (ndb *NodeDB) Delete(id node.ID) error {
	return ndb.db.RunDBTransaction(func(tx *sqlx.Tx) error {
		return ndb.db.DeleteNode(tx, id[:])
	})
}

// List returns all nodes in the database.
func (ndb *NodeDB) List() []*node.Node {
	dbNodes, err := ndb.db.GetNodes()
	if err != nil {
		ndb.logger.WithError(err).Error("failed to list nodes")
		return nil
	}

	nodes := make([]*node.Node, 0, len(dbNodes))
	for _, dbNode := range dbNodes {
		n, err := ndb.buildNodeFromDB(dbNode)
		if err != nil {
			ndb.logger.WithError(err).Error("failed to build node from DB")
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes
}

// Count returns the total number of nodes.
func (ndb *NodeDB) Count() int {
	count, err := ndb.db.CountNodes()
	if err != nil {
		ndb.logger.WithError(err).Error("failed to count nodes")
		return 0
	}
	return count
}

// LoadRandomNodes loads up to N random nodes from the database.
func (ndb *NodeDB) LoadRandomNodes(n int) []*node.Node {
	dbNodes, err := ndb.db.GetRandomNodes(n)
	if err != nil {
		ndb.logger.WithError(err).Error("failed to load random nodes")
		return nil
	}

	nodes := make([]*node.Node, 0, len(dbNodes))
	for _, dbNode := range dbNodes {
		n, err := ndb.buildNodeFromDB(dbNode)
		if err != nil {
			ndb.logger.WithError(err).Error("failed to build node from DB")
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes
}

// LoadInactiveNodes loads up to N inactive nodes from the database.
// Returns nodes ordered by oldest last_active time (NULL first).
func (ndb *NodeDB) LoadInactiveNodes(n int) []*node.Node {
	dbNodes, err := ndb.db.GetInactiveNodes(n)
	if err != nil {
		ndb.logger.WithError(err).Error("failed to load inactive nodes")
		return nil
	}

	nodes := make([]*node.Node, 0, len(dbNodes))
	for _, dbNode := range dbNodes {
		n, err := ndb.buildNodeFromDB(dbNode)
		if err != nil {
			ndb.logger.WithError(err).Error("failed to build node from DB")
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes
}

// StoreLocalENR stores the local node's ENR.
func (ndb *NodeDB) StoreLocalENR(enrBytes []byte) error {
	return ndb.db.SetState(nil, "local_enr", enrBytes)
}

// LoadLocalENR retrieves the local node's ENR.
func (ndb *NodeDB) LoadLocalENR() ([]byte, error) {
	return ndb.db.GetState("local_enr")
}

// Close waits for pending updates to complete.
// The context cancellation signals shutdown.
func (ndb *NodeDB) Close() error {
	// Wait for update queue to finish
	ndb.wg.Wait()

	// Database is closed by the application, not here
	return nil
}
