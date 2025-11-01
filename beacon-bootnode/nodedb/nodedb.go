// Package nodedb provides persistent storage for discovered nodes.
//
// The database tracks:
//   - Node ENR records
//   - Network statistics (last seen, RTT, failure counts)
//   - Node aliveness status
//
// It supports:
//   - Thread-safe concurrent access
//   - ENR-based queries with filtering
//   - Automatic expiration of old nodes
package nodedb

import (
	"fmt"
	"sync"
	"time"

	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/sirupsen/logrus"
)

// DB is the interface for node database implementations.
//
// Implementations must be thread-safe and support concurrent access.
type DB interface {
	// Store stores or updates a node in the database
	Store(n *node.Node) error

	// Load retrieves a node by ID
	Load(id node.ID) (*node.Node, error)

	// Delete removes a node from the database
	Delete(id node.ID) error

	// List returns all nodes in the database
	List() []*node.Node

	// Query returns nodes matching the given filter
	Query(filter enr.ENRFilter) []*node.Node

	// Count returns the total number of nodes
	Count() int

	// StoreLocalENR stores the local node's ENR record
	StoreLocalENR(enrBytes []byte) error

	// LoadLocalENR loads the local node's ENR record (returns nil, nil if not found)
	LoadLocalENR() ([]byte, error)

	// StoreRejection stores a rejection entry to prevent log spam
	StoreRejection(id node.ID, reason uint8, timestamp time.Time) error

	// LoadRejection retrieves a rejection entry
	LoadRejection(id node.ID) (flags uint8, timestamp time.Time, found bool, err error)

	// DeleteRejection removes a rejection entry
	DeleteRejection(id node.ID) error

	// ExpireRejections removes rejection entries older than the given duration
	ExpireRejections(ttl time.Duration) (int, error)

	// Close closes the database and releases resources
	Close() error
}

// RejectionEntry tracks when we last logged a rejection for a node.
type RejectionEntry struct {
	Flags     uint8
	Timestamp time.Time
}

// MemoryDB is an in-memory implementation of the node database.
//
// All data is stored in memory and lost when the process exits.
// This is suitable for most use cases and provides fast access.
type MemoryDB struct {
	// nodes maps node ID to node
	nodes map[node.ID]*node.Node

	// rejections tracks rejected nodes to avoid log spam
	rejections map[node.ID]*RejectionEntry

	// localENR stores the local node's ENR
	localENR []byte

	// mu protects nodes map and localENR
	mu sync.RWMutex

	// stats tracks database statistics
	stats Stats

	// logger for debug messages
	logger logrus.FieldLogger
}

// Stats contains statistics about the database.
type Stats struct {
	// TotalNodes is the total number of nodes stored
	TotalNodes int

	// AliveNodes is the number of nodes considered alive
	AliveNodes int

	// OldestSeen is the oldest last-seen time
	OldestSeen time.Time

	// NewestSeen is the newest last-seen time
	NewestSeen time.Time
}

// NewMemoryDB creates a new in-memory node database.
//
// Example:
//
//	db := NewMemoryDB(logger)
//	defer db.Close()
func NewMemoryDB(logger logrus.FieldLogger) *MemoryDB {
	return &MemoryDB{
		nodes:      make(map[node.ID]*node.Node),
		rejections: make(map[node.ID]*RejectionEntry),
		logger:     logger,
	}
}

// Store stores or updates a node in the database.
//
// If a node with the same ID already exists:
//   - The ENR is updated if the new sequence number is higher
//   - Statistics are preserved and updated
//
// Example:
//
//	if err := db.Store(node); err != nil {
//	    log.Printf("Failed to store node: %v", err)
//	}
func (db *MemoryDB) Store(n *node.Node) error {
	if n == nil {
		return fmt.Errorf("nodedb: nil node")
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	id := n.ID()

	// Check if node already exists
	existing, exists := db.nodes[id]
	if exists {
		// Update ENR if sequence number is higher
		if n.Record().Seq() > existing.Record().Seq() {
			existing.UpdateENR(n.Record())
		}

		// Copy over statistics from new node
		// (assumes caller has updated these)
		stats := n.GetStats()
		if !stats.LastSeen.IsZero() {
			existing.SetLastSeen(stats.LastSeen)
		}
		if !stats.LastPing.IsZero() {
			existing.SetLastPing(stats.LastPing)
		}
	} else {
		// New node - set FirstSeen if not already set
		stats := n.GetStats()
		if stats.FirstSeen.IsZero() {
			n.SetFirstSeen(time.Now())
		}
		// Store new node
		db.nodes[id] = n
	}

	return nil
}

// Load retrieves a node by ID.
//
// Returns node.ErrNodeNotFound if the node doesn't exist.
//
// Example:
//
//	node, err := db.Load(nodeID)
//	if err == node.ErrNodeNotFound {
//	    // Node not in database
//	}
func (db *MemoryDB) Load(id node.ID) (*node.Node, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	n, exists := db.nodes[id]
	if !exists {
		return nil, node.ErrNodeNotFound
	}

	return n, nil
}

// Delete removes a node from the database.
//
// Returns node.ErrNodeNotFound if the node doesn't exist.
//
// Example:
//
//	if err := db.Delete(nodeID); err != nil {
//	    log.Printf("Failed to delete node: %v", err)
//	}
func (db *MemoryDB) Delete(id node.ID) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.nodes[id]; !exists {
		return node.ErrNodeNotFound
	}

	delete(db.nodes, id)
	return nil
}

// List returns all nodes in the database.
//
// The returned slice is a copy and can be safely modified.
//
// Example:
//
//	nodes := db.List()
//	fmt.Printf("Database contains %d nodes\n", len(nodes))
func (db *MemoryDB) List() []*node.Node {
	db.mu.RLock()
	defer db.mu.RUnlock()

	result := make([]*node.Node, 0, len(db.nodes))
	for _, n := range db.nodes {
		result = append(result, n)
	}

	return result
}

// Query returns nodes matching the given ENR filter.
//
// If filter is nil, all nodes are returned.
//
// Example:
//
//	// Find all nodes with eth2 field
//	filter := enr.ByKey("eth2")
//	nodes := db.Query(filter)
func (db *MemoryDB) Query(filter enr.ENRFilter) []*node.Node {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []*node.Node

	for _, n := range db.nodes {
		if filter == nil || filter(n.Record()) {
			result = append(result, n)
		}
	}

	return result
}

// Count returns the total number of nodes in the database.
func (db *MemoryDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return len(db.nodes)
}

// Stats returns statistics about the database.
//
// Example:
//
//	stats := db.Stats()
//	fmt.Printf("Total nodes: %d, Alive: %d\n",
//	    stats.TotalNodes, stats.AliveNodes)
func (db *MemoryDB) Stats() Stats {
	db.mu.RLock()
	defer db.mu.RUnlock()

	stats := Stats{
		TotalNodes: len(db.nodes),
	}

	var oldestSeen, newestSeen time.Time
	maxAge := 24 * time.Hour
	maxFailures := 3

	for _, n := range db.nodes {
		// Count alive nodes
		if n.IsAlive(maxAge, maxFailures) {
			stats.AliveNodes++
		}

		// Track oldest/newest seen
		lastSeen := n.LastSeen()
		if !lastSeen.IsZero() {
			if oldestSeen.IsZero() || lastSeen.Before(oldestSeen) {
				oldestSeen = lastSeen
			}
			if newestSeen.IsZero() || lastSeen.After(newestSeen) {
				newestSeen = lastSeen
			}
		}
	}

	stats.OldestSeen = oldestSeen
	stats.NewestSeen = newestSeen

	return stats
}

// ExpireOld removes nodes that haven't been seen recently.
//
// Nodes are removed if:
//   - They haven't been seen in maxAge, OR
//   - They have more than maxFailures consecutive failures
//
// Returns the number of nodes removed.
//
// Example:
//
//	// Remove nodes not seen in 24 hours
//	count := db.ExpireOld(24 * time.Hour, 3)
//	log.Printf("Removed %d expired nodes", count)
func (db *MemoryDB) ExpireOld(maxAge time.Duration, maxFailures int) int {
	db.mu.Lock()
	defer db.mu.Unlock()

	var toDelete []node.ID

	for id, n := range db.nodes {
		if !n.IsAlive(maxAge, maxFailures) {
			toDelete = append(toDelete, id)
		}
	}

	for _, id := range toDelete {
		delete(db.nodes, id)
	}

	if len(toDelete) > 0 {
		db.logger.Info("nodedb: expired old nodes", "count", len(toDelete))
	}

	return len(toDelete)
}

// Close closes the database and releases resources.
//
// For MemoryDB, this is a no-op but satisfies the DB interface.
func (db *MemoryDB) Close() error {
	return nil
}

// StoreLocalENR stores the local node's ENR record.
func (db *MemoryDB) StoreLocalENR(enrBytes []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.localENR = enrBytes
	return nil
}

// LoadLocalENR loads the local node's ENR record.
//
// Returns nil, nil if no local ENR is stored.
func (db *MemoryDB) LoadLocalENR() ([]byte, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.localENR, nil
}

// FindClosestNodes finds the k nodes closest to the target ID.
//
// The results are sorted by distance (closest first).
// If the database contains fewer than k nodes, all nodes are returned.
//
// Example:
//
//	// Find 16 closest nodes to target
//	closest := db.FindClosestNodes(targetID, 16)
func (db *MemoryDB) FindClosestNodes(target node.ID, k int) []*node.Node {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if len(db.nodes) == 0 {
		return nil
	}

	// Collect all node IDs
	ids := make([]node.ID, 0, len(db.nodes))
	for id := range db.nodes {
		ids = append(ids, id)
	}

	// Find k closest IDs
	closestIDs := node.FindClosest(target, ids, k)

	// Convert to nodes
	result := make([]*node.Node, 0, len(closestIDs))
	for _, id := range closestIDs {
		if n, exists := db.nodes[id]; exists {
			result = append(result, n)
		}
	}

	return result
}

// FindByDistance finds nodes at a specific logarithmic distance (bucket).
//
// This is useful for random walks in the routing table.
//
// Example:
//
//	// Find nodes at distance 128 from local node
//	nodes := db.FindByDistance(localID, 128)
func (db *MemoryDB) FindByDistance(target node.ID, logDist int) []*node.Node {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []*node.Node

	for id, n := range db.nodes {
		if node.LogDistance(target, id) == logDist {
			result = append(result, n)
		}
	}

	return result
}

// StoreRejection stores a rejection entry to prevent log spam.
//
// If an entry already exists, the flags are OR-ed together.
func (db *MemoryDB) StoreRejection(id node.ID, reason uint8, timestamp time.Time) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if entry, exists := db.rejections[id]; exists {
		// Update existing entry
		entry.Flags |= reason
		entry.Timestamp = timestamp
	} else {
		// Create new entry
		db.rejections[id] = &RejectionEntry{
			Flags:     reason,
			Timestamp: timestamp,
		}
	}

	return nil
}

// LoadRejection retrieves a rejection entry.
//
// Returns found=false if no entry exists.
func (db *MemoryDB) LoadRejection(id node.ID) (flags uint8, timestamp time.Time, found bool, err error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	entry, exists := db.rejections[id]
	if !exists {
		return 0, time.Time{}, false, nil
	}

	return entry.Flags, entry.Timestamp, true, nil
}

// DeleteRejection removes a rejection entry.
func (db *MemoryDB) DeleteRejection(id node.ID) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	delete(db.rejections, id)
	return nil
}

// ExpireRejections removes rejection entries older than the given duration.
//
// Returns the number of entries removed.
func (db *MemoryDB) ExpireRejections(ttl time.Duration) (int, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now()
	removed := 0

	for id, entry := range db.rejections {
		if now.Sub(entry.Timestamp) > ttl {
			delete(db.rejections, id)
			removed++
		}
	}

	return removed, nil
}
