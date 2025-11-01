package nodedb

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
)

// LevelDB is a persistent node database backed by LevelDB.
//
// Features:
//   - Persistent storage on disk
//   - Atomic operations
//   - Efficient range queries
//   - Automatic compaction
//
// The database stores:
//   - Node ENR records
//   - Statistics (last seen, RTT, failures)
//   - Metadata (first seen, tags)
type LevelDB struct {
	// db is the underlying LevelDB database
	db *leveldb.DB

	// path is the filesystem path to the database
	path string

	// mu protects concurrent access
	mu sync.RWMutex

	// logger for debug messages
	logger logrus.FieldLogger
}

// NodeRecord is the struct stored in the database for each node.
//
// It contains the ENR record and associated statistics.
type NodeRecord struct {
	// ENRBytes is the RLP-encoded ENR record
	ENRBytes []byte

	// Stats contains node statistics
	Stats NodeStats
}

// NodeStats contains statistics tracked for each node.
type NodeStats struct {
	// FirstSeen is when we first discovered this node
	FirstSeen time.Time

	// LastSeen is when we last received a response from this node
	LastSeen time.Time

	// LastPing is when we last sent a PING to this node
	LastPing time.Time

	// FailureCount is the number of consecutive failed requests
	FailureCount int

	// SuccessCount is the total number of successful requests
	SuccessCount int

	// AverageRTT is the average round-trip time in milliseconds
	AverageRTT float64

	// TotalRequests is the total number of requests sent
	TotalRequests int
}

// Database key prefixes
const (
	nodePrefix      = "node:"      // node:<nodeID> -> NodeRecord
	statsPrefix     = "stats:"     // stats:<nodeID> -> NodeStats
	rejectionPrefix = "rejection:" // rejection:<nodeID> -> RejectionEntry
	localNodePrefix = "local:enr"  // local:enr -> ENR bytes of local node
)

// NewLevelDB creates or opens a LevelDB-backed node database.
//
// Parameters:
//   - path: Filesystem path for the database directory
//   - logger: Optional logger for debug messages
//
// The database directory will be created if it doesn't exist.
//
// Example:
//
//	db, err := NewLevelDB("/var/lib/bootoor/nodes", logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer db.Close()
func NewLevelDB(path string, logger logrus.FieldLogger) (*LevelDB, error) {
	// Open the database with default options
	opts := &opt.Options{
		ErrorIfMissing: false,           // Create if doesn't exist
		WriteBuffer:    4 * 1024 * 1024, // 4MB write buffer
	}

	db, err := leveldb.OpenFile(path, opts)
	if err != nil {
		return nil, fmt.Errorf("nodedb: failed to open leveldb: %w", err)
	}

	logger.WithField("path", path).Info("nodedb: opened LevelDB")

	return &LevelDB{
		db:     db,
		path:   path,
		logger: logger,
	}, nil
}

// Store stores or updates a node in the database.
//
// If a node with the same ID already exists:
//   - The ENR is updated if the new sequence number is higher
//   - Statistics are updated
//
// Example:
//
//	if err := db.Store(node); err != nil {
//	    log.Printf("Failed to store node: %v", err)
//	}
func (db *LevelDB) Store(n *node.Node) error {
	if n == nil {
		return fmt.Errorf("nodedb: nil node")
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	nodeID := n.ID()
	key := makeNodeKey(nodeID)

	// Check if node already exists
	existing, err := db.loadNode(nodeID)
	if err == nil && existing != nil {
		// Update ENR if sequence number is higher
		if n.Record().Seq() > existing.Record().Seq() {
			existing.UpdateENR(n.Record())
		}

		// Merge statistics - update the existing node directly
		newStats := n.GetStats()

		if !newStats.LastSeen.IsZero() {
			existing.SetLastSeen(newStats.LastSeen)
		}
		if !newStats.LastPing.IsZero() {
			existing.SetLastPing(newStats.LastPing)
		}
		existing.SetFailureCount(newStats.FailureCount)
		existing.SetSuccessCount(newStats.SuccessCount)

		// Use existing for saving (FirstSeen is preserved from original)
		n = existing
	} else {
		// New node - set FirstSeen if not already set
		stats := n.GetStats()
		if stats.FirstSeen.IsZero() {
			n.SetFirstSeen(time.Now())
		}
	}

	// Encode the ENR
	enrBytes, err := n.Record().EncodeRLP()
	if err != nil {
		return fmt.Errorf("nodedb: failed to encode ENR: %w", err)
	}

	// Create node record
	stats := n.GetStats()
	record := NodeRecord{
		ENRBytes: enrBytes,
		Stats: NodeStats{
			FirstSeen:     stats.FirstSeen,
			LastSeen:      stats.LastSeen,
			LastPing:      stats.LastPing,
			FailureCount:  stats.FailureCount,
			SuccessCount:  stats.SuccessCount,
			AverageRTT:    0, // TODO: Track RTT
			TotalRequests: 0, // TODO: Track total requests
		},
	}

	// Encode the record using gob
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(record); err != nil {
		return fmt.Errorf("nodedb: failed to encode record: %w", err)
	}

	// Write to database
	if err := db.db.Put(key, buf.Bytes(), nil); err != nil {
		return fmt.Errorf("nodedb: failed to write: %w", err)
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
func (db *LevelDB) Load(id node.ID) (*node.Node, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.loadNode(id)
}

// loadNode is the internal implementation of Load without locking.
func (db *LevelDB) loadNode(id node.ID) (*node.Node, error) {
	key := makeNodeKey(id)

	data, err := db.db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return nil, node.ErrNodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("nodedb: failed to read: %w", err)
	}

	// Decode the record
	var record NodeRecord
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&record); err != nil {
		return nil, fmt.Errorf("nodedb: failed to decode record: %w", err)
	}

	// Decode the ENR
	enrRecord := &enr.Record{}
	if err := enrRecord.DecodeRLPBytes(record.ENRBytes); err != nil {
		return nil, fmt.Errorf("nodedb: failed to decode ENR: %w", err)
	}

	// Create node
	n, err := node.New(enrRecord)
	if err != nil {
		return nil, fmt.Errorf("nodedb: failed to create node: %w", err)
	}

	// Restore statistics
	n.SetFirstSeen(record.Stats.FirstSeen)
	n.SetLastSeen(record.Stats.LastSeen)
	n.SetLastPing(record.Stats.LastPing)
	n.SetFailureCount(record.Stats.FailureCount)
	n.SetSuccessCount(record.Stats.SuccessCount)

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
func (db *LevelDB) Delete(id node.ID) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	key := makeNodeKey(id)

	err := db.db.Delete(key, nil)
	if err == leveldb.ErrNotFound {
		return node.ErrNodeNotFound
	}
	if err != nil {
		return fmt.Errorf("nodedb: failed to delete: %w", err)
	}

	return nil
}

// List returns all nodes in the database.
//
// Warning: This can be slow for large databases. Use Query with filters
// or iterate manually for better performance.
//
// Example:
//
//	nodes := db.List()
//	fmt.Printf("Database contains %d nodes\n", len(nodes))
func (db *LevelDB) List() []*node.Node {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []*node.Node

	iter := db.db.NewIterator(util.BytesPrefix([]byte(nodePrefix)), nil)
	defer iter.Release()

	for iter.Next() {
		// Decode the record
		var record NodeRecord
		dec := gob.NewDecoder(bytes.NewReader(iter.Value()))
		if err := dec.Decode(&record); err != nil {
			db.logger.WithField("error", err).Error("nodedb: failed to decode record")
			continue
		}

		// Decode the ENR
		enrRecord := &enr.Record{}
		if err := enrRecord.DecodeRLPBytes(record.ENRBytes); err != nil {
			db.logger.WithField("error", err).Error("nodedb: failed to decode ENR")
			continue
		}

		// Create node
		n, err := node.New(enrRecord)
		if err != nil {
			db.logger.WithField("error", err).Error("nodedb: failed to create node")
			continue
		}

		// Restore statistics
		n.SetFirstSeen(record.Stats.FirstSeen)
		n.SetLastSeen(record.Stats.LastSeen)
		n.SetLastPing(record.Stats.LastPing)
		n.SetFailureCount(record.Stats.FailureCount)
		n.SetSuccessCount(record.Stats.SuccessCount)

		result = append(result, n)
	}

	if err := iter.Error(); err != nil {
		db.logger.WithField("error", err).Error("nodedb: iterator error")
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
func (db *LevelDB) Query(filter enr.ENRFilter) []*node.Node {
	// Get all nodes first (could be optimized with indexed queries)
	allNodes := db.List()

	if filter == nil {
		return allNodes
	}

	// Filter the nodes
	var result []*node.Node
	for _, n := range allNodes {
		if filter(n.Record()) {
			result = append(result, n)
		}
	}

	return result
}

// Count returns the total number of nodes in the database.
func (db *LevelDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	count := 0
	iter := db.db.NewIterator(util.BytesPrefix([]byte(nodePrefix)), nil)
	defer iter.Release()

	for iter.Next() {
		count++
	}

	return count
}

// Close closes the database and releases resources.
//
// Any pending writes are flushed before closing.
func (db *LevelDB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.db == nil {
		return nil
	}

	db.logger.WithField("path", db.path).Info("nodedb: closing LevelDB")

	err := db.db.Close()
	db.db = nil

	return err
}

// makeNodeKey creates a database key for a node ID.
func makeNodeKey(id node.ID) []byte {
	return []byte(nodePrefix + id.String())
}

// Compact compacts the database to reclaim space.
//
// This should be called periodically (e.g., once per day) to optimize storage.
//
// Example:
//
//	if err := db.Compact(); err != nil {
//	    log.Printf("Failed to compact database: %v", err)
//	}
func (db *LevelDB) Compact() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.logger.Info("nodedb: starting database compaction")

	// Compact the entire key range
	err := db.db.CompactRange(util.Range{Start: nil, Limit: nil})
	if err != nil {
		return fmt.Errorf("nodedb: compaction failed: %w", err)
	}

	db.logger.Info("nodedb: database compaction complete")

	return nil
}

// StoreLocalENR stores the local node's ENR record.
//
// This is used to persist the local node's ENR across restarts,
// allowing the sequence number to be maintained.
func (db *LevelDB) StoreLocalENR(enrBytes []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if err := db.db.Put([]byte(localNodePrefix), enrBytes, nil); err != nil {
		return fmt.Errorf("nodedb: failed to store local ENR: %w", err)
	}

	return nil
}

// LoadLocalENR loads the local node's ENR record.
//
// Returns nil, nil if no local ENR is stored.
func (db *LevelDB) LoadLocalENR() ([]byte, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	data, err := db.db.Get([]byte(localNodePrefix), nil)
	if err == leveldb.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("nodedb: failed to load local ENR: %w", err)
	}

	return data, nil
}

// StoreRejection stores a rejection entry to prevent log spam.
//
// If an entry already exists, the flags are OR-ed together.
func (db *LevelDB) StoreRejection(id node.ID, reason uint8, timestamp time.Time) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	key := []byte(rejectionPrefix + id.String())

	// Check if entry already exists
	var entry RejectionEntry
	data, err := db.db.Get(key, nil)
	if err == nil {
		// Entry exists, decode it
		if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&entry); err != nil {
			return fmt.Errorf("nodedb: failed to decode rejection entry: %w", err)
		}
		// OR the flags
		entry.Flags |= reason
		entry.Timestamp = timestamp
	} else if err == leveldb.ErrNotFound {
		// New entry
		entry = RejectionEntry{
			Flags:     reason,
			Timestamp: timestamp,
		}
	} else {
		return fmt.Errorf("nodedb: failed to get rejection entry: %w", err)
	}

	// Encode and store
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&entry); err != nil {
		return fmt.Errorf("nodedb: failed to encode rejection entry: %w", err)
	}

	if err := db.db.Put(key, buf.Bytes(), nil); err != nil {
		return fmt.Errorf("nodedb: failed to store rejection entry: %w", err)
	}

	return nil
}

// LoadRejection retrieves a rejection entry.
//
// Returns found=false if no entry exists.
func (db *LevelDB) LoadRejection(id node.ID) (flags uint8, timestamp time.Time, found bool, err error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := []byte(rejectionPrefix + id.String())
	data, dbErr := db.db.Get(key, nil)
	if dbErr == leveldb.ErrNotFound {
		return 0, time.Time{}, false, nil
	}
	if dbErr != nil {
		return 0, time.Time{}, false, fmt.Errorf("nodedb: failed to get rejection entry: %w", dbErr)
	}

	var entry RejectionEntry
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&entry); err != nil {
		return 0, time.Time{}, false, fmt.Errorf("nodedb: failed to decode rejection entry: %w", err)
	}

	return entry.Flags, entry.Timestamp, true, nil
}

// DeleteRejection removes a rejection entry.
func (db *LevelDB) DeleteRejection(id node.ID) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	key := []byte(rejectionPrefix + id.String())
	if err := db.db.Delete(key, nil); err != nil && err != leveldb.ErrNotFound {
		return fmt.Errorf("nodedb: failed to delete rejection entry: %w", err)
	}

	return nil
}

// ExpireRejections removes rejection entries older than the given duration.
//
// Returns the number of entries removed.
func (db *LevelDB) ExpireRejections(ttl time.Duration) (int, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now()
	removed := 0

	// Iterate over all rejection entries
	iter := db.db.NewIterator(util.BytesPrefix([]byte(rejectionPrefix)), nil)
	defer iter.Release()

	var toDelete [][]byte

	for iter.Next() {
		key := iter.Key()
		data := iter.Value()

		var entry RejectionEntry
		if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&entry); err != nil {
			// Skip corrupted entries
			continue
		}

		if now.Sub(entry.Timestamp) > ttl {
			// Make a copy of the key since it's only valid until the next iteration
			keyCopy := make([]byte, len(key))
			copy(keyCopy, key)
			toDelete = append(toDelete, keyCopy)
		}
	}

	// Check for iteration errors
	if err := iter.Error(); err != nil {
		return 0, fmt.Errorf("nodedb: failed to iterate rejections: %w", err)
	}

	// Delete expired entries
	for _, key := range toDelete {
		if err := db.db.Delete(key, nil); err != nil {
			db.logger.WithError(err).Warn("nodedb: failed to delete expired rejection entry")
			continue
		}
		removed++
	}

	return removed, nil
}
