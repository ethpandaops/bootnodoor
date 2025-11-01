package table

import (
	"fmt"
	"sync"
	"time"

	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/sirupsen/logrus"
)

// NumBuckets is the number of k-buckets in the routing table.
// Reduced to 128 to cover distances 128-255 (where nodes actually exist with exponential distribution).
const NumBuckets = 128

// MinBucketDistance is the minimum distance we track in buckets.
// Distances 0-127 are ignored as they require millions of nodes to fill.
const MinBucketDistance = 128

// DefaultPingInterval is how often we PING nodes to check liveness.
const DefaultPingInterval = 30 * time.Second

// DefaultMaxNodeAge is the maximum time since last seen before considering a node dead.
const DefaultMaxNodeAge = 24 * time.Hour

// DefaultMaxFailures is the maximum consecutive failures before considering a node dead.
const DefaultMaxFailures = 3

// RejectionLogTTL is how long we remember that we logged a rejection for a node.
const RejectionLogTTL = 12 * time.Hour

// Rejection reason flags
const (
	RejectionIPLimit   uint8 = 0x01
	RejectionAdmission uint8 = 0x02
)

// DB is the interface for node database that supports rejection tracking.
type DB interface {
	StoreRejection(id node.ID, reason uint8, timestamp time.Time) error
	LoadRejection(id node.ID) (flags uint8, timestamp time.Time, found bool, err error)
	ExpireRejections(ttl time.Duration) (int, error)
}

// Table is the Kademlia routing table.
//
// The table organizes nodes into 256 buckets based on their distance
// from the local node. It enforces:
//   - Per-IP limits to prevent sybil attacks
//   - Admission filtering (ENR-based) before adding nodes
//   - Automatic aliveness monitoring with PING checks
//   - Dead node detection and removal
type Table struct {
	// localID is our node ID
	localID node.ID

	// buckets are the k-buckets indexed by distance
	buckets [NumBuckets]*Bucket

	// ipLimiter enforces per-IP node limits
	ipLimiter *IPLimiter

	// admissionFilter is applied before adding nodes (Stage 1 filtering)
	admissionFilter enr.ENRFilter

	// pingInterval is how often to ping nodes
	pingInterval time.Duration

	// maxNodeAge is the maximum time since last seen
	maxNodeAge time.Duration

	// maxFailures is the maximum consecutive failures
	maxFailures int

	// nodeChangedCallback is called when nodes are added/updated
	nodeChangedCallback NodeChangedCallback

	// db is used for persistent rejection tracking (optional)
	db DB

	// mu protects the table structure
	mu sync.RWMutex

	// logger for debug messages
	logger logrus.FieldLogger

	// Stats tracking
	admissionRejections int
	ipLimitRejections   int
	deadNodesRemoved    int
}

// NodeChangedCallback is called when a node is added or updated in the table.
type NodeChangedCallback func(*node.Node)

// Config contains configuration for the routing table.
type Config struct {
	// LocalID is our node ID
	LocalID node.ID

	// MaxNodesPerIP is the maximum nodes allowed per IP address
	MaxNodesPerIP int

	// AdmissionFilter is applied before adding nodes to the table
	AdmissionFilter enr.ENRFilter

	// PingInterval is how often to ping nodes
	PingInterval time.Duration

	// MaxNodeAge is the maximum time since last seen
	MaxNodeAge time.Duration

	// MaxFailures is the maximum consecutive failures
	MaxFailures int

	// NodeChangedCallback is called when a node is added or updated
	NodeChangedCallback NodeChangedCallback

	// DB is used for persistent rejection tracking (optional)
	// If provided, rejection tracking will use the database instead of memory
	DB DB

	// Logger for debug messages
	Logger logrus.FieldLogger
}

// NewTable creates a new routing table.
//
// Example:
//
//	table := NewTable(Config{
//	    LocalID: myNodeID,
//	    MaxNodesPerIP: 10,
//	    PingInterval: 30 * time.Second,
//	})
func NewTable(cfg Config) *Table {
	if cfg.MaxNodesPerIP <= 0 {
		cfg.MaxNodesPerIP = DefaultMaxNodesPerIP
	}

	if cfg.PingInterval <= 0 {
		cfg.PingInterval = DefaultPingInterval
	}

	if cfg.MaxNodeAge <= 0 {
		cfg.MaxNodeAge = DefaultMaxNodeAge
	}

	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = DefaultMaxFailures
	}

	t := &Table{
		localID:             cfg.LocalID,
		ipLimiter:           NewIPLimiter(cfg.MaxNodesPerIP),
		admissionFilter:     cfg.AdmissionFilter,
		pingInterval:        cfg.PingInterval,
		maxNodeAge:          cfg.MaxNodeAge,
		maxFailures:         cfg.MaxFailures,
		nodeChangedCallback: cfg.NodeChangedCallback,
		db:                  cfg.DB,
		logger:              cfg.Logger,
	}

	// Initialize buckets
	for i := range t.buckets {
		t.buckets[i] = NewBucket()
	}

	return t
}

// Add adds a node to the routing table.
//
// The node must pass:
//  1. Admission filter (if configured)
//  2. IP limit check
//
// Returns true if the node was added successfully.
func (t *Table) Add(n *node.Node) bool {
	if n == nil {
		return false
	}

	nodeID := n.ID()

	// Don't add self
	if nodeID == t.localID {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Apply admission filter (Stage 1)
	if t.admissionFilter != nil && !t.admissionFilter(n.Record()) {
		t.admissionRejections++
		t.logRejection(nodeID, RejectionAdmission, n.PeerID(), n.Addr().String(), n.Digest())
		return false
	}

	// Check IP limits
	if !t.ipLimiter.CanAdd(n) {
		t.ipLimitRejections++
		t.logRejection(nodeID, RejectionIPLimit, n.PeerID(), n.IP().String(), n.Digest())
		return false
	}

	// Find the bucket for this node
	dist := node.LogDistance(t.localID, nodeID)
	if dist < MinBucketDistance {
		// Ignore nodes at distances < 128 (never fill with realistic node counts)
		return false
	}

	bucketIdx := dist - MinBucketDistance
	if bucketIdx >= NumBuckets {
		return false
	}

	bucket := t.buckets[bucketIdx]

	// Try to add to bucket
	if added, existing := bucket.Add(n); added {
		// Register with IP limiter
		if !t.ipLimiter.Add(n) {
			// This shouldn't happen since we checked CanAdd above
			bucket.Remove(nodeID)
			return false
		}

		if existing {
			t.logger.WithField("peerID", n.PeerID()).WithField("addr", n.Addr()).WithField("bucket", dist).Trace("node already added to bucket")
		} else {
			t.logger.WithField("peerID", n.PeerID()).WithField("addr", n.Addr()).WithField("bucket", dist).Info("added node")
		}

		// Call persistence callback if configured
		if t.nodeChangedCallback != nil {
			t.nodeChangedCallback(n)
		}

		return true
	}

	return false
}

// Remove removes a node from the routing table.
func (t *Table) Remove(n *node.Node) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	nodeID := n.ID()

	dist := node.LogDistance(t.localID, nodeID)
	if dist < MinBucketDistance {
		return false
	}

	bucketIdx := dist - MinBucketDistance
	if bucketIdx >= NumBuckets {
		return false
	}

	bucket := t.buckets[bucketIdx]

	if bucket.Remove(nodeID) {
		t.ipLimiter.Remove(nodeID)

		t.logger.WithField("peerID", n.PeerID()).WithField("bucket", dist).Debug("table: removed node")

		return true
	}

	return false
}

// Get retrieves a node by ID from the routing table.
func (t *Table) Get(nodeID node.ID) *node.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	dist := node.LogDistance(t.localID, nodeID)
	if dist < MinBucketDistance {
		return nil
	}

	bucketIdx := dist - MinBucketDistance
	if bucketIdx >= NumBuckets {
		return nil
	}

	return t.buckets[bucketIdx].Get(nodeID)
}

// FindClosestNodes finds the k closest nodes to the target ID.
//
// Results are sorted by distance (closest first).
func (t *Table) FindClosestNodes(target node.ID, k int) []*node.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Collect all nodes from all buckets
	var allNodes []*node.Node
	for _, bucket := range t.buckets {
		allNodes = append(allNodes, bucket.Nodes()...)
	}

	// Get node IDs
	nodeIDs := nodesToIDs(allNodes)

	// Find k closest IDs
	closestIDs := node.FindClosest(target, nodeIDs, k)

	// Convert IDs back to nodes
	nodeMap := nodesMap(allNodes)
	result := make([]*node.Node, 0, len(closestIDs))
	for _, id := range closestIDs {
		if n, exists := nodeMap[id]; exists {
			result = append(result, n)
		}
	}

	return result
}

// GetNodesNeedingPing returns nodes that need a PING check.
//
// This should be called periodically by the aliveness monitor.
func (t *Table) GetNodesNeedingPing() []*node.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var result []*node.Node

	for _, bucket := range t.buckets {
		result = append(result, bucket.NeedsPing(t.pingInterval)...)
	}

	return result
}

// RemoveStaleNodes removes nodes that fail the aliveness check.
//
// Returns the number of nodes removed.
func (t *Table) RemoveStaleNodes() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	totalRemoved := 0

	for i, bucket := range t.buckets {
		removed := bucket.RemoveStaleNodes(t.maxNodeAge, t.maxFailures)

		// Update IP limiter for removed nodes
		// (bucket already removed them, we just need to clean up IP tracking)

		totalRemoved += removed

		if removed > 0 {
			t.logger.WithField("bucket", i).WithField("count", removed).Info("table: removed stale nodes")
		}
	}

	t.deadNodesRemoved += totalRemoved

	return totalRemoved
}

// Size returns the total number of nodes in the routing table.
func (t *Table) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	total := 0
	for _, bucket := range t.buckets {
		total += bucket.Len()
	}

	return total
}

// NumBucketsFilled returns the number of buckets with at least one node.
func (t *Table) NumBucketsFilled() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	count := 0
	for _, bucket := range t.buckets {
		if bucket.Len() > 0 {
			count++
		}
	}

	return count
}

// GetStats returns statistics about the routing table.
type TableStats struct {
	TotalNodes          int
	BucketsFilled       int
	AdmissionRejections int
	IPLimitRejections   int
	DeadNodesRemoved    int
	IPStats             IPStats
}

// GetStats returns detailed statistics.
func (t *Table) GetStats() TableStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return TableStats{
		TotalNodes:          t.Size(),
		BucketsFilled:       t.NumBucketsFilled(),
		AdmissionRejections: t.admissionRejections,
		IPLimitRejections:   t.ipLimitRejections,
		DeadNodesRemoved:    t.deadNodesRemoved,
		IPStats:             t.ipLimiter.GetStats(),
	}
}

// String returns a human-readable representation of the table.
func (t *Table) String() string {
	stats := t.GetStats()
	return fmt.Sprintf("RoutingTable{nodes=%d, buckets=%d/%d, rejections=%d+%d}",
		stats.TotalNodes,
		stats.BucketsFilled,
		NumBuckets,
		stats.AdmissionRejections,
		stats.IPLimitRejections,
	)
}

// GetBucketNodes returns all nodes in a specific bucket.
// bucketIndex is the distance value (128-255), not the array index.
func (t *Table) GetBucketNodes(bucketIndex int) []*node.Node {
	if bucketIndex < MinBucketDistance || bucketIndex >= MinBucketDistance+NumBuckets {
		return nil
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	bucket := t.buckets[bucketIndex-MinBucketDistance]
	return bucket.GetNodes()
}

// logRejection logs a node rejection if we haven't logged it recently.
//
// This prevents log spam from repeatedly rejected nodes.
// Assumes t.mu is already locked.
func (t *Table) logRejection(nodeID node.ID, reason uint8, peerID string, addr string, digest [4]byte) {
	now := time.Now()

	// Use database for rejection tracking if available
	if t.db != nil {
		// Check if we've logged this rejection recently
		flags, _, found, err := t.db.LoadRejection(nodeID)
		if err != nil {
			t.logger.WithError(err).Warn("failed to load rejection entry from database")
			// Continue to log anyway
		} else if found && (flags&reason) != 0 {
			// Already logged this specific rejection reason
			return
		}

		// Store the rejection in the database
		if err := t.db.StoreRejection(nodeID, reason, now); err != nil {
			t.logger.WithError(err).Warn("failed to store rejection entry in database")
		}
	}

	// Log the rejection
	switch reason {
	case RejectionAdmission:
		t.logger.WithField("peerID", peerID).WithField("addr", addr).WithField("digest", fmt.Sprintf("0x%x", digest)).Info("node rejected by admission filter")
	case RejectionIPLimit:
		t.logger.WithField("peerID", peerID).WithField("ip", addr).Info("node rejected due to IP limit")
	default:
		t.logger.WithField("peerID", peerID).WithField("addr", addr).Info("node rejected for unknown reason")
	}
}

// CleanupRejectionLog removes expired entries from the rejection log.
//
// Returns the number of entries removed.
func (t *Table) CleanupRejectionLog() int {
	// Use database for rejection tracking if available
	if t.db != nil {
		removed, err := t.db.ExpireRejections(RejectionLogTTL)
		if err != nil {
			t.logger.WithError(err).Warn("failed to expire rejection entries from database")
			return 0
		}
		return removed
	}

	// No database available, nothing to clean up
	return 0
}

// Helper functions

func nodesToIDs(nodes []*node.Node) []node.ID {
	ids := make([]node.ID, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID()
	}
	return ids
}

func nodesMap(nodes []*node.Node) map[node.ID]*node.Node {
	m := make(map[node.ID]*node.Node)
	for _, n := range nodes {
		m[n.ID()] = n
	}
	return m
}
