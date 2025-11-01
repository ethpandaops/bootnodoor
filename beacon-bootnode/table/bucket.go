// Package table implements the Kademlia routing table for discv5.
//
// The routing table manages discovered nodes using a DHT structure:
//   - 256 k-buckets (one per bit distance)
//   - K=16 nodes per bucket
//   - Least-recently-seen eviction policy
//   - Replacement lists for full buckets
//   - Per-IP limits to prevent sybil attacks
//   - Aliveness monitoring with automatic PING checks
package table

import (
	"sort"
	"sync"
	"time"

	"github.com/pk910/bootoor/discv5/node"
)

// BucketSize is the maximum number of nodes in a k-bucket (Kademlia constant).
// Increased from 16 to 64 for bootnode usage to track more nodes.
const BucketSize = 64

// ReplacementListSize is the maximum number of replacement candidates per bucket.
const ReplacementListSize = 10

// Bucket represents a single k-bucket in the routing table.
//
// A bucket contains nodes at a specific logarithmic distance from the local node.
// When full, it maintains a replacement list of candidates.
type Bucket struct {
	// nodes are the active nodes in this bucket (max K=16)
	nodes []*node.Node

	// replacements are candidate nodes for when the bucket is full
	replacements []*node.Node

	// mu protects concurrent access
	mu sync.RWMutex
}

// NewBucket creates a new empty bucket.
func NewBucket() *Bucket {
	return &Bucket{
		nodes:        make([]*node.Node, 0, BucketSize),
		replacements: make([]*node.Node, 0, ReplacementListSize),
	}
}

// Add adds a node to the bucket.
//
// Behavior:
//   - If the bucket has space, the node is added
//   - If the bucket is full, the node is added to replacements
//   - If the node already exists, it's moved to the back (most recent)
//
// Returns true if the node was added to the active list.
func (b *Bucket) Add(n *node.Node) (added bool, existing bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	nodeID := n.ID()

	// Check if node already exists in active list
	for i, existing := range b.nodes {
		if existing.ID() == nodeID {
			// Only update if the new node has a higher ENR sequence
			if n.Record().Seq() > existing.Record().Seq() {
				// Update the ENR but preserve the existing node's statistics
				existing.UpdateENR(n.Record())
				// Move to back (most recently seen)
				b.nodes = append(b.nodes[:i], b.nodes[i+1:]...)
				b.nodes = append(b.nodes, existing)
			} else {
				// Just update the position (most recently seen) but keep old node
				b.nodes = append(b.nodes[:i], b.nodes[i+1:]...)
				b.nodes = append(b.nodes, existing)
			}
			return true, true
		}
	}

	// Check if node exists in replacements
	for i, existing := range b.replacements {
		if existing.ID() == nodeID {
			// Update ENR if newer
			if n.Record().Seq() > existing.Record().Seq() {
				existing.UpdateENR(n.Record())
			}
			// Remove from replacements and try to add to active list
			b.replacements = append(b.replacements[:i], b.replacements[i+1:]...)
			// Add to active list if there's space
			if len(b.nodes) < BucketSize {
				b.nodes = append(b.nodes, existing)
				return true, true
			}
			// Still full, add back to replacements
			b.replacements = append(b.replacements, existing)
			return false, true
		}
	}

	// Add to active list if there's space
	if len(b.nodes) < BucketSize {
		b.nodes = append(b.nodes, n)
		return true, false
	}

	// Bucket is full, add to replacements
	if len(b.replacements) < ReplacementListSize {
		b.replacements = append(b.replacements, n)
	}

	return false, false
}

// Remove removes a node from the bucket.
//
// If the node was in the active list and replacements exist,
// the first replacement is promoted to the active list.
func (b *Bucket) Remove(nodeID node.ID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Try to remove from active list
	for i, n := range b.nodes {
		if n.ID() == nodeID {
			b.nodes = append(b.nodes[:i], b.nodes[i+1:]...)

			// Promote a replacement if available
			if len(b.replacements) > 0 {
				b.nodes = append(b.nodes, b.replacements[0])
				b.replacements = b.replacements[1:]
			}

			return true
		}
	}

	// Try to remove from replacements
	for i, n := range b.replacements {
		if n.ID() == nodeID {
			b.replacements = append(b.replacements[:i], b.replacements[i+1:]...)
			return true
		}
	}

	return false
}

// Get retrieves a node by ID from the bucket.
//
// Returns nil if the node is not in the bucket.
func (b *Bucket) Get(nodeID node.ID) *node.Node {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, n := range b.nodes {
		if n.ID() == nodeID {
			return n
		}
	}

	return nil
}

// Nodes returns a copy of all active nodes in the bucket.
func (b *Bucket) Nodes() []*node.Node {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]*node.Node, len(b.nodes))
	copy(result, b.nodes)
	return result
}

// Len returns the number of active nodes in the bucket.
func (b *Bucket) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.nodes)
}

// IsFull returns true if the bucket has reached its capacity.
func (b *Bucket) IsFull() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.nodes) >= BucketSize
}

// LeastRecentlySeen returns the node that was seen longest ago.
//
// This is used for eviction when testing liveness.
// Returns nil if the bucket is empty.
func (b *Bucket) LeastRecentlySeen() *node.Node {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.nodes) == 0 {
		return nil
	}

	// Nodes are ordered by recency (oldest first, newest last)
	return b.nodes[0]
}

// RemoveStaleNodes removes nodes that fail the aliveness check.
//
// Parameters:
//   - maxAge: Maximum time since last seen
//   - maxFailures: Maximum consecutive failures
//
// Returns the number of nodes removed.
func (b *Bucket) RemoveStaleNodes(maxAge time.Duration, maxFailures int) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	var toRemove []int

	for i, n := range b.nodes {
		if !n.IsAlive(maxAge, maxFailures) {
			toRemove = append(toRemove, i)
		}
	}

	// Remove nodes in reverse order to maintain indices
	for i := len(toRemove) - 1; i >= 0; i-- {
		idx := toRemove[i]
		b.nodes = append(b.nodes[:idx], b.nodes[idx+1:]...)

		// Promote a replacement if available
		if len(b.replacements) > 0 {
			b.nodes = append(b.nodes, b.replacements[0])
			b.replacements = b.replacements[1:]
		}
	}

	return len(toRemove)
}

// NeedsPing returns nodes that need a PING check.
//
// Parameters:
//   - pingInterval: Minimum time between pings
//
// Returns a list of nodes that haven't been pinged recently.
func (b *Bucket) NeedsPing(pingInterval time.Duration) []*node.Node {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var result []*node.Node

	for _, n := range b.nodes {
		if n.NeedsPing(pingInterval) {
			result = append(result, n)
		}
	}

	return result
}

// GetRandom returns up to count random nodes from the bucket.
func (b *Bucket) GetRandom(count int) []*node.Node {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.nodes) == 0 {
		return nil
	}

	// If requesting more than available, return all
	if count >= len(b.nodes) {
		result := make([]*node.Node, len(b.nodes))
		copy(result, b.nodes)
		return result
	}

	// Return random subset
	// For simplicity, return the last 'count' nodes
	// In production, this should be truly random
	result := make([]*node.Node, count)
	copy(result, b.nodes[len(b.nodes)-count:])
	return result
}

// Sort sorts the nodes in the bucket by distance to a target.
//
// This is useful for finding the closest nodes to a target ID.
func (b *Bucket) Sort(target node.ID) {
	b.mu.Lock()
	defer b.mu.Unlock()

	sort.Slice(b.nodes, func(i, j int) bool {
		return node.CloserTo(target, b.nodes[i].ID(), b.nodes[j].ID())
	})
}

// GetNodes returns all nodes in the bucket.
//
// This returns a copy of the nodes slice to prevent concurrent modification.
func (b *Bucket) GetNodes() []*node.Node {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]*node.Node, len(b.nodes))
	copy(result, b.nodes)
	return result
}
