package table

import (
	"net"
	"sync"

	"github.com/pk910/bootoor/discv5/node"
)

// DefaultMaxNodesPerIP is the default maximum nodes per IP address.
const DefaultMaxNodesPerIP = 10

// IPLimiter tracks and enforces per-IP node limits.
//
// This prevents sybil attacks where an attacker tries to fill
// the routing table with many nodes from the same IP address.
type IPLimiter struct {
	// maxNodesPerIP is the maximum allowed nodes per IP
	maxNodesPerIP int

	// ipCounts maps IP address to node count
	ipCounts map[string]int

	// nodeToIP maps node ID to IP address
	nodeToIP map[node.ID]string

	// mu protects concurrent access
	mu sync.RWMutex

	// rejections tracks total rejections for metrics
	rejections int
}

// NewIPLimiter creates a new IP limiter.
//
// Parameters:
//   - maxNodesPerIP: Maximum nodes allowed per IP (0 = unlimited)
func NewIPLimiter(maxNodesPerIP int) *IPLimiter {
	if maxNodesPerIP <= 0 {
		maxNodesPerIP = DefaultMaxNodesPerIP
	}

	return &IPLimiter{
		maxNodesPerIP: maxNodesPerIP,
		ipCounts:      make(map[string]int),
		nodeToIP:      make(map[node.ID]string),
	}
}

// CanAdd checks if a node can be added without exceeding IP limits.
//
// Returns true if the node can be added, false if the IP limit is exceeded.
func (l *IPLimiter) CanAdd(n *node.Node) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	ip := n.IP().String()
	nodeID := n.ID()

	// Check if node already exists (updating is always allowed)
	if _, exists := l.nodeToIP[nodeID]; exists {
		return true
	}

	// Check IP limit
	count := l.ipCounts[ip]
	return count < l.maxNodesPerIP
}

// Add registers a node with the IP limiter.
//
// This should be called when a node is added to the routing table.
// Returns false if the IP limit is exceeded.
func (l *IPLimiter) Add(n *node.Node) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	ip := n.IP().String()
	nodeID := n.ID()

	// Check if node already exists
	if existingIP, exists := l.nodeToIP[nodeID]; exists {
		// If IP changed, update counts
		if existingIP != ip {
			l.ipCounts[existingIP]--
			if l.ipCounts[existingIP] == 0 {
				delete(l.ipCounts, existingIP)
			}

			l.ipCounts[ip]++
			l.nodeToIP[nodeID] = ip
		}
		return true
	}

	// Check IP limit for new node
	if l.ipCounts[ip] >= l.maxNodesPerIP {
		l.rejections++
		return false
	}

	// Add node
	l.ipCounts[ip]++
	l.nodeToIP[nodeID] = ip

	return true
}

// Remove unregisters a node from the IP limiter.
//
// This should be called when a node is removed from the routing table.
func (l *IPLimiter) Remove(nodeID node.ID) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Find node's IP
	ip, exists := l.nodeToIP[nodeID]
	if !exists {
		return
	}

	// Decrement count
	l.ipCounts[ip]--
	if l.ipCounts[ip] == 0 {
		delete(l.ipCounts, ip)
	}

	// Remove node
	delete(l.nodeToIP, nodeID)
}

// GetNodeCountForIP returns the number of nodes for a given IP.
func (l *IPLimiter) GetNodeCountForIP(ip net.IP) int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.ipCounts[ip.String()]
}

// GetTotalRejections returns the total number of rejected nodes due to IP limits.
func (l *IPLimiter) GetTotalRejections() int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.rejections
}

// GetStats returns statistics about IP usage.
type IPStats struct {
	UniqueIPs       int
	TotalNodes      int
	MaxNodesPerIP   int
	Rejections      int
	IPDistribution  map[string]int // IP -> node count
}

// GetStats returns detailed statistics about IP distribution.
func (l *IPLimiter) GetStats() IPStats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	stats := IPStats{
		UniqueIPs:      len(l.ipCounts),
		TotalNodes:     len(l.nodeToIP),
		MaxNodesPerIP:  l.maxNodesPerIP,
		Rejections:     l.rejections,
		IPDistribution: make(map[string]int),
	}

	// Copy IP distribution
	for ip, count := range l.ipCounts {
		stats.IPDistribution[ip] = count
	}

	return stats
}
