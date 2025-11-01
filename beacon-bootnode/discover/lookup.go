// Package discover implements node discovery operations for discv5.
//
// The discover package provides:
//   - Iterative FINDNODE lookups
//   - PING/PONG operations
//   - Random walks for table maintenance
//   - ENR-based filtering during discovery
package discover

import (
	"context"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"sync"
	"time"

	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/pk910/bootoor/discv5/protocol"
	"github.com/pk910/bootoor/beacon-bootnode/table"
	"github.com/sirupsen/logrus"
)

// DefaultAlpha is the concurrency factor for lookups (Kademlia parameter).
const DefaultAlpha = 3

// DefaultLookupTimeout is the timeout for a complete lookup operation.
const DefaultLookupTimeout = 30 * time.Second

// LookupService manages node discovery operations.
type LookupService struct {
	// localNode is our node information
	localNode *node.Node

	// table is the routing table
	table *table.Table

	// handler is the protocol handler for sending messages
	handler *protocol.Handler

	// alpha is the concurrency factor for lookups
	alpha int

	// lookupTimeout is the timeout for lookup operations
	lookupTimeout time.Duration

	// logger for debug messages
	logger logrus.FieldLogger

	// mu protects lookup state
	mu sync.RWMutex

	// Stats
	lookupsStarted   int
	lookupsCompleted int
	lookupsFailed    int
	nodesDiscovered  int
}

// Config contains configuration for the lookup service.
type Config struct {
	// LocalNode is our node information
	LocalNode *node.Node

	// Table is the routing table
	Table *table.Table

	// Handler is the protocol handler
	Handler *protocol.Handler

	// Alpha is the concurrency factor (default 3)
	Alpha int

	// LookupTimeout is the timeout for lookup operations
	LookupTimeout time.Duration

	// Logger for debug messages
	Logger logrus.FieldLogger
}

// NewLookupService creates a new lookup service.
func NewLookupService(cfg Config) *LookupService {
	if cfg.Alpha <= 0 {
		cfg.Alpha = DefaultAlpha
	}

	if cfg.LookupTimeout <= 0 {
		cfg.LookupTimeout = DefaultLookupTimeout
	}

	return &LookupService{
		localNode:     cfg.LocalNode,
		table:         cfg.Table,
		handler:       cfg.Handler,
		alpha:         cfg.Alpha,
		lookupTimeout: cfg.LookupTimeout,
		logger:        cfg.Logger,
	}
}

// Lookup performs an iterative node lookup for the target ID.
//
// The lookup finds the k closest nodes to the target using the
// Kademlia algorithm with alpha concurrency.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - target: The target node ID to find
//   - k: The number of closest nodes to return
//
// Returns the k closest nodes found.
func (ls *LookupService) Lookup(ctx context.Context, target node.ID, k int) ([]*node.Node, error) {
	return ls.lookupInternal(ctx, target, k, false)
}

// lookupInternal performs the actual lookup with options for random walks
func (ls *LookupService) lookupInternal(ctx context.Context, target node.ID, k int, isRandomWalk bool) ([]*node.Node, error) {
	ls.mu.Lock()
	ls.lookupsStarted++
	ls.mu.Unlock()

	ls.logger.WithField("target", target).WithField("k", k).Debug("starting lookup")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, ls.lookupTimeout)
	defer cancel()

	// Track nodes we've seen and queried
	seen := make(map[node.ID]bool)
	queried := make(map[node.ID]bool)

	// Start with nodes from our routing table
	var closest []*node.Node
	if isRandomWalk {
		// For random walks, start with ALL nodes to explore diverse areas
		// This prevents getting stuck querying the same cluster repeatedly
		allNodes := ls.table.FindClosestNodes(target, ls.table.Size())
		mathrand.Shuffle(len(allNodes), func(i, j int) {
			allNodes[i], allNodes[j] = allNodes[j], allNodes[i]
		})
		closest = allNodes
		if len(closest) > k*2 {
			// Limit to avoid excessive queries, but use more than k
			closest = closest[:k*2]
		}
	} else {
		// For targeted lookups, use standard closest k nodes
		closest = ls.table.FindClosestNodes(target, k)
	}

	for _, n := range closest {
		seen[n.ID()] = true
	}

	totalAdded := 0

	for {
		select {
		case <-ctx.Done():
			ls.mu.Lock()
			ls.lookupsFailed++
			ls.mu.Unlock()
			return closest, ctx.Err()
		default:
		}

		// Find nodes to query (up to alpha nodes)
		var toQuery []*node.Node
		for _, n := range closest {
			if !queried[n.ID()] {
				toQuery = append(toQuery, n)
				if len(toQuery) >= ls.alpha {
					break
				}
			}
		}

		// If no more nodes to query, we're done
		if len(toQuery) == 0 {
			break
		}

		// Query nodes in parallel
		var wg sync.WaitGroup
		var mu sync.Mutex
		var newNodes []*node.Node

		for _, n := range toQuery {
			queried[n.ID()] = true

			wg.Add(1)
			go func(n *node.Node) {
				defer wg.Done()

				// Calculate distances
				var distances []uint
				if isRandomWalk {
					// For random walks, request a wide range of distances
					// Focus on high distances where nodes statistically exist (exponential distribution)
					// but also include some lower ones to explore diverse keyspace
					distances = []uint{240, 245, 250, 252, 254, 255}
				} else {
					// For regular lookups, use Geth algorithm to converge on target
					distances = ls.lookupDistances(target, n.ID())
				}

				ls.logger.WithFields(logrus.Fields{
					"peerID":    n.PeerID(),
					"addr":      n.Addr(),
					"target":    target,
					"distances": distances,
				}).Trace("discover: sending FINDNODE")

				// Send FINDNODE request
				respChan, err := ls.handler.SendFindNode(n, distances)
				if err != nil {
					ls.logger.WithFields(logrus.Fields{
						"peerID": n.PeerID(),
						"addr":   n.Addr(),
						"error":  err,
					}).Debug("discover: failed to send FINDNODE")
					return
				}

				// Wait for response with context cancellation
				var resp *protocol.Response
				select {
				case resp = <-respChan:
					// Response received
				case <-ctx.Done():
					// Context cancelled or deadline exceeded
					ls.logger.WithFields(logrus.Fields{
						"peerID": n.PeerID(),
						"addr":   n.Addr(),
					}).Debug("discover: lookup cancelled")
					return
				}

				if resp.Error != nil {
					ls.logger.WithFields(logrus.Fields{
						"peerID": n.PeerID(),
						"addr":   n.Addr(),
						"error":  resp.Error,
					}).Debug("discover: FINDNODE timeout or error")
					return
				}

				// Extract nodes from response
				if nodesMsg, ok := resp.Message.(*protocol.Nodes); ok {
					ls.logger.WithFields(logrus.Fields{
						"peerID":      n.PeerID(),
						"addr":        n.Addr(),
						"nodesInResp": len(nodesMsg.Records),
					}).Trace("discover: received NODES response")

					mu.Lock()
					for _, record := range nodesMsg.Records {
						newNode, err := node.New(record)
						if err != nil {
							ls.logger.WithError(err).Debug("discover: invalid node in NODES response")
							continue
						}

						// Skip if already seen
						if seen[newNode.ID()] {
							ls.logger.WithFields(logrus.Fields{
								"peerID": newNode.PeerID(),
								"addr":   newNode.Addr(),
							}).Trace("discover: node already seen, skipping")
							continue
						}

						ls.logger.WithFields(logrus.Fields{
							"peerID": newNode.PeerID(),
							"addr":   newNode.Addr(),
						}).Debug("discover: discovered new node")

						seen[newNode.ID()] = true
						newNodes = append(newNodes, newNode)
					}
					mu.Unlock()
				}
			}(n)
		}

		wg.Wait()

		ls.logger.WithFields(logrus.Fields{
			"target":       target,
			"queried":      len(toQuery),
			"newDiscovery": len(newNodes),
		}).Debug("discover: lookup iteration complete")

		// Add new nodes to routing table and track which were successfully added
		acceptedCount := 0
		var addedNodes []*node.Node
		for _, n := range newNodes {
			if ls.table.Add(n) {
				acceptedCount++
				addedNodes = append(addedNodes, n)
			}
		}

		// Note: acceptedCount includes nodes that were already in table and just refreshed
		// The actual growth is measured by totalAdded at the end
		totalAdded += acceptedCount

		ls.logger.WithFields(logrus.Fields{
			"target":     target,
			"discovered": len(newNodes),
			"accepted":   acceptedCount,
			"rejected":   len(newNodes) - acceptedCount,
		}).Debug("discover: added new nodes to routing table")

		// Update closest list - ONLY include nodes that were added to routing table
		// This prevents querying nodes outside our network (wrong fork, rejected by filters)
		allNodes := append(closest, addedNodes...)
		closest = findKClosest(target, allNodes, k)

		ls.mu.Lock()
		ls.nodesDiscovered += len(newNodes)
		ls.mu.Unlock()
	}

	ls.mu.Lock()
	ls.lookupsCompleted++
	ls.mu.Unlock()

	ls.logger.WithFields(logrus.Fields{
		"target":     target,
		"discovered": len(closest),
		"accepted":   totalAdded,
	}).Info("node discovery lookup complete")

	return closest, nil
}

// LookupWithFilter performs a lookup with an ENR filter.
//
// Only nodes that pass the filter are included in the results.
func (ls *LookupService) LookupWithFilter(ctx context.Context, target node.ID, k int, filter enr.ENRFilter) ([]*node.Node, error) {
	// Perform regular lookup
	nodes, err := ls.Lookup(ctx, target, k*2) // Request more to account for filtering
	if err != nil {
		return nil, err
	}

	// Apply filter
	var filtered []*node.Node
	for _, n := range nodes {
		if filter == nil || filter(n.Record()) {
			filtered = append(filtered, n)
			if len(filtered) >= k {
				break
			}
		}
	}

	return filtered, nil
}

// RandomWalk performs a random walk to discover new nodes.
//
// This is used for routing table maintenance and exploring the network.
func (ls *LookupService) RandomWalk(ctx context.Context) ([]*node.Node, error) {
	// Generate a completely random 256-bit target ID (Geth approach)
	// This ensures the target can be at any distance from any node in the network,
	// which allows us to explore diverse regions of the keyspace
	var target node.ID
	if _, err := rand.Read(target[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random target: %w", err)
	}

	ls.logger.WithFields(logrus.Fields{
		"target": target,
	}).Debug("discover: starting random walk")

	// Perform lookup for random target using ALL nodes to break out of clusters
	return ls.lookupInternal(ctx, target, 32, true)
}

// findKClosest finds the k closest nodes to target from a list.
func findKClosest(target node.ID, nodes []*node.Node, k int) []*node.Node {
	// Convert to IDs
	ids := make([]node.ID, len(nodes))
	nodeMap := make(map[node.ID]*node.Node)

	for i, n := range nodes {
		ids[i] = n.ID()
		nodeMap[n.ID()] = n
	}

	// Find k closest IDs
	closestIDs := node.FindClosest(target, ids, k)

	// Convert back to nodes
	result := make([]*node.Node, 0, len(closestIDs))
	for _, id := range closestIDs {
		if n, exists := nodeMap[id]; exists {
			result = append(result, n)
		}
	}

	return result
}

// GetStats returns statistics about discovery operations.
type LookupStats struct {
	LookupsStarted   int
	LookupsCompleted int
	LookupsFailed    int
	NodesDiscovered  int
}

// GetStats returns discovery statistics.
func (ls *LookupService) GetStats() LookupStats {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	return LookupStats{
		LookupsStarted:   ls.lookupsStarted,
		LookupsCompleted: ls.lookupsCompleted,
		LookupsFailed:    ls.lookupsFailed,
		NodesDiscovered:  ls.nodesDiscovered,
	}
}

// lookupDistances calculates the distance parameters for a FINDNODE request.
//
// This implements the Ethereum/Geth algorithm: request distances centered around
// the target-to-destination distance. This ensures we get nodes progressively
// closer to the target.
//
// For example, if target-to-dest distance is 150, we request [150, 151, 149].
func (ls *LookupService) lookupDistances(target, dest node.ID) []uint {
	const lookupRequestLimit = 3

	td := node.LogDistance(target, dest)
	if td < 0 {
		// Shouldn't happen (means target == dest), request all nodes
		return []uint{256}
	}

	dists := []uint{uint(td)}
	for i := 1; len(dists) < lookupRequestLimit; i++ {
		if td+i <= 256 {
			dists = append(dists, uint(td+i))
		}
		if td-i > 0 {
			dists = append(dists, uint(td-i))
		}
	}

	return dists
}
