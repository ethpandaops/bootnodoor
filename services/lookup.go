// Package services implements node discovery operations.
//
// The services package provides:
//   - Iterative FINDNODE lookups (discv5 + discv4)
//   - PING/PONG operations (discv5 + discv4)
//   - Random walks for table maintenance
//   - ENR-based filtering during discovery
//   - Dual protocol support (prefers v5, falls back to v4)
package services

import (
	"context"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"sort"
	"sync"
	"time"

	"github.com/ethpandaops/bootnodoor/db"
	"github.com/ethpandaops/bootnodoor/discv4"
	v4node "github.com/ethpandaops/bootnodoor/discv4/node"
	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/discv5/protocol"
	"github.com/ethpandaops/bootnodoor/enr"
	nodedb "github.com/ethpandaops/bootnodoor/nodes"
	"github.com/sirupsen/logrus"
)

// DefaultAlpha is the concurrency factor for lookups (Kademlia parameter).
const DefaultAlpha = 3

// DefaultLookupTimeout is the timeout for a complete lookup operation.
const DefaultLookupTimeout = 30 * time.Second

// LookupService manages node discovery operations.
// Supports both discv5 and discv4 protocols (prefers v5, falls back to v4).
type LookupService struct {
	// config contains all lookup configuration
	config Config

	// mu protects lookup state and stats
	mu sync.RWMutex

	// queryHistory tracks when we last queried each node
	// This helps avoid re-querying the same nodes and promotes diversity
	queryHistory map[node.ID]time.Time

	// Stats
	lookupsStarted   int
	lookupsCompleted int
	lookupsFailed    int
	nodesDiscovered  int
	lookupsV5        int // Lookups using v5
	lookupsV4        int // Lookups using v4
}

// Config contains configuration for the lookup service.
type Config struct {
	// LocalNode is our node information
	LocalNode *nodedb.Node

	// NodeDB is the node database
	NodeDB *nodedb.NodeDB

	// Table is the routing table
	Table *nodedb.FlatTable

	// V5Handler is the discv5 protocol handler (may be nil)
	V5Handler *protocol.Handler

	// V4Service is the discv4 service (may be nil)
	V4Service *discv4.Service

	// Database for bad node tracking (may be nil)
	Database interface {
		IsBadNode(nodeID []byte, layer db.NodeLayer, recheckInterval time.Duration) (isBad bool, shouldRecheck bool, reason string, err error)
	}

	// Layer is the layer being looked up
	Layer db.NodeLayer

	// Alpha is the concurrency factor (default 3)
	Alpha int

	// LookupTimeout is the timeout for lookup operations
	LookupTimeout time.Duration

	// OnNodeFound is called when a new node is discovered during lookup
	// The callback should handle admission checks and add the node if valid
	OnNodeFound func(*nodedb.Node) bool

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
		config:       cfg,
		queryHistory: make(map[node.ID]time.Time),
	}
}

// Lookup performs a node lookup by querying random nodes from the table.
//
// Since we use a flat table without buckets, we simply:
//   - Select 3 semi-random nodes (preferring alive ones)
//   - Query them concurrently for nodes near the target
//   - Add discovered nodes via callback
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - target: The target node ID to find
//   - k: The number of closest nodes to return
//
// Returns discovered nodes that were added to the table.
func (ls *LookupService) Lookup(ctx context.Context, target node.ID, k int) ([]*nodedb.Node, error) {
	return ls.lookupInternal(ctx, target, k, false)
}

// lookupInternal performs the actual lookup with options for random walks
func (ls *LookupService) lookupInternal(ctx context.Context, target node.ID, k int, isRandomWalk bool) ([]*nodedb.Node, error) {
	ls.mu.Lock()
	ls.lookupsStarted++
	ls.mu.Unlock()

	ls.config.Logger.WithField("target", target).WithField("k", k).Debug("starting lookup")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, ls.config.LookupTimeout)
	defer cancel()

	// Get all active nodes from table
	allNodes := ls.config.Table.GetActiveNodes()
	if len(allNodes) == 0 {
		ls.mu.Lock()
		ls.lookupsFailed++
		ls.mu.Unlock()
		return nil, fmt.Errorf("no nodes in table to query")
	}

	// Track all discovered nodes and which ones we've queried
	seen := make(map[node.ID]bool)
	queried := make(map[node.ID]bool)
	var allDiscovered []*nodedb.Node
	var mu sync.Mutex

	// Add existing table nodes to the candidate pool
	for _, n := range allNodes {
		seen[n.ID()] = true
	}

	// For iterative lookup, we need a list of candidates sorted by distance to target
	// Start with closest nodes from our table
	var candidates []*nodedb.Node
	if isRandomWalk {
		// For random walks, start with random selection for diversity
		candidates = ls.selectRandomNodes(allNodes, ls.config.Alpha*2)
	} else {
		// For regular lookups, start with closest nodes to target
		candidates = ls.config.Table.FindClosestNodes(target, k*2)
		if len(candidates) == 0 {
			// Fallback to random if no closest nodes
			candidates = ls.selectRandomNodes(allNodes, ls.config.Alpha*2)
		}
	}

	// Perform iterative lookup rounds
	maxRounds := 4 // Maximum number of query rounds
	for round := 0; round < maxRounds; round++ {
		// Select nodes to query this round
		// Pick closest unqueried nodes, considering query history
		toQuery := ls.selectNodesToQuery(candidates, queried, target, ls.config.Alpha, isRandomWalk)
		if len(toQuery) == 0 {
			ls.config.Logger.WithField("round", round).Debug("no more nodes to query, lookup converged")
			break
		}

		ls.config.Logger.WithFields(logrus.Fields{
			"round":      round,
			"target":     target,
			"queryNodes": len(toQuery),
			"isRandWalk": isRandomWalk,
		}).Debug("lookup round")

		// Query nodes in parallel for this round
		var wg sync.WaitGroup
		roundDiscovered := make([]*nodedb.Node, 0)
		var roundMu sync.Mutex

		for _, n := range toQuery {
			wg.Add(1)
			go func(n *nodedb.Node) {
				defer wg.Done()

				// Mark as queried
				mu.Lock()
				queried[n.ID()] = true
				ls.queryHistory[n.ID()] = time.Now()
				mu.Unlock()

				// Calculate distances
				var distances []uint
				if isRandomWalk {
					// For random walks, request high distances to explore diverse keyspace
					distances = []uint{250, 251, 252, 253, 254, 255}
				} else {
					// For regular lookups, use wider range for diversity
					distances = ls.lookupDistances(target, n.ID())
				}

				ls.config.Logger.WithFields(logrus.Fields{
					"round":     round,
					"peerID":    n.PeerID(),
					"addr":      n.Addr(),
					"target":    target,
					"distances": distances,
				}).Trace("sending FINDNODE")

				// Try discv5 first if available
				var discoveredNodes []*nodedb.Node
				if v5Node := n.V5(); v5Node != nil && ls.config.V5Handler != nil {
					mu.Lock()
					ls.lookupsV5++
					mu.Unlock()

					respChan, err := ls.config.V5Handler.SendFindNode(v5Node, distances)
					if err != nil {
						ls.config.Logger.WithFields(logrus.Fields{
							"peerID":   n.PeerID(),
							"addr":     n.Addr(),
							"protocol": "v5",
							"error":    err,
						}).Debug("failed to send FINDNODE v5")
						// Don't return - try v4 fallback
					} else {
						// Wait for response
						var resp *protocol.Response
						select {
						case resp = <-respChan:
							// Response received
						case <-ctx.Done():
							ls.config.Logger.WithField("peerID", n.PeerID()).Debug("lookup cancelled")
							return
						}

						if resp.Error == nil {
							// Extract nodes from v5 response
							if nodesMsg, ok := resp.Message.(*protocol.Nodes); ok {
								ls.config.Logger.WithFields(logrus.Fields{
									"round":       round,
									"peerID":      n.PeerID(),
									"protocol":    "v5",
									"nodesInResp": len(nodesMsg.Records),
								}).Trace("received NODES v5 response")

								for _, record := range nodesMsg.Records {
									v5Node, err := node.New(record)
									if err != nil {
										ls.config.Logger.WithError(err).Debug("invalid node in NODES response")
										continue
									}
									discoveredNodes = append(discoveredNodes, nodedb.NewFromV5(v5Node, ls.config.NodeDB))
								}
							}
						} else {
							ls.config.Logger.WithFields(logrus.Fields{
								"peerID":   n.PeerID(),
								"protocol": "v5",
								"error":    resp.Error,
							}).Debug("FINDNODE v5 timeout or error, trying v4 fallback")
							// Continue to v4 fallback
						}
					}
				}

				// Try discv4 fallback if no v5 results and v4 is available
				if len(discoveredNodes) == 0 && n.V4() != nil && ls.config.V4Service != nil {
					mu.Lock()
					ls.lookupsV4++
					mu.Unlock()

					v4Node := n.V4()
					// Convert target to []byte for v4
					targetBytes := target[:]
					nodes, err := ls.config.V4Service.Findnode(v4Node, targetBytes)
					if err != nil {
						ls.config.Logger.WithFields(logrus.Fields{
							"peerID":   n.PeerID(),
							"addr":     n.Addr(),
							"protocol": "v4",
							"error":    err,
						}).Debug("FINDNODE v4 error")
						return
					}

					ls.config.Logger.WithFields(logrus.Fields{
						"round":       round,
						"peerID":      n.PeerID(),
						"protocol":    "v4",
						"nodesInResp": len(nodes),
					}).Trace("received neighbors v4 response")

					// Request ENR from all discovered v4 nodes in parallel
					// Only include nodes that successfully respond with ENR
					var enrWg sync.WaitGroup
					var enrMu sync.Mutex
					nodesWithENR := make([]*nodedb.Node, 0, len(nodes))

					for _, v4n := range nodes {
						enrWg.Add(1)
						go func(v4n *v4node.Node) {
							defer enrWg.Done()

							nodeID := v4n.ID()
							peerIDStr := fmt.Sprintf("%x", nodeID[:8])

							// Check if this node is marked as bad
							if ls.config.Database != nil {
								isBad, shouldRecheck, reason, err := ls.config.Database.IsBadNode(nodeID[:], ls.config.Layer, 0)
								if err != nil {
									ls.config.Logger.WithError(err).Debug("failed to check bad node status")
								} else if isBad && !shouldRecheck {
									ls.config.Logger.WithFields(logrus.Fields{
										"peerID": peerIDStr,
										"reason": reason,
									}).Debug("skipping bad node (too soon to recheck)")
									return
								}
							}

							// Request ENR from the node
							enrRecord, err := ls.config.V4Service.RequestENR(v4n)
							if err != nil {
								ls.config.Logger.WithFields(logrus.Fields{
									"peerID":   peerIDStr,
									"addr":     v4n.Addr(),
									"protocol": "v4",
									"error":    err,
								}).Debug("failed to request ENR from discovered node")
								return
							}

							// Verify ENR has required fields
							if enrRecord.IP() == nil && enrRecord.IP6() == nil {
								ls.config.Logger.WithFields(logrus.Fields{
									"peerID": peerIDStr,
								}).Debug("discovered node ENR missing IP address, skipping")
								return
							}
							if enrRecord.UDP() == 0 {
								ls.config.Logger.WithFields(logrus.Fields{
									"peerID": peerIDStr,
								}).Debug("discovered node ENR missing UDP port, skipping")
								return
							}

							// Set the ENR on the v4 node
							v4n.SetENR(enrRecord)

							// Add to results
							enrMu.Lock()
							nodesWithENR = append(nodesWithENR, nodedb.NewFromV4(v4n, ls.config.NodeDB))
							enrMu.Unlock()

							ls.config.Logger.WithFields(logrus.Fields{
								"peerID": peerIDStr,
								"addr":   v4n.Addr(),
							}).Trace("successfully retrieved ENR for discovered v4 node")
						}(v4n)
					}

					enrWg.Wait()

					ls.config.Logger.WithFields(logrus.Fields{
						"round":           round,
						"peerID":          n.PeerID(),
						"protocol":        "v4",
						"nodesInResp":     len(nodes),
						"nodesWithENR":    len(nodesWithENR),
						"nodesWithoutENR": len(nodes) - len(nodesWithENR),
					}).Debug("completed ENR requests for discovered v4 nodes")

					// Add nodes with valid ENR to discovered nodes
					discoveredNodes = append(discoveredNodes, nodesWithENR...)
				}

				// Add discovered nodes to round results
				roundMu.Lock()
				for _, newNode := range discoveredNodes {
					// Skip if already seen
					mu.Lock()
					alreadySeen := seen[newNode.ID()]
					if !alreadySeen {
						seen[newNode.ID()] = true
					}
					mu.Unlock()

					if !alreadySeen {
						roundDiscovered = append(roundDiscovered, newNode)
					}
				}
				roundMu.Unlock()
			}(n)
		}

		wg.Wait()

		ls.config.Logger.WithFields(logrus.Fields{
			"round":      round,
			"discovered": len(roundDiscovered),
		}).Debug("lookup round complete")

		// Add this round's discoveries to the total
		mu.Lock()
		allDiscovered = append(allDiscovered, roundDiscovered...)
		mu.Unlock()

		// Check context before next round
		select {
		case <-ctx.Done():
			ls.config.Logger.WithField("round", round).Debug("lookup timeout")
			return nil, ctx.Err()
		default:
		}

		// Add newly discovered nodes to candidates for next round
		// Sort by distance to target to prioritize closer nodes
		if !isRandomWalk {
			candidates = ls.sortNodesByDistance(roundDiscovered, target)
			if len(candidates) == 0 {
				ls.config.Logger.WithField("round", round).Debug("no new candidates, lookup complete")
				break
			}
		} else {
			// For random walks, just add to candidates
			candidates = append(candidates, roundDiscovered...)
		}
	}

	ls.config.Logger.WithFields(logrus.Fields{
		"target":     target,
		"queried":    len(queried),
		"discovered": len(allDiscovered),
	}).Debug("lookup queries complete")

	// Add discovered nodes via callback (handles admission checks)
	var addedNodes []*nodedb.Node
	for _, n := range allDiscovered {
		if ls.config.OnNodeFound != nil && ls.config.OnNodeFound(n) {
			addedNodes = append(addedNodes, n)
		}
	}

	ls.mu.Lock()
	ls.nodesDiscovered += len(allDiscovered)
	ls.lookupsCompleted++
	ls.mu.Unlock()

	ls.config.Logger.WithFields(logrus.Fields{
		"target":     target,
		"discovered": len(allDiscovered),
		"accepted":   len(addedNodes),
		"rejected":   len(allDiscovered) - len(addedNodes),
	}).Info("lookup complete")

	return addedNodes, nil
}

// selectRandomNodes selects up to count semi-random nodes, preferring alive ones.
func (ls *LookupService) selectRandomNodes(nodes []*nodedb.Node, count int) []*nodedb.Node {
	if len(nodes) == 0 {
		return nil
	}

	// Separate into alive and dead nodes
	var aliveNodes []*nodedb.Node
	var deadNodes []*nodedb.Node

	// Use default values for alive check (24h, 3 failures)
	maxNodeAge := 24 * time.Hour
	maxFailures := 3

	for _, n := range nodes {
		if n.IsAlive(maxNodeAge, maxFailures) {
			aliveNodes = append(aliveNodes, n)
		} else {
			deadNodes = append(deadNodes, n)
		}
	}

	// Shuffle both lists
	mathrand.Shuffle(len(aliveNodes), func(i, j int) {
		aliveNodes[i], aliveNodes[j] = aliveNodes[j], aliveNodes[i]
	})
	mathrand.Shuffle(len(deadNodes), func(i, j int) {
		deadNodes[i], deadNodes[j] = deadNodes[j], deadNodes[i]
	})

	// Select nodes, preferring alive ones
	var selected []*nodedb.Node

	// Take alive nodes first
	for i := 0; i < len(aliveNodes) && len(selected) < count; i++ {
		selected = append(selected, aliveNodes[i])
	}

	// Fill remaining slots with dead nodes if needed
	for i := 0; i < len(deadNodes) && len(selected) < count; i++ {
		selected = append(selected, deadNodes[i])
	}

	return selected
}

// selectNodesToQuery selects up to count nodes to query from candidates.
// It prefers nodes that:
// 1. Haven't been queried yet in this lookup
// 2. Haven't been queried recently (considering query history)
// 3. Are closest to the target (for non-random-walk lookups)
func (ls *LookupService) selectNodesToQuery(candidates []*nodedb.Node, queried map[node.ID]bool, target node.ID, count int, isRandomWalk bool) []*nodedb.Node {
	if len(candidates) == 0 {
		return nil
	}

	// Filter out already queried nodes
	var unqueried []*nodedb.Node
	for _, n := range candidates {
		if !queried[n.ID()] {
			unqueried = append(unqueried, n)
		}
	}

	if len(unqueried) == 0 {
		return nil
	}

	// Score nodes based on:
	// - Distance to target (for non-random walks)
	// - Time since last query (prefer nodes not queried recently)
	type scoredNode struct {
		node  *nodedb.Node
		score float64
	}

	ls.mu.RLock()
	scored := make([]scoredNode, 0, len(unqueried))
	now := time.Now()
	queryHistoryWeight := 5 * time.Minute // Prefer nodes not queried in last 5 minutes

	for _, n := range unqueried {
		score := 0.0

		// Distance score (lower distance = higher score)
		if !isRandomWalk {
			dist := node.LogDistance(target, n.ID())
			// Invert distance so closer nodes get higher scores
			score += float64(256 - dist)
		}

		// Query history score (prefer nodes not queried recently)
		if lastQuery, exists := ls.queryHistory[n.ID()]; exists {
			timeSinceQuery := now.Sub(lastQuery)
			if timeSinceQuery < queryHistoryWeight {
				// Penalize recently queried nodes
				penalty := float64(queryHistoryWeight-timeSinceQuery) / float64(queryHistoryWeight)
				score -= penalty * 100 // Heavy penalty
			}
		} else {
			// Never queried - bonus
			score += 50
		}

		scored = append(scored, scoredNode{node: n, score: score})
	}
	ls.mu.RUnlock()

	// Sort by score (highest first)
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	// Take top count nodes
	result := make([]*nodedb.Node, 0, count)
	for i := 0; i < len(scored) && i < count; i++ {
		result = append(result, scored[i].node)
	}

	return result
}

// sortNodesByDistance sorts nodes by their distance to the target.
// Returns nodes sorted from closest to farthest.
func (ls *LookupService) sortNodesByDistance(nodes []*nodedb.Node, target node.ID) []*nodedb.Node {
	if len(nodes) == 0 {
		return nil
	}

	// Create a copy to avoid modifying the input
	sorted := make([]*nodedb.Node, len(nodes))
	copy(sorted, nodes)

	// Sort by distance to target
	sort.Slice(sorted, func(i, j int) bool {
		distI := node.LogDistance(target, sorted[i].ID())
		distJ := node.LogDistance(target, sorted[j].ID())
		return distI < distJ
	})

	return sorted
}

// LookupWithFilter performs a lookup with an ENR filter.
//
// Only nodes that pass the filter are included in the results.
func (ls *LookupService) LookupWithFilter(ctx context.Context, target node.ID, k int, filter enr.ENRFilter) ([]*nodedb.Node, error) {
	// Perform regular lookup
	nodes, err := ls.Lookup(ctx, target, k*2) // Request more to account for filtering
	if err != nil {
		return nil, err
	}

	// Apply filter
	var filtered []*nodedb.Node
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
func (ls *LookupService) RandomWalk(ctx context.Context) ([]*nodedb.Node, error) {
	// Generate a completely random 256-bit target ID
	// This ensures we explore diverse regions of the keyspace
	var target node.ID
	if _, err := rand.Read(target[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random target: %w", err)
	}

	ls.config.Logger.WithField("target", target).Debug("starting random walk")

	// Perform lookup for random target
	return ls.lookupInternal(ctx, target, 32, true)
}

// GetStats returns statistics about discovery operations.
type LookupStats struct {
	LookupsStarted   int
	LookupsCompleted int
	LookupsFailed    int
	NodesDiscovered  int
	LookupsV5        int // Lookups using discv5
	LookupsV4        int // Lookups using discv4
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
		LookupsV5:        ls.lookupsV5,
		LookupsV4:        ls.lookupsV4,
	}
}

// CleanupQueryHistory removes stale entries from the query history.
// This should be called periodically to prevent unbounded growth.
// Entries older than the given duration are removed.
func (ls *LookupService) CleanupQueryHistory(maxAge time.Duration) int {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	now := time.Now()
	removed := 0

	for nodeID, lastQuery := range ls.queryHistory {
		if now.Sub(lastQuery) > maxAge {
			delete(ls.queryHistory, nodeID)
			removed++
		}
	}

	if removed > 0 {
		ls.config.Logger.WithField("removed", removed).Debug("cleaned up query history")
	}

	return removed
}

// lookupDistances calculates the distance parameters for a FINDNODE request.
//
// This implements an improved algorithm that requests a wider range of distances
// for better diversity. Instead of just 3 distances centered around the target,
// we request 5 distances covering a broader range of the keyspace.
//
// The strategy is:
// 1. Request the exact target distance
// 2. Request nearby distances (±1, ±2)
// 3. Include a wider diversity distance to explore more of the keyspace
//
// For example, if target-to-dest distance is 150, we might request:
// [150, 151, 149, 152, 148] for nearby exploration
func (ls *LookupService) lookupDistances(target, dest node.ID) []uint {
	const lookupRequestLimit = 5 // Increased from 3 to 5 for better diversity

	td := node.LogDistance(target, dest)
	if td < 0 {
		// Shouldn't happen (means target == dest), request all nodes
		return []uint{256}
	}

	dists := []uint{uint(td)}

	// Add nearby distances in alternating pattern: +1, -1, +2, -2, +3, -3, etc.
	for i := 1; len(dists) < lookupRequestLimit; i++ {
		// Try adding higher distance first
		if td+i <= 256 {
			dists = append(dists, uint(td+i))
			if len(dists) >= lookupRequestLimit {
				break
			}
		}
		// Then try lower distance
		if td-i > 0 {
			dists = append(dists, uint(td-i))
		}
	}

	// For additional diversity, occasionally include a wider distance
	// This helps discover nodes in different regions of the keyspace
	if len(dists) < lookupRequestLimit && td < 250 {
		// Add a distance in the higher range for diversity
		wideDistance := uint(mathrand.Intn(6) + 250) // Random distance 250-255
		// Only add if not already in the list
		found := false
		for _, d := range dists {
			if d == wideDistance {
				found = true
				break
			}
		}
		if !found {
			dists = append(dists, wideDistance)
		}
	}

	return dists
}
