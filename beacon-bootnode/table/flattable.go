package table

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/pk910/bootoor/beacon-bootnode/nodedb"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/sirupsen/logrus"
)

// FlatTable configuration constants
const (
	// DefaultMaxActiveNodes is the maximum number of nodes to keep in the active state
	DefaultMaxActiveNodes = 500

	// DefaultPingRate is the maximum number of pings per minute
	DefaultPingRate = 400

	// DefaultSweepPercent is the percentage of active nodes to rotate during sweep
	DefaultSweepPercent = 10
)

// FlatTable is a flat node storage with capped active nodes.
//
// Unlike the bucket-based Kademlia table, this maintains:
//   - All nodes in DB (active and inactive)
//   - Capped active nodes in memory (max 500)
//   - Distributed ping scheduling
//   - Periodic active/inactive rotation
type FlatTable struct {
	// localID is our node ID
	localID node.ID

	// db is the primary node storage
	db *nodedb.NodeDB

	// activeNodes maps node ID to node for quick lookups
	// Only contains nodes in active state (max maxActiveNodes)
	activeNodes map[node.ID]*node.Node

	// maxActiveNodes is the cap for active nodes
	maxActiveNodes int

	// ipLimiter enforces per-IP node limits
	ipLimiter *IPLimiter

	// maxNodesPerIP is the maximum nodes allowed per IP
	maxNodesPerIP int

	// pingInterval is how often to ping nodes
	pingInterval time.Duration

	// pingRate is maximum pings per minute
	pingRate int

	// maxNodeAge is the maximum time since last seen
	maxNodeAge time.Duration

	// maxFailures is the maximum consecutive failures
	maxFailures int

	// sweepPercent is percentage of nodes to rotate during sweep
	sweepPercent int

	// nodeChangedCallback is called when nodes are added/updated
	nodeChangedCallback NodeChangedCallback

	// mu protects the active nodes map and stats
	mu sync.RWMutex

	// logger for debug messages
	logger logrus.FieldLogger

	// forkScoringInfo contains fork digest information for node scoring
	forkScoringInfo *node.ForkScoringInfo

	// Stats tracking
	admissionRejections int
	ipLimitRejections   int
	deadNodesRemoved    int
	nodesPromoted       int
	nodesDemoted        int
}

// FlatTableConfig contains configuration for the flat table.
type FlatTableConfig struct {
	// LocalID is our node ID
	LocalID node.ID

	// DB is the primary node storage
	DB *nodedb.NodeDB

	// MaxActiveNodes is the maximum number of active nodes (default 500)
	MaxActiveNodes int

	// MaxNodesPerIP is the maximum nodes allowed per IP address
	MaxNodesPerIP int

	// PingInterval is how often to ping nodes
	PingInterval time.Duration

	// PingRate is maximum pings per minute (default 400)
	PingRate int

	// MaxNodeAge is the maximum time since last seen
	MaxNodeAge time.Duration

	// MaxFailures is the maximum consecutive failures
	MaxFailures int

	// SweepPercent is percentage of nodes to rotate during sweep (default 10%)
	SweepPercent int

	// NodeChangedCallback is called when a node is added or updated
	NodeChangedCallback NodeChangedCallback

	// Logger for debug messages
	Logger logrus.FieldLogger
}

// NewFlatTable creates a new flat node table.
func NewFlatTable(cfg FlatTableConfig) (*FlatTable, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("table: DB is required")
	}

	if cfg.MaxActiveNodes <= 0 {
		cfg.MaxActiveNodes = DefaultMaxActiveNodes
	}

	if cfg.MaxNodesPerIP <= 0 {
		cfg.MaxNodesPerIP = DefaultMaxNodesPerIP
	}

	if cfg.PingInterval <= 0 {
		cfg.PingInterval = DefaultPingInterval
	}

	if cfg.PingRate <= 0 {
		cfg.PingRate = DefaultPingRate
	}

	if cfg.MaxNodeAge <= 0 {
		cfg.MaxNodeAge = DefaultMaxNodeAge
	}

	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = DefaultMaxFailures
	}

	if cfg.SweepPercent <= 0 || cfg.SweepPercent > 100 {
		cfg.SweepPercent = DefaultSweepPercent
	}

	t := &FlatTable{
		localID:             cfg.LocalID,
		db:                  cfg.DB,
		activeNodes:         make(map[node.ID]*node.Node),
		maxActiveNodes:      cfg.MaxActiveNodes,
		ipLimiter:           NewIPLimiter(cfg.MaxNodesPerIP),
		maxNodesPerIP:       cfg.MaxNodesPerIP,
		pingInterval:        cfg.PingInterval,
		pingRate:            cfg.PingRate,
		maxNodeAge:          cfg.MaxNodeAge,
		maxFailures:         cfg.MaxFailures,
		sweepPercent:        cfg.SweepPercent,
		nodeChangedCallback: cfg.NodeChangedCallback,
		logger:              cfg.Logger,
	}

	return t, nil
}

// LoadInitialNodesFromDB loads random nodes from DB into the active pool.
func (t *FlatTable) LoadInitialNodesFromDB() error {
	// Load random nodes from DB to bootstrap the active pool
	randomNodes := t.db.LoadRandomNodes(t.maxActiveNodes)

	for _, n := range randomNodes {
		if t.ipLimiter.CanAdd(n) {
			t.activeNodes[n.ID()] = n
			t.ipLimiter.Add(n)

			if err := t.db.UpdateLastActive(n.ID(), time.Now()); err != nil {
				t.logger.WithError(err).Warn("failed to mark node as active")
			}
		}
	}

	t.logger.WithField("count", len(t.activeNodes)).Info("loaded random nodes into active pool")
	return nil
}

// Add adds a node to the active pool.
//
// This method handles adding nodes to the active in-memory pool with the following strategy:
// - For nodes that already exist in active pool: updates ENR if newer.
// - For new nodes: adds to active pool even if over capacity (up to hard limit).
// - Hard limit: 2x maxActiveNodes. If reached, triggers immediate sweep.
// - IP limiter is still enforced.
//
// This allows newly discovered nodes (which may not be working) to be added without
// rejecting them immediately. The next sweep will clean up excess nodes.
//
// DB writes must be handled by caller.
func (t *FlatTable) Add(n *node.Node) bool {
	if n == nil {
		return false
	}

	nodeID := n.ID()

	// Don't add self
	if nodeID == t.localID {
		return false
	}

	t.mu.Lock()
	currentSize := len(t.activeNodes)

	// Check if already in active pool
	if existing, exists := t.activeNodes[nodeID]; exists {
		t.mu.Unlock()

		// Update ENR if newer
		newSeq := n.Record().Seq()
		if newSeq > existing.Record().Seq() {
			existing.UpdateENR(n.Record())

			// Queue ENR update (preserves stats)
			if err := t.db.UpdateNodeENR(existing); err != nil {
				t.logger.WithError(err).Warn("failed to queue node ENR update")
			}

			if t.nodeChangedCallback != nil {
				t.nodeChangedCallback(existing)
			}
		}
		return true
	}

	// Check hard limit: 2x max capacity
	hardLimit := t.maxActiveNodes * 2
	if currentSize >= hardLimit {
		t.mu.Unlock()
		t.logger.WithFields(logrus.Fields{
			"currentSize": currentSize,
			"hardLimit":   hardLimit,
			"peerID":      n.PeerID(),
		}).Warn("hard limit reached, triggering immediate sweep")

		// Trigger immediate sweep to make room
		t.performImmediateSweep()

		// Try again after sweep
		t.mu.Lock()
		currentSize = len(t.activeNodes)
		if currentSize >= hardLimit {
			t.mu.Unlock()
			t.logger.WithField("peerID", n.PeerID()).Warn("still at hard limit after sweep, rejecting node")
			return false
		}
		// Continue with lock held
	}

	// Check IP limiter
	canAddIP := t.ipLimiter.CanAdd(n)
	if !canAddIP {
		t.mu.Unlock()
		t.logger.WithField("peerID", n.PeerID()).Debug("IP limit reached, rejecting node")
		return false
	}

	// Add to active pool (even if over soft capacity)
	t.activeNodes[nodeID] = n
	t.ipLimiter.Add(n)
	t.nodesPromoted++

	overCapacity := currentSize >= t.maxActiveNodes
	t.mu.Unlock()

	if overCapacity {
		t.logger.WithFields(logrus.Fields{
			"peerID":      n.PeerID(),
			"addr":        n.Addr(),
			"currentSize": currentSize + 1,
			"maxActive":   t.maxActiveNodes,
		}).Debug("added node while over capacity (will be cleaned up at next sweep)")
	} else {
		t.logger.WithField("peerID", n.PeerID()).WithField("addr", n.Addr()).Info("added node to active pool")
	}

	// Queue ENR update to DB and mark as active
	if err := t.db.UpdateNodeENR(n); err != nil {
		t.logger.WithError(err).Warn("failed to queue new node")
		return false
	}
	if err := t.db.UpdateLastActive(nodeID, time.Now()); err != nil {
		t.logger.WithError(err).Warn("failed to mark new node as active")
	}

	if t.nodeChangedCallback != nil {
		t.nodeChangedCallback(n)
	}

	return true
}

// CanAddNodeByIP checks if we can add a node based on IP limits.
// This checks against all nodes (active + inactive) in the DB.
func (t *FlatTable) CanAddNodeByIP(n *node.Node) bool {
	// Count nodes with same IP in DB
	allNodes := t.db.List()
	sameIPCount := 0
	nodeIP := n.IP().String()

	for _, existing := range allNodes {
		if existing.IP().String() == nodeIP {
			sameIPCount++
		}
	}

	return sameIPCount < t.maxNodesPerIP
}

// Get retrieves a node by ID.
// First checks active nodes, then falls back to DB.
func (t *FlatTable) Get(nodeID node.ID) *node.Node {
	t.mu.RLock()
	// Check active nodes first
	if n, exists := t.activeNodes[nodeID]; exists {
		t.mu.RUnlock()
		return n
	}
	t.mu.RUnlock()

	// Fall back to DB
	n, err := t.db.Load(nodeID)
	if err != nil {
		return nil
	}
	return n
}

// GetActiveNodes returns a copy of all active nodes.
func (t *FlatTable) GetActiveNodes() []*node.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*node.Node, 0, len(t.activeNodes))
	for _, n := range t.activeNodes {
		result = append(result, n)
	}
	return result
}

// GetRandomActiveNodes returns up to k random active nodes.
func (t *FlatTable) GetRandomActiveNodes(k int) []*node.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.activeNodes) == 0 {
		return nil
	}

	// Collect all active nodes
	allActive := make([]*node.Node, 0, len(t.activeNodes))
	for _, n := range t.activeNodes {
		allActive = append(allActive, n)
	}

	// Shuffle and take first k
	rand.Shuffle(len(allActive), func(i, j int) {
		allActive[i], allActive[j] = allActive[j], allActive[i]
	})

	if k > len(allActive) {
		k = len(allActive)
	}

	return allActive[:k]
}

// FindClosestNodes finds the k closest active nodes to the target ID.
func (t *FlatTable) FindClosestNodes(target node.ID, k int) []*node.Node {
	activeNodes := t.GetActiveNodes()

	if len(activeNodes) == 0 {
		return nil
	}

	// Get node IDs
	nodeIDs := nodesToIDs(activeNodes)

	// Find k closest IDs
	closestIDs := node.FindClosest(target, nodeIDs, k)

	// Convert IDs back to nodes
	nodeMap := nodesMap(activeNodes)
	result := make([]*node.Node, 0, len(closestIDs))
	for _, id := range closestIDs {
		if n, exists := nodeMap[id]; exists {
			result = append(result, n)
		}
	}

	return result
}

// GetNodesNeedingPing returns active nodes that need a PING check.
//
// This implements distributed ping scheduling by limiting the number of nodes returned.
func (t *FlatTable) GetNodesNeedingPing() []*node.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var deadNodes []*node.Node
	var aliveNodes []*node.Node

	// Separate nodes needing ping into dead and alive
	for _, n := range t.activeNodes {
		if n.NeedsPing(t.pingInterval) {
			if n.IsAlive(t.maxNodeAge, t.maxFailures) {
				aliveNodes = append(aliveNodes, n)
			} else {
				deadNodes = append(deadNodes, n)
			}
		}
	}

	// Shuffle both lists for randomness
	rand.Shuffle(len(deadNodes), func(i, j int) {
		deadNodes[i], deadNodes[j] = deadNodes[j], deadNodes[i]
	})
	rand.Shuffle(len(aliveNodes), func(i, j int) {
		aliveNodes[i], aliveNodes[j] = aliveNodes[j], aliveNodes[i]
	})

	// Cap the number of pings based on ping rate
	// pingRate is per minute, so divide by 2 if we're called every 30 seconds
	maxPings := t.pingRate / 2

	// Select nodes preferring dead nodes (60% dead, 40% alive)
	var selected []*node.Node
	deadSlots := (maxPings * 60) / 100

	// Take dead nodes first (up to 60% of slots)
	for i := 0; i < len(deadNodes) && len(selected) < deadSlots; i++ {
		selected = append(selected, deadNodes[i])
	}

	// Take alive nodes (up to 40% of slots)
	for i := 0; i < len(aliveNodes) && len(selected) < maxPings; i++ {
		selected = append(selected, aliveNodes[i])
	}

	// If we didn't fill all slots with alive nodes, fill with remaining dead nodes
	for i := deadSlots; i < len(deadNodes) && len(selected) < maxPings; i++ {
		selected = append(selected, deadNodes[i])
	}

	return selected
}

// PerformSweep rotates nodes between active and inactive pools.
//
// This should be called periodically (e.g., every 10 minutes).
// Only demotes nodes when over capacity. When at or under capacity, nodes are kept
// to allow newly discovered nodes to be tested before being demoted.
// Loads inactive nodes from DB and tries to promote them to fill available slots.
func (t *FlatTable) PerformSweep() {
	t.mu.Lock()
	activeCount := len(t.activeNodes)
	t.mu.Unlock()

	// Calculate how many nodes to demote
	var demoteCount int
	var reason string

	sweepMax := activeCount
	if sweepMax > t.maxActiveNodes {
		sweepMax = t.maxActiveNodes
	}
	sweepCount := int(float64(sweepMax) * float64(t.sweepPercent) / 100.0)

	if activeCount > t.maxActiveNodes {
		// Over capacity - remove excess only
		demoteCount = activeCount - t.maxActiveNodes
		reason = "demote excess"
	} else {
		// At or under capacity - don't demote any nodes
		// This allows newly discovered nodes to remain and be tested
		demoteCount = 0
		reason = "active sweep"
	}

	// Only process demotion if we need to demote nodes
	var demotedCount int
	var slotsAvailable int

	if demoteCount > 0 {
		// Get active nodes sorted by priority (worst first)
		// Priority: dead nodes first, then by lowest score
		activeNodes := t.GetActiveNodes()

		// Get fork scoring info for node ranking
		t.mu.RLock()
		forkInfo := t.forkScoringInfo
		t.mu.RUnlock()

		sort.Slice(activeNodes, func(i, j int) bool {
			// Dead nodes first
			iDead := !activeNodes[i].IsAlive(t.maxNodeAge, t.maxFailures)
			jDead := !activeNodes[j].IsAlive(t.maxNodeAge, t.maxFailures)
			if iDead != jDead {
				return iDead // Dead nodes come first
			}
			// Then by score (lowest first) - use fork-aware scoring
			return activeNodes[i].CalculateScore(forkInfo) < activeNodes[j].CalculateScore(forkInfo)
		})

		// Demote nodes from active pool
		nodesToDemote := activeNodes
		if len(nodesToDemote) > demoteCount {
			nodesToDemote = nodesToDemote[:demoteCount]
		}

		t.mu.Lock()
		for _, n := range nodesToDemote {
			nodeID := n.ID()
			delete(t.activeNodes, nodeID)
			t.ipLimiter.Remove(nodeID)
			t.nodesDemoted++

			// Do full update to store latest request stats & timestamps
			if err := t.db.UpdateNodeFull(n); err != nil {
				t.logger.WithError(err).Warn("failed to update node")
			}
		}
		demotedCount = len(nodesToDemote)
		slotsAvailable = t.maxActiveNodes - len(t.activeNodes)
		t.mu.Unlock()
	} else {
		// No demotion needed
		t.mu.Lock()
		slotsAvailable = t.maxActiveNodes - len(t.activeNodes)
		t.mu.Unlock()
	}

	// Add sweep count to promote inactive nodes
	slotsAvailable += sweepCount

	// Load inactive nodes from DB and try to promote them
	if slotsAvailable > 0 {
		// Request more than available slots to account for IP limits and filters
		inactiveNodes := t.db.LoadInactiveNodes(slotsAvailable * 2)

		promotedCount := 0
		for _, n := range inactiveNodes {
			// Skip if already active (shouldn't happen but be safe)
			t.mu.RLock()
			_, alreadyActive := t.activeNodes[n.ID()]
			currentSize := len(t.activeNodes)
			t.mu.RUnlock()

			if alreadyActive {
				continue
			}

			// Check if we have room
			if currentSize >= t.maxActiveNodes+sweepCount {
				break
			}

			// Check IP limits
			if !t.ipLimiter.CanAdd(n) {
				continue
			}

			// Promote to active
			t.mu.Lock()
			t.activeNodes[n.ID()] = n
			t.ipLimiter.Add(n)
			t.nodesPromoted++
			t.mu.Unlock()

			// Update last_active to mark as active
			if err := t.db.UpdateLastActive(n.ID(), time.Now()); err != nil {
				t.logger.WithError(err).Warn("failed to mark node as active")
			}

			promotedCount++

			if t.nodeChangedCallback != nil {
				t.nodeChangedCallback(n)
			}
		}

		if promotedCount > 0 || demotedCount > 0 {
			t.logger.WithFields(logrus.Fields{
				"promoted": promotedCount,
				"demoted":  demotedCount,
				"reason":   reason,
				"slots":    slotsAvailable,
				"sweep":    sweepCount,
			}).Info("active pool sweep completed")
		}
	}
}

// performImmediateSweep performs an immediate sweep to reduce the active pool size.
// This is called when the hard limit (2x capacity) is reached.
// It aggressively demotes nodes to bring the pool back to the soft limit.
func (t *FlatTable) performImmediateSweep() {
	t.logger.Warn("performing immediate sweep due to hard limit")

	t.mu.Lock()
	activeCount := len(t.activeNodes)
	t.mu.Unlock()

	// Calculate how many nodes to demote - bring back to max capacity
	demoteCount := activeCount - t.maxActiveNodes
	if demoteCount <= 0 {
		t.logger.Debug("immediate sweep: already at or under capacity")
		return
	}

	// Get active nodes sorted by priority (worst first)
	// Priority: dead nodes first, then by lowest score
	activeNodes := t.GetActiveNodes()

	// Get fork scoring info for node ranking
	t.mu.RLock()
	forkInfo := t.forkScoringInfo
	t.mu.RUnlock()

	sort.Slice(activeNodes, func(i, j int) bool {
		// Dead nodes first
		iDead := !activeNodes[i].IsAlive(t.maxNodeAge, t.maxFailures)
		jDead := !activeNodes[j].IsAlive(t.maxNodeAge, t.maxFailures)
		if iDead != jDead {
			return iDead // Dead nodes come first
		}
		// Then by score (lowest first) - use fork-aware scoring
		return activeNodes[i].CalculateScore(forkInfo) < activeNodes[j].CalculateScore(forkInfo)
	})

	// Demote worst nodes from active pool
	nodesToDemote := activeNodes
	if len(nodesToDemote) > demoteCount {
		nodesToDemote = nodesToDemote[:demoteCount]
	}

	t.mu.Lock()
	for _, n := range nodesToDemote {
		nodeID := n.ID()
		delete(t.activeNodes, nodeID)
		t.ipLimiter.Remove(nodeID)
		t.nodesDemoted++

		// Update last_active to mark as inactive
		if err := t.db.UpdateLastActive(nodeID, time.Now()); err != nil {
			t.logger.WithError(err).Warn("failed to mark node as inactive")
		}
	}
	demotedCount := len(nodesToDemote)
	newSize := len(t.activeNodes)
	t.mu.Unlock()

	t.logger.WithFields(logrus.Fields{
		"demoted": demotedCount,
		"newSize": newSize,
		"target":  t.maxActiveNodes,
	}).Warn("immediate sweep complete")
}

// Size returns the total number of nodes (active + inactive).
func (t *FlatTable) Size() int {
	return t.db.Count()
}

// ActiveSize returns the number of active nodes.
func (t *FlatTable) ActiveSize() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.activeNodes)
}

// NumBucketsFilled returns a compatibility value for the flat table.
// Since we don't have buckets, we return 1 if we have any active nodes, 0 otherwise.
func (t *FlatTable) NumBucketsFilled() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.activeNodes) > 0 {
		return 1
	}
	return 0
}

// GetStats returns statistics about the table.
func (t *FlatTable) GetStats() TableStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	activeCount := len(t.activeNodes)
	totalCount := t.db.Count()

	return TableStats{
		TotalNodes:          totalCount,
		ActiveNodes:         activeCount,
		BucketsFilled:       0, // Not applicable for flat table
		AdmissionRejections: t.admissionRejections,
		IPLimitRejections:   t.ipLimitRejections,
		DeadNodesRemoved:    t.deadNodesRemoved,
		IPStats:             t.ipLimiter.GetStats(),
	}
}

// GetBucketNodes is kept for compatibility but returns empty for flat table.
func (t *FlatTable) GetBucketNodes(bucketIndex int) []*node.Node {
	return nil
}

// SetForkScoringInfo updates the fork scoring information used for node ranking.
// This should be called periodically to reflect fork changes.
func (t *FlatTable) SetForkScoringInfo(info *node.ForkScoringInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.forkScoringInfo = info
}

// GetNodesByDistance returns nodes at specific distances with score-weighted random selection.
//
// For each requested distance, it finds all matching nodes and selects up to k nodes
// with probability weighted by their score (RTT, success rate, fork compatibility).
//
// This ensures:
//   - Different results on each call (randomized)
//   - Better nodes are returned more frequently (score-weighted)
//   - Specific distances are respected
func (t *FlatTable) GetNodesByDistance(targetID node.ID, distances []uint, k int) []*node.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.activeNodes) == 0 {
		return nil
	}

	// Collect all active nodes
	allNodes := make([]*node.Node, 0, len(t.activeNodes))
	for _, n := range t.activeNodes {
		allNodes = append(allNodes, n)
	}

	// Filter by distance if not requesting all (256)
	var candidateNodes []*node.Node
	if len(distances) == 1 && distances[0] == 256 {
		// Special case: return all nodes
		candidateNodes = allNodes
	} else {
		// Filter by specific distances
		distanceMap := make(map[int]bool)
		for _, d := range distances {
			distanceMap[int(d)] = true
		}

		for _, n := range allNodes {
			dist := node.LogDistance(targetID, n.ID())
			if distanceMap[dist] {
				candidateNodes = append(candidateNodes, n)
			}
		}
	}

	if len(candidateNodes) == 0 {
		return nil
	}

	// If we have fewer candidates than k, return all
	if len(candidateNodes) <= k {
		return candidateNodes
	}

	// Score-weighted random selection
	return t.selectByScore(candidateNodes, k)
}

// selectByScore performs score-weighted random selection of k nodes.
//
// Nodes with higher scores have higher probability of being selected.
// This ensures diversity while favoring better nodes.
func (t *FlatTable) selectByScore(nodes []*node.Node, k int) []*node.Node {
	if len(nodes) <= k {
		return nodes
	}

	// Calculate scores for all nodes
	type scoredNode struct {
		node  *node.Node
		score float64
	}

	scoredNodes := make([]scoredNode, len(nodes))
	totalScore := 0.0

	for i, n := range nodes {
		score := n.CalculateScore(t.forkScoringInfo)
		// Add small baseline to ensure all nodes have some probability
		score = score + 0.1
		scoredNodes[i] = scoredNode{node: n, score: score}
		totalScore += score
	}

	// If total score is zero (shouldn't happen with baseline), fall back to random
	if totalScore == 0 {
		rand.Shuffle(len(nodes), func(i, j int) {
			nodes[i], nodes[j] = nodes[j], nodes[i]
		})
		return nodes[:k]
	}

	// Weighted random selection without replacement
	selected := make([]*node.Node, 0, k)
	remaining := make([]scoredNode, len(scoredNodes))
	copy(remaining, scoredNodes)
	currentTotal := totalScore

	for i := 0; i < k && len(remaining) > 0; i++ {
		// Pick a random value in [0, currentTotal)
		r := rand.Float64() * currentTotal

		// Find the node corresponding to this value
		sum := 0.0
		selectedIdx := 0
		for idx, sn := range remaining {
			sum += sn.score
			if sum >= r {
				selectedIdx = idx
				break
			}
		}

		// Add selected node
		selected = append(selected, remaining[selectedIdx].node)

		// Remove from remaining and update total
		currentTotal -= remaining[selectedIdx].score
		remaining = append(remaining[:selectedIdx], remaining[selectedIdx+1:]...)
	}

	return selected
}
