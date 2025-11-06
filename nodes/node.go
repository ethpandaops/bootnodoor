package nodes

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethpandaops/bootnodoor/discv4/node"
	discv5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enode"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/stats"
)

// DirtyFlags represents which fields need database updates.
type DirtyFlags uint8

const (
	DirtyFull       DirtyFlags = 0x01 // Full upsert (initial add)
	DirtyENR        DirtyFlags = 0x02 // seq+enr+ip update
	DirtyLastActive DirtyFlags = 0x04 // last_active timestamp
	DirtyLastSeen   DirtyFlags = 0x08 // last_seen timestamp
	DirtyProtocol   DirtyFlags = 0x10 // has_v4/has_v5 flags
	DirtyStats      DirtyFlags = 0x20 // packet stats (success/failure/rtt)
)

// Node is a generic node type that can hold both discv4 and discv5 nodes.
//
// A node can have:
//   - Only v4 (legacy execution layer nodes)
//   - Only v5 (consensus layer nodes)
//   - Both v4 and v5 (modern execution layer nodes)
//
// The node is identified by its node ID which is consistent across protocols.
type Node struct {
	nodedb *NodeDB

	// id is the node identifier (Keccak256 of public key)
	id [32]byte

	// pubKey is the node's secp256k1 public key
	pubKey *ecdsa.PublicKey

	// enr is the node's ENR record
	enr *enr.Record

	// Protocol-specific nodes
	v4Node *node.Node
	v5Node *discv5node.Node

	// Network info
	mu   sync.RWMutex
	addr *net.UDPAddr

	// Shared statistics - used by both v4 and v5 nodes
	// The SharedStats struct includes its own mutex for thread-safe access
	nodeStats *stats.SharedStats

	// lastActive is when the node was last active in the routing table
	lastActive time.Time

	// Dirty tracking for database updates
	dirtyMu     sync.Mutex
	dirtyFields DirtyFlags
}

// NewFromV4 creates a generic Node from a discv4 node.
func NewFromV4(v4 *node.Node, nodedb *NodeDB) *Node {
	// Create shared stats
	nodeStats := stats.NewSharedStats(time.Now())
	nodeStats.SetLastSeen(v4.LastSeen())

	n := &Node{
		nodedb:    nodedb,
		id:        v4.ID(),
		pubKey:    v4.PublicKey(),
		enr:       v4.ENR(),
		v4Node:    v4,
		addr:      v4.Addr(),
		nodeStats: nodeStats,
	}

	// Set up callback on shared stats to trigger DB updates
	n.setupSharedStatsCallback()

	// Pass shared stats to v4 node so it updates them
	v4.SetStats(nodeStats)

	return n
}

// NewFromV5 creates a generic Node from a discv5 node.
func NewFromV5(v5 *discv5node.Node, nodedb *NodeDB) *Node {
	v5Stats := v5.GetStats()

	// Create shared stats and populate from v5 stats
	nodeStats := stats.NewSharedStats(v5Stats.FirstSeen)
	nodeStats.SetLastSeen(v5Stats.LastSeen)
	nodeStats.SetLastPing(v5Stats.LastPing)
	nodeStats.SetSuccessCount(v5Stats.SuccessCount)
	nodeStats.SetFailureCount(v5Stats.FailureCount)
	if v5Stats.AvgRTT > 0 {
		nodeStats.UpdateRTT(v5Stats.AvgRTT)
	}

	n := &Node{
		nodedb:    nodedb,
		id:        v5.ID(),
		pubKey:    v5.PublicKey(),
		enr:       v5.Record(),
		v5Node:    v5,
		addr:      v5.Addr(),
		nodeStats: nodeStats,
	}

	// Set up callback on shared stats to trigger DB updates
	n.setupSharedStatsCallback()

	// Pass shared stats to v5 node so it updates them
	v5.SetStats(nodeStats)

	return n
}

// ID returns the node identifier.
func (n *Node) ID() [32]byte {
	return n.id
}

// IDBytes returns the node ID as a byte slice.
func (n *Node) IDBytes() []byte {
	return n.id[:]
}

// PublicKey returns the node's public key.
func (n *Node) PublicKey() *ecdsa.PublicKey {
	return n.pubKey
}

// ENR returns the node's ENR record.
func (n *Node) ENR() *enr.Record {
	return n.enr
}

// Addr returns the node's UDP address.
func (n *Node) Addr() *net.UDPAddr {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.addr
}

// SetAddr updates the node's address.
func (n *Node) SetAddr(addr *net.UDPAddr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.addr = addr

	// Update protocol-specific nodes
	if n.v4Node != nil {
		n.v4Node.SetAddr(addr)
	}
}

// V4 returns the discv4 node if available.
func (n *Node) V4() *node.Node {
	return n.v4Node
}

// V5 returns the discv5 node if available.
func (n *Node) V5() *discv5node.Node {
	return n.v5Node
}

// HasV4 returns true if this node supports discv4.
func (n *Node) HasV4() bool {
	return n.v4Node != nil
}

// HasV5 returns true if this node supports discv5.
func (n *Node) HasV5() bool {
	return n.v5Node != nil
}

// SetV4 sets the discv4 node and marks protocol support dirty.
func (n *Node) SetV4(v4 *node.Node) {
	n.v4Node = v4
	if v4 != nil && n.nodeStats != nil {
		// Ensure callback is set up (in case stats were created elsewhere)
		n.setupSharedStatsCallback()
		// Pass shared stats to v4 node so it updates them
		v4.SetStats(n.nodeStats)
	}
	n.MarkDirty(DirtyProtocol)
}

// SetV5 sets the discv5 node and marks protocol support dirty.
func (n *Node) SetV5(v5 *discv5node.Node) {
	n.v5Node = v5
	if v5 != nil && n.nodeStats != nil {
		// Ensure callback is set up (in case stats were created elsewhere)
		n.setupSharedStatsCallback()
		// Pass shared stats to v5 node so it updates them
		v5.SetStats(n.nodeStats)
	}
	n.MarkDirty(DirtyProtocol)
}

// Enode returns the node's enode:// URL representation.
func (n *Node) Enode() *enode.Enode {
	if n.v4Node != nil {
		return n.v4Node.Enode()
	}

	// Build from generic node info
	addr := n.Addr()
	if addr == nil {
		return nil
	}

	return &enode.Enode{
		PublicKey: n.pubKey,
		IP:        addr.IP,
		UDP:       uint16(addr.Port),
		TCP:       uint16(addr.Port),
	}
}

// String returns a human-readable representation.
func (n *Node) String() string {
	protocols := ""
	if n.HasV4() {
		protocols += "v4"
	}
	if n.HasV5() {
		if protocols != "" {
			protocols += "+"
		}
		protocols += "v5"
	}

	return fmt.Sprintf("Node{id=%x, addr=%s, protocols=%s}",
		n.id[:8], n.Addr().String(), protocols)
}

// Statistics Methods

// FirstSeen returns when we first discovered this node.
func (n *Node) FirstSeen() time.Time {
	return n.nodeStats.FirstSeen()
}

// SetFirstSeen sets the first seen timestamp.
func (n *Node) SetFirstSeen(t time.Time) {
	n.nodeStats.SetFirstSeen(t)
}

// LastSeen returns when we last saw a packet from this node.
func (n *Node) LastSeen() time.Time {
	return n.nodeStats.LastSeen()
}

// SetLastSeen updates the last seen timestamp.
func (n *Node) SetLastSeen(t time.Time) {
	n.nodeStats.SetLastSeen(t)
}

// UpdateLastSeen updates the last seen timestamp to now.
func (n *Node) UpdateLastSeen() {
	n.SetLastSeen(time.Now())
}

// LastPing returns when we last sent a PING to this node.
func (n *Node) LastPing() time.Time {
	return n.nodeStats.LastPing()
}

// SetLastPing updates the last ping time.
func (n *Node) SetLastPing(t time.Time) {
	n.nodeStats.SetLastPing(t)
}

// SuccessCount returns the number of successful communications.
func (n *Node) SuccessCount() int {
	return n.nodeStats.SuccessCount()
}

// SetSuccessCount sets the success count.
func (n *Node) SetSuccessCount(count int) {
	n.nodeStats.SetSuccessCount(count)
}

// IncrementSuccess increments the success counter and updates last seen.
func (n *Node) IncrementSuccess() {
	n.nodeStats.IncrementSuccessCount()
	n.nodeStats.SetLastSeen(time.Now())
}

// FailureCount returns the number of failed communications.
func (n *Node) FailureCount() int {
	return n.nodeStats.FailureCount()
}

// SetFailureCount sets the failure count.
func (n *Node) SetFailureCount(count int) {
	n.nodeStats.SetFailureCount(count)
}

// IncrementFailure increments the failure counter.
func (n *Node) IncrementFailure() {
	n.nodeStats.IncrementFailureCount()
}

// ResetFailureCount resets the failure count to 0 and increments the success count.
func (n *Node) ResetFailureCount() {
	n.nodeStats.ResetFailureCount()
	n.nodeStats.SetLastSeen(time.Now())
}

// IncrementFailureCount increments the failure counter.
// Alias for IncrementFailure for consistency with other packages.
func (n *Node) IncrementFailureCount() {
	n.IncrementFailure()
}

// AvgRTT returns the average round-trip time.
func (n *Node) AvgRTT() time.Duration {
	return n.nodeStats.AvgRTT()
}

// UpdateRTT updates the average RTT with exponential moving average.
func (n *Node) UpdateRTT(rtt time.Duration) {
	n.nodeStats.UpdateRTT(rtt)
}

// GetStats returns a snapshot of node statistics.
func (n *Node) GetStats() NodeStats {
	snapshot := n.nodeStats.GetSnapshot()
	return NodeStats{
		FirstSeen:    snapshot.FirstSeen,
		LastSeen:     snapshot.LastSeen,
		SuccessCount: snapshot.SuccessCount,
		FailureCount: snapshot.FailureCount,
		AvgRTT:       snapshot.AvgRTT,
	}
}

// setupSharedStatsCallback sets up the callback on SharedStats to notify when stats change.
// This is called internally when SharedStats are created or assigned.
func (n *Node) setupSharedStatsCallback() {
	if n.nodeStats == nil {
		return
	}

	// Set callback on SharedStats to mark dirty and trigger DB notification
	// The SharedStats passes dirty flags indicating what changed
	n.nodeStats.SetCallback(func(statsDirtyFlags stats.DirtyFlags) {
		// Map SharedStats dirty flags to Node dirty flags
		var nodeDirtyFlags DirtyFlags
		if statsDirtyFlags&stats.DirtyLastSeen != 0 {
			nodeDirtyFlags |= DirtyLastSeen
		}
		if statsDirtyFlags&stats.DirtyStats != 0 {
			nodeDirtyFlags |= DirtyStats
		}

		// Mark dirty and trigger DB write
		n.MarkDirty(nodeDirtyFlags)
		n.nodedb.QueueUpdate(n)
	})
}

// NodeStats contains statistics about a node.
type NodeStats struct {
	FirstSeen    time.Time
	LastSeen     time.Time
	SuccessCount int
	FailureCount int
	AvgRTT       time.Duration
}

// Record returns the node's ENR record.
func (n *Node) Record() *enr.Record {
	return n.enr
}

// PeerID returns the libp2p peer ID for this node.
// Delegates to the v5 node if available, otherwise builds it from the public key.
func (n *Node) PeerID() string {
	if n.v5Node != nil {
		return n.v5Node.PeerID()
	}
	// Fallback: build peer ID from public key
	if n.pubKey != nil {
		return discv5node.BuildPeerID(n.pubKey)
	}
	return ""
}

// UpdateENR updates the node's ENR record if the new one has a higher sequence number.
// Returns true if the record was updated.
func (n *Node) UpdateENR(newRecord *enr.Record) bool {
	if newRecord == nil {
		return false
	}

	// Update our ENR
	if newRecord.Seq() > n.enr.Seq() {
		n.enr = newRecord

		// Update v5 node if available
		if n.v5Node != nil {
			n.v5Node.UpdateENR(newRecord)
		}

		return true
	}

	return false
}

// NeedsPing checks if the node needs a liveness check.
func (n *Node) NeedsPing(pingInterval time.Duration) bool {
	return n.nodeStats.NeedsPing(pingInterval)
}

// IsAlive checks if the node is considered alive.
// A node is alive if it has been seen recently and has acceptable failure rate.
func (n *Node) IsAlive(maxAge time.Duration, maxFailures int) bool {
	return n.nodeStats.IsAlive(maxAge, maxFailures)
}

// CalculateScore computes a quality score for the node.
// Delegates to the v5 node if available.
func (n *Node) CalculateScore(forkInfo *ForkScoringInfo) float64 {
	if n.v5Node != nil {
		// Cast forkInfo to the v5 node's ForkScoringInfo type
		if forkInfo != nil {
			// Convert table.ForkScoringInfo to discv5/node.ForkScoringInfo
			v5ForkInfo := &discv5node.ForkScoringInfo{
				CurrentForkDigest:  forkInfo.CurrentForkDigest,
				PreviousForkDigest: forkInfo.PreviousForkDigest,
				GenesisForkDigest:  forkInfo.GenesisForkDigest,
				GracePeriodEnd:     forkInfo.GracePeriodEnd,
			}
			return n.v5Node.CalculateScore(v5ForkInfo)
		}
		// If forkInfo is nil or wrong type, call with nil
		return n.v5Node.CalculateScore(nil)
	}
	// Basic fallback score based on success rate
	successCount := n.SuccessCount()
	failureCount := n.FailureCount()
	totalAttempts := successCount + failureCount
	if totalAttempts > 0 {
		return float64(successCount) / float64(totalAttempts)
	}
	return 0.5
}

// MarkDirty marks specific fields as dirty (needing database update).
func (n *Node) MarkDirty(flags DirtyFlags) {
	n.dirtyMu.Lock()
	n.dirtyFields |= flags
	n.dirtyMu.Unlock()
}

// GetDirtyFlags returns and clears the dirty flags atomically.
func (n *Node) GetDirtyFlags() DirtyFlags {
	n.dirtyMu.Lock()
	defer n.dirtyMu.Unlock()
	flags := n.dirtyFields
	return flags
}

// ClearDirtyFlags clears all dirty flags.
func (n *Node) ClearDirtyFlags() {
	n.dirtyMu.Lock()
	n.dirtyFields = 0
	n.dirtyMu.Unlock()
}

// LastActive returns the last active timestamp.
func (n *Node) LastActive() time.Time {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.lastActive
}

// SetLastActive sets the last active timestamp and marks it dirty.
func (n *Node) SetLastActive(t time.Time) {
	n.mu.Lock()
	n.lastActive = t
	n.mu.Unlock()
	n.MarkDirty(DirtyLastActive)
}

// NewV5NodeFromRecord creates a discv5 node from an ENR record.
// This is a helper for protocol support checks.
func NewV5NodeFromRecord(record *enr.Record) (*discv5node.Node, error) {
	return discv5node.New(record)
}

// NewV4NodeFromRecord creates a discv4 node from an ENR record and address.
// This is a helper for protocol support checks.
func NewV4NodeFromRecord(record *enr.Record, addr *net.UDPAddr) (*node.Node, error) {
	return node.FromENR(record, addr)
}
