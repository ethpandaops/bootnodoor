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
	dirtyGen    uint64
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

// ENR returns the node's ENR record. Alias for Record.
func (n *Node) ENR() *enr.Record {
	return n.Record()
}

// Addr returns the node's UDP address.
func (n *Node) Addr() *net.UDPAddr {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.addr
}

// V4 returns the discv4 node if available.
func (n *Node) V4() *node.Node {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.v4Node
}

// V5 returns the discv5 node if available.
func (n *Node) V5() *discv5node.Node {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.v5Node
}

// HasV4 returns true if this node supports discv4.
func (n *Node) HasV4() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.v4Node != nil
}

// HasV5 returns true if this node supports discv5.
func (n *Node) HasV5() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.v5Node != nil
}

// SetV4 sets the discv4 node and its verified endpoint.
func (n *Node) SetV4(v4 *node.Node) {
	dirty := DirtyProtocol
	n.mu.Lock()
	n.v4Node = v4
	if v4 != nil {
		addr := v4.Addr()
		if addr != nil && (n.addr == nil || !n.addr.IP.Equal(addr.IP) || n.addr.Port != addr.Port || n.addr.Zone != addr.Zone) {
			n.addr = addr
			dirty |= DirtyENR
		}
	}
	n.mu.Unlock()

	if v4 != nil && n.nodeStats != nil {
		// Ensure callback is set up (in case stats were created elsewhere)
		n.setupSharedStatsCallback()
		// Pass shared stats to v4 node so it updates them
		v4.SetStats(n.nodeStats)
	}
	n.MarkDirty(dirty)
}

// AdoptProtocolsFrom fills protocol slots this node has empty from a wrapper for
// the same peer, advances the record if the other's is newer, and reports each.
//
// It fills only: which endpoint a protocol should use is the discovery layer's
// call, not the table's. discv4 moves an address solely on a matched PONG
// (promoteAddr), and discv5 moves its own when its record advances. A table that
// also ranked pointers would be arbitrating endpoints on weaker evidence.
// The wrapper's own addr follows the same rules: it moves with an advancing
// record only while no discv4-verified endpoint exists to protect.
func (n *Node) AdoptProtocolsFrom(other *Node) (adopted, advanced bool) {
	// Self-merge is a no-op, not a re-install: a caller re-admitting a table entry
	// would otherwise snapshot its own pointer, race a concurrent clear, and
	// resurrect a protocol the node no longer supports.
	if other == nil || other == n {
		return false, false
	}

	otherRecord := other.Record()
	if otherRecord == nil {
		return false, false
	}
	otherV4, otherV5 := other.V4(), other.V5()
	carrierSeq := otherRecord.Seq()

	n.mu.Lock()
	if n.enr != nil && carrierSeq < n.recordSeqLocked() {
		n.mu.Unlock()
		return false, false
	}

	// Snapshot before adoption: a v4 pointer adopted in this same call carries
	// the other wrapper's endpoint, not one this node verified, so it must not
	// block the addr refresh below.
	hadV4 := n.v4Node != nil

	if otherV4 != nil && n.v4Node == nil {
		n.v4Node = otherV4
		adopted = true
	}
	if otherV5 != nil && n.v5Node == nil {
		n.v5Node = otherV5
		adopted = true
	}

	if n.enr == nil || carrierSeq > n.recordSeqLocked() {
		n.enr = otherRecord
		if !hadV4 {
			if ep := otherRecord.UDPEndpoint(); ep != nil {
				n.addr = ep
			}
		}
		advanced = true
	}

	stats := n.nodeStats
	current := n.enr
	v4, v5 := n.v4Node, n.v5Node
	n.mu.Unlock()

	if adopted && stats != nil {
		n.setupSharedStatsCallback()
		if otherV4 != nil && v4 != nil {
			v4.SetStats(stats)
		}
		if otherV5 != nil && v5 != nil {
			v5.SetStats(stats)
		}
	}
	// Bring the v5 pointer up to the record the wrapper now holds, whether that is
	// because the record advanced or because an older pointer just filled an empty
	// slot. UpdateENR ignores anything not newer, and this stays outside n.mu so
	// the two mutexes never nest.
	if (adopted || advanced) && v5 != nil {
		v5.UpdateENR(current)
	}

	if adopted {
		n.MarkDirty(DirtyProtocol)
	}
	if advanced {
		n.MarkDirty(DirtyENR)
	}
	return adopted, advanced
}

// ApplyProbeResult installs or clears both protocol pointers from a completed
// probe, and reports whether anything changed.
//
// Gated on the record still being the one the probe measured: a result that
// arrived after the peer published a new record describes endpoints it may have
// left, so it must neither install nor clear. Both protocols are decided under one
// lock hold so they see the same record.
func (n *Node) ApplyProbeResult(probedSeq uint64, v4 *node.Node, v4OK bool, v5 *discv5node.Node, v5OK bool) bool {
	n.mu.Lock()
	if n.enr == nil || n.recordSeqLocked() != probedSeq {
		n.mu.Unlock()
		return false
	}

	changed := false
	switch {
	case v4OK && v4 != nil && n.v4Node == nil:
		n.v4Node = v4
		changed = true
	case !v4OK && n.v4Node != nil:
		n.v4Node = nil
		changed = true
	}

	switch {
	case v5OK && v5 != nil && n.v5Node == nil:
		n.v5Node = v5
		changed = true
	case !v5OK && n.v5Node != nil:
		n.v5Node = nil
		changed = true
	}

	stats := n.nodeStats
	installedV4, installedV5 := n.v4Node, n.v5Node
	n.mu.Unlock()

	if !changed {
		return false
	}

	if stats != nil {
		n.setupSharedStatsCallback()
		if installedV4 != nil {
			installedV4.SetStats(stats)
		}
		if installedV5 != nil {
			installedV5.SetStats(stats)
		}
	}
	n.MarkDirty(DirtyProtocol)
	return true
}

// SetV5AtSeq installs a discv5 node only while the record it was probed from is
// still current, so a result that arrived after the peer moved is discarded
// rather than pinning traffic to the old endpoint.
func (n *Node) SetV5AtSeq(v5 *discv5node.Node, seq uint64) bool {
	if v5 == nil {
		return false
	}
	v5Seq := v5RecordSeq(v5)

	n.mu.Lock()
	if n.enr == nil || n.enr.Seq() != seq || v5Seq != seq {
		n.mu.Unlock()
		return false
	}
	n.v5Node = v5
	stats := n.nodeStats
	n.mu.Unlock()

	if stats != nil {
		n.setupSharedStatsCallback()
		v5.SetStats(stats)
	}
	n.MarkDirty(DirtyProtocol)
	return true
}

// SetV5 sets the discv5 node and marks protocol support dirty.
func (n *Node) SetV5(v5 *discv5node.Node) {
	n.mu.Lock()
	n.v5Node = v5
	n.mu.Unlock()

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
	n.mu.RLock()
	v4 := n.v4Node
	n.mu.RUnlock()

	if v4 != nil {
		return v4.Enode()
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

// MarkSeen records verified contact from the peer: it refreshes lastSeen and
// ends the failure streak. The clear is guarded so an already-clean node is
// not marked dirty for nothing.
func (n *Node) MarkSeen(t time.Time) {
	n.SetLastSeen(t)
	if n.FailureCount() > 0 {
		n.SetFailureCount(0)
	}
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
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.enr
}

// PeerID returns the libp2p peer ID for this node.
// Delegates to the v5 node if available, otherwise builds it from the public key.
func (n *Node) PeerID() string {
	n.mu.RLock()
	v5 := n.v5Node
	n.mu.RUnlock()

	if v5 != nil {
		return v5.PeerID()
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
	n.mu.Lock()
	if n.enr != nil && newRecord.Seq() <= n.recordSeqLocked() {
		n.mu.Unlock()
		return false
	}
	n.enr = newRecord
	// A newer signed record supersedes an endpoint learned from the old one —
	// but never a discv4-verified address, which moves only on a matched PONG
	// (SetV4). Without this, updateNodeENRTx persists the stale addr next to
	// the new record and buildNodeFromDB restores it after every restart.
	if n.v4Node == nil {
		if ep := newRecord.UDPEndpoint(); ep != nil {
			n.addr = ep
		}
	}
	v5 := n.v5Node
	n.mu.Unlock()

	// Update v5 node if available - outside the lock so n.mu never nests with
	// the v5 node's own mutex.
	if v5 != nil {
		v5.UpdateENR(newRecord)
	}

	n.MarkDirty(DirtyENR)
	return true
}

// IsAlive checks if the node is considered alive.
// A node is alive if it has been seen recently and has acceptable failure rate.
func (n *Node) IsAlive(maxAge time.Duration, maxFailures int) bool {
	return n.nodeStats.IsAlive(maxAge, maxFailures)
}

// CalculateScore computes a quality score for the node.
// Delegates to the v5 node if available.
func (n *Node) CalculateScore(forkInfo *ForkScoringInfo) float64 {
	n.mu.RLock()
	v5 := n.v5Node
	n.mu.RUnlock()

	if v5 != nil {
		// Cast forkInfo to the v5 node's ForkScoringInfo type
		if forkInfo != nil {
			// Convert table.ForkScoringInfo to discv5/node.ForkScoringInfo
			v5ForkInfo := &discv5node.ForkScoringInfo{
				CurrentForkDigest:  forkInfo.CurrentForkDigest,
				PreviousForkDigest: forkInfo.PreviousForkDigest,
				GenesisForkDigest:  forkInfo.GenesisForkDigest,
				GracePeriodEnd:     forkInfo.GracePeriodEnd,
			}
			return v5.CalculateScore(v5ForkInfo)
		}
		// If forkInfo is nil or wrong type, call with nil
		return v5.CalculateScore(nil)
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
	n.dirtyGen++
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

// DirtySnapshot returns the current flags and a generation that changes on every
// subsequent MarkDirty, so a writer can tell whether anything was marked while it
// was working.
func (n *Node) DirtySnapshot() (DirtyFlags, uint64) {
	n.dirtyMu.Lock()
	defer n.dirtyMu.Unlock()
	return n.dirtyFields, n.dirtyGen
}

// ClearDirtySnapshot clears the snapshotted flags and reports whether the node is
// still dirty. Clearing is skipped entirely when the generation moved: the same
// bit may have been re-marked for a newer value, which is indistinguishable from
// the one just written, so the field would otherwise be dropped unwritten.
func (n *Node) ClearDirtySnapshot(flags DirtyFlags, gen uint64) bool {
	n.dirtyMu.Lock()
	defer n.dirtyMu.Unlock()
	if n.dirtyGen != gen {
		return true
	}
	n.dirtyFields &^= flags
	return n.dirtyFields != 0
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

// recordSeq reads a record's sequence, treating a missing record as sequence 0.
func recordSeq(rec *enr.Record) uint64 {
	if rec == nil {
		return 0
	}
	return rec.Seq()
}

// v5RecordSeq reads the sequence of the record a discv5 pointer was built from.
func v5RecordSeq(v5 *discv5node.Node) uint64 {
	if v5 == nil {
		return 0
	}
	return recordSeq(v5.Record())
}

func (n *Node) recordSeqLocked() uint64 {
	return recordSeq(n.enr)
}
