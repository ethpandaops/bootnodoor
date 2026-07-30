// Package node provides core types for representing network nodes.
//
// A Node combines:
//   - Identity: ENR record with node metadata
//   - Network info: IP address, UDP/TCP ports
//   - Statistics: Last seen, failure counts, RTT
//
// Nodes are the fundamental unit in the discv5 peer discovery system.
package node

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/stats"
)

// ID represents a unique node identifier (32 bytes).
//
// The node ID is derived from the node's public key:
//
//	nodeID = keccak256(uncompressed_pubkey[1:])
//
// This ID is used in the Kademlia DHT for routing and distance calculations.
type ID [32]byte

// String returns the hex representation of the node ID.
func (id ID) String() string {
	return fmt.Sprintf("%x", id[:])
}

// Bytes returns the byte slice representation of the node ID.
func (id ID) Bytes() []byte {
	return id[:]
}

// PubkeyToID converts a public key to a node ID.
//
// Example:
//
//	privKey, _ := crypto.GenerateKey()
//	nodeID := PubkeyToID(&privKey.PublicKey)
func PubkeyToID(pub *ecdsa.PublicKey) ID {
	var id ID
	// Remove 0x04 prefix from uncompressed public key
	hash := crypto.Keccak256(crypto.FromECDSAPub(pub)[1:])
	copy(id[:], hash)
	return id
}

// Node represents a network node in the discv5 protocol.
//
// It combines the node's ENR record with additional runtime information
// like network statistics and last seen time.
type Node struct {
	// mu guards record, addr, tcpPort and the stats pointer: UpdateENR and
	// SetStats replace them while packet handling and scoring read them from
	// other goroutines. The pointed-to values need no guard - enr.Record has
	// its own lock and is never mutated after signing, addr is replaced whole,
	// and SharedStats synchronizes internally.
	mu sync.RWMutex

	// record is the ENR record containing node identity and metadata
	record *enr.Record

	// id is the cached node ID derived from the public key
	id ID

	// addr is the network address (IP + UDP port)
	addr *net.UDPAddr

	// tcpPort is the TCP port (if different from UDP)
	tcpPort uint16

	// stats points to shared statistics (may be owned by parent node)
	stats *stats.SharedStats
}

// New creates a new Node from an ENR record.
//
// The node ID and network address are extracted from the ENR.
// Returns an error if the ENR is missing required fields.
//
// Example:
//
//	privKey, _ := crypto.GenerateKey()
//	record, _ := enr.CreateSignedRecord(
//	    privKey,
//	    "ip", net.IPv4(192, 168, 1, 1),
//	    "udp", uint16(9000),
//	)
//	node, err := New(record)
func New(record *enr.Record) (*Node, error) {
	if record == nil {
		return nil, fmt.Errorf("node: nil ENR record")
	}

	// Extract public key and derive node ID
	pubKey := record.PublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("node: ENR missing public key")
	}
	id := PubkeyToID(pubKey)

	addr, err := udpEndpoint(record)
	if err != nil {
		return nil, err
	}

	// Extract optional TCP port
	tcpPort := record.TCP()

	// Create local stats (will be replaced by parent stats if needed)
	now := time.Now()
	nodeStats := stats.NewSharedStats(now)

	return &Node{
		record:  record,
		id:      id,
		addr:    addr,
		tcpPort: tcpPort,
		stats:   nodeStats,
	}, nil
}

// udpEndpoint extracts the discovery endpoint from a record, keeping the port
// paired with its address family: ip goes with udp, ip6 with udp6 (falling
// back to udp, which dual-stack records share across both families).
func udpEndpoint(record *enr.Record) (*net.UDPAddr, error) {
	ip := record.IP()
	port := record.UDP()
	if ip == nil {
		ip = record.IP6()
		if p := record.UDP6(); p != 0 {
			port = p
		}
	}
	if ip == nil {
		return nil, fmt.Errorf("node: ENR missing IP address")
	}
	if port == 0 {
		return nil, fmt.Errorf("node: ENR missing UDP port")
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

// ID returns the node's unique identifier.
func (n *Node) ID() ID {
	return n.id
}

// Record returns the node's ENR record.
func (n *Node) Record() *enr.Record {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.record
}

// Addr returns the node's UDP address.
func (n *Node) Addr() *net.UDPAddr {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.addr
}

// statsRef returns the current shared stats pointer for use outside the lock.
func (n *Node) statsRef() *stats.SharedStats {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.stats
}

// SetStats replaces the node's stats with a shared stats pointer.
// This allows the node to update stats owned by a parent node.
func (n *Node) SetStats(sharedStats *stats.SharedStats) {
	if sharedStats != nil {
		n.mu.Lock()
		n.stats = sharedStats
		n.mu.Unlock()
	}
}

// IP returns the node's IP address.
func (n *Node) IP() net.IP {
	return n.Addr().IP
}

// UDPPort returns the node's UDP port.
func (n *Node) UDPPort() uint16 {
	return uint16(n.Addr().Port)
}

// TCPPort returns the node's TCP port (0 if not set).
func (n *Node) TCPPort() uint16 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.tcpPort
}

// PublicKey returns the node's public key.
func (n *Node) PublicKey() *ecdsa.PublicKey {
	return n.Record().PublicKey()
}

// PeerID returns the libp2p peer ID for this node.
//
// The peer ID is constructed from the secp256k1 public key using the libp2p format:
//   - Compressed secp256k1 public key (33 bytes)
//   - Wrapped in libp2p PublicKey protobuf message:
//   - Field 1 (Type): 0x08 0x02 (secp256k1 = 2)
//   - Field 2 (Data): 0x12 0x21 [33 bytes of compressed key]
//   - Wrapped in IDENTITY multihash (code 0x00)
//   - Base58 encoded
//
// Example output: "16Uiu2HAkyttpvpDTRdEnUqSPvbDpRgbSgrmeqTqi4R7EWECG5jso"
func (n *Node) PeerID() string {
	pubKey := n.PublicKey()
	if pubKey == nil {
		return ""
	}

	return BuildPeerID(pubKey)
}

// Digest returns the node's fork digest.
func (n *Node) Digest() [4]byte {
	eth2Data, ok := n.Record().Eth2()
	if !ok {
		return [4]byte{}
	}
	return eth2Data.ForkDigest
}

// SetLastSeen updates the last seen time.
func (n *Node) SetLastSeen(t time.Time) {
	n.statsRef().SetLastSeen(t)
}

// SetLastPing updates the last ping time.
func (n *Node) SetLastPing(t time.Time) {
	n.statsRef().SetLastPing(t)
}

// SetFailureCount sets the failure count.
func (n *Node) SetFailureCount(count int) {
	n.statsRef().SetFailureCount(count)
}

// SetSuccessCount sets the success count.
func (n *Node) SetSuccessCount(count int) {
	n.statsRef().SetSuccessCount(count)
}

// IncrementFailureCount increases the failure count by 1.
func (n *Node) IncrementFailureCount() {
	n.statsRef().IncrementFailureCount()
}

// ResetFailureCount resets the failure count to 0 and increments success count.
func (n *Node) ResetFailureCount() {
	n.statsRef().ResetFailureCount()
}

// UpdateRTT updates the average RTT using exponential moving average.
func (n *Node) UpdateRTT(rtt time.Duration) {
	n.statsRef().UpdateRTT(rtt)
}

// UpdateENR updates the node's ENR record if the new one has a higher sequence number.
//
// Returns true if the record was updated, false if the current record is newer.
func (n *Node) UpdateENR(newRecord *enr.Record) bool {
	if newRecord == nil {
		return false
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Only update if new record has higher sequence number
	if newRecord.Seq() > n.record.Seq() {
		n.record = newRecord

		// Update network address if changed
		if addr, err := udpEndpoint(newRecord); err == nil {
			n.addr = addr
		}

		n.tcpPort = newRecord.TCP()
		return true
	}

	return false
}

// String returns a human-readable representation of the node.
//
// Format: Node[id=abc123..., addr=192.168.1.1:9000, seen=1m ago]
func (n *Node) String() string {
	lastSeen := n.statsRef().LastSeen()

	var seenStr string
	if lastSeen.IsZero() {
		seenStr = "never"
	} else {
		seenStr = fmt.Sprintf("%v ago", time.Since(lastSeen).Round(time.Second))
	}

	return fmt.Sprintf("Node[id=%s, addr=%s, seen=%s]",
		n.id.String()[:8]+"...", // First 8 chars of ID
		n.Addr().String(),
		seenStr,
	)
}

// Stats returns a snapshot of the node's statistics.
type Stats struct {
	FirstSeen    time.Time
	LastSeen     time.Time
	LastPing     time.Time
	FailureCount int
	SuccessCount int
	AvgRTT       time.Duration
	ENRSeq       uint64
}

// GetStats returns the current statistics for the node.
func (n *Node) GetStats() Stats {
	snapshot := n.statsRef().GetSnapshot()
	return Stats{
		FirstSeen:    snapshot.FirstSeen,
		LastSeen:     snapshot.LastSeen,
		LastPing:     snapshot.LastPing,
		FailureCount: snapshot.FailureCount,
		SuccessCount: snapshot.SuccessCount,
		AvgRTT:       snapshot.AvgRTT,
		ENRSeq:       n.Record().Seq(),
	}
}

// ForkScoringInfo contains fork digest information for node scoring.
type ForkScoringInfo struct {
	// CurrentForkDigest is the current expected fork digest
	CurrentForkDigest [4]byte

	// PreviousForkDigest is the previous fork digest (current - 1)
	PreviousForkDigest [4]byte

	// GenesisForkDigest is the genesis fork digest
	GenesisForkDigest [4]byte

	// GracePeriodEnd is when the grace period for the previous fork ends
	// If zero, there is no grace period active
	GracePeriodEnd time.Time
}

// CalculateScore computes a quality score including fork digest compatibility.
//
// The score considers:
//   - RTT (lower is better): 30% weight
//   - Success rate: 25% weight
//   - Uptime (time since first seen): 15% weight
//   - Recency (time since last seen): 10% weight
//   - Fork digest compatibility: 20% weight
//
// Fork digest scoring:
//   - Current fork digest: 1.0 multiplier
//   - Previous fork (in grace period): 0.8 multiplier
//   - Genesis fork (syncing clients): 0.5 multiplier
//   - Previous fork (expired grace): 0.2 multiplier (outdated clients)
//   - Unknown/no fork data: 0.3 multiplier
//
// Returns a score between 0.0 (worst) and 1.0 (best).
func (n *Node) CalculateScore(forkInfo *ForkScoringInfo) float64 {
	snapshot := n.statsRef().GetSnapshot()
	now := time.Now()

	// RTT score (30% weight, adjusted from 40%)
	// Assume 0ms = 1.0, 500ms = 0.0
	rttScore := 0.0
	if snapshot.AvgRTT > 0 {
		rttMs := float64(snapshot.AvgRTT.Milliseconds())
		rttScore = 1.0 - (rttMs / 500.0)
		if rttScore < 0 {
			rttScore = 0
		}
	}

	// Success rate score (25% weight, adjusted from 30%)
	successRate := 0.0
	totalAttempts := snapshot.SuccessCount + snapshot.FailureCount
	if totalAttempts > 0 {
		successRate = float64(snapshot.SuccessCount) / float64(totalAttempts)
	}

	// Uptime score (15% weight, adjusted from 20%)
	// Nodes seen longer get higher scores (up to 24 hours)
	uptimeScore := 0.0
	if !snapshot.FirstSeen.IsZero() {
		uptimeHours := now.Sub(snapshot.FirstSeen).Hours()
		uptimeScore = uptimeHours / 24.0
		if uptimeScore > 1.0 {
			uptimeScore = 1.0
		}
	}

	// Recency score (10% weight)
	// Recently seen nodes get higher scores
	recencyScore := 0.0
	if !snapshot.LastSeen.IsZero() {
		hoursSinceLastSeen := now.Sub(snapshot.LastSeen).Hours()
		recencyScore = 1.0 - (hoursSinceLastSeen / 24.0)
		if recencyScore < 0 {
			recencyScore = 0
		}
	}

	// Fork digest score (20% weight)
	forkScore := 1.0 // Default to 1.0 if no fork info provided
	if forkInfo != nil {
		nodeDigest := n.Digest()

		// Check if node has fork data
		if nodeDigest == [4]byte{} {
			// No fork data - heavily penalize
			forkScore = 0.3
		} else if nodeDigest == forkInfo.CurrentForkDigest {
			// Current fork digest - perfect score
			forkScore = 1.0
		} else if nodeDigest == forkInfo.PreviousForkDigest && !forkInfo.GracePeriodEnd.IsZero() {
			// Previous fork digest - check grace period
			if now.Before(forkInfo.GracePeriodEnd) {
				// Within grace period
				forkScore = 0.8
			} else {
				// Grace period expired - outdated client
				forkScore = 0.2
			}
		} else if nodeDigest == forkInfo.GenesisForkDigest {
			// Genesis fork digest - syncing client
			forkScore = 0.5
		} else {
			// Unknown or very old fork digest
			forkScore = 0.2
		}
	}

	// Weighted total
	// When fork info is provided: RTT(30%) + Success(25%) + Uptime(15%) + Recency(10%) + Fork(20%)
	// When fork info is nil: Fork multiplier is 1.0, so effectively the old weights
	score := (rttScore * 0.3) + (successRate * 0.25) + (uptimeScore * 0.15) + (recencyScore * 0.1) + (forkScore * 0.2)
	return score
}
