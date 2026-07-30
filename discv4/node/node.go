// Package node implements the Node representation for discv4.
//
// Unlike discv5 nodes which track sessions and ENR sequences, discv4 nodes
// track bond status and last seen timestamps for the bond mechanism.
package node

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/enode"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/stats"
)

// ID represents a node identifier (32-byte Keccak256 hash of public key).
type ID [32]byte

// Node represents a discv4 node with bond tracking.
//
// The bond mechanism in discv4 requires nodes to complete a PING/PONG exchange
// before they can send FINDNODE requests. This prevents amplification attacks.
type Node struct {
	// id is the node identifier (Keccak256 of public key)
	id ID

	// pubKey is the node's secp256k1 public key
	pubKey *ecdsa.PublicKey

	// mu guards addr, enr and the stats pointer: SetAddr/SetENR/SetStats
	// replace them from other goroutines while packet handling reads them.
	// The pointed-to values synchronize themselves or are replaced whole.
	mu sync.RWMutex

	// addr is the node's UDP address
	addr *net.UDPAddr

	// enr is the node's ENR record (optional, discv4 also supports enode://)
	enr *enr.Record

	// enode is the node's enode:// URL representation (for legacy nodes)
	enode *enode.Enode

	// Bond tracking
	bondMu             sync.RWMutex
	bondStatus         BondStatus
	lastPingSent       time.Time
	lastPingRecv       time.Time
	lastPongSent       time.Time
	lastPongRecv       time.Time
	bondExpiration     time.Time
	consecutiveTimeout uint32 // Bond-specific consecutive timeout counter

	// bondedIPs maps a proven remote IP to when its bond expires. Keyed per IP
	// because a bond proves reachability at one address only: addr is rewritten
	// from whatever source last sent us a packet, so serving requests on the
	// strength of a bond earned elsewhere lets a spoofed source reflect our
	// replies at a third party. Ports are excluded so a NAT remap does not
	// silently drop a peer mid-bond.
	bondedIPs map[string]time.Time

	// Statistics (shared with generic node wrapper)
	stats *stats.SharedStats

	// Packet counters (local, not part of shared stats)
	packetMu         sync.RWMutex
	totalPacketsRecv uint64
	totalPacketsSent uint64
}

// BondStatus represents the bonding state of a node.
type BondStatus int

const (
	// BondStatusUnknown means we have never interacted with this node
	BondStatusUnknown BondStatus = iota

	// BondStatusPingSent means we sent a PING and are waiting for PONG
	BondStatusPingSent

	// BondStatusBonded means we have completed a successful PING/PONG exchange
	BondStatusBonded

	// BondStatusExpired means the bond has expired (24 hours since last PONG)
	BondStatusExpired
)

// String returns the string representation of bond status.
func (s BondStatus) String() string {
	switch s {
	case BondStatusUnknown:
		return "unknown"
	case BondStatusPingSent:
		return "ping_sent"
	case BondStatusBonded:
		return "bonded"
	case BondStatusExpired:
		return "expired"
	default:
		return "invalid"
	}
}

// New creates a new discv4 node from a public key and UDP address.
func New(pubKey *ecdsa.PublicKey, addr *net.UDPAddr) *Node {
	id := PubkeyToID(pubKey)
	now := time.Now()
	return &Node{
		id:         id,
		pubKey:     pubKey,
		addr:       addr,
		bondStatus: BondStatusUnknown,
		stats:      stats.NewSharedStats(now),
	}
}

// FromENR creates a new node from an ENR record.
func FromENR(record *enr.Record, addr *net.UDPAddr) (*Node, error) {
	pubKey := record.PublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("enr: missing public key")
	}

	node := New(pubKey, addr)
	node.enr = record
	return node, nil
}

// FromEnode creates a new node from an enode:// URL.
func FromEnode(en *enode.Enode) (*Node, error) {
	if en.PublicKey == nil {
		return nil, fmt.Errorf("enode: missing public key")
	}

	addr := en.UDPAddr()
	if addr == nil {
		return nil, fmt.Errorf("enode: missing UDP address")
	}

	node := New(en.PublicKey, addr)
	node.enode = en
	return node, nil
}

// ParseEnode creates a node from an enode:// URL string.
func ParseEnode(rawurl string) (*Node, error) {
	en, err := enode.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	return FromEnode(en)
}

// ID returns the node identifier.
func (n *Node) ID() ID {
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

// Addr returns the node's UDP address.
func (n *Node) Addr() *net.UDPAddr {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.addr
}

// SetAddr updates the node's address.
//
// This is used when we receive packets from a different address than expected.
func (n *Node) SetAddr(addr *net.UDPAddr) {
	n.mu.Lock()
	n.addr = addr
	n.mu.Unlock()
}

// ENR returns the node's ENR record, if available.
func (n *Node) ENR() *enr.Record {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.enr
}

// SetENR updates the node's ENR record.
func (n *Node) SetENR(record *enr.Record) {
	n.mu.Lock()
	n.enr = record
	n.mu.Unlock()
}

// UpdateENR installs the record only if it is newer than the current one, so
// a replayed response cannot roll the node back to an older record.
func (n *Node) UpdateENR(record *enr.Record) bool {
	if record == nil {
		return false
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.enr != nil && record.Seq() <= n.enr.Seq() {
		return false
	}
	n.enr = record

	return true
}

// statsRef returns the current shared stats pointer for use outside the lock.
func (n *Node) statsRef() *stats.SharedStats {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.stats
}

// Enode returns the node's enode:// representation.
func (n *Node) Enode() *enode.Enode {
	if n.enode != nil {
		return n.enode
	}

	addr := n.Addr()

	// Build enode from node info
	return &enode.Enode{
		PublicKey: n.pubKey,
		IP:        addr.IP,
		UDP:       uint16(addr.Port),
		TCP:       uint16(addr.Port), // Assume same port for TCP
	}
}

// String returns a human-readable representation of the node.
func (n *Node) String() string {
	n.bondMu.RLock()
	bondStatus := n.bondStatus
	n.bondMu.RUnlock()

	return fmt.Sprintf("Node{id=%x, addr=%s, bond=%s}",
		n.id[:8], n.Addr().String(), bondStatus)
}

// Bond Status Methods

// BondStatus returns the current bond status.
func (n *Node) BondStatus() BondStatus {
	n.bondMu.RLock()
	defer n.bondMu.RUnlock()
	return n.bondStatus
}

// IsBonded returns true if the node has a valid bond.
func (n *Node) IsBonded() bool {
	n.bondMu.RLock()
	defer n.bondMu.RUnlock()

	if n.bondStatus != BondStatusBonded {
		return false
	}

	// Check if bond has expired
	if time.Now().After(n.bondExpiration) {
		return false
	}

	return true
}

// IsBondedFrom reports whether this node proved reachability at addr's IP and
// that proof is still valid. Inbound request handlers must use this rather than
// IsBonded, so a bond earned at one address cannot serve replies to another.
func (n *Node) IsBondedFrom(addr *net.UDPAddr) bool {
	if addr == nil || addr.IP == nil {
		return false
	}

	n.bondMu.RLock()
	defer n.bondMu.RUnlock()

	expiry, ok := n.bondedIPs[addr.IP.String()]
	return ok && time.Now().Before(expiry)
}

// MarkPingSent records that we sent a PING to this node.
func (n *Node) MarkPingSent() {
	now := time.Now()

	n.bondMu.Lock()
	n.lastPingSent = now
	if n.bondStatus == BondStatusUnknown {
		n.bondStatus = BondStatusPingSent
	}
	n.bondMu.Unlock()

	n.statsRef().SetLastPing(now)
}

// MarkPingReceived records that we received a PING from this node.
func (n *Node) MarkPingReceived() {
	now := time.Now()

	n.bondMu.Lock()
	n.lastPingRecv = now
	n.bondMu.Unlock()

	n.UpdateLastSeen()
}

// MarkPongSent records that we sent a PONG to this node.
func (n *Node) MarkPongSent() {
	n.bondMu.Lock()
	defer n.bondMu.Unlock()

	n.lastPongSent = time.Now()
}

// MarkPongReceived records that we received a PONG from this node.
//
// This establishes or renews the bond. provenAddr is the address the answered
// PING was sent to, not the PONG's source: the source is attacker-chosen on a
// spoofed packet, so binding the bond to it would prove nothing. Pass nil only
// where no endpoint was proven.
func (n *Node) MarkPongReceived(bondDuration time.Duration, provenAddr *net.UDPAddr) {
	now := time.Now()

	n.bondMu.Lock()
	n.lastPongRecv = now
	n.bondStatus = BondStatusBonded
	n.bondExpiration = now.Add(bondDuration)
	n.consecutiveTimeout = 0
	if provenAddr != nil && provenAddr.IP != nil {
		if n.bondedIPs == nil {
			n.bondedIPs = make(map[string]time.Time)
		}
		for ip, expiry := range n.bondedIPs {
			if now.After(expiry) {
				delete(n.bondedIPs, ip)
			}
		}
		n.bondedIPs[provenAddr.IP.String()] = now.Add(bondDuration)
	}
	n.bondMu.Unlock()

	n.statsRef().ResetFailureCount()
	n.UpdateLastSeen()
}

// MarkTimeout records a timeout (failed to receive expected response).
func (n *Node) MarkTimeout() {
	n.bondMu.Lock()
	n.consecutiveTimeout++
	n.bondMu.Unlock()

	n.statsRef().IncrementFailureCount()
}

// LastPingSent returns when we last sent a PING.
func (n *Node) LastPingSent() time.Time {
	n.bondMu.RLock()
	defer n.bondMu.RUnlock()
	return n.lastPingSent
}

// LastPongReceived returns when we last received a PONG.
func (n *Node) LastPongReceived() time.Time {
	n.bondMu.RLock()
	defer n.bondMu.RUnlock()
	return n.lastPongRecv
}

// BondExpiration returns when the current bond expires.
func (n *Node) BondExpiration() time.Time {
	n.bondMu.RLock()
	defer n.bondMu.RUnlock()
	return n.bondExpiration
}

// Statistics Methods

// UpdateLastSeen updates the last seen timestamp.
func (n *Node) UpdateLastSeen() {
	n.statsRef().SetLastSeen(time.Now())
}

// LastSeen returns when we last saw a packet from this node.
func (n *Node) LastSeen() time.Time {
	return n.statsRef().LastSeen()
}

// FailedPings returns the number of failed ping attempts.
func (n *Node) FailedPings() uint32 {
	return uint32(n.statsRef().FailureCount())
}

// IncrementPacketsReceived increments the received packet counter.
func (n *Node) IncrementPacketsReceived() {
	n.packetMu.Lock()
	defer n.packetMu.Unlock()
	n.totalPacketsRecv++
}

// IncrementPacketsSent increments the sent packet counter.
func (n *Node) IncrementPacketsSent() {
	n.packetMu.Lock()
	defer n.packetMu.Unlock()
	n.totalPacketsSent++
}

// TotalPacketsReceived returns the total packets received from this node.
func (n *Node) TotalPacketsReceived() uint64 {
	n.packetMu.RLock()
	defer n.packetMu.RUnlock()
	return n.totalPacketsRecv
}

// TotalPacketsSent returns the total packets sent to this node.
func (n *Node) TotalPacketsSent() uint64 {
	n.packetMu.RLock()
	defer n.packetMu.RUnlock()
	return n.totalPacketsSent
}

// ConsecutiveTimeouts returns the number of consecutive timeouts.
func (n *Node) ConsecutiveTimeouts() uint32 {
	n.bondMu.RLock()
	defer n.bondMu.RUnlock()
	return n.consecutiveTimeout
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

// Utility Functions

// PubkeyToID converts a public key to a node ID.
//
// The node ID is the Keccak256 hash of the uncompressed public key
// (without the 0x04 prefix).
func PubkeyToID(pubKey *ecdsa.PublicKey) ID {
	pubBytes := crypto.FromECDSAPub(pubKey)[1:] // Remove 0x04 prefix
	hash := crypto.Keccak256Hash(pubBytes)
	var id ID
	copy(id[:], hash[:])
	return id
}

// Distance calculates the XOR distance between two node IDs.
//
// This is used for Kademlia-style routing (if needed by higher layers).
func Distance(a, b ID) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// DistanceCmp compares the distance from target to a vs b.
//
// Returns:
//   - negative if distance(target, a) < distance(target, b)
//   - zero if distance(target, a) == distance(target, b)
//   - positive if distance(target, a) > distance(target, b)
func DistanceCmp(target, a, b ID) int {
	for i := 0; i < len(target); i++ {
		da := target[i] ^ a[i]
		db := target[i] ^ b[i]
		if da < db {
			return -1
		} else if da > db {
			return 1
		}
	}
	return 0
}
