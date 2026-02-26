// Package protocol implements the Discovery v4 wire protocol.
//
// The discv4 protocol uses UDP packets with the following structure:
//   - MAC (32 bytes): Keccak256 hash of signature + packet data
//   - Signature (65 bytes): ECDSA signature over packet hash
//   - Packet type (1 byte): Message type identifier
//   - RLP-encoded message data
//
// Total header size: 97 bytes (32 + 65)
package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"net"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethpandaops/bootnodoor/enr"
)

// Packet type constants
const (
	PingPacket = iota + 1 // zero is reserved
	PongPacket
	FindnodePacket
	NeighborsPacket
	ENRRequestPacket
	ENRResponsePacket
)

// MaxNeighbors is the maximum number of nodes in a Neighbors packet.
// This limit ensures packets fit within the 1280 byte MTU.
const MaxNeighbors = 12

// Packet is the interface for all discv4 messages.
type Packet interface {
	// Name returns the packet name for logging
	Name() string
	// Kind returns the packet type byte
	Kind() byte
}

// Ping represents a PING message.
//
// Ping is used for:
//  1. Liveness check
//  2. Endpoint verification (NAT detection)
//  3. Establishing bonds before FINDNODE
//  4. ENR sequence number exchange (EIP-868)
type Ping struct {
	// Version is the discovery protocol version (currently 4)
	Version uint

	// From is the sender's endpoint information
	From Endpoint

	// To is the recipient's endpoint (as known by sender)
	To Endpoint

	// Expiration is the UNIX timestamp when this packet expires
	Expiration uint64

	// ENRSeq is the sender's ENR sequence number (optional, EIP-868)
	ENRSeq uint64 `rlp:"optional"`

	// Rest allows forward compatibility with future fields
	Rest []rlp.RawValue `rlp:"tail"`
}

// Name returns the packet name.
func (p *Ping) Name() string { return "PING/v4" }

// Kind returns the packet type byte.
func (p *Ping) Kind() byte { return PingPacket }

// Pong represents a PONG message (reply to PING).
//
// Pong is used to:
//  1. Confirm liveness
//  2. Report the sender's external IP/port (for NAT traversal)
//  3. Establish a bond with the requester
//  4. Exchange ENR sequence numbers
type Pong struct {
	// To is the recipient's endpoint as seen by the sender
	// This allows the recipient to discover their external address
	To Endpoint

	// ReplyTok is the hash of the PING packet we're responding to
	// This allows the requester to match PONG to PING
	ReplyTok []byte

	// Expiration is the UNIX timestamp when this packet expires
	Expiration uint64

	// ENRSeq is the sender's ENR sequence number (optional, EIP-868)
	ENRSeq uint64 `rlp:"optional"`

	// Rest allows forward compatibility
	Rest []rlp.RawValue `rlp:"tail"`
}

// Name returns the packet name.
func (p *Pong) Name() string { return "PONG/v4" }

// Kind returns the packet type byte.
func (p *Pong) Kind() byte { return PongPacket }

// Findnode represents a FINDNODE request.
//
// Findnode queries for nodes close to a target in the Kademlia DHT.
// The sender must have an active bond (recent PING/PONG exchange)
// before the recipient will respond.
type Findnode struct {
	// Target is the public key we're searching for neighbors of
	// The response should contain nodes close to this target
	Target Pubkey

	// Expiration is the UNIX timestamp when this packet expires
	Expiration uint64

	// Rest allows forward compatibility
	Rest []rlp.RawValue `rlp:"tail"`
}

// Name returns the packet name.
func (f *Findnode) Name() string { return "FINDNODE/v4" }

// Kind returns the packet type byte.
func (f *Findnode) Kind() byte { return FindnodePacket }

// Neighbors represents a NEIGHBORS response (reply to FINDNODE).
//
// Neighbors contains up to 12 node records. If more nodes need to be
// sent, multiple Neighbors packets are used.
type Neighbors struct {
	// Nodes is the list of nodes close to the target
	Nodes []NodeRecord

	// Expiration is the UNIX timestamp when this packet expires
	Expiration uint64

	// Rest allows forward compatibility
	Rest []rlp.RawValue `rlp:"tail"`
}

// Name returns the packet name.
func (n *Neighbors) Name() string { return "NEIGHBORS/v4" }

// Kind returns the packet type byte.
func (n *Neighbors) Kind() byte { return NeighborsPacket }

// ENRRequest represents an ENRREQUEST message.
//
// ENRRequest queries for the node's current ENR record.
// This allows nodes to retrieve updated ENR information (added by EIP-868).
type ENRRequest struct {
	// Expiration is the UNIX timestamp when this packet expires
	Expiration uint64

	// Rest allows forward compatibility
	Rest []rlp.RawValue `rlp:"tail"`
}

// Name returns the packet name.
func (e *ENRRequest) Name() string { return "ENRREQUEST/v4" }

// Kind returns the packet type byte.
func (e *ENRRequest) Kind() byte { return ENRRequestPacket }

// ENRResponse represents an ENRRESPONSE message (reply to ENRREQUEST).
//
// ENRResponse contains the node's current ENR record.
type ENRResponse struct {
	// ReplyTok is the hash of the ENRREQUEST packet we're responding to
	ReplyTok []byte

	// Record is the sender's ENR record
	Record *enr.Record

	// Rest allows forward compatibility
	Rest []rlp.RawValue `rlp:"tail"`
}

// Name returns the packet name.
func (e *ENRResponse) Name() string { return "ENRRESPONSE/v4" }

// Kind returns the packet type byte.
func (e *ENRResponse) Kind() byte { return ENRResponsePacket }

// Supporting Types

// Pubkey represents an encoded 64-byte secp256k1 public key.
//
// This is the uncompressed public key format (X and Y coordinates,
// 32 bytes each) without the 0x04 prefix.
type Pubkey [64]byte

// ID returns the node ID (Keccak256 hash of the public key).
func (p Pubkey) ID() []byte {
	hash := crypto.Keccak256(p[:])
	return hash
}

// EncodePubkey encodes an ECDSA public key to the wire format.
func EncodePubkey(key *ecdsa.PublicKey) Pubkey {
	var p Pubkey
	math.ReadBits(key.X, p[:len(p)/2])
	math.ReadBits(key.Y, p[len(p)/2:])
	return p
}

// DecodePubkey decodes a wire-format public key to ECDSA format.
func DecodePubkey(curve elliptic.Curve, p Pubkey) (*ecdsa.PublicKey, error) {
	// Build uncompressed public key: 0x04 || X (32 bytes) || Y (32 bytes)
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	copy(uncompressed[1:33], p[:32])
	copy(uncompressed[33:65], p[32:])

	// Validate the point is on the secp256k1 curve by parsing it
	if _, err := secp256k1.ParsePubKey(uncompressed); err != nil {
		return nil, fmt.Errorf("invalid curve point: %w", err)
	}

	return crypto.UnmarshalPubkey(uncompressed)
}

// NodeRecord represents information about a node in the DHT.
//
// This is used in NEIGHBORS responses to communicate node information.
type NodeRecord struct {
	// IP is the node's IP address (4 bytes for IPv4, 16 for IPv6)
	IP net.IP

	// UDP is the UDP port for discovery
	UDP uint16

	// TCP is the TCP port for RLPx
	TCP uint16

	// ID is the node's public key
	ID Pubkey
}

// Endpoint represents a network endpoint.
//
// This is used in PING/PONG messages to communicate address information.
type Endpoint struct {
	// IP is the IP address (4 bytes for IPv4, 16 for IPv6)
	IP net.IP

	// UDP is the UDP port
	UDP uint16

	// TCP is the TCP port
	TCP uint16
}

// NewEndpoint creates an endpoint from a UDP address.
func NewEndpoint(addr *net.UDPAddr, tcpPort uint16) Endpoint {
	ip := addr.IP
	// Use IPv4 format for IPv4 addresses
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return Endpoint{
		IP:  ip,
		UDP: uint16(addr.Port),
		TCP: tcpPort,
	}
}

// UDPAddr converts the endpoint to a UDPAddr.
func (e Endpoint) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   e.IP,
		Port: int(e.UDP),
	}
}

// TCPAddr converts the endpoint to a TCPAddr.
func (e Endpoint) TCPAddr() *net.TCPAddr {
	return &net.TCPAddr{
		IP:   e.IP,
		Port: int(e.TCP),
	}
}

// Utility Functions

// Expired checks if a UNIX timestamp is in the past.
func Expired(ts uint64) bool {
	return time.Unix(int64(ts), 0).Before(time.Now())
}

// MakeExpiration creates an expiration timestamp for the given duration from now.
func MakeExpiration(d time.Duration) uint64 {
	return uint64(time.Now().Add(d).Unix())
}
