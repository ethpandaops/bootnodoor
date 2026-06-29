// Package enr implements Ethereum Node Records (ENR) as defined in EIP-778.
//
// An ENR is a signed, versioned data structure containing information about
// a node's network addresses and capabilities. Each record contains:
//   - A sequence number (incremented on updates)
//   - An identity scheme and signature
//   - Arbitrary key-value pairs for node metadata
//
// ENRs are limited to 300 bytes and are encoded using RLP (Recursive Length Prefix).
package enr

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// MaxRecordSize is the maximum allowed size of an ENR in bytes.
	// This limit ensures records can fit in UDP packets.
	MaxRecordSize = 300
)

var (
	// ErrRecordTooLarge is returned when an ENR exceeds MaxRecordSize.
	ErrRecordTooLarge = errors.New("enr: record size exceeds 300 bytes")

	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("enr: invalid signature")

	// ErrNoKey is returned when a requested key is not present in the record.
	ErrNoKey = errors.New("enr: key not found")

	// ErrInvalidRecord is returned when a record has invalid structure.
	ErrInvalidRecord = errors.New("enr: invalid record structure")
)

// Record represents an Ethereum Node Record (ENR) as defined in EIP-778.
//
// A record consists of:
//   - Signature: Cryptographic signature over the record content
//   - Seq: Sequence number, incremented on each update
//   - Pairs: Key-value pairs containing node metadata
//
// The record is immutable once created. To update a record, create a new
// one with an incremented sequence number.
type Record struct {
	// signature is the cryptographic signature over the record content
	signature []byte

	// seq is the sequence number, incremented on updates
	seq uint64

	// pairs contains the key-value pairs in the record
	pairs map[string]interface{}

	// raw is the RLP-encoded form of the record
	raw []byte

	// mu protects concurrent access to the record
	mu sync.RWMutex
}

// New creates a new empty ENR record.
//
// The record will have a sequence number of 0 and no entries.
// Use Load or Decode to create a record from existing data.
func New() *Record {
	return &Record{
		seq:   0,
		pairs: make(map[string]interface{}),
	}
}

// Seq returns the sequence number of the record.
//
// The sequence number is incremented each time the record is updated.
// It allows peers to determine which version of a record is newer.
func (r *Record) Seq() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.seq
}

// SetSeq sets the sequence number of the record.
//
// This should be called when creating an updated version of a record.
// The new sequence number must be greater than the current one.
func (r *Record) SetSeq(seq uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq = seq
	r.raw = nil // Invalidate cached encoding
}

// Clone creates a deep copy of the record by marshaling and unmarshaling.
//
// This is useful when you need to modify a record without affecting the original.
// The cloned record will have the same sequence number and all fields.
//
// Example:
//
//	clone := record.Clone()
//	clone.SetSeq(record.Seq() + 1)
//	clone.Set("ip", newIP)
func (r *Record) Clone() (*Record, error) {
	// Encode the current record to RLP bytes
	data, err := r.EncodeRLP()
	if err != nil {
		return nil, fmt.Errorf("failed to encode record for cloning: %w", err)
	}

	// Create a new record and decode the bytes into it
	clone := New()
	if err := clone.DecodeRLPBytes(data); err != nil {
		return nil, fmt.Errorf("failed to decode record for cloning: %w", err)
	}

	return clone, nil
}

// Set stores a key-value pair in the record.
//
// The key must be a string and the value must be RLP-encodable.
// Common keys include:
//   - "id": Identity scheme (e.g., "v4")
//   - "ip": IPv4 address
//   - "ip6": IPv6 address
//   - "tcp": TCP port
//   - "udp": UDP port
//   - "secp256k1": Compressed secp256k1 public key
//   - "eth2": Ethereum 2.0 metadata
//
// Example:
//
//	r.Set("ip", net.IPv4(192, 168, 1, 1))
//	r.Set("udp", uint16(9000))
func (r *Record) Set(key string, value interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if key == "" {
		return errors.New("enr: key cannot be empty")
	}

	r.pairs[key] = value
	r.raw = nil // Invalidate cached encoding
	return nil
}

// Get retrieves a value from the record by key.
//
// The value is decoded into the provided destination pointer.
// Returns ErrNoKey if the key is not present in the record.
//
// Example:
//
//	var ip net.IP
//	if err := r.Get("ip", &ip); err != nil {
//	    // Key not found or decoding error
//	}
func (r *Record) Get(key string, dest interface{}) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	value, exists := r.pairs[key]
	if !exists {
		return ErrNoKey
	}

	// Handle direct assignment for common types
	switch d := dest.(type) {
	case *net.IP:
		if ip, ok := value.(net.IP); ok {
			*d = ip
			return nil
		}
	case *uint16:
		if port, ok := value.(uint16); ok {
			*d = port
			return nil
		}
	case *string:
		if str, ok := value.(string); ok {
			*d = str
			return nil
		}
	case *[]byte:
		if bytes, ok := value.([]byte); ok {
			*d = bytes
			return nil
		}
	}

	// For complex types, use RLP encoding/decoding
	if encodedBytes, ok := value.([]byte); ok {
		if err := rlp.DecodeBytes(encodedBytes, dest); err == nil {
			return nil
		}
	}

	encoded, err := rlp.EncodeToBytes(value)
	if err != nil {
		return fmt.Errorf("enr: failed to encode value: %w", err)
	}

	if err := rlp.DecodeBytes(encoded, dest); err != nil {
		return fmt.Errorf("enr: failed to decode value: %w", err)
	}

	return nil
}

// Has checks if a key exists in the record.
//
// Example:
//
//	if r.Has("udp") {
//	    var port uint16
//	    r.Get("udp", &port)
//	}
func (r *Record) Has(key string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.pairs[key]
	return exists
}

// Keys returns all keys present in the record.
//
// The returned slice is a copy and can be safely modified.
func (r *Record) Keys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := make([]string, 0, len(r.pairs))
	for k := range r.pairs {
		keys = append(keys, k)
	}
	return keys
}

// Pairs returns a copy of all key-value pairs in the record.
//
// The returned map is a copy and can be safely modified.
func (r *Record) Pairs() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]interface{}, len(r.pairs))
	for k, v := range r.pairs {
		result[k] = v
	}
	return result
}

// IP returns the IPv4 address from the record.
//
// Returns nil if no "ip" key is present or if the value is not a valid IP.
func (r *Record) IP() net.IP {
	var ip net.IP
	if err := r.Get("ip", &ip); err == nil {
		return ip
	}
	return nil
}

// IP6 returns the IPv6 address from the record.
//
// Returns nil if no "ip6" key is present or if the value is not a valid IP.
func (r *Record) IP6() net.IP {
	var ip net.IP
	if err := r.Get("ip6", &ip); err == nil {
		return ip
	}
	return nil
}

// UDP returns the UDP port from the record.
//
// Returns 0 if no "udp" key is present or if the value is not a valid port.
func (r *Record) UDP() uint16 {
	var port uint16
	if err := r.Get("udp", &port); err == nil {
		return port
	}
	return 0
}

// TCP returns the TCP port from the record.
//
// Returns 0 if no "tcp" key is present or if the value is not a valid port.
func (r *Record) TCP() uint16 {
	var port uint16
	if err := r.Get("tcp", &port); err == nil {
		return port
	}
	return 0
}

// IdentityScheme returns the identity scheme of the record.
//
// Common schemes:
//   - "v4": secp256k1-based identity (most common)
//
// Returns empty string if no "id" key is present.
func (r *Record) IdentityScheme() string {
	var id string
	if err := r.Get("id", &id); err == nil {
		return id
	}
	return ""
}

// PublicKey returns the secp256k1 public key from the record.
//
// Returns nil if no "secp256k1" key is present or if the key is invalid.
func (r *Record) PublicKey() *ecdsa.PublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.publicKeyUnlocked()
}

// publicKeyUnlocked is the internal version (must be called with lock held).
func (r *Record) publicKeyUnlocked() *ecdsa.PublicKey {
	value, exists := r.pairs["secp256k1"]
	if !exists {
		return nil
	}

	keyBytes, ok := value.([]byte)
	if !ok {
		return nil
	}

	key, err := crypto.DecompressPubkey(keyBytes)
	if err != nil {
		return nil
	}

	return key
}

// NodeID returns the node ID derived from the public key.
//
// The node ID is the keccak256 hash of the uncompressed public key (without the 0x04 prefix).
// Returns nil if the record has no valid public key.
func (r *Record) NodeID() []byte {
	pubKey := r.PublicKey()
	if pubKey == nil {
		return nil
	}

	return crypto.Keccak256(crypto.FromECDSAPub(pubKey)[1:])
}

// Eth2 returns the Ethereum 2.0 metadata from the record.
//
// Returns nil and false if no "eth2" key is present or if decoding fails.
func (r *Record) Eth2() (*Eth2ENRData, bool) {
	if !r.Has("eth2") {
		return nil, false
	}

	// Get eth2 field as raw bytes
	var eth2Bytes []byte
	if err := r.Get("eth2", &eth2Bytes); err != nil {
		return nil, false
	}

	// Eth2 field format:
	// - Bytes 0-3: Current fork digest
	// - Bytes 4-7: Next fork version
	// - Bytes 8-15: Next fork epoch (big endian)
	if len(eth2Bytes) < 16 {
		return nil, false
	}

	var eth2Data Eth2ENRData
	copy(eth2Data.ForkDigest[:], eth2Bytes[0:4])
	copy(eth2Data.NextForkVersion[:], eth2Bytes[4:8])

	// Decode next fork epoch (big endian)
	eth2Data.NextForkEpoch = uint64(eth2Bytes[8])<<56 |
		uint64(eth2Bytes[9])<<48 |
		uint64(eth2Bytes[10])<<40 |
		uint64(eth2Bytes[11])<<32 |
		uint64(eth2Bytes[12])<<24 |
		uint64(eth2Bytes[13])<<16 |
		uint64(eth2Bytes[14])<<8 |
		uint64(eth2Bytes[15])

	return &eth2Data, true
}

// Eth returns the Ethereum metadata from the record.
//
// Returns nil and false if no "eth" key is present or if decoding fails.
func (r *Record) Eth() (EthENRData, bool) {
	if !r.Has("eth") {
		return nil, false
	}

	var forkList EthENRData
	if err := r.Get("eth", &forkList); err != nil {
		// No eth field or decoding failed
		return nil, false
	}

	// Check if we have at least one fork ID
	if len(forkList) == 0 {
		return nil, false
	}

	return forkList, true
}

// Sign signs the record with the provided private key.
//
// This updates the signature field and invalidates any cached encoding.
// The identity scheme is automatically set to "v4" (secp256k1).
//
// Example:
//
//	privateKey, _ := crypto.GenerateKey()
//	record := New()
//	record.Set("ip", net.IPv4(192, 168, 1, 1))
//	record.Set("udp", uint16(9000))
//	if err := record.Sign(privateKey); err != nil {
//	    // Handle error
//	}
func (r *Record) Sign(privKey *ecdsa.PrivateKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Set identity scheme to v4 (secp256k1)
	r.pairs["id"] = "v4"

	// Store the compressed public key
	pubKeyBytes := crypto.CompressPubkey(&privKey.PublicKey)
	r.pairs["secp256k1"] = pubKeyBytes

	// Create the content to sign
	content, err := r.encodeContent()
	if err != nil {
		return fmt.Errorf("enr: failed to encode content: %w", err)
	}

	// Sign the content
	hash := crypto.Keccak256(content)
	sig, err := crypto.Sign(hash, privKey)
	if err != nil {
		return fmt.Errorf("enr: failed to sign: %w", err)
	}

	// Remove recovery ID from signature (last byte)
	r.signature = sig[:len(sig)-1]
	r.raw = nil // Invalidate cached encoding

	return nil
}

// VerifySignature verifies the record's signature.
//
// Returns true if the signature is valid for the record's content and public key.
// Returns false if the signature is missing, invalid, or doesn't match the public key.
func (r *Record) VerifySignature() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.verifySignature()
}

// verifySignature is the internal signature verification method (must be called with lock held).
func (r *Record) verifySignature() bool {
	if len(r.signature) == 0 {
		return false
	}

	pubKey := r.publicKeyUnlocked()
	if pubKey == nil {
		return false
	}

	content, err := r.encodeContent()
	if err != nil {
		return false
	}

	hash := crypto.Keccak256(content)
	return crypto.VerifySignature(crypto.CompressPubkey(pubKey), hash, r.signature)
}

// Size returns the RLP-encoded size of the record in bytes.
//
// This is useful for checking if the record exceeds the maximum size (300 bytes).
func (r *Record) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.raw) > 0 {
		return len(r.raw)
	}

	// Estimate size by encoding
	encoded, err := r.encode()
	if err != nil {
		return 0
	}

	return len(encoded)
}

// encodeContent creates the content that is signed.
// This is the RLP encoding of [seq, k1, v1, k2, v2, ...].
// Must be called with lock held.
func (r *Record) encodeContent() ([]byte, error) {
	// Collect key-value pairs in sorted order
	keys := make([]string, 0, len(r.pairs))
	for k := range r.pairs {
		keys = append(keys, k)
	}

	// Sort keys lexicographically (required by spec)
	sortKeys(keys)

	// Build content: [seq, k1, v1, k2, v2, ...]
	content := []interface{}{r.seq}
	for _, k := range keys {
		content = append(content, k, r.pairs[k])
	}

	return rlp.EncodeToBytes(content)
}

// encode creates the full RLP encoding of the record.
// This is [signature, seq, k1, v1, k2, v2, ...].
// Must be called with lock held.
func (r *Record) encode() ([]byte, error) {
	// Collect key-value pairs in sorted order
	keys := make([]string, 0, len(r.pairs))
	for k := range r.pairs {
		keys = append(keys, k)
	}

	// Sort keys lexicographically (required by spec)
	sortKeys(keys)

	// Build record: [signature, seq, k1, v1, k2, v2, ...]
	record := []interface{}{r.signature, r.seq}
	for _, k := range keys {
		record = append(record, k, r.pairs[k])
	}

	encoded, err := rlp.EncodeToBytes(record)
	if err != nil {
		return nil, err
	}

	// Check size limit
	if len(encoded) > MaxRecordSize {
		return nil, ErrRecordTooLarge
	}

	return encoded, nil
}

// ToEnode converts the ENR record to a go-ethereum enode.Node.
//
// This is useful for interoperability with go-ethereum's p2p stack.
// Returns nil if the record cannot be converted (missing required fields).
func (r *Record) ToEnode() *enode.Node {
	encoded, err := r.EncodeRLP()
	if err != nil {
		return nil
	}

	node, err := enode.Parse(enode.ValidSchemes, fmt.Sprintf("enr:%x", encoded))
	if err != nil {
		return nil
	}

	return node
}

// String returns a human-readable representation of the record.
//
// Format: ENR[seq=X, keys=[k1, k2, ...]]
func (r *Record) String() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return fmt.Sprintf("ENR[seq=%d, keys=%v]", r.seq, r.Keys())
}

// sortKeys sorts strings lexicographically (required by ENR spec).
func sortKeys(keys []string) {
	// Simple insertion sort (keys list is typically small)
	for i := 1; i < len(keys); i++ {
		key := keys[i]
		j := i - 1
		for j >= 0 && keys[j] > key {
			keys[j+1] = keys[j]
			j--
		}
		keys[j+1] = key
	}
}
