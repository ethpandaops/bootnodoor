package enr

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/ethereum/go-ethereum/rlp"
)

// EncodeRLP returns the RLP encoding of the record.
//
// The encoding format is: [signature, seq, k1, v1, k2, v2, ...]
// where keys are sorted lexicographically.
//
// The encoding is cached after first call. The cache is invalidated
// when the record is modified.
//
// Returns ErrRecordTooLarge if the encoded record exceeds 300 bytes.
func (r *Record) EncodeRLP() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Return cached encoding if available
	if len(r.raw) > 0 {
		return r.raw, nil
	}

	// Encode the record
	encoded, err := r.encode()
	if err != nil {
		return nil, err
	}

	// Cache the encoding
	r.raw = encoded
	return encoded, nil
}

// DecodeRLPBytes decodes an RLP-encoded record from a byte slice.
//
// The input must be a valid RLP list containing:
// [signature, seq, k1, v1, k2, v2, ...]
//
// After decoding, the signature is automatically verified.
// Returns ErrInvalidSignature if verification fails.
//
// Example:
//
//	encoded := []byte{...}
//	record := New()
//	if err := record.DecodeRLPBytes(encoded); err != nil {
//	    // Handle error
//	}
func (r *Record) DecodeRLPBytes(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Enforce the EIP-778 300-byte size limit on ingest, matching go-ethereum and
	// sigp/discv5. Without this, an oversized (but validly signed) ENR received in a
	// NODES/handshake message could be stored and later re-served, and a single
	// oversized record makes real clients discard the entire NODES message.
	if len(data) > MaxRecordSize {
		return ErrRecordTooLarge
	}

	// Decode the RLP list
	var items []interface{}
	if err := rlp.DecodeBytes(data, &items); err != nil {
		return fmt.Errorf("enr: failed to decode RLP: %w", err)
	}

	// Must have at least [signature, seq]
	if len(items) < 2 {
		return ErrInvalidRecord
	}

	// Check that we have pairs (signature, seq, then key-value pairs)
	if (len(items)-2)%2 != 0 {
		return ErrInvalidRecord
	}

	// Extract signature
	sigBytes, ok := items[0].([]byte)
	if !ok {
		return fmt.Errorf("enr: invalid signature type")
	}
	r.signature = sigBytes

	// Extract sequence number
	seqBytes, ok := items[1].([]byte)
	if !ok {
		return fmt.Errorf("enr: invalid sequence number type")
	}
	r.seq = bytesToUint64(seqBytes)

	// Extract key-value pairs
	r.pairs = make(map[string]interface{})
	for i := 2; i < len(items); i += 2 {
		keyBytes, ok := items[i].([]byte)
		if !ok {
			return fmt.Errorf("enr: invalid key type at index %d", i)
		}
		key := string(keyBytes)

		// Store the raw value
		r.pairs[key] = items[i+1]
	}

	// Verify signature (lock already held by caller)
	if !r.verifySignature() {
		return ErrInvalidSignature
	}

	// Cache the raw encoding
	r.raw = data

	return nil
}

// DecodeRLP decodes an RLP stream into a record.
//
// This method implements the rlp.Decoder interface, allowing Record to be
// automatically decoded when embedded in other structures using rlp.DecodeBytes.
//
// The stream must contain the raw RLP bytes of the ENR record.
func (r *Record) DecodeRLP(s *rlp.Stream) error {
	// Get the raw RLP bytes from the stream
	raw, err := s.Raw()
	if err != nil {
		// Return rlp.EOL directly if we hit end of list
		if err == rlp.EOL || err == io.EOF {
			return rlp.EOL
		}
		return err
	}

	// Decode using the DecodeRLPBytes method
	return r.DecodeRLPBytes(raw)
}

// EncodeBase64 encodes the record in base64 format.
//
// This is the standard format for sharing ENRs in text form.
// The output is URL-safe base64 without padding.
//
// Example output: "enr:-IS4QHCYrYZ..."
func (r *Record) EncodeBase64() (string, error) {
	encoded, err := r.EncodeRLP()
	if err != nil {
		return "", err
	}

	b64 := base64.RawURLEncoding.EncodeToString(encoded)
	return "enr:" + b64, nil
}

// DecodeBase64 decodes a base64-encoded record.
//
// The input must be in the format "enr:BASE64" where BASE64
// is URL-safe base64 without padding.
//
// Example:
//
//	record := New()
//	if err := record.DecodeBase64("enr:-IS4QHCYrYZ..."); err != nil {
//	    // Handle error
//	}
func DecodeBase64(input string) (*Record, error) {
	// Check for "enr:" prefix
	if !strings.HasPrefix(input, "enr:") {
		return nil, fmt.Errorf("enr: invalid format, expected 'enr:' prefix")
	}

	// Remove prefix
	b64 := strings.TrimPrefix(input, "enr:")

	// Decode base64
	data, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("enr: failed to decode base64: %w", err)
	}

	// Decode RLP
	record := New()
	if err := record.DecodeRLPBytes(data); err != nil {
		return nil, err
	}

	return record, nil
}

// Load loads a record from an RLP-encoded byte slice.
//
// This is a convenience function equivalent to:
//
//	record := New()
//	record.DecodeRLPBytes(data)
func Load(data []byte) (*Record, error) {
	record := New()
	if err := record.DecodeRLPBytes(data); err != nil {
		return nil, err
	}
	return record, nil
}

// bytesToUint64 converts a big-endian byte slice to uint64.
func bytesToUint64(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}

	var result uint64
	for _, byte := range b {
		result = (result << 8) | uint64(byte)
	}
	return result
}
