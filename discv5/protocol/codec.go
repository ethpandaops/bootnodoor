package protocol

import (
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
)

// encodeMessage encodes message content as RLP.
//
// Format: rlp(message-content)
//
// The message type byte is NOT included here - it's prepended by the handler.
// This is a helper function used by all message types.
func encodeMessage(msgType byte, content []interface{}) ([]byte, error) {
	// RLP encode the content only
	encoded, err := rlp.EncodeToBytes(content)
	if err != nil {
		return nil, fmt.Errorf("failed to RLP encode message: %w", err)
	}

	return encoded, nil
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

// uint64ToBytes converts a uint64 to a big-endian byte slice.
func uint64ToBytes(n uint64) []byte {
	if n == 0 {
		return []byte{0}
	}

	// Find the minimum number of bytes needed
	bytes := make([]byte, 0, 8)
	for n > 0 {
		bytes = append([]byte{byte(n & 0xFF)}, bytes...)
		n >>= 8
	}
	return bytes
}
