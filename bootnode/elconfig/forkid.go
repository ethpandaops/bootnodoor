// Package elconfig implements Execution Layer config parsing and fork ID calculation.
//
// This package provides functionality to:
//   - Parse geth-format chain configs
//   - Calculate EIP-2124 fork IDs
//   - Validate fork IDs from remote nodes
package elconfig

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"math/big"
	"sort"
	"strings"
)

// ForkID represents an EIP-2124 fork identifier.
//
// A fork ID consists of:
//   - Hash: CRC32 checksum of genesis + passed fork numbers
//   - Next: Next upcoming fork (block number or timestamp)
type ForkID struct {
	Hash [4]byte // CRC32 checksum
	Next uint64  // Next fork (0 if no upcoming forks)
}

// String returns a human-readable representation of the fork ID.
func (id ForkID) String() string {
	return fmt.Sprintf("ForkID{Hash: %#x, Next: %d}", id.Hash, id.Next)
}

// ComputeForkID calculates the fork ID for a given chain state.
//
// Parameters:
//   - genesisHash: The genesis block hash
//   - forksByBlock: Fork block numbers (sorted)
//   - forksByTime: Fork timestamps (sorted)
//   - currentBlock: Current head block number
//   - currentTime: Current head timestamp
//
// Returns the fork ID representing the current state.
func ComputeForkID(genesisHash [32]byte, forksByBlock, forksByTime []uint64, currentBlock, currentTime uint64) ForkID {
	// Calculate starting checksum from genesis hash
	hash := crc32.ChecksumIEEE(genesisHash[:])

	// Process block-based forks
	for _, fork := range forksByBlock {
		if fork <= currentBlock {
			// Fork already passed, update checksum
			hash = checksumUpdate(hash, fork)
			continue
		}
		// Found next upcoming fork
		return ForkID{Hash: checksumToBytes(hash), Next: fork}
	}

	// Process time-based forks
	for _, fork := range forksByTime {
		if fork <= currentTime {
			// Fork already passed, update checksum
			hash = checksumUpdate(hash, fork)
			continue
		}
		// Found next upcoming fork
		return ForkID{Hash: checksumToBytes(hash), Next: fork}
	}

	// No upcoming forks
	return ForkID{Hash: checksumToBytes(hash), Next: 0}
}

// ComputeAllForkIDs calculates all possible fork IDs for a chain.
//
// This is useful for creating a filter that accepts nodes on any
// valid fork of the chain (past, current, or future).
//
// Returns a list of all valid fork IDs.
func ComputeAllForkIDs(genesisHash [32]byte, forksByBlock, forksByTime []uint64) []ForkID {
	// Combine all forks
	allForks := append(append([]uint64{}, forksByBlock...), forksByTime...)

	// Calculate checksums for each fork transition
	forkIDs := make([]ForkID, 0, len(allForks)+1)

	// Initial fork ID (genesis)
	hash := crc32.ChecksumIEEE(genesisHash[:])
	if len(allForks) > 0 {
		forkIDs = append(forkIDs, ForkID{Hash: checksumToBytes(hash), Next: allForks[0]})
	} else {
		forkIDs = append(forkIDs, ForkID{Hash: checksumToBytes(hash), Next: 0})
	}

	// Fork IDs for each fork transition
	for i, fork := range allForks {
		hash = checksumUpdate(hash, fork)
		if i+1 < len(allForks) {
			forkIDs = append(forkIDs, ForkID{Hash: checksumToBytes(hash), Next: allForks[i+1]})
		} else {
			forkIDs = append(forkIDs, ForkID{Hash: checksumToBytes(hash), Next: 0})
		}
	}

	return forkIDs
}

// checksumUpdate calculates the next CRC32 checksum by appending a fork number.
//
// This implements: CRC32(previous-checksum || fork-number)
func checksumUpdate(hash uint32, fork uint64) uint32 {
	var blob [8]byte
	binary.BigEndian.PutUint64(blob[:], fork)
	return crc32.Update(hash, crc32.IEEETable, blob[:])
}

// checksumToBytes converts a uint32 checksum to [4]byte.
func checksumToBytes(hash uint32) [4]byte {
	var blob [4]byte
	binary.BigEndian.PutUint32(blob[:], hash)
	return blob
}

// GatherForks extracts fork block numbers and timestamps from a chain config.
//
// Parameters:
//   - config: The chain configuration
//   - genesisTime: Genesis block timestamp
//
// Returns two sorted lists: fork block numbers and fork timestamps.
func GatherForks(config *ChainConfig, genesisTime uint64) (forksByBlock, forksByTime []uint64) {
	// Extract forks from raw config if not already done
	if len(config.forksByBlock) == 0 && len(config.forksByTime) == 0 && config.rawConfig != nil {
		config.extractForkData()
	}

	// Collect block-based fork values (excluding 0 which is genesis)
	for _, fork := range config.forksByBlock {
		if fork.value > 0 {
			forksByBlock = append(forksByBlock, fork.value)
		}
	}

	// Collect time-based fork values (excluding genesis time)
	for _, fork := range config.forksByTime {
		if fork.value > genesisTime {
			forksByTime = append(forksByTime, fork.value)
		}
	}

	// Deduplicate forks (multiple forks can activate at same block/time)
	forksByBlock = deduplicate(forksByBlock)
	forksByTime = deduplicate(forksByTime)

	return forksByBlock, forksByTime
}

// extractForkData dynamically extracts fork information from the raw config map.
// It looks for keys ending with "Block" or "Time" (excluding special fields).
func (c *ChainConfig) extractForkData() {
	if c.rawConfig == nil {
		return
	}

	// Temporary maps to collect fork data
	blockForks := make(map[string]uint64)
	timeForks := make(map[string]uint64)

	// Special fields to exclude (not forks)
	excludedFields := map[string]bool{
		"chainId":                     true,
		"terminalTotalDifficulty":     true,
		"terminalTotalDifficultyPassed": true,
		"blobSchedule":                true,
		"depositContractAddress":      true,
	}

	// Extract fork data from config map
	for key, value := range c.rawConfig {
		if excludedFields[key] {
			continue
		}

		if strings.HasSuffix(key, "Block") {
			// Extract fork name (e.g., "homesteadBlock" -> "homestead")
			forkName := strings.TrimSuffix(key, "Block")
			forkName = strings.ToLower(forkName)

			// Convert to uint64
			blockNum, ok := convertToUint64(value)
			if ok {
				blockForks[forkName] = blockNum
			}
		} else if strings.HasSuffix(key, "Time") {
			// Extract fork name (e.g., "shanghaiTime" -> "shanghai")
			forkName := strings.TrimSuffix(key, "Time")
			forkName = strings.ToLower(forkName)

			// Convert to uint64
			timestamp, ok := convertToUint64(value)
			if ok {
				timeForks[forkName] = timestamp
			}
		}
	}

	// Build sorted fork lists
	c.forksByBlock = buildForkList(blockForks)
	c.forksByTime = buildForkList(timeForks)
}

// convertToUint64 converts various numeric types to uint64.
func convertToUint64(value interface{}) (uint64, bool) {
	switch v := value.(type) {
	case int:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case uint64:
		return v, true
	case float64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case json.Number:
		if i64, err := v.Int64(); err == nil && i64 >= 0 {
			return uint64(i64), true
		}
	}
	return 0, false
}

// buildForkList builds a sorted fork list from a map.
func buildForkList(forks map[string]uint64) []forkEntry {
	// Collect all entries
	entries := make([]forkEntry, 0, len(forks))
	for name, value := range forks {
		entries = append(entries, forkEntry{
			name:  name,
			value: value,
		})
	}

	// Sort by value (block or time), then by name for equal values
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].value != entries[j].value {
			return entries[i].value < entries[j].value
		}
		return entries[i].name < entries[j].name
	})

	return entries
}

// ForkInfo contains information about a fork activation.
type ForkInfo struct {
	Name      string // Fork name (e.g., "homestead", "shanghai")
	Block     *uint64 // Block number (nil for time-based forks)
	Timestamp *uint64 // Timestamp (nil for block-based forks)
}

// GetAllForks returns all forks in chronological order.
// Block-based forks come before time-based forks.
func (c *ChainConfig) GetAllForks() []ForkInfo {
	// Extract forks if not already done
	if len(c.forksByBlock) == 0 && len(c.forksByTime) == 0 && c.rawConfig != nil {
		c.extractForkData()
	}

	// Collect all forks
	forks := make([]ForkInfo, 0, len(c.forksByBlock)+len(c.forksByTime))

	// Add block-based forks first
	for _, fork := range c.forksByBlock {
		blockNum := fork.value
		forks = append(forks, ForkInfo{
			Name:      fork.name,
			Block:     &blockNum,
			Timestamp: nil,
		})
	}

	// Add time-based forks second
	for _, fork := range c.forksByTime {
		timestamp := fork.value
		forks = append(forks, ForkInfo{
			Name:      fork.name,
			Block:     nil,
			Timestamp: &timestamp,
		})
	}

	return forks
}

// deduplicate removes duplicate values from a sorted uint64 slice.
func deduplicate(values []uint64) []uint64 {
	if len(values) == 0 {
		return values
	}

	// Sort would be needed here if not already sorted
	// For simplicity, assume caller provides sorted values

	result := make([]uint64, 0, len(values))
	result = append(result, values[0])

	for i := 1; i < len(values); i++ {
		if values[i] != values[i-1] {
			result = append(result, values[i])
		}
	}

	return result
}

// ChainConfig represents an Execution Layer chain configuration.
//
// This is fork-independent and dynamically parses fork data from config fields.
type ChainConfig struct {
	ChainID *big.Int `json:"chainId"`

	// Dynamically extracted forks (sorted by block/time)
	forksByBlock []forkEntry
	forksByTime  []forkEntry

	// Raw config for accessing other fields
	rawConfig map[string]interface{}
}

// forkEntry represents a single fork activation point.
type forkEntry struct {
	name  string // Fork name (e.g., "homestead", "shanghai")
	value uint64 // Block number or timestamp
}
