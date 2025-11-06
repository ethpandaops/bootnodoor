package elconfig

import (
	"fmt"
)

// ForkFilter validates fork IDs from remote nodes.
//
// It checks if a remote fork ID is compatible with the local chain.
type ForkFilter struct {
	// validForkIDs contains all acceptable fork IDs
	validForkIDs map[[4]byte]bool

	// allForkIDs contains the complete list for debugging
	allForkIDs []ForkID

	// genesisHash is the genesis block hash
	genesisHash [32]byte

	// chainConfig is the chain configuration
	chainConfig *ChainConfig
}

// NewForkFilter creates a new fork ID filter.
//
// It pre-computes all valid fork IDs for the chain so that nodes
// on any valid fork (past, current, or future) are accepted.
//
// Parameters:
//   - genesisHash: Genesis block hash
//   - config: Chain configuration
//   - genesisTime: Genesis block timestamp
//
// Returns a filter that can validate remote fork IDs.
func NewForkFilter(genesisHash [32]byte, config *ChainConfig, genesisTime uint64) *ForkFilter {
	// Gather all forks
	forksByBlock, forksByTime := GatherForks(config, genesisTime)

	// Compute all possible fork IDs
	allForkIDs := ComputeAllForkIDs(genesisHash, forksByBlock, forksByTime)

	// Build lookup map for fast validation
	validForkIDs := make(map[[4]byte]bool)
	for _, id := range allForkIDs {
		validForkIDs[id.Hash] = true
	}

	return &ForkFilter{
		validForkIDs: validForkIDs,
		allForkIDs:   allForkIDs,
		genesisHash:  genesisHash,
		chainConfig:  config,
	}
}

// Filter checks if a fork ID is valid for this chain.
//
// Returns true if the fork ID is acceptable, false otherwise.
//
// This implementation is permissive - it accepts any node that appears
// to be on the same chain, regardless of whether they're ahead or behind.
func (f *ForkFilter) Filter(id ForkID) bool {
	return f.validForkIDs[id.Hash]
}

// FilterStrict performs strict fork ID validation.
//
// Returns nil if valid, error describing the issue otherwise.
func (f *ForkFilter) FilterStrict(id ForkID, currentBlock, currentTime uint64) error {
	// Check if hash is valid
	if !f.validForkIDs[id.Hash] {
		return fmt.Errorf("incompatible fork ID hash: %#x", id.Hash)
	}

	// For strict validation, we could also check id.Next against our state
	// to detect if the remote is on a stale fork. For now, we accept any
	// valid hash.

	return nil
}

// GetAllForkIDs returns all valid fork IDs for debugging.
func (f *ForkFilter) GetAllForkIDs() []ForkID {
	return f.allForkIDs
}

// GetCurrentForkID calculates the current fork ID based on chain state.
func (f *ForkFilter) GetCurrentForkID(currentBlock, currentTime uint64) ForkID {
	forksByBlock, forksByTime := GatherForks(f.chainConfig, 0)
	return ComputeForkID(f.genesisHash, forksByBlock, forksByTime, currentBlock, currentTime)
}

// ForkIDWithName pairs a fork ID with its name and activation point.
type ForkIDWithName struct {
	ForkID     ForkID
	Name       string
	Activation uint64 // Block number or timestamp
	IsTime     bool   // True if activation is timestamp, false if block number
}

// GetAllForkIDsWithNames returns all fork IDs along with their names.
// This is useful for displaying fork information in the UI.
func (f *ForkFilter) GetAllForkIDsWithNames(genesisTime uint64) []ForkIDWithName {
	if f.chainConfig == nil {
		return nil
	}

	// Extract fork data if not already done
	if len(f.chainConfig.forksByBlock) == 0 && len(f.chainConfig.forksByTime) == 0 && f.chainConfig.rawConfig != nil {
		f.chainConfig.extractForkData()
	}

	// Collect all forks with their activation points
	type forkWithValue struct {
		name  string
		value uint64
		isTime bool
	}

	var allForks []forkWithValue

	// Add genesis
	allForks = append(allForks, forkWithValue{name: "genesis", value: 0, isTime: false})

	// Add block-based forks
	for _, fork := range f.chainConfig.forksByBlock {
		if fork.value > 0 {
			allForks = append(allForks, forkWithValue{name: fork.name, value: fork.value, isTime: false})
		}
	}

	// Add time-based forks
	for _, fork := range f.chainConfig.forksByTime {
		if fork.value > genesisTime {
			allForks = append(allForks, forkWithValue{name: fork.name, value: fork.value, isTime: true})
		}
	}

	// Gather fork values for computing fork IDs
	forksByBlock, forksByTime := GatherForks(f.chainConfig, genesisTime)

	// Compute all fork IDs
	allForkIDs := ComputeAllForkIDs(f.genesisHash, forksByBlock, forksByTime)

	// Build result - match fork IDs to names
	// The fork IDs are in order: genesis, then each subsequent fork
	result := make([]ForkIDWithName, 0, len(allForkIDs))

	if len(allForkIDs) > 0 {
		// First fork ID is always genesis
		result = append(result, ForkIDWithName{
			ForkID:     allForkIDs[0],
			Name:       "Genesis",
			Activation: 0,
			IsTime:     false,
		})

		// Subsequent fork IDs correspond to activation points in chronological order
		forkIdx := 1
		for _, fork := range allForks {
			if fork.name != "genesis" && forkIdx < len(allForkIDs) {
				// Capitalize first letter of fork name for display
				displayName := fork.name
				if len(displayName) > 0 {
					displayName = string(displayName[0]-32) + displayName[1:]
				}

				result = append(result, ForkIDWithName{
					ForkID:     allForkIDs[forkIdx],
					Name:       displayName,
					Activation: fork.value,
					IsTime:     fork.isTime,
				})
				forkIdx++
			}
		}
	}

	return result
}
