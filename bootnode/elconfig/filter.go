package elconfig

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
)

// ForkFilter validates fork IDs from remote nodes.
//
// It ports go-ethereum's EIP-2124 validation ruleset evaluated with a static
// head stance: a bootnode tracks no chain head, so every block-scheduled fork
// is treated as passed (exact on post-merge networks, which can only schedule
// forks by time) and the time head is the wall clock at validation time.
type ForkFilter struct {
	// genesisHash is the genesis block hash
	genesisHash [32]byte

	// chainConfig is the chain configuration
	chainConfig *ChainConfig

	// genesisTime is the genesis block timestamp; fork-id math must drop
	// time-scheduled forks at or before it, exactly like go-ethereum's
	// gatherForks(config, genesis.Time()).
	genesisTime uint64

	// forks holds every canonical fork boundary (blocks then times) plus the
	// MaxUint64 sentry go-ethereum appends so the last real fork needs no
	// special casing.
	forks []uint64

	// numBlockForks indexes the first time fork in forks. Every block fork is
	// passed under the static head stance, so validation starts scanning here.
	numBlockForks int

	// allForkIDs[i].Hash is the checksum after passing the first i boundaries.
	allForkIDs []ForkID

	// Admission outcomes, recorded by the admission call sites only (the
	// filter is also invoked for per-packet layer classification, which must
	// not pollute these numbers).
	statsMu        sync.Mutex
	totalChecks    uint64
	accepted       uint64
	rejected       uint64
	lastRejectedID ForkID
}

// FilterStats is a snapshot of admission outcomes.
type FilterStats struct {
	TotalChecks    uint64
	Accepted       uint64
	Rejected       uint64
	LastRejectedID ForkID
}

// NewForkFilter creates a new fork ID filter.
//
// It pre-computes the canonical fork checksum chain so remote fork IDs can be
// validated with go-ethereum's ruleset.
//
// Parameters:
//   - genesisHash: Genesis block hash
//   - config: Chain configuration
//   - genesisTime: Genesis block timestamp
//
// Returns a filter that can validate remote fork IDs.
func NewForkFilter(genesisHash [32]byte, config *ChainConfig, genesisTime uint64) *ForkFilter {
	forksByBlock, forksByTime := GatherForks(config, genesisTime)

	forks := append(append([]uint64{}, forksByBlock...), forksByTime...)
	forks = append(forks, math.MaxUint64)

	return &ForkFilter{
		genesisHash:   genesisHash,
		chainConfig:   config,
		genesisTime:   genesisTime,
		forks:         forks,
		numBlockForks: len(forksByBlock),
		allForkIDs:    ComputeAllForkIDs(genesisHash, forksByBlock, forksByTime),
	}
}

// Filter checks if a fork ID is valid for this chain.
//
// Returns true if the fork ID is acceptable, false otherwise.
func (f *ForkFilter) Filter(id ForkID) bool {
	return f.validate(id, uint64(time.Now().Unix())) == nil
}

// validate runs go-ethereum's fork checksum validation ruleset with the
// static head stance (see the ForkFilter doc). now is a parameter so tests
// can pin the time head.
//
// The ruleset, verbatim from go-ethereum:
//  1. If local and remote FORK_CSUM matches, compare local head to FORK_NEXT.
//     1a. A remotely announced but remotely not passed block is already
//     passed locally: reject, the chains are incompatible.
//     1b. No remotely announced fork, or not yet passed locally: accept.
//  2. If the remote FORK_CSUM is a subset of the local past forks and the
//     remote FORK_NEXT matches the locally following fork: accept (they are
//     syncing).
//  3. If the remote FORK_CSUM is a superset of the local past forks and can
//     be completed with locally known future forks: accept (we are syncing).
//  4. Reject in all other cases.
func (f *ForkFilter) validate(id ForkID, now uint64) error {
	for i := f.numBlockForks; i < len(f.forks); i++ {
		if now >= f.forks[i] {
			continue
		}
		// Found the first unpassed fork, check the remote against it (rule #1).
		if f.allForkIDs[i].Hash == id.Hash {
			// A remote-announced fork we have already passed means the remote
			// is stale (rule #1a). Every unpassed fork here is time-scheduled
			// (block forks are all passed under the static stance), so the
			// head to compare is the wall clock.
			if id.Next > 0 && now >= id.Next {
				return fmt.Errorf("remote is stale: announced fork %d already passed", id.Next)
			}
			return nil
		}
		// Different fork state: subset means the remote is syncing (rule #2).
		for j := 0; j < i; j++ {
			if f.allForkIDs[j].Hash == id.Hash {
				if f.forks[j] != id.Next {
					return fmt.Errorf("remote is stale: subset checksum with next %d, want %d", id.Next, f.forks[j])
				}
				return nil
			}
		}
		// Superset means we would be the one syncing (rule #3).
		for j := i + 1; j < len(f.allForkIDs); j++ {
			if f.allForkIDs[j].Hash == id.Hash {
				return nil
			}
		}
		return fmt.Errorf("incompatible fork ID hash: %#x", id.Hash)
	}
	// Unreachable: the MaxUint64 sentry can never be passed.
	return nil
}

// RecordAdmission records an admission decision for the stats surface. Its only
// caller is ENRManager.AdmitELNode, which owns the eth-entry gate; the pure
// predicate path (ClassifyELNode) must never reach here.
func (f *ForkFilter) RecordAdmission(acceptedNode bool, id ForkID) {
	f.statsMu.Lock()
	defer f.statsMu.Unlock()
	f.totalChecks++
	if acceptedNode {
		f.accepted++
		return
	}
	f.rejected++
	f.lastRejectedID = id
}

// GetStats returns a snapshot of the admission outcomes.
func (f *ForkFilter) GetStats() FilterStats {
	f.statsMu.Lock()
	defer f.statsMu.Unlock()
	return FilterStats{
		TotalChecks:    f.totalChecks,
		Accepted:       f.accepted,
		Rejected:       f.rejected,
		LastRejectedID: f.lastRejectedID,
	}
}

// GetAllForkIDs returns all valid fork IDs for debugging. Copied because
// validate reads allForkIDs to decide admission; mutating it would corrupt
// peer filtering.
func (f *ForkFilter) GetAllForkIDs() []ForkID {
	return slices.Clone(f.allForkIDs)
}

// GetCurrentForkID calculates the current fork ID based on chain state.
func (f *ForkFilter) GetCurrentForkID(currentBlock, currentTime uint64) ForkID {
	forksByBlock, forksByTime := GatherForks(f.chainConfig, f.genesisTime)
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
//
// Multiple upgrades activating at one block or timestamp share a single fork
// ID, so names are grouped per deduplicated boundary instead of paired
// positionally.
func (f *ForkFilter) GetAllForkIDsWithNames() []ForkIDWithName {
	if f.chainConfig == nil {
		return nil
	}
	if len(f.chainConfig.forksByBlock) == 0 && len(f.chainConfig.forksByTime) == 0 && f.chainConfig.rawConfig != nil {
		f.chainConfig.extractForkData()
	}

	type boundary struct {
		names  []string
		value  uint64
		isTime bool
	}
	var boundaries []boundary
	appendFork := func(name string, value uint64, isTime bool) {
		for i := range boundaries {
			if boundaries[i].value == value && boundaries[i].isTime == isTime {
				boundaries[i].names = append(boundaries[i].names, name)
				return
			}
		}
		boundaries = append(boundaries, boundary{names: []string{name}, value: value, isTime: isTime})
	}
	for _, fork := range f.chainConfig.forksByBlock {
		if fork.value > 0 {
			appendFork(fork.name, fork.value, false)
		}
	}
	for _, fork := range f.chainConfig.forksByTime {
		if fork.value > f.genesisTime {
			appendFork(fork.name, fork.value, true)
		}
	}

	result := make([]ForkIDWithName, 0, len(f.allForkIDs))
	result = append(result, ForkIDWithName{
		ForkID:     f.allForkIDs[0],
		Name:       "Genesis",
		Activation: 0,
		IsTime:     false,
	})
	for i, b := range boundaries {
		if i+1 >= len(f.allForkIDs) {
			break
		}
		names := make([]string, 0, len(b.names))
		for _, n := range b.names {
			if len(n) > 0 {
				n = strings.ToUpper(n[:1]) + n[1:]
			}
			names = append(names, n)
		}
		result = append(result, ForkIDWithName{
			ForkID:     f.allForkIDs[i+1],
			Name:       strings.Join(names, "/"),
			Activation: b.value,
			IsTime:     b.isTime,
		})
	}
	return result
}
