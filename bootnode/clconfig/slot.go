package clconfig

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"
)

// SlotDurationEntry is one segment of the slot duration schedule: the slot
// duration that applies from the first slot of Epoch onwards.
type SlotDurationEntry struct {
	Epoch      uint64
	DurationMs uint64
}

// slotDurationKeyPrefix introduces a per-fork slot duration. The suffix names
// the fork whose epoch the duration takes effect at: SLOT_DURATION_MS_HEZE on
// the heze devnets, SLOT_DURATION_MS_EIP8198 in the feature spec.
const slotDurationKeyPrefix = "SLOT_DURATION_MS_"

// defaultSlotDurationMs applies when a config names no slot duration at all.
const defaultSlotDurationMs = 12000

// extractSlotDurations builds the schedule from the raw YAML map, mirroring
// get_slot_durations in the spec: the genesis duration followed by every
// SLOT_DURATION_MS_<FORK> whose fork is scheduled. Fork names are resolved the
// same way as *_FORK_EPOCH keys, so the fork list must already be populated.
func (c *Config) extractSlotDurations(rawConfig map[string]any) error {
	changes := make([]SlotDurationEntry, 0, 1)
	for key, value := range rawConfig {
		if !strings.HasPrefix(key, slotDurationKeyPrefix) {
			continue
		}
		forkName := toTitleCase(strings.TrimPrefix(key, slotDurationKeyPrefix))
		epoch := c.GetForkEpoch(forkName)
		if epoch == nil {
			return fmt.Errorf("%s refers to unknown fork %s", key, forkName)
		}
		duration, ok := yamlUint64(value)
		if !ok {
			return fmt.Errorf("%s is not an integer", key)
		}
		if duration == 0 {
			return fmt.Errorf("%s must be positive", key)
		}
		// An unscheduled fork changes nothing, as in the spec.
		if *epoch == math.MaxUint64 {
			continue
		}
		changes = append(changes, SlotDurationEntry{Epoch: *epoch, DurationMs: duration})
	}

	// Map iteration is unordered; two forks sharing an epoch with different
	// durations would otherwise pick a winner at random.
	sort.Slice(changes, func(i, j int) bool {
		return changes[i].Epoch < changes[j].Epoch
	})
	for i := 1; i < len(changes); i++ {
		if changes[i].Epoch == changes[i-1].Epoch && changes[i].DurationMs != changes[i-1].DurationMs {
			return fmt.Errorf("conflicting slot durations %dms and %dms at epoch %d",
				changes[i-1].DurationMs, changes[i].DurationMs, changes[i].Epoch)
		}
	}

	schedule := make([]SlotDurationEntry, 0, len(changes)+1)
	schedule = append(schedule, SlotDurationEntry{Epoch: 0, DurationMs: c.genesisSlotDurationMs()})
	for _, change := range changes {
		last := &schedule[len(schedule)-1]
		switch {
		case change.Epoch == last.Epoch:
			// A fork at genesis overrides the base duration.
			last.DurationMs = change.DurationMs
		case change.DurationMs != last.DurationMs:
			schedule = append(schedule, change)
		}
	}
	c.slotDurations = schedule
	return nil
}

// yamlUint64 reads an integer the YAML decoder may have produced as any of its
// numeric types.
func yamlUint64(value any) (uint64, bool) {
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
		if v < 0 || v != math.Trunc(v) {
			return 0, false
		}
		return uint64(v), true
	default:
		return 0, false
	}
}

// genesisSlotDurationMs returns the slot duration in effect at genesis.
func (c *Config) genesisSlotDurationMs() uint64 {
	if c.SlotDurationMs != 0 {
		return c.SlotDurationMs
	}
	if c.SecondsPerSlot != 0 && c.SecondsPerSlot <= math.MaxUint64/1000 {
		return c.SecondsPerSlot * 1000
	}
	return defaultSlotDurationMs
}

// SlotDurations returns the slot duration schedule in ascending epoch order.
// The first entry is always the genesis segment at epoch 0; a config without
// any change has exactly one entry.
func (c *Config) SlotDurations() []SlotDurationEntry {
	if len(c.slotDurations) == 0 {
		return []SlotDurationEntry{{Epoch: 0, DurationMs: c.genesisSlotDurationMs()}}
	}
	return slices.Clone(c.slotDurations)
}

// SlotDuration returns the slot duration in effect at epoch.
func (c *Config) SlotDuration(epoch uint64) time.Duration {
	var ms uint64
	for _, entry := range c.SlotDurations() {
		if epoch >= entry.Epoch {
			ms = entry.DurationMs
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// SlotDurationSummary renders the schedule for logs and the overview page,
// e.g. "12s" or "12s, 9s from epoch 5".
func (c *Config) SlotDurationSummary() string {
	entries := c.SlotDurations()
	parts := make([]string, 0, len(entries))
	for i, entry := range entries {
		d := time.Duration(entry.DurationMs) * time.Millisecond
		if i == 0 {
			parts = append(parts, d.String())
			continue
		}
		parts = append(parts, fmt.Sprintf("%s from epoch %d", d, entry.Epoch))
	}
	return strings.Join(parts, ", ")
}

// slotSegment is a schedule entry resolved to its first slot and the
// milliseconds from genesis at which that slot starts.
type slotSegment struct {
	startSlot  uint64
	startMs    uint64
	durationMs uint64
}

// slotSegments resolves the schedule against slots-per-epoch. The genesis
// segment is always present. A segment whose start slot or start time would
// overflow is dropped together with everything after it: no representable
// slot or instant reaches it.
func (c *Config) slotSegments() []slotSegment {
	slotsPerEpoch := c.GetSlotsPerEpoch()
	entries := c.SlotDurations()
	segments := make([]slotSegment, 0, len(entries))
	for _, entry := range entries {
		if entry.Epoch > math.MaxUint64/slotsPerEpoch {
			break
		}
		startSlot := entry.Epoch * slotsPerEpoch
		var startMs uint64
		if n := len(segments); n > 0 {
			prev := segments[n-1]
			slots := startSlot - prev.startSlot
			if slots > math.MaxUint64/prev.durationMs || prev.startMs > math.MaxUint64-slots*prev.durationMs {
				break
			}
			startMs = prev.startMs + slots*prev.durationMs
		}
		segments = append(segments, slotSegment{startSlot: startSlot, startMs: startMs, durationMs: entry.DurationMs})
	}
	return segments
}

// slotStartMs returns the milliseconds from genesis to the start of a slot,
// reporting false if the result would overflow. This is the spec's
// compute_time_at_slot_ms without the genesis offset.
func (c *Config) slotStartMs(slot uint64) (uint64, bool) {
	segments := c.slotSegments()
	seg := segments[0]
	for _, candidate := range segments[1:] {
		if candidate.startSlot > slot {
			break
		}
		seg = candidate
	}
	slots := slot - seg.startSlot
	if slots > math.MaxUint64/seg.durationMs || seg.startMs > math.MaxUint64-slots*seg.durationMs {
		return 0, false
	}
	return seg.startMs + slots*seg.durationMs, true
}

// slotAtMs returns the slot active the given milliseconds after genesis. This
// is the spec's compute_slot_at_time_ms without the genesis offset.
func (c *Config) slotAtMs(ms uint64) uint64 {
	segments := c.slotSegments()
	seg := segments[0]
	for _, candidate := range segments[1:] {
		if candidate.startMs > ms {
			break
		}
		seg = candidate
	}
	return seg.startSlot + (ms-seg.startMs)/seg.durationMs
}

// SlotStartTime returns the wall clock start of a slot, reporting false
// without a genesis time or if the slot is beyond representable time.
func (c *Config) SlotStartTime(slot uint64) (time.Time, bool) {
	genesis := c.GetGenesisTime()
	if genesis == 0 || genesis > math.MaxInt64 {
		return time.Time{}, false
	}
	offset, ok := c.slotStartMs(slot)
	if !ok || offset/1000 > uint64(math.MaxInt64)-genesis {
		return time.Time{}, false
	}
	return time.Unix(int64(genesis+offset/1000), int64(offset%1000)*int64(time.Millisecond)), true
}

// EpochStartTime returns the wall clock start of an epoch, reporting false
// without a genesis time or if the epoch is beyond representable time.
func (c *Config) EpochStartTime(epoch uint64) (time.Time, bool) {
	slotsPerEpoch := c.GetSlotsPerEpoch()
	if epoch > math.MaxUint64/slotsPerEpoch {
		return time.Time{}, false
	}
	return c.SlotStartTime(epoch * slotsPerEpoch)
}

// SlotAtTime returns the slot active at t, or 0 before genesis. The second
// return is false when no genesis time is configured.
func (c *Config) SlotAtTime(t time.Time) (uint64, bool) {
	genesis := c.GetGenesisTime()
	if genesis == 0 {
		return 0, false
	}
	// A genesis past the representable millisecond range lies after any t.
	if genesis > math.MaxInt64/1000 {
		return 0, true
	}
	elapsed := t.UnixMilli() - int64(genesis)*1000
	if elapsed < 0 {
		return 0, true
	}
	return c.slotAtMs(uint64(elapsed)), true
}

// EpochAtTime returns the epoch active at t, or 0 before genesis. The second
// return is false when no genesis time is configured.
func (c *Config) EpochAtTime(t time.Time) (uint64, bool) {
	slot, ok := c.SlotAtTime(t)
	if !ok {
		return 0, false
	}
	return slot / c.GetSlotsPerEpoch(), true
}
