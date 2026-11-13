package clconfig

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const devnet3Genesis = 1760000000

// loadSlotConfig writes a Fulu-at-genesis config plus extra and loads it. A
// HEZE_FORK_EPOCH or ISAN_FORK_EPOCH in extra gets its version added.
func loadSlotConfig(t *testing.T, extra string) *Config {
	t.Helper()

	cfg, err := tryLoadSlotConfig(t, extra)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func tryLoadSlotConfig(t *testing.T, extra string) (*Config, error) {
	t.Helper()

	yaml := "PRESET_BASE: mainnet\n" +
		"MIN_GENESIS_TIME: " + strconv.Itoa(devnet3Genesis) + "\n" +
		"GENESIS_DELAY: 0\n" +
		"SECONDS_PER_SLOT: 12\n" +
		"GENESIS_FORK_VERSION: 0x10000000\n" +
		"FULU_FORK_VERSION: 0x70000000\nFULU_FORK_EPOCH: 0\n" + extra
	if strings.Contains(extra, "HEZE_FORK_EPOCH") {
		yaml += "HEZE_FORK_VERSION: 0x90000000\n"
	}
	if strings.Contains(extra, "ISAN_FORK_EPOCH") {
		yaml += "ISAN_FORK_VERSION: 0xa0000000\n"
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

func epochStartUnixMilli(t *testing.T, cfg *Config, epoch uint64) int64 {
	t.Helper()

	start, ok := cfg.EpochStartTime(epoch)
	if !ok {
		t.Fatalf("epoch %d has no start time", epoch)
	}
	return start.UnixMilli()
}

func TestHezeSlotDurationChange(t *testing.T) {
	cfg := loadSlotConfig(t, "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 9000\n")

	genesisMs := int64(devnet3Genesis) * 1000
	for _, tc := range []struct {
		epoch  uint64
		offset int64
	}{
		{0, 0},
		{4, 4 * 32 * 12000},
		{5, 5 * 32 * 12000},
		{6, 5*32*12000 + 32*9000},
		{10, 5*32*12000 + 5*32*9000},
	} {
		if got := epochStartUnixMilli(t, cfg, tc.epoch) - genesisMs; got != tc.offset {
			t.Errorf("epoch %d starts %dms after genesis, want %dms", tc.epoch, got, tc.offset)
		}
	}

	for _, tc := range []struct {
		offset int64
		epoch  uint64
	}{
		{-1000, 0},
		{0, 0},
		{1920*1000 - 1, 4},
		{1920 * 1000, 5},
		{1920*1000 + 288*1000 - 1, 5},
		{1920*1000 + 288*1000, 6},
		{3360*1000 - 1, 9},
		{3360 * 1000, 10},
	} {
		got, ok := cfg.EpochAtTime(time.UnixMilli(genesisMs + tc.offset))
		if !ok || got != tc.epoch {
			t.Errorf("epoch %dms after genesis = %d (%v), want %d", tc.offset, got, ok, tc.epoch)
		}
	}

	if got, want := cfg.slotAtMs(1920*1000+9000), uint64(5*32+1); got != want {
		t.Errorf("slot 9s after the Heze boundary = %d, want %d", got, want)
	}
	if got, ok := cfg.SlotAtTime(time.UnixMilli(genesisMs + 1920*1000 + 9000)); !ok || got != 5*32+1 {
		t.Errorf("SlotAtTime 9s after the Heze boundary = %d (%v), want %d", got, ok, 5*32+1)
	}
	if got, ok := cfg.SlotStartTime(5*32 + 1); !ok || got.UnixMilli() != genesisMs+1920*1000+9000 {
		t.Errorf("SlotStartTime(161) = %v (%v), want genesis+1929s", got, ok)
	}

	if got, want := cfg.SlotDuration(4), 12*time.Second; got != want {
		t.Errorf("slot duration at epoch 4 = %v, want %v", got, want)
	}
	if got, want := cfg.SlotDuration(5), 9*time.Second; got != want {
		t.Errorf("slot duration at epoch 5 = %v, want %v", got, want)
	}
	if got, want := cfg.SlotDurationSummary(), "12s, 9s from epoch 5"; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
}

// The schedule is a sequence, not a single switch: a second change must stack
// on the first, and the spec's feature key spelling must work like the devnet one.
func TestSlotDurationScheduleStacks(t *testing.T) {
	cfg := loadSlotConfig(t, "SLOT_DURATION_MS: 12000\n"+
		"HEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 9000\n"+
		"ISAN_FORK_EPOCH: 10\nSLOT_DURATION_MS_ISAN: 6000\n")

	want := []SlotDurationEntry{{0, 12000}, {5, 9000}, {10, 6000}}
	got := cfg.SlotDurations()
	if len(got) != len(want) {
		t.Fatalf("schedule = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("schedule[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	genesisMs := int64(devnet3Genesis) * 1000
	epoch12 := int64(5*32*12000 + 5*32*9000 + 2*32*6000)
	if got := epochStartUnixMilli(t, cfg, 12) - genesisMs; got != epoch12 {
		t.Errorf("epoch 12 starts %dms after genesis, want %dms", got, epoch12)
	}
	if got, ok := cfg.EpochAtTime(time.UnixMilli(genesisMs + epoch12 - 1)); !ok || got != 11 {
		t.Errorf("epoch just before epoch 12 = %d (%v), want 11", got, ok)
	}
	if got, ok := cfg.EpochAtTime(time.UnixMilli(genesisMs + epoch12)); !ok || got != 12 {
		t.Errorf("epoch at epoch 12 start = %d (%v), want 12", got, ok)
	}
	if got, want := cfg.SlotDurationSummary(), "12s, 9s from epoch 5, 6s from epoch 10"; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
}

func TestSlotDurationFeatureKeyName(t *testing.T) {
	cfg := loadSlotConfig(t, "SLOT_DURATION_MS: 12000\n"+
		"EIP8198_FORK_VERSION: 0x90000000\nEIP8198_FORK_EPOCH: 5\nSLOT_DURATION_MS_EIP8198: 10000\n")

	if got, want := cfg.SlotDuration(5), 10*time.Second; got != want {
		t.Errorf("slot duration at epoch 5 = %v, want %v", got, want)
	}
	if got := epochStartUnixMilli(t, cfg, 6) - int64(devnet3Genesis)*1000; got != 5*32*12000+32*10000 {
		t.Errorf("epoch 6 starts %dms after genesis", got)
	}
}

func TestSlotDurationAtGenesisForkOverridesBase(t *testing.T) {
	cfg := loadSlotConfig(t, "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 0\nSLOT_DURATION_MS_HEZE: 9000\n")

	if got := cfg.SlotDurations(); len(got) != 1 || got[0] != (SlotDurationEntry{0, 9000}) {
		t.Errorf("schedule = %+v, want a single 9000ms genesis segment", got)
	}
	if got := epochStartUnixMilli(t, cfg, 1) - int64(devnet3Genesis)*1000; got != 32*9000 {
		t.Errorf("epoch 1 starts %dms after genesis, want %d", got, 32*9000)
	}
}

func TestSlotDurationInvalidConfigs(t *testing.T) {
	for name, extra := range map[string]string{
		"unknown fork":          "SLOT_DURATION_MS: 12000\nSLOT_DURATION_MS_NOPE: 9000\n",
		"zero duration":         "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 0\n",
		"non-integer":           "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: fast\n",
		"base beyond duration":  "SLOT_DURATION_MS: 9223372036855\n",
		"fork beyond duration":  "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 9223372036855\n",
		"conflict at one epoch": "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 9000\nISAN_FORK_EPOCH: 5\nSLOT_DURATION_MS_ISAN: 6000\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tryLoadSlotConfig(t, extra); err == nil {
				t.Error("config loaded without error")
			}
		})
	}
}

func TestHezeSlotDurationBPOActivation(t *testing.T) {
	cfg := loadSlotConfig(t, "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 9000\n"+
		"BLOB_SCHEDULE:\n  - EPOCH: 10\n    MAX_BLOBS_PER_BLOCK: 21\n")

	start, ok := cfg.EpochStartTime(10)
	if !ok {
		t.Fatal("BPO epoch has no start time")
	}
	if want := time.Unix(devnet3Genesis+3360, 0); !start.Equal(want) {
		t.Fatalf("BPO activation = %v, want %v", start, want)
	}

	before, _ := cfg.EpochAtTime(start.Add(-time.Millisecond))
	after, _ := cfg.EpochAtTime(start)
	if cfg.GetForkDigestForEpoch(before) == cfg.GetForkDigestForEpoch(after) {
		t.Fatal("fork digest does not change at the BPO activation time")
	}
}

func TestSlotDurationUnchangedMatchesSingleDuration(t *testing.T) {
	for name, extra := range map[string]string{
		"no slot duration fields":   "HEZE_FORK_EPOCH: 5\n",
		"same heze duration":        "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 12000\n",
		"heze far future":           "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 18446744073709551615\nSLOT_DURATION_MS_HEZE: 9000\n",
		"heze duration absent":      "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\n",
		"heze not in config at all": "SLOT_DURATION_MS: 12000\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := loadSlotConfig(t, extra)
			if got := cfg.SlotDurations(); len(got) != 1 || got[0] != (SlotDurationEntry{0, 12000}) {
				t.Errorf("schedule = %+v, want a single 12000ms segment", got)
			}
			if got, want := cfg.SlotDurationSummary(), "12s"; got != want {
				t.Errorf("summary = %q, want %q", got, want)
			}
			for _, epoch := range []uint64{0, 5, 10, 1000} {
				want := int64(devnet3Genesis)*1000 + int64(epoch)*32*12000
				if got := epochStartUnixMilli(t, cfg, epoch); got != want {
					t.Errorf("epoch %d start = %d, want %d", epoch, got, want)
				}
				got, _ := cfg.EpochAtTime(time.UnixMilli(want - 1))
				if epoch > 0 && got != epoch-1 {
					t.Errorf("epoch just before %d = %d", epoch, got)
				}
			}
			if _, ok := cfg.EpochStartTime(math.MaxUint64); ok {
				t.Error("FAR_FUTURE_EPOCH reported a start time")
			}
		})
	}
}

// Configs built without LoadConfig (tests, embedders) have no parsed schedule
// and must still derive the genesis duration from the struct fields.
func TestSlotDurationFallbacks(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want uint64
	}{
		{Config{SlotDurationMs: 6000, SecondsPerSlot: 12}, 6000},
		{Config{SecondsPerSlot: 6}, 6000},
		{Config{}, 12000},
		// An absurd legacy value cannot be represented, so it falls back.
		{Config{SecondsPerSlot: math.MaxUint64}, 12000},
	} {
		if got := tc.cfg.genesisSlotDurationMs(); got != tc.want {
			t.Errorf("%+v: slot duration = %d, want %d", tc.cfg, got, tc.want)
		}
		if got := tc.cfg.SlotDurations(); len(got) != 1 || got[0].DurationMs != tc.want {
			t.Errorf("%+v: schedule = %+v, want one %dms segment", tc.cfg, got, tc.want)
		}
	}
}

// A hand-built config skips LoadConfig's bound, so the Duration conversion
// must saturate rather than wrap negative.
func TestSlotDurationSaturates(t *testing.T) {
	cfg := Config{SlotDurationMs: math.MaxUint64}
	if got := cfg.SlotDuration(0); got != time.Duration(math.MaxInt64) {
		t.Errorf("SlotDuration = %v, want saturated maximum", got)
	}
	if got := cfg.SlotDurationSummary(); strings.HasPrefix(got, "-") {
		t.Errorf("summary went negative: %q", got)
	}
}

func TestSlotDurationOverflowGuards(t *testing.T) {
	cfg := loadSlotConfig(t, "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 9000\n")

	if _, ok := cfg.EpochStartTime(math.MaxUint64); ok {
		t.Error("FAR_FUTURE_EPOCH reported a start time")
	}
	if _, ok := cfg.slotStartMs(math.MaxUint64); ok {
		t.Error("max slot reported a start offset")
	}
	// A change scheduled so far out that its slot number overflows must leave
	// the earlier segments intact rather than panic or wrap.
	far := loadSlotConfig(t, "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 9000\n"+
		"ISAN_FORK_EPOCH: 18446744073709551000\nSLOT_DURATION_MS_ISAN: 6000\n")
	if got := epochStartUnixMilli(t, far, 6) - int64(devnet3Genesis)*1000; got != 5*32*12000+32*9000 {
		t.Errorf("epoch 6 starts %dms after genesis", got)
	}
	if got := far.slotAtMs(math.MaxUint64); got == 0 {
		t.Error("slotAtMs(max) = 0")
	}
}
