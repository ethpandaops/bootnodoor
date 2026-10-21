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

func loadSlotConfig(t *testing.T, extra string) *Config {
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

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
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
		"heze duration zero":        "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 0\n",
		"heze not in config at all": "SLOT_DURATION_MS: 12000\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := loadSlotConfig(t, extra)
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

func TestSlotDurationFallbacks(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want uint64
	}{
		{Config{SlotDurationMs: 6000, SecondsPerSlot: 12}, 6000},
		{Config{SecondsPerSlot: 6}, 6000},
		{Config{}, 12000},
	} {
		if got := tc.cfg.genesisSlotDurationMs(); got != tc.want {
			t.Errorf("%+v: slot duration = %d, want %d", tc.cfg, got, tc.want)
		}
	}
}

func TestHezeFarFutureEpochStartOverflow(t *testing.T) {
	cfg := loadSlotConfig(t, "SLOT_DURATION_MS: 12000\nHEZE_FORK_EPOCH: 5\nSLOT_DURATION_MS_HEZE: 9000\n")

	if _, ok := cfg.EpochStartTime(math.MaxUint64); ok {
		t.Error("FAR_FUTURE_EPOCH reported a start time")
	}
	if _, ok := cfg.slotStartMs(math.MaxUint64); ok {
		t.Error("max slot reported a start offset")
	}
}
