package clconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func enumerationConfig(currentEpoch uint64) *Config {
	const (
		secondsPerSlot = 12
		slotsPerEpoch  = 32
	)
	return &Config{
		SecondsPerSlot:      secondsPerSlot,
		customGenesisTime:   uint64(time.Now().Unix()) - (currentEpoch * secondsPerSlot * slotsPerEpoch) - 60,
		customSlotsPerEpoch: slotsPerEpoch,
		genesisForkVersion:  [4]byte{0x00, 0x00, 0x00, 0x01},
		forks: []forkDefinition{
			{name: "Altair", epoch: 0, parsedVersion: [4]byte{0x01, 0x00, 0x00, 0x00}},
			{name: "Bellatrix", epoch: 0, parsedVersion: [4]byte{0x02, 0x00, 0x00, 0x00}},
			{name: "Capella", epoch: 50, parsedVersion: [4]byte{0x03, 0x00, 0x00, 0x00}},
		},
	}
}

// TestGetAllForkDigestsEqualsPerEpochEnumeration pins the unified digest
// computation: one digest per boundary epoch through GetForkDigestForEpoch,
// no phantom digests for same-epoch intermediate forks, and the live current
// digest always contained in the set.
func TestGetAllForkDigestsEqualsPerEpochEnumeration(t *testing.T) {
	for _, currentEpoch := range []uint64{10, 100} {
		cfg := enumerationConfig(currentEpoch)

		digests := cfg.GetAllForkDigests()
		if len(digests) != 2 {
			t.Fatalf("epoch %d: enumerated %d digests, want 2 boundaries (0, 50) with no phantom same-epoch intermediates", currentEpoch, len(digests))
		}
		if digests[0] != cfg.GetForkDigestForEpoch(0) || digests[1] != cfg.GetForkDigestForEpoch(50) {
			t.Fatalf("epoch %d: enumeration diverges from GetForkDigestForEpoch", currentEpoch)
		}

		current := cfg.GetCurrentForkDigest()
		found := false
		for _, d := range digests {
			if d == current {
				found = true
			}
		}
		if !found {
			t.Fatalf("epoch %d: current digest %s not in enumerated set", currentEpoch, current.String())
		}

		infos := cfg.GetAllForkDigestInfos()
		if len(infos) != len(digests) {
			t.Fatalf("epoch %d: infos (%d) and digests (%d) disagree", currentEpoch, len(infos), len(digests))
		}
		if infos[0].Name != "Bellatrix" || infos[1].Name != "Capella" {
			t.Fatalf("epoch %d: info names = %q, %q; want the wire-active fork per boundary", currentEpoch, infos[0].Name, infos[1].Name)
		}
	}

	cfg := enumerationConfig(100)
	if got := cfg.GetPreviousForkDigest(); got != cfg.GetForkDigestForEpoch(0) {
		t.Fatalf("previous digest = %s, want the epoch-0 boundary digest", got.String())
	}
	if got := cfg.GetPreviousForkName(); got != "Bellatrix" {
		t.Fatalf("previous fork name = %q, want Bellatrix", got)
	}
}

// TestBlobScheduleSortedAtParse verifies an unsorted BLOB_SCHEDULE is sorted
// on load, so GetBlobParamsForEpoch's early break returns the right entry.
func TestBlobScheduleSortedAtParse(t *testing.T) {
	yaml := `
CONFIG_NAME: sorttest
MIN_GENESIS_TIME: 1700000000
GENESIS_DELAY: 0
GENESIS_FORK_VERSION: 0x00000001
SECONDS_PER_SLOT: 12
ELECTRA_FORK_EPOCH: 10
ELECTRA_FORK_VERSION: 0x05000001
FULU_FORK_EPOCH: 100
FULU_FORK_VERSION: 0x06000001
MAX_BLOBS_PER_BLOCK_ELECTRA: 9
BLOB_SCHEDULE:
  - EPOCH: 300
    MAX_BLOBS_PER_BLOCK: 21
  - EPOCH: 100
    MAX_BLOBS_PER_BLOCK: 12
  - EPOCH: 200
    MAX_BLOBS_PER_BLOCK: 15
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i < len(cfg.BlobSchedule); i++ {
		if cfg.BlobSchedule[i].Epoch < cfg.BlobSchedule[i-1].Epoch {
			t.Fatalf("blob schedule not sorted: %+v", cfg.BlobSchedule)
		}
	}
	if got := cfg.GetBlobParamsForEpoch(250); got == nil || got.MaxBlobsPerBlock != 15 {
		t.Fatalf("blob params at 250 = %+v, want the epoch-200 entry (15)", got)
	}
	if got := cfg.GetBlobParamsForEpoch(50); got != nil {
		t.Fatalf("blob params before fulu = %+v, want nil", got)
	}
	if got := cfg.GetBlobParamsForEpoch(150); got == nil || got.MaxBlobsPerBlock != 12 {
		t.Fatalf("blob params at 150 = %+v, want the epoch-100 entry (12)", got)
	}
}

// TestEncodeETH2FieldEpochIsLittleEndian pins the SSZ encoding of
// ENRForkID.next_fork_epoch. A big-endian epoch is byte-identical when the
// value is FAR_FUTURE_EPOCH, so only a scheduled fork exposes the difference —
// which is why every all-forks-at-genesis devnet missed this.
func TestEncodeETH2FieldEpochIsLittleEndian(t *testing.T) {
	digest := ForkDigest{0xaa, 0xbb, 0xcc, 0xdd}
	version := [4]byte{0x70, 0x00, 0x00, 0x38}

	field := EncodeETH2Field(digest, version, 5)
	if len(field) != 16 {
		t.Fatalf("eth2 field = %d bytes, want 16", len(field))
	}
	want := []byte{0x05, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(field[8:16], want) {
		t.Fatalf("next_fork_epoch bytes = % x, want % x (little-endian 5)", field[8:16], want)
	}

	// FAR_FUTURE_EPOCH is palindromic, so it must round-trip either way.
	if got := EncodeETH2Field(digest, version, ^uint64(0)); !bytes.Equal(got[8:16], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Fatalf("far-future epoch bytes = % x", got[8:16])
	}
}
