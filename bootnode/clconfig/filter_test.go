package clconfig

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/enr"
)

func TestNextForkInfoReturnsUpcomingFork(t *testing.T) {
	const (
		secondsPerSlot = 12
		slotsPerEpoch  = 32
		currentEpoch   = 100
	)

	genesisTime := uint64(time.Now().Unix()) - (currentEpoch * secondsPerSlot * slotsPerEpoch) - 60

	cfg := &Config{
		SecondsPerSlot:      secondsPerSlot,
		customGenesisTime:   genesisTime,
		customSlotsPerEpoch: slotsPerEpoch,
		genesisForkVersion:  [4]byte{0x00, 0x00, 0x00, 0x01},
		forks: []forkDefinition{
			{name: "Altair", epoch: 0, parsedVersion: [4]byte{0x01, 0x00, 0x00, 0x00}},
			{name: "Capella", epoch: 50, parsedVersion: [4]byte{0x02, 0x00, 0x00, 0x00}},
			{name: "Deneb", epoch: 200, parsedVersion: [4]byte{0x03, 0x00, 0x00, 0x00}},
		},
	}

	filter := &ForkDigestFilter{config: cfg}
	nextVersion, nextEpoch := filter.nextForkInfo()

	if nextVersion != [4]byte{0x03, 0x00, 0x00, 0x00} {
		t.Fatalf("unexpected next fork version: got %x", nextVersion)
	}

	if nextEpoch != 200 {
		t.Fatalf("unexpected next fork epoch: got %d", nextEpoch)
	}
}

func TestNextForkInfoFallsBackToFarFuture(t *testing.T) {
	const (
		secondsPerSlot = 12
		slotsPerEpoch  = 32
		currentEpoch   = 100
	)

	genesisTime := uint64(time.Now().Unix()) - (currentEpoch * secondsPerSlot * slotsPerEpoch) - 60

	cfg := &Config{
		SecondsPerSlot:      secondsPerSlot,
		customGenesisTime:   genesisTime,
		customSlotsPerEpoch: slotsPerEpoch,
		genesisForkVersion:  [4]byte{0x00, 0x00, 0x00, 0x01},
		forks: []forkDefinition{
			{name: "Altair", epoch: 0, parsedVersion: [4]byte{0x01, 0x00, 0x00, 0x00}},
			{name: "Capella", epoch: 50, parsedVersion: [4]byte{0x02, 0x00, 0x00, 0x00}},
		},
	}

	filter := &ForkDigestFilter{config: cfg}
	nextVersion, nextEpoch := filter.nextForkInfo()

	if nextVersion != [4]byte{0x02, 0x00, 0x00, 0x00} {
		t.Fatalf("unexpected fallback next fork version: got %x", nextVersion)
	}

	if nextEpoch != math.MaxUint64 {
		t.Fatalf("unexpected fallback next fork epoch: got %d", nextEpoch)
	}
}

// TestFilterSkipsRecordsWithoutEth2: a record with no eth2 entry is an
// execution node, not an invalid consensus node, so it must not move any
// counter (mirrors the EL side's RecordELAdmission gate). A malformed eth2
// entry still counts as invalid.
func TestFilterSkipsRecordsWithoutEth2(t *testing.T) {
	cfg := &Config{
		SecondsPerSlot:      12,
		customSlotsPerEpoch: 32,
		genesisForkVersion:  [4]byte{0x00, 0x00, 0x00, 0x01},
		forks: []forkDefinition{
			{name: "Altair", epoch: 0, parsedVersion: [4]byte{0x01, 0x00, 0x00, 0x00}},
		},
	}
	cfg.SetGenesisTime(uint64(time.Now().Unix()) - 60)
	filter := NewForkDigestFilter(cfg, time.Hour)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	noEth2 := enr.New()
	if err := noEth2.Set("ip", net.IPv4(1, 2, 3, 4)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	noEth2.SetSeq(1)
	if err := noEth2.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if filter.Filter(noEth2) {
		t.Fatal("record without eth2 passed the CL filter")
	}
	stats := filter.GetStats()
	if stats.TotalChecks != 0 || stats.RejectedInvalid != 0 {
		t.Fatalf("no-eth2 record moved counters: checks=%d rejectedInvalid=%d, want 0/0",
			stats.TotalChecks, stats.RejectedInvalid)
	}

	malformed := enr.New()
	if err := malformed.Set("eth2", []byte{0x01, 0x02}); err != nil {
		t.Fatalf("set eth2: %v", err)
	}
	malformed.SetSeq(1)
	if err := malformed.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if filter.Filter(malformed) {
		t.Fatal("malformed eth2 passed the CL filter")
	}
	stats = filter.GetStats()
	if stats.TotalChecks != 1 || stats.RejectedInvalid != 1 {
		t.Fatalf("malformed eth2 counters: checks=%d rejectedInvalid=%d, want 1/1",
			stats.TotalChecks, stats.RejectedInvalid)
	}

	undecodable := enr.New()
	if err := undecodable.Set("eth2", []uint64{1, 2}); err != nil {
		t.Fatalf("set eth2: %v", err)
	}
	undecodable.SetSeq(1)
	if err := undecodable.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if filter.Filter(undecodable) {
		t.Fatal("undecodable eth2 passed the CL filter")
	}
	stats = filter.GetStats()
	if stats.TotalChecks != 2 || stats.RejectedInvalid != 2 {
		t.Fatalf("undecodable eth2 counters: checks=%d rejectedInvalid=%d, want 2/2",
			stats.TotalChecks, stats.RejectedInvalid)
	}
}

// TestForkDigestFilterUpdateTransition verifies Update() tracks an epoch
// crossing: the current digest swaps, the old digest lands in the grace map
// and stays accepted, and the recomputed eth2 field reflects the new digest.
func TestForkDigestFilterUpdateTransition(t *testing.T) {
	const (
		secondsPerSlot = 12
		slotsPerEpoch  = 32
	)
	cfg := &Config{
		SecondsPerSlot:      secondsPerSlot,
		customSlotsPerEpoch: slotsPerEpoch,
		genesisForkVersion:  [4]byte{0x00, 0x00, 0x00, 0x01},
		forks: []forkDefinition{
			{name: "Altair", epoch: 0, parsedVersion: [4]byte{0x01, 0x00, 0x00, 0x00}},
			{name: "Capella", epoch: 100, parsedVersion: [4]byte{0x02, 0x00, 0x00, 0x00}},
		},
	}
	cfg.SetGenesisTime(uint64(time.Now().Unix()) - (50 * secondsPerSlot * slotsPerEpoch) - 60)

	filter := NewForkDigestFilter(cfg, time.Hour)
	before := cfg.GetForkDigestForEpoch(50)
	after := cfg.GetForkDigestForEpoch(100)
	if got := filter.GetStats().CurrentDigest; got != before {
		t.Fatalf("initial digest = %s, want pre-transition %s", got.String(), before.String())
	}

	cfg.SetGenesisTime(uint64(time.Now().Unix()) - (150 * secondsPerSlot * slotsPerEpoch) - 60)
	filter.Update()

	stats := filter.GetStats()
	if stats.CurrentDigest != after {
		t.Fatalf("post-update digest = %s, want %s", stats.CurrentDigest.String(), after.String())
	}
	if stats.OldDigests != 1 {
		t.Fatalf("old digests = %d, want the pre-transition digest in the grace map", stats.OldDigests)
	}
	field := filter.ComputeEth2Field()
	if len(field) < 4 {
		t.Fatalf("eth2 field too short: %d bytes", len(field))
	}
	var gotDigest ForkDigest
	copy(gotDigest[:], field[:4])
	if gotDigest != after {
		t.Fatalf("eth2 field digest = %s, want post-transition %s", gotDigest.String(), after.String())
	}
}
