package clconfig

import (
	"math"
	"testing"
	"time"
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
