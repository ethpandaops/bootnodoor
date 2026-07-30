package bootnode

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
)

func boundaryService(t *testing.T, genesis uint64, electraEpoch string) *Service {
	t.Helper()

	yaml := "PRESET_BASE: mainnet\n" +
		"MIN_GENESIS_TIME: " + strconv.FormatUint(genesis, 10) + "\n" +
		"GENESIS_DELAY: 0\n" +
		"SECONDS_PER_SLOT: 12\n" +
		"SLOTS_PER_EPOCH: 32\n" +
		"GENESIS_FORK_VERSION: 0x10000000\n" +
		"ALTAIR_FORK_VERSION: 0x20000000\nALTAIR_FORK_EPOCH: 0\n" +
		"BELLATRIX_FORK_VERSION: 0x30000000\nBELLATRIX_FORK_EPOCH: 0\n" +
		"CAPELLA_FORK_VERSION: 0x40000000\nCAPELLA_FORK_EPOCH: 0\n" +
		"DENEB_FORK_VERSION: 0x50000000\nDENEB_FORK_EPOCH: 0\n" +
		"ELECTRA_FORK_VERSION: 0x60000000\nELECTRA_FORK_EPOCH: " + electraEpoch + "\n"

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cl, err := clconfig.LoadConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return &Service{config: &Config{CLConfig: cl}}
}

// A free-running ticker left the record advertising the previous fork for up to
// its full period, so the wait has to track the next scheduled boundary.
func TestNextForkBoundaryTracksSchedule(t *testing.T) {
	now := time.Now()
	s := boundaryService(t, uint64(now.Unix()), "1")

	next, ok := s.nextForkBoundary(now)
	if !ok {
		t.Fatal("no boundary found for an epoch-1 fork")
	}
	wantAt := now.Add(384 * time.Second)
	if diff := next.Sub(wantAt); diff > 2*time.Second || diff < -2*time.Second {
		t.Errorf("boundary = %v, want ~%v", next, wantAt)
	}
}

// Boundaries already passed must not yield a negative or immediate timer.
func TestNextForkBoundaryAllPassed(t *testing.T) {
	now := time.Now()
	s := boundaryService(t, uint64(now.Add(-10*time.Hour).Unix()), "1")

	if _, ok := s.nextForkBoundary(now); ok {
		t.Error("a past boundary was reported as upcoming")
	}
	if delay := s.nextForkRefreshDelay(); delay != maxForkRefreshDelay {
		t.Errorf("delay = %v, want the backstop %v", delay, maxForkRefreshDelay)
	}
}

// With no genesis data no epoch has a wall clock, so the backstop must carry the
// refresh instead of the timer firing continuously.
func TestNextForkBoundaryWithoutGenesis(t *testing.T) {
	s := &Service{config: &Config{CLConfig: &clconfig.Config{SecondsPerSlot: 12}}}

	if _, ok := s.nextForkBoundary(time.Now()); ok {
		t.Error("a boundary was reported with no genesis time")
	}
	if delay := s.nextForkRefreshDelay(); delay != maxForkRefreshDelay {
		t.Errorf("delay = %v, want the backstop %v", delay, maxForkRefreshDelay)
	}
}

// A distant boundary is capped so the reconciliation backstop still runs.
// Genesis is placed beyond the settle window, since genesis is itself a boundary
// and would otherwise put this inside the post-boundary polling period.
func TestNextForkRefreshDelayCapped(t *testing.T) {
	now := time.Now()
	s := boundaryService(t, uint64(now.Add(-2*forkSettleWindow).Unix()), "100")

	if delay := s.nextForkRefreshDelay(); delay != maxForkRefreshDelay {
		t.Errorf("delay = %v, want the cap %v", delay, maxForkRefreshDelay)
	}
}

// A boundary that has just passed is skipped by nextForkBoundary, so arming for
// the following one leaves a full backstop hole: a fire landing on the boundary
// before the digest is computable does not look again for a minute. A devnet BPO
// transition took 75s that way.
func TestForkRefreshPollsAfterABoundary(t *testing.T) {
	now := time.Now()
	genesis := uint64(now.Add(-384 * time.Second).Unix())

	s := boundaryService(t, genesis, "1")

	last, ok := s.lastForkBoundary(now)
	if !ok {
		t.Fatal("the boundary that just passed was not reported")
	}
	if now.Sub(last) > 5*time.Second {
		t.Fatalf("last boundary = %v, want ~now", last)
	}

	if delay := s.nextForkRefreshDelay(); delay != forkSettlePoll {
		t.Errorf("delay just after a boundary = %v, want the settle poll %v", delay, forkSettlePoll)
	}
}

// Outside the settle window the refresh must go back to waiting for the next
// boundary rather than polling every second forever.
func TestForkRefreshStopsPollingAfterSettleWindow(t *testing.T) {
	now := time.Now()
	genesis := uint64(now.Add(-(384 + 200) * time.Second).Unix())

	s := boundaryService(t, genesis, "1")

	if delay := s.nextForkRefreshDelay(); delay == forkSettlePoll {
		t.Error("still polling long after the boundary settled")
	}
}
