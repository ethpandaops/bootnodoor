package clconfig

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/enr"
)

func admitTestFilter(t *testing.T) *ForkDigestFilter {
	t.Helper()

	cfg := &Config{
		SecondsPerSlot:      12,
		customSlotsPerEpoch: 32,
		genesisForkVersion:  [4]byte{0x00, 0x00, 0x00, 0x01},
		forks: []forkDefinition{
			{name: "Altair", epoch: 0, parsedVersion: [4]byte{0x01, 0x00, 0x00, 0x00}},
		},
	}
	cfg.SetGenesisTime(uint64(time.Now().Unix()) - 60)
	return NewForkDigestFilter(cfg, time.Hour)
}

func recordWithEth2(t *testing.T, eth2 []byte) *enr.Record {
	t.Helper()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rec := enr.New()
	if err := rec.Set("ip", net.IPv4(1, 2, 3, 4)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if eth2 != nil {
		if err := rec.Set("eth2", eth2); err != nil {
			t.Fatalf("set eth2: %v", err)
		}
	}
	rec.SetSeq(1)
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return rec
}

// Matches is the per-packet classification entry point, so it must decide
// without moving any counter — those numbers report admissions, and packet
// traffic dwarfs admissions by orders of magnitude.
func TestMatchesRecordsNoStats(t *testing.T) {
	filter := admitTestFilter(t)
	current := filter.GetCurrentForkDigest()

	cases := []struct {
		name string
		eth2 []byte
		want bool
	}{
		{"no eth2", nil, false},
		{"malformed", []byte{0x01, 0x02}, false},
		{"current digest", EncodeETH2Field(current, [4]byte{0x01, 0x00, 0x00, 0x00}, ^uint64(0)), true},
		{"unknown digest", EncodeETH2Field(ForkDigest{0xde, 0xad, 0xbe, 0xef}, [4]byte{}, 0), false},
	}

	for _, tc := range cases {
		rec := recordWithEth2(t, tc.eth2)
		if got := filter.Matches(rec); got != tc.want {
			t.Errorf("Matches(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}

	stats := filter.GetStats()
	if stats.TotalChecks != 0 || stats.AcceptedCurrent != 0 || stats.AcceptedOld != 0 ||
		stats.AcceptedHistorical != 0 || stats.RejectedInvalid != 0 {
		t.Fatalf("Matches moved counters: %+v", stats)
	}
}

// Admit is the only counting entry point, and TotalChecks must always equal the
// sum of the buckets — the web UI renders them in one table, so a reader must
// never see rows that do not add up.
func TestAdmitRecordsOneBucketPerCall(t *testing.T) {
	filter := admitTestFilter(t)
	current := filter.GetCurrentForkDigest()

	cases := []struct {
		name        string
		eth2        []byte
		wantAccept  bool
		wantChecks  int
		wantCurrent int
		wantInvalid int
	}{
		{"no eth2 is uncounted", nil, false, 0, 0, 0},
		{"current digest", EncodeETH2Field(current, [4]byte{0x01, 0x00, 0x00, 0x00}, ^uint64(0)), true, 1, 1, 0},
		{"unknown digest", EncodeETH2Field(ForkDigest{0xde, 0xad, 0xbe, 0xef}, [4]byte{}, 0), false, 2, 1, 1},
		{"malformed", []byte{0x01, 0x02}, false, 3, 1, 2},
	}

	for _, tc := range cases {
		rec := recordWithEth2(t, tc.eth2)
		if got := filter.Admit(rec); got != tc.wantAccept {
			t.Errorf("Admit(%s) = %v, want %v", tc.name, got, tc.wantAccept)
		}

		stats := filter.GetStats()
		if stats.TotalChecks != tc.wantChecks {
			t.Errorf("after %s: TotalChecks = %d, want %d", tc.name, stats.TotalChecks, tc.wantChecks)
		}
		if stats.AcceptedCurrent != tc.wantCurrent {
			t.Errorf("after %s: AcceptedCurrent = %d, want %d", tc.name, stats.AcceptedCurrent, tc.wantCurrent)
		}
		if stats.RejectedInvalid != tc.wantInvalid {
			t.Errorf("after %s: RejectedInvalid = %d, want %d", tc.name, stats.RejectedInvalid, tc.wantInvalid)
		}

		sum := stats.AcceptedCurrent + stats.AcceptedOld + stats.AcceptedHistorical + stats.RejectedInvalid
		if stats.TotalChecks != sum {
			t.Errorf("after %s: TotalChecks = %d but buckets sum to %d", tc.name, stats.TotalChecks, sum)
		}
	}
}

// Update mutates oldForkDigests while packets are being filtered, so the digest
// lookups must happen under the lock. Publishing the map reference and indexing
// it afterwards is a concurrent map read/write, which aborts the process.
func TestAdmitConcurrentWithUpdate(t *testing.T) {
	filter := admitTestFilter(t)

	rec := recordWithEth2(t, EncodeETH2Field(ForkDigest{0x11, 0x22, 0x33, 0x44}, [4]byte{}, 0))

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Update only writes oldForkDigests on a fork activation or a grace expiry,
	// so seed an already-expired entry each round to make its cleanup loop
	// delete — the same map write, just at test frequency.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				filter.mu.Lock()
				filter.oldForkDigests[ForkDigest{0x11, 0x22, 0x33, 0x44}] = time.Now().Add(-2 * time.Hour)
				filter.mu.Unlock()
				filter.Update()
			}
		}
	}()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if i%2 == 0 {
					filter.Admit(rec)
				} else {
					filter.Matches(rec)
				}
			}
		}(i)
	}

	// The Update loop runs until the readers finish, then is joined separately.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	<-done

	stats := filter.GetStats()
	sum := stats.AcceptedCurrent + stats.AcceptedOld + stats.AcceptedHistorical + stats.RejectedInvalid
	if stats.TotalChecks != sum {
		t.Fatalf("TotalChecks = %d but buckets sum to %d under concurrency", stats.TotalChecks, sum)
	}
}
