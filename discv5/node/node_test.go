package node

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/stats"
)

func signedRecord(t *testing.T, seq uint64, port uint16) *enr.Record {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rec := enr.New()
	if err := rec.Set("ip", net.IPv4(3, 3, 3, 3)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", port); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	rec.SetSeq(seq)
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return rec
}

// TestNodeConcurrentENRAndStatsAccess exercises UpdateENR and SetStats against
// every reader of the guarded fields. Under the race detector it fails if any
// access to record, addr, tcpPort or the stats pointer is unsynchronized.
func TestNodeConcurrentENRAndStatsAccess(t *testing.T) {
	n, err := New(signedRecord(t, 1, 30303))
	if err != nil {
		t.Fatal(err)
	}
	newer := signedRecord(t, 2, 30304)
	shared := stats.NewSharedStats(time.Now())

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				n.UpdateENR(newer)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				n.SetStats(shared)
			}
		}
	}()

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = n.Record()
					_ = n.Addr()
					_ = n.IP()
					_ = n.UDPPort()
					_ = n.TCPPort()
					_ = n.PublicKey()
					_ = n.PeerID()
					_ = n.Digest()
					_ = n.GetStats()
					_ = n.CalculateScore(nil)
					_ = n.String()
					n.SetLastSeen(time.Now())
					n.IncrementFailureCount()
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestUpdateENRSeqMonotonicUnderConcurrency verifies interleaved refreshes can
// never install a lower-sequence record over a higher one.
func TestUpdateENRSeqMonotonicUnderConcurrency(t *testing.T) {
	n, err := New(signedRecord(t, 1, 30303))
	if err != nil {
		t.Fatal(err)
	}
	older := signedRecord(t, 5, 30305)
	newest := signedRecord(t, 9, 30309)

	var wg sync.WaitGroup
	for r := 0; r < 8; r++ {
		rec := older
		if r%2 == 0 {
			rec = newest
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				n.UpdateENR(rec)
			}
		}()
	}
	wg.Wait()

	if got := n.Record().Seq(); got != 9 {
		t.Fatalf("record seq = %d, want the highest installed sequence 9", got)
	}
}
