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

// TestNodeConcurrentFieldAccess exercises SetAddr/SetENR/SetStats against every
// reader of the guarded fields, including Enode and String which read addr
// directly. Under the race detector it fails if any access is unsynchronized.
func TestNodeConcurrentFieldAccess(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	n := New(&key.PublicKey, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303})

	rec := enr.New()
	if err := rec.Set("ip", net.IPv4(5, 6, 7, 8)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	shared := stats.NewSharedStats(time.Now())

	var wg sync.WaitGroup
	stop := make(chan struct{})

	writer := func(mutate func(i int)) {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				mutate(i)
			}
		}
	}

	wg.Add(3)
	go writer(func(i int) {
		n.SetAddr(&net.UDPAddr{IP: net.IPv4(9, 9, 9, byte(i%256)), Port: 30303})
	})
	go writer(func(i int) {
		if i%2 == 0 {
			n.SetENR(rec)
		} else {
			n.SetENR(nil)
		}
	})
	go writer(func(int) { n.SetStats(shared) })

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = n.Addr()
					_ = n.ENR()
					_ = n.Enode()
					_ = n.String()
					n.UpdateLastSeen()
					_ = n.LastSeen()
					n.MarkPingSent()
					_ = n.IsBonded()
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}
