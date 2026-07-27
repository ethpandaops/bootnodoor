package nodes

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	discv4node "github.com/ethpandaops/bootnodoor/discv4/node"
	discv5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
)

// newTestNode builds a node for exercising the protocol-pointer accessors.
// nodeStats is left nil so SetV4/SetV5 only touch the v4Node/v5Node pointers,
// keeping these tests focused on their synchronization.
func newTestNode(t *testing.T) *Node {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &Node{
		pubKey: &key.PublicKey,
		addr:   &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303},
	}
}

func makeV4(t *testing.T) *discv4node.Node {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return discv4node.New(&key.PublicKey, &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 30303})
}

func makeV5(t *testing.T) *discv5node.Node {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rec := enr.New()
	if err := rec.Set("ip", net.IPv4(3, 3, 3, 3)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(30303)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	v5, err := discv5node.New(rec)
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	return v5
}

// TestNodeConcurrentProtocolPointerAccess exercises the readers and writers of
// the v4Node/v5Node pointers concurrently. Under the race detector it fails if
// any access to those pointers is unsynchronized.
func TestNodeConcurrentProtocolPointerAccess(t *testing.T) {
	n := newTestNode(t)
	v4 := makeV4(t)
	v5 := makeV5(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	writer := func(set func(i int)) {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				set(i)
			}
		}
	}

	wg.Add(2)
	go writer(func(i int) {
		if i%2 == 0 {
			n.SetV4(v4)
		} else {
			n.SetV4(nil)
		}
	})
	go writer(func(i int) {
		if i%2 == 0 {
			n.SetV5(v5)
		} else {
			n.SetV5(nil)
		}
	})

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = n.V4()
					_ = n.V5()
					_ = n.HasV4()
					_ = n.HasV5()
					_ = n.PeerID()
					_ = n.Enode()
					_ = n.String()
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestNodeNoNilDerefDuringProtocolSwap targets the check-then-deref reader
// PeerID: while a node repeatedly gains and loses its v5 support, PeerID must
// never dereference a pointer that was cleared between the nil check and the
// call. CalculateScore reads the same pointer through the identical locked
// path.
func TestNodeNoNilDerefDuringProtocolSwap(t *testing.T) {
	n := newTestNode(t)
	v5 := makeV5(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				if i%2 == 0 {
					n.SetV5(v5)
				} else {
					n.SetV5(nil)
				}
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
					_ = n.PeerID()
					_ = n.V5()
					_ = n.HasV5()
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}
