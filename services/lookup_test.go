package services

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	v4node "github.com/ethpandaops/bootnodoor/discv4/node"
	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
	nodedb "github.com/ethpandaops/bootnodoor/nodes"
	"github.com/sirupsen/logrus"
)

func testNode(t *testing.T, last byte) *nodedb.Node {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rec := enr.New()
	if err := rec.Set("ip", net.IPv4(10, 0, 0, last)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(9000)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	v5, err := node.New(rec)
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	return nodedb.NewFromV5(v5, nil)
}

func quietLookupService(localIDs [][32]byte) *LookupService {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	return NewLookupService(Config{LocalIDs: localIDs, Logger: logger})
}

// TestSelectNodesToQuerySkipsSelf verifies our own identities are never chosen
// as query targets, even when a table-sourced candidate list contains them.
func TestSelectNodesToQuerySkipsSelf(t *testing.T) {
	selfEL := testNode(t, 1)
	selfCL := testNode(t, 2)
	peer := testNode(t, 3)

	ls := quietLookupService([][32]byte{selfEL.ID(), selfCL.ID()})

	candidates := []*nodedb.Node{selfEL, selfCL, peer}
	got := ls.selectNodesToQuery(candidates, map[node.ID]bool{}, node.ID(peer.ID()), 3, false)

	if len(got) != 1 {
		t.Fatalf("selected %d nodes, want only the non-self peer", len(got))
	}
	if got[0].ID() != peer.ID() {
		t.Fatalf("selected %x, want the peer %x", got[0].ID(), peer.ID())
	}
}

// TestIsLocalCoversBothIdentities verifies the check spans every configured
// identity (dual EL/CL keys) and accepts discv4 IDs too.
func TestIsLocalCoversBothIdentities(t *testing.T) {
	selfEL := testNode(t, 1)
	selfCL := testNode(t, 2)
	peer := testNode(t, 3)

	ls := quietLookupService([][32]byte{selfEL.ID(), selfCL.ID()})

	if !ls.isLocal(selfEL.ID()) || !ls.isLocal(selfCL.ID()) {
		t.Fatal("a configured local identity was not recognized as self")
	}
	if ls.isLocal(peer.ID()) {
		t.Fatal("a remote peer was misidentified as self")
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	v4Self := v4node.New(&key.PublicKey, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 9000})
	ls4 := quietLookupService([][32]byte{v4Self.ID()})
	if !ls4.isLocal(v4Self.ID()) {
		t.Fatal("a discv4 local id was not recognized as self")
	}
}

// TestPingServiceStatsRace exercises the counters from many goroutines while a
// reader polls GetStats, which is what the web UI handler does.
func TestPingServiceStatsRace(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	ps := NewPingService(nil, nil, logger)

	var writers, reader sync.WaitGroup
	stop := make(chan struct{})

	reader.Add(1)
	go func() {
		defer reader.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = ps.GetStats()
			}
		}
	}()

	for i := 0; i < 4; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for j := 0; j < 200; j++ {
				ps.countPingSent()
				ps.countProtocol(j%2 == 0)
				ps.countPong(time.Millisecond)
				ps.countTimeout()
			}
		}()
	}

	writers.Wait()
	close(stop)
	reader.Wait()

	stats := ps.GetStats()
	if stats.PingsSent != 800 || stats.PongsReceived != 800 || stats.PingTimeouts != 800 {
		t.Fatalf("counters lost updates: %+v", stats)
	}
	if stats.PingsV5+stats.PingsV4 != 800 {
		t.Fatalf("protocol counters = %d+%d, want 800 total", stats.PingsV5, stats.PingsV4)
	}
}
