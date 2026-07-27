package services

import (
	"crypto/ecdsa"
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

func recordAtSeq(t *testing.T, key *ecdsa.PrivateKey, last byte, seq uint64) *enr.Record {
	t.Helper()
	rec := enr.New()
	if err := rec.Set("ip", net.IPv4(10, 0, 0, last)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(9000)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	rec.SetSeq(seq)
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return rec
}

// v5NodeAtSeq builds a node the way a discv5 NODES response does.
func v5NodeAtSeq(t *testing.T, key *ecdsa.PrivateKey, last byte, seq uint64) *nodedb.Node {
	t.Helper()
	v5, err := node.New(recordAtSeq(t, key, last, seq))
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	return nodedb.NewFromV5(v5, nil)
}

// v4NodeAtSeq builds a node the way the discv4 NEIGHBORS path does, where the
// record came from dialing the peer for its ENR rather than from a relay.
func v4NodeAtSeq(t *testing.T, key *ecdsa.PrivateKey, last byte, seq uint64) *nodedb.Node {
	t.Helper()
	v4 := v4node.New(&key.PublicKey, &net.UDPAddr{IP: net.IPv4(10, 0, 0, last), Port: 9000})
	v4.SetENR(recordAtSeq(t, key, last, seq))
	return nodedb.NewFromV4(v4, nil)
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

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// TestNoteDiscoveredRefreshesKnownNode covers the bug this whole path exists
// for: a peer we cannot bond with only ever learns a newer record when another
// discv5 peer relays it, so a known node with a higher sequence must reach
// admission without being treated as a new frontier candidate.
func TestNoteDiscoveredRefreshesKnownNode(t *testing.T) {
	key := testKey(t)
	known := v5NodeAtSeq(t, key, 1, 4)
	ls := quietLookupService(nil)

	tests := []struct {
		name      string
		candidate *nodedb.Node
		admitted  bool
	}{
		{"newer v5 record refreshes", v5NodeAtSeq(t, key, 1, 6), true},
		{"newer v4 record is not a relay", v4NodeAtSeq(t, key, 1, 6), false},
		{"equal sequence is not newer", v5NodeAtSeq(t, key, 1, 4), false},
		{"older sequence is ignored", v5NodeAtSeq(t, key, 1, 3), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := newDiscoveries([]*nodedb.Node{known})

			if frontier := ls.noteDiscovered(d, tc.candidate); frontier {
				t.Fatal("a known node must never re-enter the frontier")
			}

			got := d.admit()
			if tc.admitted && len(got) != 1 {
				t.Fatalf("admitted %d nodes, want the refreshed record", len(got))
			}
			if !tc.admitted && len(got) != 0 {
				t.Fatalf("admitted %d nodes, want none", len(got))
			}
		})
	}
}

// TestNoteDiscoveredEligibilityPrecedesDedupe pins the rule ordering: a v4
// record must not slip past the known-node gate just because it outranks a v5
// record already held for that node.
func TestNoteDiscoveredEligibilityPrecedesDedupe(t *testing.T) {
	key := testKey(t)
	known := v5NodeAtSeq(t, key, 1, 4)
	relayed := v5NodeAtSeq(t, key, 1, 5)
	dialed := v4NodeAtSeq(t, key, 1, 6)

	ls := quietLookupService(nil)
	d := newDiscoveries([]*nodedb.Node{known})

	ls.noteDiscovered(d, relayed)
	ls.noteDiscovered(d, dialed)

	got := d.admit()
	if len(got) != 1 {
		t.Fatalf("admitted %d nodes, want 1", len(got))
	}
	if !got[0].HasV5() || got[0].Record().Seq() != 5 {
		t.Fatalf("admitted seq %d (v5=%t), want the relayed v5 record at seq 5",
			got[0].Record().Seq(), got[0].HasV5())
	}
}

// TestNoteDiscoveredKeepsBestOfDuplicates verifies a newer duplicate replaces
// the record without queueing the peer for a second query in the same round.
func TestNoteDiscoveredKeepsBestOfDuplicates(t *testing.T) {
	key := testKey(t)
	ls := quietLookupService(nil)
	d := newDiscoveries(nil)

	if !ls.noteDiscovered(d, v5NodeAtSeq(t, key, 1, 5)) {
		t.Fatal("an unknown node should enter the frontier")
	}
	if ls.noteDiscovered(d, v5NodeAtSeq(t, key, 1, 6)) {
		t.Fatal("a duplicate must not enter the frontier twice")
	}

	got := d.admit()
	if len(got) != 1 {
		t.Fatalf("admitted %d nodes, want 1", len(got))
	}
	if got[0].Record().Seq() != 6 {
		t.Fatalf("admitted seq %d, want the newer duplicate at seq 6", got[0].Record().Seq())
	}
}

// TestAdmitSkipsRecordsOvertakenMidLookup covers a direct refresh landing while
// the lookup is still running: the relayed record is no longer newer by the
// time we admit, and re-offering it would run the fork filter against a record
// the table has already moved past.
func TestAdmitSkipsRecordsOvertakenMidLookup(t *testing.T) {
	key := testKey(t)
	known := v5NodeAtSeq(t, key, 1, 4)

	ls := quietLookupService(nil)
	d := newDiscoveries([]*nodedb.Node{known})

	ls.noteDiscovered(d, v5NodeAtSeq(t, key, 1, 5))

	known.UpdateENR(recordAtSeq(t, key, 1, 7))

	if got := d.admit(); len(got) != 0 {
		t.Fatalf("admitted %d nodes, want none once the table overtook them", len(got))
	}
}

// TestNoteDiscoveredSkipsSelf verifies our own relayed record never reaches
// admission, at any sequence number.
func TestNoteDiscoveredSkipsSelf(t *testing.T) {
	key := testKey(t)
	self := v5NodeAtSeq(t, key, 1, 1)

	ls := quietLookupService([][32]byte{self.ID()})
	d := newDiscoveries(nil)

	if ls.noteDiscovered(d, v5NodeAtSeq(t, key, 1, 9)) {
		t.Fatal("our own record entered the frontier")
	}
	if got := d.admit(); len(got) != 0 {
		t.Fatalf("admitted %d nodes, want none", len(got))
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
