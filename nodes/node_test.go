package nodes

import (
	"crypto/ecdsa"
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

func TestUpdateENRInstallsSequenceZeroOnRecordlessNode(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(10, 20, 0, 1), Port: 9000}
	n := NewFromV4(discv4node.New(&key.PublicKey, addr), nil)
	record := signedRecordAt(t, key, 0, addr.IP)

	if !n.UpdateENR(record) {
		t.Fatal("sequence-zero ENR was rejected for a node with no record")
	}
	if got := n.Record(); got != record {
		t.Fatal("sequence-zero ENR was not installed")
	}
}

func TestSetV5AtSeqRejectsRecordlessSequenceZeroTarget(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(10, 20, 0, 2), Port: 9000}
	n := NewFromV4(discv4node.New(&key.PublicKey, addr), nil)
	probed, err := discv5node.New(signedRecordAt(t, key, 0, addr.IP))
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}

	if n.SetV5AtSeq(probed, 0) {
		t.Fatal("installed a probe result on a target with no current ENR")
	}
}

func TestAdoptInstallsSequenceZeroCarrierOnRecordlessNode(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(10, 20, 0, 13), Port: 9000}
	entry := NewFromV4(discv4node.New(&key.PublicKey, addr), nil)
	record := signedRecordAt(t, key, 0, addr.IP)
	v5, err := discv5node.New(record)
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}

	adopted, advanced := entry.AdoptProtocolsFrom(NewFromV5(v5, nil))
	if !adopted || !advanced {
		t.Fatalf("sequence-zero adoption = (%v, %v), want (true, true)", adopted, advanced)
	}
	if got := entry.Record(); got != record {
		t.Fatal("sequence-zero carrier ENR was not installed")
	}
}

func TestSetV5AtSeqRejectsProbeNodeThatAdvanced(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	record1 := signedRecordAt(t, key, 1, net.IPv4(10, 20, 0, 3))
	v4, err := discv4node.FromENR(record1, &net.UDPAddr{IP: record1.IP(), Port: int(record1.UDP())})
	if err != nil {
		t.Fatalf("new v4 node: %v", err)
	}
	n := NewFromV4(v4, nil)

	probed, err := discv5node.New(record1)
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	if !probed.UpdateENR(signedRecordAt(t, key, 2, net.IPv4(10, 20, 0, 4))) {
		t.Fatal("advance probe node: update rejected")
	}

	if n.SetV5AtSeq(probed, 1) {
		t.Fatal("installed a probe node that advanced beyond the probed record")
	}
}

func signedRecordSeq(t *testing.T, key *ecdsa.PrivateKey, seq uint64, ip net.IP) *enr.Record {
	t.Helper()
	rec := enr.New()
	if err := rec.Set("ip", ip); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(30303)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	rec.SetSeq(seq)
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return rec
}

// A probe describes the endpoints of the record it ran against. Applying it after
// a newer record arrived would install an endpoint the peer has already left, or
// clear a pointer that newer record brought in.
func TestApplyProbeResultRejectsStaleRecord(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	base, err := discv5node.New(signedRecordSeq(t, key, 1, net.IPv4(10, 30, 0, 1)))
	if err != nil {
		t.Fatalf("base v5: %v", err)
	}
	n := NewFromV5(base, nil)

	// The node moves on while the probe is outstanding.
	if !n.UpdateENR(signedRecordSeq(t, key, 7, net.IPv4(10, 30, 0, 2))) {
		t.Fatal("record did not advance")
	}

	v4 := discv4node.New(base.PublicKey(), base.Addr())
	if n.ApplyProbeResult(1, v4, true, nil, false) {
		t.Error("applied a probe result against a record the node had already left")
	}
	if n.HasV4() {
		t.Error("installed a v4 pointer from a superseded probe")
	}
	if !n.HasV5() {
		t.Error("cleared the v5 pointer from a superseded probe")
	}
}

// A probe that fails against the current record must be able to clear, and both
// protocol decisions have to land together rather than one at a time.
func TestApplyProbeResultAppliesBothDecisionsAtCurrentSeq(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	rec := signedRecordSeq(t, key, 4, net.IPv4(10, 31, 0, 1))
	base, err := discv5node.New(rec)
	if err != nil {
		t.Fatalf("base v5: %v", err)
	}
	n := NewFromV5(base, nil)

	v4 := discv4node.New(base.PublicKey(), base.Addr())
	if !n.ApplyProbeResult(4, v4, true, nil, false) {
		t.Fatal("probe at the current sequence was rejected")
	}
	if !n.HasV4() {
		t.Error("v4 confirmed by the probe was not installed")
	}
	if n.HasV5() {
		t.Error("v5 unconfirmed by the probe was not cleared")
	}
}

// TestUpdateENRRefreshesAddrFromAdvancedRecord verifies a v5-only node's addr
// follows an advancing record, so the persisted endpoint cannot go stale.
func TestUpdateENRRefreshesAddrFromAdvancedRecord(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	oldIP := net.IPv4(10, 21, 0, 1)
	newIP := net.IPv4(10, 21, 0, 2)
	v5, err := discv5node.New(signedRecordAt(t, key, 1, oldIP))
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	n := NewFromV5(v5, nil)

	if !n.UpdateENR(signedRecordAt(t, key, 2, newIP)) {
		t.Fatal("newer record was rejected")
	}
	if got := n.Addr().IP; !got.Equal(newIP) {
		t.Fatalf("addr = %v, want %v", got, newIP)
	}

	if n.UpdateENR(signedRecordAt(t, key, 1, oldIP)) {
		t.Fatal("older record was accepted")
	}
	if got := n.Addr().IP; !got.Equal(newIP) {
		t.Fatalf("addr moved on a stale record: %v", got)
	}

	noEndpoint := enr.New()
	noEndpoint.SetSeq(3)
	if err := noEndpoint.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !n.UpdateENR(noEndpoint) {
		t.Fatal("endpoint-less newer record was rejected")
	}
	if got := n.Addr().IP; !got.Equal(newIP) {
		t.Fatalf("addr cleared by an endpoint-less record: %v", got)
	}

	ip6 := net.ParseIP("2001:db8::1")
	sharedUDP := enr.New()
	if err := sharedUDP.Set("ip6", ip6.To16()); err != nil {
		t.Fatalf("set ip6: %v", err)
	}
	if err := sharedUDP.Set("udp", uint16(9100)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	sharedUDP.SetSeq(4)
	if err := sharedUDP.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !n.UpdateENR(sharedUDP) {
		t.Fatal("ip6 record was rejected")
	}
	if got := n.Addr(); !got.IP.Equal(ip6) || got.Port != 9100 {
		t.Fatalf("addr = %v, want [%v]:9100 from the ip6+udp record", got, ip6)
	}
}

// TestUpdateENRPreservesVerifiedV4Addr verifies an advancing record never moves
// a discv4-verified endpoint: that moves only on a matched PONG.
func TestUpdateENRPreservesVerifiedV4Addr(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	verified := &net.UDPAddr{IP: net.IPv4(10, 21, 1, 1), Port: 9000}
	advertised := net.IPv4(10, 21, 1, 2)
	n := NewFromV4(discv4node.New(&key.PublicKey, verified), nil)

	if !n.UpdateENR(signedRecordAt(t, key, 2, advertised)) {
		t.Fatal("newer record was rejected")
	}
	if got := n.Addr().IP; !got.Equal(verified.IP) {
		t.Fatalf("verified v4 addr was replaced by the advertised one: %v", got)
	}
}

// TestAdoptProtocolsFromRefreshesAddrOnAdvance verifies the record-advance path
// through adoption applies the same addr rules as UpdateENR.
func TestAdoptProtocolsFromRefreshesAddrOnAdvance(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	oldIP := net.IPv4(10, 22, 0, 1)
	newIP := net.IPv4(10, 22, 0, 2)

	v5Old, err := discv5node.New(signedRecordAt(t, key, 1, oldIP))
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	entry := NewFromV5(v5Old, nil)
	v5New, err := discv5node.New(signedRecordAt(t, key, 2, newIP))
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	if _, advanced := entry.AdoptProtocolsFrom(NewFromV5(v5New, nil)); !advanced {
		t.Fatal("newer carrier record did not advance")
	}
	if got := entry.Addr().IP; !got.Equal(newIP) {
		t.Fatalf("addr = %v, want %v", got, newIP)
	}

	verified := &net.UDPAddr{IP: net.IPv4(10, 22, 1, 1), Port: 9000}
	v4Entry := NewFromV4(discv4node.New(&key.PublicKey, verified), nil)
	v5Carrier, err := discv5node.New(signedRecordAt(t, key, 3, newIP))
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	if _, advanced := v4Entry.AdoptProtocolsFrom(NewFromV5(v5Carrier, nil)); !advanced {
		t.Fatal("newer carrier record did not advance")
	}
	if got := v4Entry.Addr().IP; !got.Equal(verified.IP) {
		t.Fatalf("verified v4 addr was replaced through adoption: %v", got)
	}
}

// TestAdoptProtocolsFromRefreshesAddrOnCombinedV4AdoptAndAdvance verifies the
// combined path: a v4 pointer adopted in the same call carries the other
// wrapper's endpoint, not one this node verified, so it must not block the
// addr refresh from the advancing record.
func TestAdoptProtocolsFromRefreshesAddrOnCombinedV4AdoptAndAdvance(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	oldIP := net.IPv4(10, 23, 0, 1)
	newIP := net.IPv4(10, 23, 0, 2)

	v5Old, err := discv5node.New(signedRecordAt(t, key, 1, oldIP))
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	entry := NewFromV5(v5Old, nil)

	carrierRecord := signedRecordAt(t, key, 2, newIP)
	carrier := NewFromV4(discv4node.New(&key.PublicKey, &net.UDPAddr{IP: newIP, Port: 9000}), nil)
	if !carrier.UpdateENR(carrierRecord) {
		t.Fatal("carrier record was not installed")
	}

	adopted, advanced := entry.AdoptProtocolsFrom(carrier)
	if !adopted || !advanced {
		t.Fatalf("adoption = (%v, %v), want (true, true)", adopted, advanced)
	}
	if got := entry.Addr().IP; !got.Equal(newIP) {
		t.Fatalf("addr = %v, want %v from the advancing record", got, newIP)
	}
}
