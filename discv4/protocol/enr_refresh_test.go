package protocol

import (
	"context"
	"crypto/ecdsa"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/discv4/node"
)

// scriptedPeer decodes what the handler sends and answers it the way a real peer
// would. recordingTransport cannot be used here: it discards the packet bytes,
// and a PONG-triggered refresh emits nothing unless its PINGs are answered.
type scriptedPeer struct {
	t   *testing.T
	h   *Handler
	key *ecdsa.PrivateKey

	mu           sync.Mutex
	pings        int
	enrReqs      int
	enrSeq       uint64
	stopped      bool
	bumpEachPong bool
	pongAddr     *net.UDPAddr
}

func (p *scriptedPeer) SendTo(data []byte, to *net.UDPAddr) error {
	packet, _, hash, err := Decode(data)
	if err != nil {
		return nil
	}

	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return nil
	}
	switch packet.(type) {
	case *Ping:
		p.pings++
		// Bump on PING only, so every round's PONG advertises strictly more than
		// the record the previous round installed. Bumping on the ENRREQUEST too
		// would put the installed record ahead and the loop would not re-arm.
		if p.bumpEachPong {
			p.enrSeq++
		}
	case *ENRRequest:
		p.enrReqs++
	}
	seq := p.enrSeq
	p.mu.Unlock()

	var reply []byte
	switch packet.(type) {
	case *Ping:
		reply, _ = EncodePacket(p.key, &Pong{
			To:         Endpoint{IP: net.IPv4(127, 0, 0, 1), UDP: 30303},
			ReplyTok:   hash,
			Expiration: MakeExpiration(20 * time.Second),
			ENRSeq:     seq,
		})
	case *ENRRequest:
		reply, _ = EncodePacket(p.key, &ENRResponse{
			ReplyTok: hash,
			Record:   signedV4Record(p.t, p.key, seq),
		})
	}

	if reply != nil {
		go func() {
			if err := p.h.HandlePacket(reply, p.pongAddr, nil); err != nil {
				p.t.Logf("reply not accepted: %v", err)
			}
		}()
	}
	return nil
}

func (p *scriptedPeer) Send(data []byte, to *net.UDPAddr, _ *net.UDPAddr) error {
	return p.SendTo(data, to)
}

func (p *scriptedPeer) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pings, p.enrReqs
}

func (p *scriptedPeer) stop() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
}

// A PONG advertising a sequence above the cached record starts an ENR refresh.
// That refresh PINGs, and its PONG re-enters handlePong with the cached sequence
// still stale, so an unguarded trigger spawns another refresh at RTT speed —
// thousands of PING/ENRREQUEST pairs against one peer in the devnet capture.
func TestPongDrivenENRRefreshRunsOnce(t *testing.T) {
	peer := &scriptedPeer{t: t, enrSeq: 5, pongAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303}}

	h, cancel := newScriptedHandler(t, peer)
	defer cancel()
	peer.h = h

	n, key := makeKeyedNode(t, 30303)
	peer.key = key
	if !n.UpdateENR(signedV4Record(t, key, 1)) {
		t.Fatal("seed record was not installed")
	}
	h.nodesMu.Lock()
	h.nodes[n.ID()] = n
	h.nodesMu.Unlock()

	req, err := h.addPendingRequest([]byte("seed-ping-hash"), n, PingPacket, n.Addr())
	if err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

	pong := &Pong{
		To:         Endpoint{IP: net.IPv4(127, 0, 0, 1), UDP: 30303},
		ReplyTok:   req.RequestHash,
		Expiration: MakeExpiration(20 * time.Second),
		ENRSeq:     5,
	}
	data, err := EncodePacket(key, pong)
	if err != nil {
		t.Fatalf("encode pong: %v", err)
	}
	if err := h.HandlePacket(data, n.Addr(), nil); err != nil {
		t.Fatalf("handle pong: %v", err)
	}

	time.Sleep(2 * time.Second)
	peer.stop()
	pings, enrReqs := peer.counts()

	if enrReqs > 1 {
		t.Errorf("ENRREQUESTs sent = %d, want at most 1 (refresh not coalesced)", enrReqs)
	}
	if pings > 2 {
		t.Errorf("PINGs sent = %d, want at most 2 (refresh not coalesced)", pings)
	}
	t.Logf("pings=%d enrRequests=%d", pings, enrReqs)
}

func newScriptedHandler(t *testing.T, peer *scriptedPeer) (*Handler, func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	h := NewHandler(ctx, HandlerConfig{
		PrivateKey:       mustHandlerKey(t),
		LocalAddr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30304},
		BondExpiration:   time.Hour,
		NodeTTL:          time.Hour,
		ExpirationWindow: 20 * time.Second,
	}, peer)
	return h, cancel
}

func mustHandlerKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	_, key := makeKeyedNode(t, 1)
	return key
}

func (p *scriptedPeer) setSeq(seq uint64) {
	p.mu.Lock()
	p.enrSeq = seq
	p.mu.Unlock()
}

func deliverPong(t *testing.T, h *Handler, n *node.Node, key *ecdsa.PrivateKey, token []byte, seq uint64) {
	t.Helper()

	req, err := h.addPendingRequest(token, n, PingPacket, n.Addr())
	if err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}
	data, err := EncodePacket(key, &Pong{
		To:         Endpoint{IP: net.IPv4(127, 0, 0, 1), UDP: 30303},
		ReplyTok:   req.RequestHash,
		Expiration: MakeExpiration(20 * time.Second),
		ENRSeq:     seq,
	})
	if err != nil {
		t.Fatalf("encode pong: %v", err)
	}
	if err := h.HandlePacket(data, n.Addr(), nil); err != nil {
		t.Fatalf("handle pong: %v", err)
	}
}

// A sequence advertised after the running attempt started is real new data, so it
// must produce exactly one more refresh — coalescing must not swallow it.
func TestENRRefreshRearmsForBumpDuringRefresh(t *testing.T) {
	peer := &scriptedPeer{t: t, enrSeq: 5, pongAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303}}

	h, cancel := newScriptedHandler(t, peer)
	defer cancel()
	peer.h = h

	n, key := makeKeyedNode(t, 30303)
	peer.key = key
	if !n.UpdateENR(signedV4Record(t, key, 1)) {
		t.Fatal("seed record was not installed")
	}
	h.nodesMu.Lock()
	h.nodes[n.ID()] = n
	h.nodesMu.Unlock()

	deliverPong(t, h, n, key, []byte("first-ping-hash"), 5)

	// Ping sleeps 500ms before the ENRREQUEST, so this lands mid-refresh.
	time.Sleep(100 * time.Millisecond)
	peer.setSeq(6)
	deliverPong(t, h, n, key, []byte("second-ping-hash"), 6)

	time.Sleep(3 * time.Second)
	peer.stop()
	_, enrReqs := peer.counts()

	if enrReqs != 2 {
		t.Errorf("ENRREQUESTs sent = %d, want 2 (one per observed bump)", enrReqs)
	}
}

// Eviction removes the refresh state; a refresh completing afterwards must not
// resurrect an entry, or the map grows for every peer that ever left.
func TestENRRefreshStateClearedOnEviction(t *testing.T) {
	peer := &scriptedPeer{t: t, enrSeq: 5, pongAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303}}

	h, cancel := newScriptedHandler(t, peer)
	defer cancel()
	peer.h = h

	n, key := makeKeyedNode(t, 30303)
	peer.key = key
	if !n.UpdateENR(signedV4Record(t, key, 1)) {
		t.Fatal("seed record was not installed")
	}

	h.startENRRefresh(n, 5)

	h.enrRefreshMu.Lock()
	delete(h.enrRefresh, n.ID())
	h.enrRefreshMu.Unlock()

	time.Sleep(2 * time.Second)
	peer.stop()

	h.enrRefreshMu.Lock()
	_, present := h.enrRefresh[n.ID()]
	h.enrRefreshMu.Unlock()

	if present {
		t.Error("refresh state was recreated after eviction")
	}
}

// Concurrent triggers must not race on the refresh map.
func TestENRRefreshConcurrentTriggers(t *testing.T) {
	peer := &scriptedPeer{t: t, enrSeq: 5, pongAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303}}

	h, cancel := newScriptedHandler(t, peer)
	defer cancel()
	peer.h = h

	n, key := makeKeyedNode(t, 30303)
	peer.key = key
	if !n.UpdateENR(signedV4Record(t, key, 1)) {
		t.Fatal("seed record was not installed")
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(seq uint64) {
			defer wg.Done()
			h.startENRRefresh(n, seq)
		}(uint64(5 + i%3))
	}
	wg.Wait()

	time.Sleep(1500 * time.Millisecond)
	peer.stop()
}

// A peer that advertises a higher sequence in every PONG could otherwise re-arm
// the refresh forever, holding a goroutine and generating traffic until shutdown.
func TestENRRefreshBoundedAgainstEndlessBumps(t *testing.T) {
	peer := &scriptedPeer{t: t, enrSeq: 5, pongAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303}, bumpEachPong: true}

	h, cancel := newScriptedHandler(t, peer)
	defer cancel()
	peer.h = h

	n, key := makeKeyedNode(t, 30303)
	peer.key = key
	if !n.UpdateENR(signedV4Record(t, key, 1)) {
		t.Fatal("seed record was not installed")
	}
	h.nodesMu.Lock()
	h.nodes[n.ID()] = n
	h.nodesMu.Unlock()

	deliverPong(t, h, n, key, []byte("bump-ping-hash"), 5)

	time.Sleep(4 * time.Second)
	peer.stop()
	_, enrReqs := peer.counts()

	// Literal, not maxENRRefreshRounds: comparing against the constant under test
	// makes the assertion vacuous when the bound is raised.
	if enrReqs > 4 {
		t.Errorf("ENRREQUESTs sent = %d, want at most 4 rounds per claim", enrReqs)
	}

	h.enrRefreshMu.Lock()
	inFlight := h.enrRefresh[n.ID()].inFlight
	h.enrRefreshMu.Unlock()
	if inFlight {
		t.Error("refresh still marked in flight after the round bound was reached")
	}
}
