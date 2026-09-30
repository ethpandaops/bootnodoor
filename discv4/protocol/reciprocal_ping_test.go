package protocol

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv4/node"
)

type failingTransport struct{}

func (failingTransport) SendTo([]byte, *net.UDPAddr) error { return errors.New("send failed") }
func (failingTransport) Send([]byte, *net.UDPAddr, *net.UDPAddr) error {
	return errors.New("send failed")
}

func reciprocalHandler(t *testing.T, tr Transport, timeout time.Duration) (*Handler, context.CancelFunc) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return NewHandler(ctx, HandlerConfig{PrivateKey: key, LocalAddr: testAddr(), RequestTimeout: timeout}, tr), cancel
}

func pendingPings(h *Handler, id node.ID) []*PendingRequest {
	h.requestsMu.RLock()
	defer h.requestsMu.RUnlock()
	var out []*PendingRequest
	for _, reqs := range h.requests {
		for _, req := range reqs {
			if req.PacketType == PingPacket && req.ToNode.ID() == id {
				out = append(out, req)
			}
		}
	}
	return out
}

// waitTimersDone waits for every reciprocal-PING timer to have fired.
func waitTimersDone(t *testing.T, h *Handler) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for h.reciprocalPings.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("outstanding reciprocal PINGs = %d, want 0", h.reciprocalPings.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func peerNode(t *testing.T) (*node.Node, *net.UDPAddr) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	return node.New(&key.PublicKey, addr), addr
}

// TestInboundPingBurstStartsNoGoroutines: each inbound PING from a new identity
// earns a reciprocal PING, which a timer owns rather than a waiting goroutine.
func TestInboundPingBurstStartsNoGoroutines(t *testing.T) {
	h, cancel := reciprocalHandler(t, &recordingTransport{}, time.Minute)
	defer cancel()

	const burst = 200
	before := runtime.NumGoroutine()
	for range burst {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := encodeFrom(t, key, &Ping{
			Version:    4,
			From:       NewEndpoint(testAddr(), 0),
			To:         NewEndpoint(testAddr(), 0),
			Expiration: MakeExpiration(20 * time.Second),
		})
		_ = h.HandlePacket(data, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}, testAddr())
	}

	if grew := runtime.NumGoroutine() - before; grew > 10 {
		t.Fatalf("goroutines grew by %d over %d inbound PINGs", grew, burst)
	}
	if got := h.reciprocalPings.Load(); got != burst {
		t.Fatalf("outstanding reciprocal PINGs = %d, want %d", got, burst)
	}
}

// TestReciprocalPingAnswered: a PONG bonds the node and the timer then records
// no failure.
func TestReciprocalPingAnswered(t *testing.T) {
	h, cancel := reciprocalHandler(t, &recordingTransport{}, 30*time.Millisecond)
	defer cancel()
	n, addr := peerNode(t)

	h.sendReciprocalPing(n, addr)
	reqs := pendingPings(h, n.ID())
	if len(reqs) != 1 {
		t.Fatalf("pending PINGs = %d, want 1", len(reqs))
	}
	if err := h.handlePong(n, addr, &Pong{
		To:         NewEndpoint(testAddr(), 0),
		ReplyTok:   reqs[0].RequestHash,
		Expiration: MakeExpiration(20 * time.Second),
	}); err != nil {
		t.Fatalf("handlePong: %v", err)
	}
	if !n.IsBondedFrom(addr) {
		t.Fatal("PONG to the reciprocal PING did not bond the node")
	}

	waitTimersDone(t, h)
	if got := n.FailedPings(); got != 0 {
		t.Fatalf("failed pings = %d after an answered PING, want 0", got)
	}
}

// TestReciprocalPingTimeout: an unanswered PING is removed and counted as one
// failure when its timer fires, even if cleanup runs after its deadline first.
func TestReciprocalPingTimeout(t *testing.T) {
	h, cancel := reciprocalHandler(t, &recordingTransport{}, 30*time.Millisecond)
	defer cancel()
	n, addr := peerNode(t)

	h.sendReciprocalPing(n, addr)
	reqs := pendingPings(h, n.ID())
	if len(reqs) != 1 {
		t.Fatalf("pending PINGs = %d, want 1", len(reqs))
	}
	h.requestsMu.Lock()
	reqs[0].Timeout = time.Now().Add(-time.Second)
	h.requestsMu.Unlock()
	h.cleanup()
	if len(pendingPings(h, n.ID())) != 1 {
		t.Fatal("cleanup removed a PING its timer owns")
	}

	waitTimersDone(t, h)
	if got := n.FailedPings(); got != 1 {
		t.Fatalf("failed pings = %d, want 1", got)
	}
	if len(pendingPings(h, n.ID())) != 0 {
		t.Fatal("timed-out PING still pending")
	}
}

// TestReciprocalPingSendError: a failed send leaves nothing pending.
func TestReciprocalPingSendError(t *testing.T) {
	h, cancel := reciprocalHandler(t, failingTransport{}, time.Minute)
	defer cancel()
	n, addr := peerNode(t)

	h.sendReciprocalPing(n, addr)
	if len(pendingPings(h, n.ID())) != 0 {
		t.Fatal("failed send left a pending PING")
	}
	waitTimersDone(t, h)
}

// TestReciprocalPingCap: at the cap the reciprocal PING is skipped, and the
// PONG to the inbound PING is still sent.
func TestReciprocalPingCap(t *testing.T) {
	tr := &recordingTransport{}
	h, cancel := reciprocalHandler(t, tr, time.Minute)
	defer cancel()
	h.reciprocalPings.Store(maxReciprocalPings)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	from := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	data, _ := encodeFrom(t, key, &Ping{
		Version:    4,
		From:       NewEndpoint(from, 0),
		To:         NewEndpoint(testAddr(), 0),
		Expiration: MakeExpiration(20 * time.Second),
	})
	_ = h.HandlePacket(data, from, testAddr())

	tr.mu.Lock()
	sent := len(tr.sent)
	tr.mu.Unlock()
	if sent != 1 {
		t.Fatalf("sent %d packets at the cap, want 1 (the PONG only)", sent)
	}
	if got := h.reciprocalPings.Load(); got != maxReciprocalPings {
		t.Fatalf("outstanding reciprocal PINGs = %d, want %d", got, maxReciprocalPings)
	}
}

// TestExpiredPingDoesNotTakeLiveReply: an expired request not yet removed by
// its owner must leave a matching PONG to a live request on the same key.
func TestExpiredPingDoesNotTakeLiveReply(t *testing.T) {
	h, cancel := reciprocalHandler(t, &recordingTransport{}, time.Minute)
	defer cancel()
	n, addr := peerNode(t)
	hash := []byte("same-second-ping")

	expired, err := h.addPendingRequest(hash, n, PingPacket, addr)
	if err != nil {
		t.Fatal(err)
	}
	live, err := h.addPendingRequest(hash, n, PingPacket, addr)
	if err != nil {
		t.Fatal(err)
	}
	h.requestsMu.Lock()
	expired.Timeout = time.Now().Add(-time.Second)
	h.requestsMu.Unlock()

	if got := h.consumePendingPing(hash, n.ID(), addr); got != live {
		t.Fatal("PONG matched the expired request instead of the live one")
	}
}

// TestConcurrentInboundPingAndPing exercises the reciprocal path against a
// waiting Ping to the same peer under the race detector.
func TestConcurrentInboundPingAndPing(t *testing.T) {
	h, cancel := reciprocalHandler(t, &recordingTransport{}, 20*time.Millisecond)
	defer cancel()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	from := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	n := h.lookupOrCreateNode(node.PubkeyToID(&key.PublicKey), &key.PublicKey, from)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			data, _ := encodeFrom(t, key, &Ping{
				Version:    4,
				From:       NewEndpoint(from, 0),
				To:         NewEndpoint(testAddr(), 0),
				Expiration: MakeExpiration(20 * time.Second),
			})
			_ = h.HandlePacket(data, from, testAddr())
		}()
		go func() {
			defer wg.Done()
			_, _ = h.Ping(n)
		}()
	}
	wg.Wait()
	waitTimersDone(t, h)
}

type slowTransport struct{ delay time.Duration }

func (s slowTransport) SendTo([]byte, *net.UDPAddr) error {
	time.Sleep(s.delay)
	return nil
}
func (s slowTransport) Send(b []byte, to *net.UDPAddr, _ *net.UDPAddr) error { return s.SendTo(b, to) }

// TestSlowSendKeepsPingDeadline: the request deadline starts when the packet is
// out, so a PONG right after a slow write still matches.
func TestSlowSendKeepsPingDeadline(t *testing.T) {
	h, cancel := reciprocalHandler(t, slowTransport{delay: 60 * time.Millisecond}, 30*time.Millisecond)
	defer cancel()
	n, addr := peerNode(t)

	h.sendReciprocalPing(n, addr)
	reqs := pendingPings(h, n.ID())
	if len(reqs) != 1 {
		t.Fatalf("pending PINGs = %d, want 1", len(reqs))
	}
	if got := h.consumePendingPing(reqs[0].RequestHash, n.ID(), addr); got != reqs[0] {
		t.Fatal("PONG right after a slow send did not match its PING")
	}
	waitTimersDone(t, h)
}
