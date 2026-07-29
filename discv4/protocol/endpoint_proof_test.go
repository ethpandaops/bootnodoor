package protocol

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv4/node"
)

// recordingTransport captures the destinations we send to, so a test can assert
// that no reply was reflected at a spoofed address.
type recordingTransport struct {
	mu   sync.Mutex
	sent []string
}

func (r *recordingTransport) SendTo(_ []byte, to *net.UDPAddr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, to.String())
	return nil
}

func (r *recordingTransport) Send(_ []byte, to *net.UDPAddr, _ *net.UDPAddr) error {
	return r.SendTo(nil, to)
}

func (r *recordingTransport) sentTo(addr *net.UDPAddr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sent {
		if s == addr.String() {
			return true
		}
	}
	return false
}

func proofHandler(t *testing.T) (*Handler, *recordingTransport, context.CancelFunc) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tr := &recordingTransport{}
	return NewHandler(ctx, HandlerConfig{PrivateKey: key, LocalAddr: testAddr()}, tr), tr, cancel
}

// bondAt drives a full PING/PONG exchange so the node ends up bonded at addr,
// the way production does: register the PING we sent, then answer it.
func bondAt(t *testing.T, h *Handler, n *node.Node, addr *net.UDPAddr) {
	t.Helper()

	n.SetAddr(addr)
	hash := []byte("ping-hash-" + addr.String())
	if _, err := h.addPendingRequest(hash, n, PingPacket); err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}
	pong := &Pong{ReplyTok: hash, Expiration: MakeExpiration(20 * time.Second)}
	if err := h.handlePong(n, addr, pong); err != nil {
		t.Fatalf("handlePong: %v", err)
	}
	if !n.IsBondedFrom(addr) {
		t.Fatalf("node not bonded at %s after a matched PONG", addr)
	}
}

// A bond proves reachability at one address only. Serving FINDNODE from any
// other source lets an attacker who bonded legitimately spoof a victim's source
// and have us reflect the much larger NEIGHBORS at that victim.
func TestFindnodeFromUnbondedAddressRejected(t *testing.T) {
	h, tr, cancel := proofHandler(t)
	defer cancel()

	n, _ := makeKeyedNode(t, 30303)
	attacker := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303}
	bondAt(t, h, n, attacker)

	victim := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 30303}
	err := h.handleFindnode(n, victim, testAddr(), &Findnode{Expiration: MakeExpiration(20 * time.Second)})
	if err == nil {
		t.Fatal("FINDNODE from an unbonded source address was served")
	}
	if tr.sentTo(victim) {
		t.Fatal("reflected a reply at the spoofed victim address")
	}
	if h.GetStats().UnbondedFindnode == 0 {
		t.Error("unbondedFindnode counter did not move")
	}
}

// The legitimate case must still work, or the gate has simply broken discovery.
func TestFindnodeFromBondedAddressServed(t *testing.T) {
	h, _, cancel := proofHandler(t)
	defer cancel()

	n, _ := makeKeyedNode(t, 30303)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303}
	bondAt(t, h, n, addr)

	if err := h.handleFindnode(n, addr, testAddr(), &Findnode{Expiration: MakeExpiration(20 * time.Second)}); err != nil {
		t.Fatalf("FINDNODE from the bonded address was refused: %v", err)
	}
}

// One node ID can legitimately bond over both address families, so a per-IP bond
// must not let the second exchange invalidate the first.
func TestDualStackPeerKeepsBothBonds(t *testing.T) {
	h, _, cancel := proofHandler(t)
	defer cancel()

	n, _ := makeKeyedNode(t, 30303)
	v4 := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303}
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 30303}

	bondAt(t, h, n, v4)
	bondAt(t, h, n, v6)

	if !n.IsBondedFrom(v4) {
		t.Error("IPv4 bond was lost when the IPv6 bond was established")
	}
	if !n.IsBondedFrom(v6) {
		t.Error("IPv6 bond was not established")
	}
}

// Receiving a PING proves nothing about the source: we pong whatever address the
// packet claimed, so bonding here would bond a spoofed victim.
func TestInboundPingDoesNotBond(t *testing.T) {
	h, _, cancel := proofHandler(t)
	defer cancel()

	n, _ := makeKeyedNode(t, 30303)
	addr := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 30303}
	n.SetAddr(addr)

	ping := &Ping{Version: 4, Expiration: MakeExpiration(20 * time.Second)}
	if err := h.handlePing(n, addr, testAddr(), ping, []byte("hash")); err != nil {
		t.Fatalf("handlePing: %v", err)
	}

	if n.IsBondedFrom(addr) {
		t.Fatal("an inbound PING alone established a bond")
	}
	if n.LastSeen().IsZero() {
		t.Error("MarkPingReceived did not take effect")
	}
}

// A PONG must not be matched by a token belonging to a different request type:
// peers know the hashes of the packets we send them.
func TestPongMatchingRejectsNonPingRequest(t *testing.T) {
	h, _, cancel := proofHandler(t)
	defer cancel()

	n, _ := makeKeyedNode(t, 30303)
	addr := n.Addr()

	called := 0
	h.config.OnPongReceived = func(*node.Node, net.IP, uint16) { called++ }

	hash := []byte("enr-request-hash")
	if _, err := h.addPendingRequest(hash, n, ENRRequestPacket); err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

	pong := &Pong{
		ReplyTok:   hash,
		To:         NewEndpoint(&net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 30303}, 0),
		Expiration: MakeExpiration(20 * time.Second),
	}
	if err := h.handlePong(n, addr, pong); err != nil {
		t.Fatalf("handlePong: %v", err)
	}

	if n.IsBondedFrom(addr) {
		t.Error("a PONG matching an ENRREQUEST token established a bond")
	}
	if called != 0 {
		t.Errorf("OnPongReceived fired %d times for a non-PING match", called)
	}
}

// The match is consumed once, so a replayed PONG cannot cast repeated
// external-IP votes off a single PING.
func TestReplayedPongAppliesSideEffectsOnce(t *testing.T) {
	h, _, cancel := proofHandler(t)
	defer cancel()

	n, _ := makeKeyedNode(t, 30303)
	addr := n.Addr()

	called := 0
	h.config.OnPongReceived = func(*node.Node, net.IP, uint16) { called++ }

	hash := []byte("ping-hash")
	if _, err := h.addPendingRequest(hash, n, PingPacket); err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

	pong := &Pong{
		ReplyTok:   hash,
		To:         NewEndpoint(&net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 30303}, 0),
		Expiration: MakeExpiration(20 * time.Second),
	}
	for i := 0; i < 3; i++ {
		if err := h.handlePong(n, addr, pong); err != nil {
			t.Fatalf("handlePong %d: %v", i, err)
		}
	}

	if called != 1 {
		t.Fatalf("OnPongReceived fired %d times for a replayed PONG, want 1", called)
	}
}

// A PONG whose source is not the address the PING went to proves only that
// somebody received that PING, which is what the spoofing attack relies on.
func TestPongFromWrongSourceRejected(t *testing.T) {
	h, _, cancel := proofHandler(t)
	defer cancel()

	n, _ := makeKeyedNode(t, 30303)
	sentTo := n.Addr()

	hash := []byte("ping-hash")
	if _, err := h.addPendingRequest(hash, n, PingPacket); err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

	victim := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 30303}
	pong := &Pong{ReplyTok: hash, Expiration: MakeExpiration(20 * time.Second)}
	if err := h.handlePong(n, victim, pong); err != nil {
		t.Fatalf("handlePong: %v", err)
	}

	if n.IsBondedFrom(victim) {
		t.Fatal("a PONG spoofed from a victim address bonded that address")
	}
	if n.IsBondedFrom(sentTo) {
		t.Fatal("a PONG from the wrong source bonded the PING destination")
	}
}
