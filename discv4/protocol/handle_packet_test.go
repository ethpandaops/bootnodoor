package protocol

import (
	"crypto/ecdsa"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv4/node"
)

// encodeFrom builds a real signed packet from a peer, so tests can drive
// HandlePacket end to end rather than calling handlers directly.
func encodeFrom(t *testing.T, key *ecdsa.PrivateKey, msg Packet) ([]byte, []byte) {
	t.Helper()
	data, hash, err := Encode(key, msg)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return data, hash
}

// A peer's claimed source address must not become the node's canonical address:
// every sender reads it and sendNeighbors republishes it, so an unauthenticated
// packet could otherwise steer our traffic and poison what we tell others.
func TestHandlePacketDoesNotMoveCanonicalAddress(t *testing.T) {
	h, _, cancel := proofHandler(t)
	defer cancel()

	peerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	knownAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	n := node.New(&peerKey.PublicKey, knownAddr)

	h.nodesMu.Lock()
	h.nodes[n.ID()] = n
	h.nodesMu.Unlock()

	spoofed := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 40404}
	data, _ := encodeFrom(t, peerKey, &Findnode{
		Target:     EncodePubkey(&peerKey.PublicKey),
		Expiration: MakeExpiration(20 * time.Second),
	})
	_ = h.HandlePacket(data, spoofed, testAddr())

	if got := n.Addr().String(); got != knownAddr.String() {
		t.Fatalf("canonical address moved to %s on an unauthenticated packet, want %s", got, knownAddr)
	}
}

// An expired packet must not refresh liveness or fire OnNodeSeen. The node has to
// pre-exist, because creating one stamps LastSeen.
func TestHandlePacketExpiredTouchesNothing(t *testing.T) {
	h, _, cancel := proofHandler(t)
	defer cancel()

	seen := 0
	h.config.OnNodeSeen = func(*node.Node, time.Time) { seen++ }

	peerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	n := node.New(&peerKey.PublicKey, addr)

	h.nodesMu.Lock()
	h.nodes[n.ID()] = n
	h.nodesMu.Unlock()

	before := n.LastSeen()
	time.Sleep(5 * time.Millisecond)

	data, _ := encodeFrom(t, peerKey, &Findnode{
		Target:     EncodePubkey(&peerKey.PublicKey),
		Expiration: uint64(time.Now().Add(-time.Minute).Unix()),
	})
	_ = h.HandlePacket(data, addr, testAddr())

	if !n.LastSeen().Equal(before) {
		t.Error("expired packet refreshed liveness")
	}
	if seen != 0 {
		t.Errorf("expired packet fired OnNodeSeen %d times", seen)
	}
}

// An unbonded FINDNODE is refused, so it must not admit the node either — that is
// the callback which can spawn outbound traffic toward an unproven address.
func TestHandlePacketUnbondedFindnodeDoesNotAdmit(t *testing.T) {
	h, _, cancel := proofHandler(t)
	defer cancel()

	seen := 0
	h.config.OnNodeSeen = func(*node.Node, time.Time) { seen++ }

	peerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}

	data, _ := encodeFrom(t, peerKey, &Findnode{
		Target:     EncodePubkey(&peerKey.PublicKey),
		Expiration: MakeExpiration(20 * time.Second),
	})
	_ = h.HandlePacket(data, addr, testAddr())

	if seen != 0 {
		t.Fatalf("unbonded FINDNODE fired OnNodeSeen %d times, want 0", seen)
	}
}

// The blackhole regression test. Removing the address rewrite means a peer that
// moves is only reachable if the reciprocal PING goes to the source we just
// ponged; otherwise it is pinged at its old address forever, never bonds, and is
// refused service permanently.
func TestHandlePacketMovedPeerRebondsAtNewAddress(t *testing.T) {
	h, tr, cancel := proofHandler(t)
	defer cancel()

	peerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	oldAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	newAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 77), Port: 30303}
	n := node.New(&peerKey.PublicKey, oldAddr)

	h.nodesMu.Lock()
	h.nodes[n.ID()] = n
	h.nodesMu.Unlock()

	// The peer pings us from its new address.
	data, _ := encodeFrom(t, peerKey, &Ping{
		Version:    4,
		From:       NewEndpoint(newAddr, 0),
		To:         NewEndpoint(testAddr(), 0),
		Expiration: MakeExpiration(20 * time.Second),
	})
	if err := h.HandlePacket(data, newAddr, testAddr()); err != nil {
		t.Fatalf("HandlePacket(ping): %v", err)
	}

	// The reciprocal PING is sent from a goroutine.
	deadline := time.Now().Add(2 * time.Second)
	var pingHash []byte
	for time.Now().Before(deadline) {
		if req := h.findPendingPingTo(n.ID(), newAddr); req != nil {
			pingHash = req.RequestHash
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if pingHash == nil {
		t.Fatalf("no PING was sent to the peer's new address; destinations: %v", tr.sent)
	}

	// Its PONG from the new address proves the endpoint.
	pongData, _ := encodeFrom(t, peerKey, &Pong{
		To:         NewEndpoint(testAddr(), 0),
		ReplyTok:   pingHash,
		Expiration: MakeExpiration(20 * time.Second),
	})
	if err := h.HandlePacket(pongData, newAddr, testAddr()); err != nil {
		t.Fatalf("HandlePacket(pong): %v", err)
	}

	if !n.IsBondedFrom(newAddr) {
		t.Error("peer did not bond at its new address")
	}
	if got := n.Addr().String(); got != newAddr.String() {
		t.Errorf("canonical address = %s after a proven PONG, want %s", got, newAddr)
	}
}

// findPendingPingTo reports the pending PING sent to addr, for tests that need the
// reply token of a PING the handler emitted itself.
func (h *Handler) findPendingPingTo(id node.ID, addr *net.UDPAddr) *PendingRequest {
	h.requestsMu.RLock()
	defer h.requestsMu.RUnlock()

	for _, reqs := range h.requests {
		for _, req := range reqs {
			if req.PacketType == PingPacket && req.ToNode != nil && req.ToNode.ID() == id &&
				req.DestIP != nil && req.DestIP.Equal(addr.IP) {
				return req
			}
		}
	}
	return nil
}
