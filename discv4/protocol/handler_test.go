package protocol

import (
	"context"
	"crypto/ecdsa"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv4/node"
)

func testAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303}
}

// makeNodeID returns a fresh, valid secp256k1 public key and its node ID,
// standing in for a distinct peer (or a fabricated NEIGHBORS record).
func makeNodeID(t *testing.T) (*ecdsa.PublicKey, node.ID) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := &key.PublicKey
	return pub, node.PubkeyToID(pub)
}

// TestGetOrCreateNodeRespectsMaxNodes verifies the tracked-node map is hard
// bounded: a flood of distinct node IDs (the NM-012/NM-104 vector) cannot grow
// it past MaxNodes.
func TestGetOrCreateNodeRespectsMaxNodes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes = 100
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: time.Hour}, nil)

	for i := 0; i < maxNodes*5; i++ {
		pub, id := makeNodeID(t)
		h.getOrCreateNode(id, pub, testAddr())
	}

	if got := len(h.AllNodes()); got != maxNodes {
		t.Fatalf("node map not bounded: got %d nodes, want %d", got, maxNodes)
	}
}

// TestCleanupEvictsStaleUnbondedNodes verifies cleanup reclaims unbonded nodes
// past their TTL while keeping bonded nodes.
func TestCleanupEvictsStaleUnbondedNodes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := NewHandler(ctx, HandlerConfig{MaxNodes: 1000, NodeTTL: 20 * time.Millisecond}, nil)

	pubStale, idStale := makeNodeID(t)
	h.getOrCreateNode(idStale, pubStale, testAddr())

	pubBonded, idBonded := makeNodeID(t)
	bonded := h.getOrCreateNode(idBonded, pubBonded, testAddr())
	bonded.MarkPongReceived(time.Hour) // establish a live bond

	time.Sleep(40 * time.Millisecond) // age both past NodeTTL

	h.cleanup()

	if h.GetNode(idStale) != nil {
		t.Error("stale unbonded node was not evicted")
	}
	if h.GetNode(idBonded) == nil {
		t.Error("bonded node was wrongly evicted")
	}
}

// TestCleanupReclaimsFloodedNodes verifies that a burst of unbonded nodes (a
// NEIGHBORS-injection flood) is fully reclaimed once it ages out.
func TestCleanupReclaimsFloodedNodes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := NewHandler(ctx, HandlerConfig{MaxNodes: 10000, NodeTTL: 10 * time.Millisecond}, nil)

	for i := 0; i < 500; i++ {
		pub, id := makeNodeID(t)
		h.getOrCreateNode(id, pub, testAddr())
	}
	if got := len(h.AllNodes()); got != 500 {
		t.Fatalf("setup: expected 500 tracked nodes, got %d", got)
	}

	time.Sleep(20 * time.Millisecond)
	h.cleanup()

	if got := len(h.AllNodes()); got != 0 {
		t.Fatalf("flooded nodes not reclaimed: %d still tracked", got)
	}
}

// TestPingDoesNotBondBeforePong verifies that receiving a PING must not by itself
// bond the sender. The bond is only established once the peer answers our
// ping-back with a PONG (endpoint proof), matching go-ethereum.
func TestPingDoesNotBondBeforePong(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key, _ := crypto.GenerateKey()
	h := NewHandler(ctx, HandlerConfig{PrivateKey: key, BondExpiration: time.Hour, LocalAddr: testAddr(), RequestTimeout: 20 * time.Millisecond}, stubTransport{})

	pub, id := makeNodeID(t)
	n := h.getOrCreateNode(id, pub, testAddr())

	// Handling an inbound PING sends a PONG + a ping-back but must not bond.
	if err := h.handlePing(n, testAddr(), nil, &Ping{Version: 4, Expiration: MakeExpiration(time.Minute)}, []byte{0x01}); err != nil {
		t.Fatalf("handlePing: %v", err)
	}
	if n.IsBonded() {
		t.Fatal("node became bonded from an inbound PING alone")
	}

	// Once the peer answers our ping-back with a PONG, the bond is established.
	n.MarkPongReceived(time.Hour)
	if !n.IsBonded() {
		t.Fatal("node should be bonded after receiving a PONG to our ping")
	}
}

// TestFloodDoesNotEvictBondedPeers verifies that when the node map is full,
// inserts evict a stale unbonded entry (so genuine new peers are never locked
// out) while bonded, endpoint-proven peers are retained.
func TestFloodDoesNotEvictBondedPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes = 10
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: time.Hour}, nil)

	// A genuine, bonded peer.
	pub, bondedID := makeNodeID(t)
	bonded := h.getOrCreateNode(bondedID, pub, testAddr())
	bonded.MarkPongReceived(time.Hour)

	// Fill the rest with unbonded nodes, then flood well past the cap.
	for i := 0; i < maxNodes*20; i++ {
		p, id := makeNodeID(t)
		h.getOrCreateNode(id, p, testAddr())
	}

	if got := len(h.AllNodes()); got != maxNodes {
		t.Fatalf("map not bounded under flood: got %d want %d", got, maxNodes)
	}
	if h.GetNode(bondedID) == nil {
		t.Fatal("bonded peer was evicted by an unbonded-ID flood")
	}
	// A brand-new node still gets retained (evicting an unbonded entry).
	p, freshID := makeNodeID(t)
	h.getOrCreateNode(freshID, p, testAddr())
	if h.GetNode(freshID) == nil {
		t.Fatal("new peer not retained when map full")
	}
}
