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
	bonded.MarkPongReceived(time.Hour, testAddr()) // establish a live bond

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
