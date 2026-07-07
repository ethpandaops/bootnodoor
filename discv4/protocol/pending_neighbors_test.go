package protocol

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv4/node"
)

func newNeighborsHandler(t *testing.T) (*Handler, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	return NewHandler(ctx, HandlerConfig{}, nil), cancel
}

func makeDiscv4Node(t *testing.T) *node.Node {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return node.New(&key.PublicKey, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 30303})
}

func makeNeighbors(t *testing.T, count int) *Neighbors {
	t.Helper()
	recs := make([]NodeRecord, count)
	for i := range recs {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		recs[i] = NodeRecord{
			IP:  net.IPv4(9, 9, 9, byte(i%256)),
			UDP: 30303,
			TCP: 30303,
			ID:  EncodePubkey(&key.PublicKey),
		}
	}
	return &Neighbors{Nodes: recs, Expiration: uint64(time.Now().Add(time.Minute).Unix())}
}

// TestUnsolicitedNeighborsDropped verifies that NEIGHBORS from a node we never
// sent a FINDNODE to create no pending accumulation.
func TestUnsolicitedNeighborsDropped(t *testing.T) {
	h, cancel := newNeighborsHandler(t)
	defer cancel()

	from := makeDiscv4Node(t)
	if err := h.handleNeighbors(from, from.Addr(), makeNeighbors(t, 10)); err != nil {
		t.Fatalf("handleNeighbors: %v", err)
	}

	h.pendingNeighborsMu.RLock()
	n := len(h.pendingNeighbors)
	h.pendingNeighborsMu.RUnlock()
	if n != 0 {
		t.Fatalf("unsolicited NEIGHBORS created %d pending entries, want 0", n)
	}
}

// TestNeighborsAccumulationCapped verifies the accumulated nodes for a single
// FINDNODE never exceed the cap, even across multiple oversized packets.
func TestNeighborsAccumulationCapped(t *testing.T) {
	h, cancel := newNeighborsHandler(t)
	defer cancel()

	from := makeDiscv4Node(t)
	h.addPendingRequest([]byte("req"), from, FindnodePacket)

	// Pre-build packets so no slow key generation happens between the calls and
	// the read (the delivery goroutine deletes the entry after the window).
	pkt1 := makeNeighbors(t, maxNeighborsPerResponse+20)
	pkt2 := makeNeighbors(t, 20)

	if err := h.handleNeighbors(from, from.Addr(), pkt1); err != nil {
		t.Fatal(err)
	}
	if err := h.handleNeighbors(from, from.Addr(), pkt2); err != nil {
		t.Fatal(err)
	}

	h.pendingNeighborsMu.RLock()
	pending := h.pendingNeighbors[string(from.IDBytes())]
	h.pendingNeighborsMu.RUnlock()
	if pending == nil {
		t.Fatal("expected a pending entry for the matched FINDNODE")
	}
	if len(pending.Nodes) != maxNeighborsPerResponse {
		t.Fatalf("accumulated %d nodes, want cap %d", len(pending.Nodes), maxNeighborsPerResponse)
	}
}

// TestNeighborsDeliveredToWaiter verifies the happy path still delivers the
// collected nodes to the waiting FINDNODE.
func TestNeighborsDeliveredToWaiter(t *testing.T) {
	h, cancel := newNeighborsHandler(t)
	defer cancel()

	from := makeDiscv4Node(t)
	req := h.addPendingRequest([]byte("req"), from, FindnodePacket)

	if err := h.handleNeighbors(from, from.Addr(), makeNeighbors(t, 5)); err != nil {
		t.Fatal(err)
	}

	select {
	case resp := <-req.ResponseChan:
		nodes, ok := resp.([]*node.Node)
		if !ok || len(nodes) != 5 {
			t.Fatalf("unexpected delivery: %T len=%d", resp, len(nodes))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("collected nodes were not delivered to the waiter")
	}
}

// TestCleanupEvictsStalePendingNeighbors verifies cleanup evicts entries by
// creation time, so a stream of packets can no longer keep an entry alive.
func TestCleanupEvictsStalePendingNeighbors(t *testing.T) {
	h, cancel := newNeighborsHandler(t)
	defer cancel()

	h.pendingNeighborsMu.Lock()
	h.pendingNeighbors["stale"] = &PendingNeighborsResponse{CreatedAt: time.Now().Add(-neighborsTimeout - time.Second)}
	h.pendingNeighbors["fresh"] = &PendingNeighborsResponse{CreatedAt: time.Now()}
	h.pendingNeighborsMu.Unlock()

	h.cleanup()

	h.pendingNeighborsMu.RLock()
	_, staleExists := h.pendingNeighbors["stale"]
	_, freshExists := h.pendingNeighbors["fresh"]
	h.pendingNeighborsMu.RUnlock()
	if staleExists {
		t.Error("stale pending entry was not evicted")
	}
	if !freshExists {
		t.Error("fresh pending entry was wrongly evicted")
	}
}
