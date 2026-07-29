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
	if _, err := h.addPendingRequest([]byte("req"), from, FindnodePacket, from.Addr()); err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

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
	pending := h.pendingNeighbors[requestKey([]byte("req"), from.ID())]
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
	req, err := h.addPendingRequest([]byte("req"), from, FindnodePacket, from.Addr())
	if err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

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

// TestNeighborsCapAppliesBeforeNodePersistence verifies records past the
// per-response cap are not persisted in the global node map either, so a
// queried peer cannot grow memory by flooding unique records.
func TestNeighborsCapAppliesBeforeNodePersistence(t *testing.T) {
	h, cancel := newNeighborsHandler(t)
	defer cancel()

	from := makeDiscv4Node(t)
	if _, err := h.addPendingRequest([]byte("req"), from, FindnodePacket, from.Addr()); err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

	if err := h.handleNeighbors(from, from.Addr(), makeNeighbors(t, maxNeighborsPerResponse+20)); err != nil {
		t.Fatal(err)
	}

	h.nodesMu.RLock()
	n := len(h.nodes)
	h.nodesMu.RUnlock()
	if n != maxNeighborsPerResponse {
		t.Fatalf("node map persisted %d records, want at most the cap %d", n, maxNeighborsPerResponse)
	}
}

// TestFreshNodeSurvivesCleanup verifies a newly created node is not evicted by
// the next cleanup run before its NodeTTL: creation stamps last-seen, so a
// node learned from a NEIGHBORS record does not carry a zero timestamp.
func TestFreshNodeSurvivesCleanup(t *testing.T) {
	h, cancel := newNeighborsHandler(t)
	defer cancel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id := node.PubkeyToID(&key.PublicKey)
	h.getOrCreateNode(id, &key.PublicKey, &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 30303})

	h.cleanup()

	if h.GetNode(id) == nil {
		t.Fatal("fresh unbonded node was evicted before NodeTTL")
	}
}

type stubTransport struct{}

func (stubTransport) SendTo([]byte, *net.UDPAddr) error { return nil }

func (stubTransport) Send([]byte, *net.UDPAddr, *net.UDPAddr) error { return nil }

// TestFindnodeRemovesCompletedRequest verifies a delivered FINDNODE leaves no
// pending request behind, so later NEIGHBORS from the same node cannot keep
// matching it and reopening collection windows.
func TestFindnodeRemovesCompletedRequest(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := NewHandler(ctx, HandlerConfig{PrivateKey: key}, stubTransport{})

	to := makeDiscv4Node(t)
	to.MarkPongReceived(time.Hour, to.Addr())
	target := EncodePubkey(&key.PublicKey)

	type result struct {
		nodes []*node.Node
		err   error
	}
	done := make(chan result, 1)
	go func() {
		nodes, err := h.Findnode(to, target[:])
		done <- result{nodes, err}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for h.findPendingFindnode(to.ID(), to.Addr()) == nil {
		if time.Now().After(deadline) {
			t.Fatal("pending FINDNODE never registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := h.handleNeighbors(to, to.Addr(), makeNeighbors(t, 3)); err != nil {
		t.Fatal(err)
	}

	res := <-done
	if res.err != nil || len(res.nodes) != 3 {
		t.Fatalf("Findnode = %d nodes, %v", len(res.nodes), res.err)
	}
	h.requestsMu.RLock()
	remaining := len(h.requests)
	h.requestsMu.RUnlock()
	if remaining != 0 {
		t.Fatalf("%d pending requests remain after a completed FINDNODE, want 0", remaining)
	}
}

// TestNeighborsPersistenceCapExactUnderConcurrency verifies that packets
// processed on concurrent dispatch goroutines cannot jointly persist more than
// the cap: room is reserved under the lock before any record is decoded.
func TestNeighborsPersistenceCapExactUnderConcurrency(t *testing.T) {
	h, cancel := newNeighborsHandler(t)
	defer cancel()

	from := makeDiscv4Node(t)
	if _, err := h.addPendingRequest([]byte("req"), from, FindnodePacket, from.Addr()); err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

	packets := make([]*Neighbors, 6)
	for i := range packets {
		packets[i] = makeNeighbors(t, maxNeighborsPerResponse)
	}

	var wg sync.WaitGroup
	for _, pkt := range packets {
		wg.Add(1)
		go func(p *Neighbors) {
			defer wg.Done()
			if err := h.handleNeighbors(from, from.Addr(), p); err != nil {
				t.Errorf("handleNeighbors: %v", err)
			}
		}(pkt)
	}
	wg.Wait()

	h.nodesMu.RLock()
	persisted := len(h.nodes)
	h.nodesMu.RUnlock()
	if persisted != maxNeighborsPerResponse {
		t.Fatalf("node map persisted %d records under concurrent packets, want exactly the cap %d", persisted, maxNeighborsPerResponse)
	}
}

// TestNeighborsAfterDeliveryPersistNothing verifies the delivered entry is
// tombstoned rather than deleted: a packet processed after the collection
// window must not reopen accumulation or persist records.
func TestNeighborsAfterDeliveryPersistNothing(t *testing.T) {
	h, cancel := newNeighborsHandler(t)
	defer cancel()

	from := makeDiscv4Node(t)
	req, err := h.addPendingRequest([]byte("req"), from, FindnodePacket, from.Addr())
	if err != nil {
		t.Fatalf("addPendingRequest: %v", err)
	}

	if err := h.handleNeighbors(from, from.Addr(), makeNeighbors(t, 2)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-req.ResponseChan:
	case <-time.After(2 * time.Second):
		t.Fatal("collected nodes were not delivered")
	}

	h.nodesMu.RLock()
	before := len(h.nodes)
	h.nodesMu.RUnlock()

	if err := h.handleNeighbors(from, from.Addr(), makeNeighbors(t, 5)); err != nil {
		t.Fatal(err)
	}

	h.nodesMu.RLock()
	after := len(h.nodes)
	h.nodesMu.RUnlock()
	if after != before {
		t.Fatalf("a post-delivery packet persisted %d records, want 0", after-before)
	}
	h.pendingNeighborsMu.RLock()
	pending := h.pendingNeighbors[requestKey([]byte("req"), from.ID())]
	h.pendingNeighborsMu.RUnlock()
	if pending == nil || !pending.Closed || len(pending.Nodes) != 2 {
		t.Fatalf("tombstone state = %+v, want closed with the delivered 2 nodes", pending)
	}
}
