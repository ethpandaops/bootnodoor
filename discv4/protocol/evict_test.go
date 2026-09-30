package protocol

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/discv4/node"
)

type testKey struct {
	pub *ecdsa.PublicKey
	id  node.ID
}

func makeKeys(t testing.TB, n int) []testKey {
	t.Helper()
	keys := make([]testKey, n)
	for i := range keys {
		pub, id := makeNodeID(t)
		keys[i] = testKey{pub, id}
	}
	return keys
}

// fillBonded fills h to MaxNodes with bonded nodes.
func fillBonded(t testing.TB, h *Handler) {
	t.Helper()
	for _, k := range makeKeys(t, h.config.MaxNodes) {
		h.lookupOrCreateNode(k.id, k.pub, testAddr()).MarkPongReceived(time.Hour, testAddr())
	}
}

// BenchmarkLookupUnknownIDFullBondedMap measures the per-packet cost of an
// unknown sender once the map is full of bonded peers: the state that stalled
// the dcl1 mainnet bootnode, where each such packet walked all 50000 entries
// under the write lock.
func BenchmarkLookupUnknownIDFullBondedMap(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := NewHandler(ctx, HandlerConfig{MaxNodes: defaultMaxNodes, NodeTTL: time.Hour}, nil)
	fillBonded(b, h)
	h.cleanup()
	keys := makeKeys(b, 1024)

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		k := keys[i%len(keys)]
		h.lookupOrCreateNode(k.id, k.pub, testAddr())
	}
}

// TestFullMapAdmitsNewNodesWithoutCleanup: with one unbonded slot in a full
// map, each new node takes the slot of the previous new node. New nodes feed
// the queue on insert, so no cleanup pass is needed between them.
func TestFullMapAdmitsNewNodesWithoutCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes = 50
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: time.Hour}, nil)
	for _, k := range makeKeys(t, maxNodes-1) {
		h.lookupOrCreateNode(k.id, k.pub, testAddr()).MarkPongReceived(time.Hour, testAddr())
	}

	var prev node.ID
	for i, k := range makeKeys(t, 5) {
		h.lookupOrCreateNode(k.id, k.pub, testAddr())
		if h.GetNode(k.id) == nil {
			t.Fatalf("new node %d not retained", i)
		}
		if i > 0 && h.GetNode(prev) != nil {
			t.Fatalf("new node %d did not evict the previous unbonded node", i)
		}
		if got := len(h.AllNodes()); got != maxNodes {
			t.Fatalf("map size = %d, want %d", got, maxNodes)
		}
		prev = k.id
	}
}

// TestExpiredBondBecomesCandidate: a bond can expire while the node keeps
// signing packets, so it is never stale. Cleanup must still offer it for
// eviction, or a full map would lock out new peers.
func TestExpiredBondBecomesCandidate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes = 20
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: time.Hour}, nil)
	keys := makeKeys(t, maxNodes)
	for i, k := range keys {
		bond := time.Hour
		if i == 0 {
			bond = time.Millisecond
		}
		h.lookupOrCreateNode(k.id, k.pub, testAddr()).MarkPongReceived(bond, testAddr())
	}
	h.cleanup()

	expiring := h.GetNode(keys[0].id)
	for expiring.IsBonded() {
		time.Sleep(time.Millisecond)
	}
	expiring.UpdateLastSeen()

	pub, id := makeNodeID(t)
	h.lookupOrCreateNode(id, pub, testAddr())
	if h.GetNode(id) != nil {
		t.Fatal("new node retained before cleanup saw the expired bond")
	}

	h.cleanup()
	h.lookupOrCreateNode(id, pub, testAddr())
	if h.GetNode(id) == nil {
		t.Fatal("new node not retained after cleanup")
	}
	if h.GetNode(keys[0].id) != nil {
		t.Fatal("node with the expired bond was not evicted")
	}
}

// TestInsertDuringScanStaysCandidate: a node inserted between cleanup's
// read-locked scan and its publish is missing from the scan; replacing the
// queue must keep it.
func TestInsertDuringScanStaysCandidate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes = 20
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: time.Hour}, nil)
	for _, k := range makeKeys(t, maxNodes-1) {
		h.lookupOrCreateNode(k.id, k.pub, testAddr()).MarkPongReceived(time.Hour, testAddr())
	}

	scan := h.scanNodes(time.Now())
	pubMid, idMid := makeNodeID(t)
	h.lookupOrCreateNode(idMid, pubMid, testAddr())
	h.applyNodeScan(time.Now(), scan)

	pub, id := makeNodeID(t)
	h.lookupOrCreateNode(id, pub, testAddr())
	if h.GetNode(id) == nil {
		t.Fatal("new node not retained: the node inserted mid-scan was dropped from the queue")
	}
	if h.GetNode(idMid) != nil {
		t.Fatal("node inserted mid-scan was not evicted")
	}
}

// TestFullBondedMapRejectsWithoutWalking: when every entry is bonded, an
// unknown sender is not retained and leaves the queue empty, so the next one
// does no scan either.
func TestFullBondedMapRejectsWithoutWalking(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes = 200
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: time.Hour}, nil)
	fillBonded(t, h)
	h.cleanup()

	for _, k := range makeKeys(t, 1000) {
		h.lookupOrCreateNode(k.id, k.pub, testAddr())
	}

	if got := len(h.AllNodes()); got != maxNodes {
		t.Fatalf("map size = %d, want %d", got, maxNodes)
	}
	h.nodesMu.RLock()
	queued := len(h.evictable) - h.evictHead
	h.nodesMu.RUnlock()
	if queued != 0 {
		t.Fatalf("%d entries queued on a fully bonded map, want 0", queued)
	}
}

// TestEvictableBoundedUnderReinsertChurn: IDs re-inserted between a scan and
// its publish are queued twice, but each publish replaces the queue, so the
// duplicates never outlive one pass. The queue stays within MaxNodes plus the
// inserts of a single scan gap.
func TestEvictableBoundedUnderReinsertChurn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes = 2
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: time.Hour}, nil)
	keys := makeKeys(t, 3)
	for _, k := range keys[:maxNodes] {
		h.lookupOrCreateNode(k.id, k.pub, testAddr())
	}

	const insertsPerGap = 5
	for pass := 0; pass < 100; pass++ {
		scan := h.scanNodes(time.Now())
		for i := 0; i < insertsPerGap; i++ {
			k := keys[(pass+i)%len(keys)]
			h.lookupOrCreateNode(k.id, k.pub, testAddr())
		}
		h.applyNodeScan(time.Now(), scan)

		h.nodesMu.RLock()
		queued := len(h.evictable) - h.evictHead
		h.nodesMu.RUnlock()
		if queued > maxNodes+insertsPerGap {
			t.Fatalf("pass %d: %d entries queued, want at most %d", pass, queued, maxNodes+insertsPerGap)
		}
	}
}
