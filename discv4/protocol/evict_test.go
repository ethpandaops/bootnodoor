package protocol

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/discv4/node"
	"github.com/ethpandaops/bootnodoor/stats"
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

// fillBonded fills h to MaxNodes with bonded nodes that sent a packet just now,
// so the idle floor protects all of them.
func fillBonded(t testing.TB, h *Handler) {
	t.Helper()
	for _, k := range makeKeys(t, h.config.MaxNodes) {
		n := h.lookupOrCreateNode(k.id, k.pub, testAddr())
		n.MarkPongReceived(time.Hour, testAddr())
		n.MarkPacketReceived()
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
		n := h.lookupOrCreateNode(k.id, k.pub, testAddr())
		n.MarkPongReceived(bond, testAddr())
		n.MarkPacketReceived()
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

// TestFullBondedMapRejectsWithoutWalking: when every entry is bonded and active, an
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
	walked := h.evictBondedHead
	h.nodesMu.RUnlock()
	if queued != 0 {
		t.Fatalf("%d entries queued on a fully bonded map, want 0", queued)
	}
	if walked != 0 {
		t.Fatalf("bonded fallback walked %d active entries, want 0", walked)
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

// fillIdleBonded fills h with bonded nodes whose last packet is older than
// NodeTTL, oldest first in the returned order.
func fillIdleBonded(t *testing.T, h *Handler, n int) []testKey {
	t.Helper()
	keys := makeKeys(t, n)
	for _, k := range keys {
		nd := h.lookupOrCreateNode(k.id, k.pub, testAddr())
		nd.MarkPongReceived(time.Hour, testAddr())
		nd.MarkPacketReceived()
		time.Sleep(time.Millisecond)
	}
	time.Sleep(h.config.NodeTTL)
	return keys
}

// TestFullBondedMapEvictsOldestIdle: with no unbonded entry left, a new node
// takes the slot of the bonded node heard from least recently, once it is idle.
func TestFullBondedMapEvictsOldestIdle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes = 10
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: 30 * time.Millisecond}, nil)
	keys := fillIdleBonded(t, h, maxNodes)
	h.cleanup()

	pub, id := makeNodeID(t)
	h.lookupOrCreateNode(id, pub, testAddr())

	if h.GetNode(id) == nil {
		t.Fatal("new node not retained on a full map of idle bonded nodes")
	}
	if h.GetNode(keys[0].id) != nil {
		t.Fatal("least recently heard-from bonded node was not the one evicted")
	}
	if got := len(h.AllNodes()); got != maxNodes {
		t.Fatalf("map size = %d, want %d", got, maxNodes)
	}
	if got := h.GetStats().BondedEvictions; got != 1 {
		t.Fatalf("BondedEvictions = %d, want 1", got)
	}
}

// TestBondedFloodEvictsOnlyIdlePeers: a flood of identities that each bond as
// soon as they are admitted may take the slots of idle bonded peers, but never
// of active ones. An unbonded flood only churns its own entries.
func TestBondedFloodEvictsOnlyIdlePeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes, idle = 20, 10
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: 30 * time.Millisecond}, nil)
	fillIdleBonded(t, h, idle)
	active := makeKeys(t, maxNodes-idle)
	flood := makeKeys(t, maxNodes*3)
	for _, k := range active {
		n := h.lookupOrCreateNode(k.id, k.pub, testAddr())
		n.MarkPongReceived(time.Hour, testAddr())
		n.MarkPacketReceived()
	}
	h.cleanup()

	for _, k := range flood {
		n := h.lookupOrCreateNode(k.id, k.pub, testAddr())
		n.MarkPongReceived(time.Hour, testAddr())
		n.MarkPacketReceived()
	}

	for i, k := range active {
		if h.GetNode(k.id) == nil {
			t.Fatalf("active bonded peer %d was evicted by the flood", i)
		}
	}
	if got := h.GetStats().BondedEvictions; got != idle {
		t.Fatalf("BondedEvictions = %d, want %d", got, idle)
	}
	if got := len(h.AllNodes()); got != maxNodes {
		t.Fatalf("map size = %d, want %d", got, maxNodes)
	}
}

// TestIdleFloorIgnoresSwappedStats: the routing table swaps a node's shared
// stats for stored ones, whose last-seen time can be old. The idle floor must
// go by the packets the handler saw, not by that time.
func TestIdleFloorIgnoresSwappedStats(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxNodes = 5
	h := NewHandler(ctx, HandlerConfig{MaxNodes: maxNodes, NodeTTL: time.Hour}, nil)
	fillBonded(t, h)
	for _, n := range h.AllNodes() {
		n.SetStats(stats.NewSharedStats(time.Now().Add(-24 * time.Hour)))
	}
	h.cleanup()

	pub, id := makeNodeID(t)
	h.lookupOrCreateNode(id, pub, testAddr())
	if h.GetNode(id) != nil {
		t.Fatal("an active bonded peer was evicted because its shared stats were old")
	}
}

// TestCleanupSweepsOrphanedENRRefresh: refresh state for a node that left the
// map is dropped, however it got there; state for a tracked node is kept.
func TestCleanupSweepsOrphanedENRRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := NewHandler(ctx, HandlerConfig{MaxNodes: 10, NodeTTL: time.Hour}, nil)
	pub, tracked := makeNodeID(t)
	h.lookupOrCreateNode(tracked, pub, testAddr())
	_, orphan := makeNodeID(t)

	h.enrRefreshMu.Lock()
	h.enrRefresh[tracked] = &enrRefreshState{}
	h.enrRefresh[orphan] = &enrRefreshState{}
	h.enrRefreshMu.Unlock()

	h.cleanup()

	h.enrRefreshMu.Lock()
	defer h.enrRefreshMu.Unlock()
	if _, ok := h.enrRefresh[orphan]; ok {
		t.Error("refresh state for an untracked node survived cleanup")
	}
	if _, ok := h.enrRefresh[tracked]; !ok {
		t.Error("refresh state for a tracked node was dropped")
	}
}
