package nodes

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ethpandaops/bootnodoor/db"
	v4node "github.com/ethpandaops/bootnodoor/discv4/node"
	discv5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
)

func makeV5At(t *testing.T, ip net.IP) *discv5node.Node {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rec := enr.New()
	if err := rec.Set("ip", ip); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(9000)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	v5, err := discv5node.New(rec)
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	return v5
}

// TestLoadInitialNodesFromDBRespectsSoftCap verifies the bulk load stops at
// maxActiveNodes when traffic has already admitted nodes before it runs.
func TestLoadInitialNodesFromDBRespectsSoftCap(t *testing.T) {
	logger := quietTableLogger()
	database := persistTestDB(t, filepath.Join(t.TempDir(), "test.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)

	for i := 0; i < 4; i++ {
		n := NewFromV5(makeV5At(t, net.IPv4(10, 0, 0, byte(i+1))), ndb)
		n.MarkDirty(DirtyFull)
		if err := ndb.QueueUpdate(n); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for ndb.Count() < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of 4 seeded nodes were persisted", ndb.Count())
		}
		time.Sleep(50 * time.Millisecond)
	}

	table, err := NewFlatTable(FlatTableConfig{DB: ndb, MaxActiveNodes: 2, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		n := NewFromV5(makeV5At(t, net.IPv4(10, 0, 1, byte(i+1))), ndb)
		table.mu.Lock()
		table.activeNodes[n.ID()] = n
		table.ipLimiter.Add(n)
		table.mu.Unlock()
	}

	if err := table.LoadInitialNodesFromDB(); err != nil {
		t.Fatal(err)
	}

	table.mu.RLock()
	got := len(table.activeNodes)
	table.mu.RUnlock()
	if got != 2 {
		t.Fatalf("active pool holds %d nodes after bulk load, want the soft cap 2", got)
	}
}

// TestLoadInitialNodesFromDBSkipsSelf verifies a persisted record of ourselves
// is not loaded into the active pool, where every lookup round would dial it.
func TestLoadInitialNodesFromDBSkipsSelf(t *testing.T) {
	logger := quietTableLogger()
	database := persistTestDB(t, filepath.Join(t.TempDir(), "test.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)

	selfNode := NewFromV5(makeV5At(t, net.IPv4(10, 9, 0, 1)), ndb)
	selfNode.MarkDirty(DirtyFull)
	if err := ndb.QueueUpdate(selfNode); err != nil {
		t.Fatal(err)
	}
	other := NewFromV5(makeV5At(t, net.IPv4(10, 9, 0, 2)), ndb)
	other.SetLastSeen(time.Now())
	other.MarkDirty(DirtyFull)
	if err := ndb.QueueUpdate(other); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for ndb.Count() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of 2 nodes persisted", ndb.Count())
		}
		time.Sleep(50 * time.Millisecond)
	}

	table, err := NewFlatTable(FlatTableConfig{DB: ndb, LocalID: selfNode.ID(), MaxActiveNodes: 10, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	if err := table.LoadInitialNodesFromDB(); err != nil {
		t.Fatal(err)
	}

	table.mu.RLock()
	_, selfLoaded := table.activeNodes[selfNode.ID()]
	count := len(table.activeNodes)
	table.mu.RUnlock()
	if selfLoaded {
		t.Fatal("our own persisted record was loaded into the active pool")
	}
	if count != 1 {
		t.Fatalf("active pool holds %d nodes, want only the non-self node", count)
	}
}

// TestLoadInitialNodesFromDBLoadsNeverContactedFreshNode verifies a persisted
// row with NULL last_seen loads again after a restart while it is fresh, and
// stays filtered once first_seen ages past maxNodeAge.
func TestLoadInitialNodesFromDBLoadsNeverContactedFreshNode(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "fresh-load.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)

	fresh := NewFromV5(makeV5At(t, net.IPv4(10, 4, 0, 1)), ndb)
	fresh.MarkDirty(DirtyFull)
	if err := ndb.QueueUpdate(fresh); err != nil {
		t.Fatal(err)
	}
	stale := NewFromV5(makeV5At(t, net.IPv4(10, 4, 0, 2)), ndb)
	stale.SetFirstSeen(time.Now().Add(-2 * time.Hour))
	stale.MarkDirty(DirtyFull)
	if err := ndb.QueueUpdate(stale); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for ndb.Count() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of 2 nodes persisted", ndb.Count())
		}
		time.Sleep(50 * time.Millisecond)
	}

	table, err := NewFlatTable(FlatTableConfig{
		DB:             ndb,
		MaxActiveNodes: 10,
		MaxNodeAge:     time.Hour,
		Logger:         logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := table.LoadInitialNodesFromDB(); err != nil {
		t.Fatal(err)
	}

	table.mu.RLock()
	_, freshLoaded := table.activeNodes[fresh.ID()]
	_, staleLoaded := table.activeNodes[stale.ID()]
	table.mu.RUnlock()
	if !freshLoaded {
		t.Error("fresh never-contacted node was not loaded")
	}
	if staleLoaded {
		t.Error("stale never-contacted node was loaded")
	}
}

// TestLoadInitialNodesFromDBSkipsStaleRowsInSQL verifies the database excludes
// stale rows before the table scans eligible candidates.
func TestLoadInitialNodesFromDBSkipsStaleRowsInSQL(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "stale-sample.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)

	const maxActive = 3
	freshIDs := make(map[[32]byte]bool)
	for i := 0; i < maxActive; i++ {
		n := NewFromV5(makeV5At(t, net.IPv4(10, 5, 0, byte(i+1))), ndb)
		n.SetLastSeen(time.Now())
		n.MarkDirty(DirtyFull)
		if err := ndb.QueueUpdate(n); err != nil {
			t.Fatal(err)
		}
		freshIDs[n.ID()] = true
	}
	for i := 0; i < maxActive*3; i++ {
		n := NewFromV5(makeV5At(t, net.IPv4(10, 5, 1, byte(i+1))), ndb)
		n.SetFirstSeen(time.Now().Add(-2 * time.Hour))
		n.MarkDirty(DirtyFull)
		if err := ndb.QueueUpdate(n); err != nil {
			t.Fatal(err)
		}
	}
	total := maxActive + maxActive*3
	deadline := time.Now().Add(5 * time.Second)
	for ndb.Count() < total {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d nodes persisted", ndb.Count(), total)
		}
		time.Sleep(50 * time.Millisecond)
	}

	table, err := NewFlatTable(FlatTableConfig{
		DB:             ndb,
		MaxActiveNodes: maxActive,
		MaxNodeAge:     time.Hour,
		Logger:         logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := table.LoadInitialNodesFromDB(); err != nil {
		t.Fatal(err)
	}

	table.mu.RLock()
	defer table.mu.RUnlock()
	if len(table.activeNodes) != maxActive {
		t.Fatalf("active pool holds %d nodes, want %d", len(table.activeNodes), maxActive)
	}
	for id := range table.activeNodes {
		if !freshIDs[id] {
			t.Error("a stale row was loaded into the active pool")
		}
	}
}

func TestPersistedAdmissionFillsStartupAndFiltersSweep(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "persisted-admission.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)

	const maxActive = 2
	accepted := make(map[[32]byte]bool, maxActive)
	for i := 0; i < maxActive+6; i++ {
		n := NewFromV5(makeV5At(t, net.IPv4(10, 6, 0, byte(i+1))), ndb)
		n.SetLastSeen(time.Now())
		n.MarkDirty(DirtyFull)
		if err := ndb.QueueUpdate(n); err != nil {
			t.Fatal(err)
		}
		if i >= 6 {
			accepted[n.ID()] = true
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for ndb.Count() < maxActive+6 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d nodes persisted", ndb.Count())
		}
		time.Sleep(20 * time.Millisecond)
	}

	newTable := func() *FlatTable {
		table, err := NewFlatTable(FlatTableConfig{
			DB:                 ndb,
			MaxActiveNodes:     maxActive,
			MaxNodeAge:         time.Hour,
			AdmitPersistedNode: func(n *Node) bool { return accepted[n.ID()] },
			Logger:             logger,
		})
		if err != nil {
			t.Fatal(err)
		}
		return table
	}
	check := func(table *FlatTable) {
		t.Helper()
		nodes := table.GetActiveNodes()
		if len(nodes) != maxActive {
			t.Fatalf("active pool holds %d nodes, want %d", len(nodes), maxActive)
		}
		for _, n := range nodes {
			if !accepted[n.ID()] {
				t.Fatal("active pool contains a rejected node")
			}
		}
	}

	startup := newTable()
	if err := startup.LoadInitialNodesFromDB(); err != nil {
		t.Fatal(err)
	}
	check(startup)

	sweep := newTable()
	sweep.PerformSweep()
	check(sweep)
}

// TestPruneDeadNodesKeepsNeverContactedFreshNode verifies a freshly discovered
// node with no lastSeen yet survives pruning and is served, so it can be pinged
// before it is judged.
func TestPruneDeadNodesKeepsNeverContactedFreshNode(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "fresh.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)
	table, err := NewFlatTable(FlatTableConfig{
		DB:             ndb,
		MaxActiveNodes: 10,
		MaxFailures:    2,
		MaxNodeAge:     time.Hour,
		Logger:         logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	fresh := NewFromV5(makeV5At(t, net.IPv4(10, 3, 0, 1)), ndb)
	if !table.Add(fresh) {
		t.Fatal("fresh node was not admitted")
	}

	if removed := table.PruneDeadNodes(); removed != 0 {
		t.Fatalf("PruneDeadNodes removed %d fresh nodes, want 0", removed)
	}
	if got := len(table.GetActiveNodes()); got != 1 {
		t.Fatalf("active nodes = %d, want 1", got)
	}
	if got := table.GetNodesByDistance(fresh.ID(), []uint{256}, 8); len(got) != 1 {
		t.Errorf("GetNodesByDistance returned %d nodes, want 1", len(got))
	}

	stale := NewFromV5(makeV5At(t, net.IPv4(10, 3, 0, 2)), ndb)
	stale.SetFirstSeen(time.Now().Add(-2 * time.Hour))
	if !table.Add(stale) {
		t.Fatal("stale node was not admitted")
	}
	if removed := table.PruneDeadNodes(); removed != 1 {
		t.Fatalf("PruneDeadNodes removed %d stale nodes, want 1", removed)
	}
	if _, active := table.activeNodes[fresh.ID()]; !active {
		t.Error("fresh node was pruned alongside the stale one")
	}
}

func TestDeadNodesAreNotServedAndArePruned(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "dead.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)
	table, err := NewFlatTable(FlatTableConfig{
		DB:             ndb,
		MaxActiveNodes: 10,
		MaxFailures:    2,
		MaxNodeAge:     time.Hour,
		Logger:         logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	n := NewFromV5(makeV5At(t, net.IPv4(10, 2, 0, 1)), ndb)
	n.SetLastSeen(time.Now())
	if !table.Add(n) {
		t.Fatal("node was not admitted")
	}
	deadline := time.Now().Add(5 * time.Second)
	for ndb.Count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("node was not persisted")
		}
		time.Sleep(20 * time.Millisecond)
	}

	n.SetFailureCount(2)
	if got := table.FindClosestNodes(n.ID(), 16); len(got) != 0 {
		t.Errorf("FindClosestNodes returned %d dead nodes", len(got))
	}
	if got := table.GetNodesByDistance(n.ID(), []uint{256}, 8); len(got) != 0 {
		t.Errorf("GetNodesByDistance returned %d dead nodes", len(got))
	}
	if removed := table.PruneDeadNodes(); removed != 1 {
		t.Fatalf("PruneDeadNodes removed %d nodes, want 1", removed)
	}
	if got := len(table.GetActiveNodes()); got != 0 {
		t.Errorf("active nodes = %d, want 0", got)
	}
	stats := table.GetStats()
	if stats.DeadNodesRemoved != 1 {
		t.Errorf("DeadNodesRemoved = %d, want 1", stats.DeadNodesRemoved)
	}
	if stats.IPStats.TotalNodes != 0 {
		t.Errorf("IP limiter tracks %d nodes, want 0", stats.IPStats.TotalNodes)
	}

	deadline = time.Now().Add(5 * time.Second)
	for {
		stored, loadErr := ndb.Load(n.ID())
		if loadErr == nil && stored.FailureCount() == 2 {
			restored, tableErr := NewFlatTable(FlatTableConfig{
				DB:             ndb,
				MaxActiveNodes: 10,
				MaxFailures:    2,
				MaxNodeAge:     time.Hour,
				Logger:         logger,
			})
			if tableErr != nil {
				t.Fatal(tableErr)
			}
			if loadErr := restored.LoadInitialNodesFromDB(); loadErr != nil {
				t.Fatal(loadErr)
			}
			if got := len(restored.GetActiveNodes()); got != 0 {
				t.Errorf("restored active nodes = %d, want 0", got)
			}

			stored.SetLastSeen(time.Now())
			stored.SetFailureCount(0)
			if !restored.Add(stored) {
				t.Fatal("verified peer was not re-admitted")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dead peer statistics were not retained")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestENRMoveRespectsDestinationIPLimit verifies a move that happens inside
// Add — the record advances during adoption, after the limiter check at the
// top already saw the old addr — still goes through the IP limiter.
func TestENRMoveRespectsDestinationIPLimit(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "enr-move-limit.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerEL, logger)
	table, err := NewFlatTable(FlatTableConfig{DB: ndb, MaxActiveNodes: 10, MaxNodesPerIP: 1, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	oldIP := net.IPv4(10, 6, 0, 1)
	destinationIP := net.IPv4(10, 6, 0, 2)
	v5Old, err := discv5node.New(signedRecordAt(t, key, 1, oldIP))
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	mover := NewFromV5(v5Old, ndb)
	mover.SetLastSeen(time.Now())
	if !table.Add(mover) {
		t.Fatal("mover was not admitted")
	}

	occupant := NewFromV5(makeV5At(t, destinationIP), ndb)
	occupant.SetLastSeen(time.Now())
	if !table.Add(occupant) {
		t.Fatal("occupant was not admitted")
	}

	v5New, err := discv5node.New(signedRecordAt(t, key, 2, destinationIP))
	if err != nil {
		t.Fatalf("new v5 node: %v", err)
	}
	if table.Add(NewFromV5(v5New, ndb)) {
		t.Fatal("ENR move bypassed the destination IP limit")
	}
	for _, active := range table.GetActiveNodes() {
		if active.ID() == mover.ID() {
			t.Fatal("rejected moved node remained active")
		}
	}
	if got := table.ipLimiter.GetNodeCountForIP(oldIP); got != 0 {
		t.Errorf("old IP count = %d, want 0", got)
	}
	if got := table.ipLimiter.GetNodeCountForIP(destinationIP); got != 1 {
		t.Errorf("destination IP count = %d, want 1", got)
	}
}

func TestMovedNodeRespectsDestinationIPLimit(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "move-limit.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerEL, logger)
	table, err := NewFlatTable(FlatTableConfig{DB: ndb, MaxActiveNodes: 10, MaxNodesPerIP: 1, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}

	oldIP := net.IPv4(10, 3, 0, 1)
	destinationIP := net.IPv4(10, 3, 0, 2)
	firstV5 := makeV5At(t, oldIP)
	first := NewFromV5(firstV5, ndb)
	first.SetV4(v4node.New(firstV5.PublicKey(), &net.UDPAddr{IP: oldIP, Port: 9000}))
	first.SetLastSeen(time.Now())
	if !table.Add(first) {
		t.Fatal("first node was not admitted")
	}

	second := NewFromV5(makeV5At(t, destinationIP), ndb)
	second.SetLastSeen(time.Now())
	if !table.Add(second) {
		t.Fatal("second node was not admitted")
	}

	first.SetV4(v4node.New(firstV5.PublicKey(), &net.UDPAddr{IP: destinationIP, Port: 9100}))
	if table.Add(first) {
		t.Fatal("moved node bypassed the destination IP limit")
	}
	for _, active := range table.GetActiveNodes() {
		if active.ID() == first.ID() {
			t.Fatal("rejected moved node remained active")
		}
	}
	if got := table.ipLimiter.GetNodeCountForIP(oldIP); got != 0 {
		t.Errorf("old IP count = %d, want 0", got)
	}
	if got := table.ipLimiter.GetNodeCountForIP(destinationIP); got != 1 {
		t.Errorf("destination IP count = %d, want 1", got)
	}
}

func TestRemoveEvictsActiveNode(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "remove.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerEL, logger)
	table, err := NewFlatTable(FlatTableConfig{DB: ndb, MaxActiveNodes: 10, MaxNodesPerIP: 1, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}

	ip := net.IPv4(10, 10, 0, 1)
	n := NewFromV5(makeV5At(t, ip), ndb)
	if !table.Add(n) {
		t.Fatal("node was not admitted")
	}

	removed := table.Remove(n.ID())
	if removed != n {
		t.Fatalf("Remove returned %v, want the active node", removed)
	}
	if got := len(table.GetActiveNodes()); got != 0 {
		t.Errorf("active nodes = %d, want 0", got)
	}
	if got := table.ipLimiter.GetNodeCountForIP(ip); got != 0 {
		t.Errorf("IP count = %d, want 0", got)
	}
	if again := table.Remove(n.ID()); again != nil {
		t.Fatalf("second Remove returned %v, want nil", again)
	}
}
