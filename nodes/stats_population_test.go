package nodes

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/db"
)

// TotalNodes came from the database and ActiveNodes from memory, so consumers
// subtracting them could report more active than total and a negative inactive
// count. The three populations are asserted exactly, because the inequality
// alone is also satisfied by reporting total == active and inactive == 0.
func TestGetStatsCountsPopulationsExactly(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "pop.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)
	table := newPersistTable(t, ndb, logger)

	// Persisted but never admitted: two rows written straight through the queue.
	for i := 0; i < 2; i++ {
		n := NewFromV5(makeV5At(t, net.IPv4(10, 1, 0, byte(i+1))), ndb)
		n.MarkDirty(DirtyFull)
		if err := ndb.QueueUpdate(n); err != nil {
			t.Fatalf("queue: %v", err)
		}
	}
	waitForPersisted(t, ndb, 2)

	// Admitted, and therefore also persisted: overlapping population.
	admitted := make([]*Node, 0, 3)
	for i := 0; i < 3; i++ {
		n := NewFromV5(makeV5At(t, net.IPv4(10, 2, 0, byte(i+1))), ndb)
		if !table.Add(n) {
			t.Fatalf("node %d not admitted", i)
		}
		admitted = append(admitted, n)
	}
	waitForPersisted(t, ndb, 5)

	stats := table.GetStats()
	if stats.ActiveNodes != 3 {
		t.Errorf("ActiveNodes = %d, want 3", stats.ActiveNodes)
	}
	if stats.TotalNodes != 5 {
		t.Errorf("TotalNodes = %d, want 5 (union of persisted and active)", stats.TotalNodes)
	}
	if stats.InactiveNodes != 2 {
		t.Errorf("InactiveNodes = %d, want 2 (persisted but not active)", stats.InactiveNodes)
	}

	// Demotion drops a node from the active pool while its row remains.
	table.mu.Lock()
	delete(table.activeNodes, admitted[0].ID())
	table.mu.Unlock()

	stats = table.GetStats()
	if stats.ActiveNodes != 2 {
		t.Errorf("after demotion ActiveNodes = %d, want 2", stats.ActiveNodes)
	}
	if stats.TotalNodes != 5 {
		t.Errorf("after demotion TotalNodes = %d, want 5", stats.TotalNodes)
	}
	if stats.InactiveNodes != 3 {
		t.Errorf("after demotion InactiveNodes = %d, want 3", stats.InactiveNodes)
	}
}

// An active node whose write has not landed yet must not make active exceed
// total, which is what produced the negative count in the devnet run.
func TestGetStatsHoldsInvariantBeforePersistence(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "lag.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)
	table := newPersistTable(t, ndb, logger)

	for i := 0; i < 4; i++ {
		n := NewFromV5(makeV5At(t, net.IPv4(10, 3, 0, byte(i+1))), ndb)
		table.mu.Lock()
		table.activeNodes[n.ID()] = n
		table.ipLimiter.Add(n)
		table.mu.Unlock()
	}

	stats := table.GetStats()
	if stats.ActiveNodes > stats.TotalNodes {
		t.Errorf("ActiveNodes %d > TotalNodes %d", stats.ActiveNodes, stats.TotalNodes)
	}
	if stats.InactiveNodes < 0 {
		t.Errorf("InactiveNodes = %d, want >= 0", stats.InactiveNodes)
	}
}

func waitForPersisted(t *testing.T, ndb *NodeDB, want int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for ndb.Count() < want {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d nodes persisted", ndb.Count(), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
