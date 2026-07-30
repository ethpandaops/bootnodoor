package nodes

import (
	"context"
	"crypto/ecdsa"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/db"
	v4node "github.com/ethpandaops/bootnodoor/discv4/node"
	discv5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/sirupsen/logrus"
)

func persistTestDB(t *testing.T, file string) *db.Database {
	t.Helper()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	database := db.NewDatabase(&db.SqliteDatabaseConfig{File: file}, logger)
	if err := database.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := database.ApplyEmbeddedDbSchema(-2); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return database
}

func quietTableLogger() logrus.FieldLogger {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	return logger
}

func newPersistTable(t *testing.T, ndb *NodeDB, logger logrus.FieldLogger) *FlatTable {
	t.Helper()

	table, err := NewFlatTable(FlatTableConfig{DB: ndb, MaxActiveNodes: 10, Logger: logger})
	if err != nil {
		t.Fatalf("new table: %v", err)
	}
	return table
}

// Admission puts a node in the active pool and marks it dirty, but nothing ever
// enqueued it, so organically discovered nodes were never written at all.
func TestAdmissionPersistsNode(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "admit.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)
	table := newPersistTable(t, ndb, logger)

	n := NewFromV5(makeV5At(t, net.IPv4(10, 0, 0, 7)), ndb)
	if !table.Add(n) {
		t.Fatal("node was not admitted")
	}

	deadline := time.Now().Add(5 * time.Second)
	for ndb.Count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("admitted node was never persisted")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A node admitted immediately before shutdown must not be lost: the consumer
// abandons the channel backlog on ctx cancellation, so Close has to drain it.
func TestAdmissionSurvivesImmediateClose(t *testing.T) {
	file := filepath.Join(t.TempDir(), "close.db")
	database := persistTestDB(t, file)

	ctx, cancel := context.WithCancel(context.Background())
	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)
	table := newPersistTable(t, ndb, logger)

	n := NewFromV5(makeV5At(t, net.IPv4(10, 0, 0, 9)), ndb)
	if !table.Add(n) {
		t.Fatal("node was not admitted")
	}

	cancel()
	ndb.Close()
	database.Close()

	reopened := persistTestDB(t, file)
	defer reopened.Close()

	count, err := reopened.CountNodes(db.LayerCL)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("persisted nodes after immediate close = %d, want 1", count)
	}
}

// QueueUpdate must refuse work once Close has begun rather than accept it into a
// queue nobody will drain.
func TestQueueUpdateRejectedAfterClose(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "gate.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)

	cancel()
	ndb.Close()

	n := NewFromV5(makeV5At(t, net.IPv4(10, 0, 0, 11)), ndb)
	n.MarkDirty(DirtyFull)
	if err := ndb.QueueUpdate(n); err == nil {
		t.Error("QueueUpdate accepted a node after Close; it will never be written")
	}
}

// The DirtyFull branch clears every remaining flag after upserting, so the
// upsert itself has to carry last_active or the DirtyLastActive set during
// admission is discarded and the row sorts as the most inactive.
func TestFullUpsertPersistsLastActive(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "active.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)

	n := NewFromV5(makeV5At(t, net.IPv4(10, 0, 0, 21)), ndb)
	n.SetLastActive(time.Now())
	n.MarkDirty(DirtyFull)
	if err := ndb.QueueUpdate(n); err != nil {
		t.Fatalf("queue: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for ndb.Count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("node was never persisted")
		}
		time.Sleep(20 * time.Millisecond)
	}

	id := n.IDBytes()
	stored, err := database.GetNode(db.LayerCL, id[:])
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !stored.LastActive.Valid || stored.LastActive.Int64 == 0 {
		t.Error("last_active was written as NULL by the full upsert")
	}
}

// batchUpdate snapshots the dirty flags, writes, then clears. Clearing
// everything discarded any flag marked while the write was in flight, because
// that caller saw the node already queued and did not enqueue it again.
func TestClearDirtySnapshotKeepsUnobservedFlags(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "flags.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ndb := NewNodeDB(ctx, database, db.LayerCL, quietTableLogger())
	n := NewFromV5(makeV5At(t, net.IPv4(10, 4, 0, 1)), ndb)

	n.MarkDirty(DirtyENR)
	observed, gen := n.DirtySnapshot()
	n.MarkDirty(DirtyLastActive)

	if remaining := n.ClearDirtySnapshot(observed, gen); !remaining {
		t.Error("ClearDirtySnapshot reported nothing left, so the later mark would not be requeued")
	}
	if got := n.GetDirtyFlags(); got&DirtyLastActive == 0 {
		t.Error("a flag marked after the snapshot was cleared unwritten")
	}

	// Re-marking the same bit must also survive: the generation moved, so the
	// observed write cannot be assumed to cover the newer value.
	observed, gen = n.DirtySnapshot()
	n.MarkDirty(DirtyLastActive)
	if remaining := n.ClearDirtySnapshot(observed, gen); !remaining {
		t.Error("a same-bit re-mark during the write was dropped")
	}
	if got := n.GetDirtyFlags(); got&DirtyLastActive == 0 {
		t.Error("same-bit re-mark was cleared unwritten")
	}
}

// A peer found over discv4 can be admitted as v5-only first, if its handshake
// completes before the v4 admission lands. Add previously refreshed only a newer
// ENR, so the v4 pointer was dropped and the peer persisted as v5-only.
func TestAddMergesProtocolCapabilities(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "merge.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerEL, logger)
	table := newPersistTable(t, ndb, logger)

	v5 := makeV5At(t, net.IPv4(10, 9, 0, 1))
	first := NewFromV5(v5, ndb)
	if !table.Add(first) {
		t.Fatal("v5-only node was not admitted")
	}
	if table.Get(first.ID()).HasV4() {
		t.Fatal("precondition: entry should start v5-only")
	}

	// The same peer arriving over discv4, as the probe path produces it.
	second := NewFromV5(v5, ndb)
	second.SetV4(makeV4For(t, v5))
	if !table.Add(second) {
		t.Fatal("second admission was rejected")
	}

	entry := table.Get(first.ID())
	if !entry.HasV4() {
		t.Error("v4 capability was lost: the table entry is still v5-only")
	}
	if !entry.HasV5() {
		t.Error("v5 capability was dropped by the merge")
	}
}

func makeV4For(t *testing.T, v5 *discv5node.Node) *v4node.Node {
	t.Helper()
	return v4node.New(v5.PublicKey(), v5.Addr())
}

// Senders use the adopted protocol node's own address, so a protocol pointer from
// an older record would aim that protocol at an endpoint the peer has left.
func TestAddDoesNotAdoptProtocolFromStaleRecord(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "stale.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := quietTableLogger()
	ndb := NewNodeDB(ctx, database, db.LayerEL, logger)
	table := newPersistTable(t, ndb, logger)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	newer := signedRecordAt(t, key, 5, net.IPv4(10, 8, 0, 1))
	older := signedRecordAt(t, key, 2, net.IPv4(10, 8, 0, 2))

	newerV5, err := discv5node.New(newer)
	if err != nil {
		t.Fatalf("v5 from newer: %v", err)
	}
	existing := NewFromV5(newerV5, ndb)
	if !table.Add(existing) {
		t.Fatal("first admission rejected")
	}

	olderV5, err := discv5node.New(older)
	if err != nil {
		t.Fatalf("v5 from older: %v", err)
	}
	stale := NewFromV5(olderV5, ndb)
	stale.SetV4(v4node.New(olderV5.PublicKey(), olderV5.Addr()))
	table.Add(stale)

	if table.Get(existing.ID()).HasV4() {
		t.Error("adopted a v4 pointer from a record older than the entry's")
	}
}

func signedRecordAt(t *testing.T, key *ecdsa.PrivateKey, seq uint64, ip net.IP) *enr.Record {
	t.Helper()
	rec := enr.New()
	if err := rec.Set("ip", ip); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(9000)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	rec.SetSeq(seq)
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return rec
}

// Adoption only ever fills an empty slot, so a pointer installed from a stale
// record is permanent. The freshness check and the install must therefore happen
// under one lock hold, or a concurrent advance can slip between them.
func TestAdoptProtocolsFromIsAtomicUnderRace(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "race.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ndb := NewNodeDB(ctx, database, db.LayerEL, quietTableLogger())

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	for round := 0; round < 200; round++ {
		base, _ := discv5node.New(signedRecordAt(t, key, 3, net.IPv4(10, 7, 0, 1)))
		entry := NewFromV5(base, ndb)

		staleV5, _ := discv5node.New(signedRecordAt(t, key, 1, net.IPv4(10, 7, 0, 2)))
		stale := NewFromV5(staleV5, ndb)
		stale.SetV4(v4node.New(staleV5.PublicKey(), staleV5.Addr()))

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); entry.AdoptProtocolsFrom(stale) }()
		go func() { defer wg.Done(); entry.UpdateENR(signedRecordAt(t, key, 9, net.IPv4(10, 7, 0, 3))) }()
		wg.Wait()

		if v4 := entry.V4(); v4 != nil && v4.Addr().IP.Equal(net.IPv4(10, 7, 0, 2)) {
			t.Fatalf("round %d: installed a v4 pointer from the stale record", round)
		}
	}
}
