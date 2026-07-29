package nodes

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/bootnodoor/db"
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
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	database := db.NewDatabase(&db.SqliteDatabaseConfig{File: ":memory:"}, logger)
	if err := database.Init(); err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.ApplyEmbeddedDbSchema(-2); err != nil {
		t.Fatal(err)
	}

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
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	database := db.NewDatabase(&db.SqliteDatabaseConfig{File: ":memory:"}, logger)
	if err := database.Init(); err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.ApplyEmbeddedDbSchema(-2); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ndb := NewNodeDB(ctx, database, db.LayerCL, logger)

	selfNode := NewFromV5(makeV5At(t, net.IPv4(10, 9, 0, 1)), ndb)
	selfNode.MarkDirty(DirtyFull)
	if err := ndb.QueueUpdate(selfNode); err != nil {
		t.Fatal(err)
	}
	other := NewFromV5(makeV5At(t, net.IPv4(10, 9, 0, 2)), ndb)
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
