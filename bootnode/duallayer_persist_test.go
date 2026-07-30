package bootnode

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	"github.com/ethpandaops/bootnodoor/db"
	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/nodes"
)

// serveAllServiceAt builds a file-backed service with classification disabled,
// which is what puts one node ID into both tables.
//
// No real peer advertises eth and eth2 together — EL and CL run as separate
// identities with separate keys — so serve-all, not a dual-stack client, is how
// the same node ID reaches both layers in practice.
func serveAllServiceAt(t *testing.T, file string) (*Service, *db.Database, context.CancelFunc) {
	t.Helper()

	logger := quietLogger()
	database := db.NewDatabase(&db.SqliteDatabaseConfig{File: file, MaxOpenConns: 5, MaxIdleConns: 2}, logger)
	if err := database.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	if err := database.ApplyEmbeddedDbSchema(-2); err != nil {
		t.Fatalf("db schema: %v", err)
	}

	cfg := &Config{
		Logger:        logger,
		Database:      database,
		ELConfig:      &elconfig.ChainConfig{},
		ELGenesisHash: [32]byte{1, 2, 3},
		ELGenesisTime: 1000,
		CLConfig:      &clconfig.Config{},
		ServeAll:      true,
	}

	key := mustKey(t)
	ln, err := createLocalNode(cfg, key, net.ParseIP("1.2.3.4"), nil, 9000, nil)
	if err != nil {
		t.Fatalf("createLocalNode: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Service{config: cfg, ctx: ctx, enrManager: NewENRManager(cfg, key, ln, true, true)}
	s.elNodeDB = nodes.NewNodeDB(ctx, database, db.LayerEL, logger)
	s.clNodeDB = nodes.NewNodeDB(ctx, database, db.LayerCL, logger)
	if s.elTable, err = s.createTable(ln.ID(), s.elNodeDB, "EL"); err != nil {
		t.Fatalf("createTable EL: %v", err)
	}
	if s.clTable, err = s.createTable(ln.ID(), s.clNodeDB, "CL"); err != nil {
		t.Fatalf("createTable CL: %v", err)
	}
	return s, database, cancel
}

// plainCLNode is an ordinary single-layer peer: eth2 only, as a real beacon node
// advertises.
func plainCLNode(t *testing.T, ip net.IP) *v5node.Node {
	t.Helper()

	key := mustKey(t)
	rec := enr.New()
	if err := rec.Set("ip", ip); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(9000)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	if err := rec.Set("eth2", clconfig.EncodeETH2Field(clconfig.ForkDigest{1, 2, 3, 4}, [4]byte{}, ^uint64(0))); err != nil {
		t.Fatalf("set eth2: %v", err)
	}
	rec.SetSeq(1)
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}

	n, err := v5node.New(rec)
	if err != nil {
		t.Fatalf("v5node.New: %v", err)
	}
	return n
}

// Under serve-all every discovered peer is pooled into every enabled table, so an
// ordinary CL-only node occupies both layers. With nodeid as the sole primary key
// the second write replaced the first, so one layer was lost on every restart —
// for every peer, not just an exotic one.
func TestServeAllPeerPersistsToBothLayers(t *testing.T) {
	file := filepath.Join(t.TempDir(), "serveall.db")

	s, database, cancel := serveAllServiceAt(t, file)
	n := plainCLNode(t, net.IPv4(9, 9, 9, 9))

	if !s.checkAndAddNode(n) {
		t.Fatal("node was not admitted under serve-all")
	}
	if s.elTable.Get(n.ID()) == nil {
		t.Fatal("serve-all did not pool the node into the EL table")
	}
	if s.clTable.Get(n.ID()) == nil {
		t.Fatal("serve-all did not pool the node into the CL table")
	}

	waitForRows(t, database, 2)

	id := n.ID()
	if _, err := database.GetNode(db.LayerEL, id[:]); err != nil {
		t.Errorf("EL row missing: %v", err)
	}
	if _, err := database.GetNode(db.LayerCL, id[:]); err != nil {
		t.Errorf("CL row missing: %v", err)
	}

	// Cancel before Close: the queue processor exits on the context, and Close
	// waits for it.
	cancel()
	s.elNodeDB.Close()
	s.clNodeDB.Close()
	database.Close()

	_, reopened, cancel2 := serveAllServiceAt(t, file)
	defer cancel2()
	defer reopened.Close()

	elBack, err := reopened.GetNode(db.LayerEL, id[:])
	if err != nil {
		t.Fatalf("EL row did not survive the restart: %v", err)
	}
	clBack, err := reopened.GetNode(db.LayerCL, id[:])
	if err != nil {
		t.Fatalf("CL row did not survive the restart: %v", err)
	}
	if elBack.Layer != string(db.LayerEL) || clBack.Layer != string(db.LayerCL) {
		t.Errorf("layer tags wrong after reload: el=%q cl=%q", elBack.Layer, clBack.Layer)
	}
}

func waitForRows(t *testing.T, database *db.Database, want int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := database.CountAllNodes()
		if err == nil && got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d rows persisted", got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
