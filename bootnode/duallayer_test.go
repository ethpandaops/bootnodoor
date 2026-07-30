package bootnode

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	"github.com/ethpandaops/bootnodoor/db"
	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/nodes"
)

// newDualLayerService wires both tables so a record carrying eth and eth2 is
// admitted to each.
func newDualLayerService(t *testing.T) *Service {
	t.Helper()

	logger := quietLogger()
	database := db.NewDatabase(&db.SqliteDatabaseConfig{File: ":memory:", MaxOpenConns: 5, MaxIdleConns: 2}, logger)
	if err := database.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() { database.Close() })
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
	}

	key := mustKey(t)
	ln, err := createLocalNode(cfg, key, net.ParseIP("1.2.3.4"), nil, 9000, nil)
	if err != nil {
		t.Fatalf("createLocalNode: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	s := &Service{config: cfg, ctx: ctx, enrManager: NewENRManager(cfg, key, ln, true, true)}
	s.elNodeDB = nodes.NewNodeDB(ctx, database, db.LayerEL, logger)
	s.clNodeDB = nodes.NewNodeDB(ctx, database, db.LayerCL, logger)
	if s.elTable, err = s.createTable(ln.ID(), s.elNodeDB, "EL"); err != nil {
		t.Fatalf("createTable EL: %v", err)
	}
	if s.clTable, err = s.createTable(ln.ID(), s.clNodeDB, "CL"); err != nil {
		t.Fatalf("createTable CL: %v", err)
	}
	return s
}

// dualLayerNode builds a v5 node advertising the fork id and fork digest this
// service currently accepts, so it is admitted to both tables.
func dualLayerNode(t *testing.T, s *Service) *v5node.Node {
	t.Helper()

	forkID := s.enrManager.GetELFilter().GetCurrentForkID(StaticHead())
	digest := s.enrManager.GetCLFilter().GetCurrentForkDigest()

	key := mustKey(t)
	rec := enr.New()
	if err := rec.Set("ip", net.IPv4(9, 9, 9, 9)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(9000)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	if err := rec.Set("eth", []struct {
		Hash []byte
		Next uint64
	}{{Hash: forkID.Hash[:], Next: forkID.Next}}); err != nil {
		t.Fatalf("set eth: %v", err)
	}
	if err := rec.Set("eth2", clconfig.EncodeETH2Field(digest, [4]byte{}, ^uint64(0))); err != nil {
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

// A dual-layer peer occupies both tables as two node objects with their own
// last-seen. The handler's SetLastSeen reaches only whichever one currently
// shares stats with the v5 node, and re-admission repoints that at a wrapper the
// tables discarded — so onNodeSeen has to refresh both itself.
func TestOnNodeSeenRefreshesBothLayers(t *testing.T) {
	s := newDualLayerService(t)
	n := dualLayerNode(t, s)

	// Admit with a known last-seen, so a later failure shows a stale timestamp
	// rather than a zero one and cannot be mistaken for "never populated".
	admitted := time.Now()
	n.SetLastSeen(admitted)

	if !s.checkAndAddNode(n) {
		t.Fatal("dual-layer node was not admitted")
	}
	el, cl := s.elTable.Get(n.ID()), s.clTable.Get(n.ID())
	if el == nil || cl == nil {
		t.Fatalf("node not in both tables: el=%v cl=%v", el != nil, cl != nil)
	}
	if el == cl {
		t.Skip("tables share one node object; this test only means something when they differ")
	}

	// Re-admission, as an ENR refresh would do: repoints the v5 node's stats at a
	// wrapper the tables do not hold.
	s.checkAndAddNode(n)

	// One inbound packet, in the order the handler produces it.
	refreshed := time.Now().Add(time.Hour)
	n.SetLastSeen(refreshed)
	s.onNodeSeen(n, refreshed)

	if got := s.elTable.Get(n.ID()).LastSeen(); !got.Equal(refreshed) {
		t.Errorf("EL last-seen = %v, want the refreshed %v", got, refreshed)
	}
	if got := s.clTable.Get(n.ID()).LastSeen(); !got.Equal(refreshed) {
		t.Errorf("CL last-seen = %v, want the refreshed %v", got, refreshed)
	}
}
