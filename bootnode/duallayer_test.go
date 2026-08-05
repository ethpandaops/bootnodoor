package bootnode

import (
	"context"
	"crypto/ecdsa"
	"net"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	"github.com/ethpandaops/bootnodoor/db"
	v4node "github.com/ethpandaops/bootnodoor/discv4/node"
	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	v5protocol "github.com/ethpandaops/bootnodoor/discv5/protocol"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/nodes"
)

// newDualLayerService wires both tables so a record carrying eth and eth2 is
// admitted to each.
func newDualLayerService(t *testing.T) *Service {
	t.Helper()

	logger := quietLogger()
	database := newTestDatabase(t)

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

// forkRecord builds a signed record advertising the given eth fork ID and,
// when eth2 is non-nil, the given encoded eth2 field.
func forkRecord(t *testing.T, key *ecdsa.PrivateKey, seq uint64, ip net.IP, hash [4]byte, next uint64, eth2 []byte) *enr.Record {
	t.Helper()

	rec := enr.New()
	if err := rec.Set("ip", ip); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(9000)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	if err := rec.Set("eth", []struct {
		Hash []byte
		Next uint64
	}{{Hash: hash[:], Next: next}}); err != nil {
		t.Fatalf("set eth: %v", err)
	}
	if eth2 != nil {
		if err := rec.Set("eth2", eth2); err != nil {
			t.Fatalf("set eth2: %v", err)
		}
	}
	rec.SetSeq(seq)
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return rec
}

// v5NodeWithForkFields builds a v5 node advertising the given eth fork ID and,
// when eth2 is non-nil, the given encoded eth2 field.
func v5NodeWithForkFields(t *testing.T, ip net.IP, hash [4]byte, next uint64, eth2 []byte) *v5node.Node {
	t.Helper()

	n, err := v5node.New(forkRecord(t, mustKey(t), 1, ip, hash, next, eth2))
	if err != nil {
		t.Fatalf("v5node.New: %v", err)
	}
	return n
}

// dualLayerNode builds a v5 node advertising the fork id and fork digest this
// service currently accepts, so it is admitted to both tables.
func dualLayerNode(t *testing.T, s *Service) *v5node.Node {
	t.Helper()

	forkID := s.enrManager.GetELFilter().GetCurrentForkID(StaticHead())
	digest := s.enrManager.GetCLFilter().GetCurrentForkDigest()
	return v5NodeWithForkFields(t, net.IPv4(9, 9, 9, 9), forkID.Hash, forkID.Next,
		clconfig.EncodeETH2Field(digest, [4]byte{}, ^uint64(0)))
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

func TestConfiguredGenericBootnodeUsesDeclaredLayers(t *testing.T) {
	s := newDualLayerService(t)
	record := storedENRWith(t, mustKey(t), nil)
	encoded, err := record.EncodeBase64()
	if err != nil {
		t.Fatalf("encode generic ENR: %v", err)
	}
	s.config.ELBootnodes = []string{encoded}
	s.config.CLBootnodes = []string{encoded}
	s.indexConfiguredBootnodes()

	v5, err := v5node.New(record)
	if err != nil {
		t.Fatalf("v5 node: %v", err)
	}
	nodeID := [32]byte(v5.ID())
	if err := s.config.Database.StoreBadNode(nodeID[:], db.LayerEL, "not_el"); err != nil {
		t.Fatal(err)
	}
	if err := s.config.Database.StoreBadNode(nodeID[:], db.LayerCL, "not_cl"); err != nil {
		t.Fatal(err)
	}

	s.connectELBootnodeENR(record)
	s.connectCLBootnodes()

	for layer, table := range map[db.NodeLayer]*nodes.FlatTable{
		db.LayerEL: s.elTable,
		db.LayerCL: s.clTable,
	} {
		active := false
		for _, n := range table.GetActiveNodes() {
			if n.ID() == nodeID {
				active = true
				break
			}
		}
		if !active {
			t.Errorf("configured generic bootnode was not active in %s", layer)
		}
		isBad, _, reason, checkErr := s.config.Database.IsBadNode(nodeID[:], layer, time.Hour)
		if checkErr != nil {
			t.Fatal(checkErr)
		}
		if isBad {
			t.Errorf("configured generic bootnode remains bad in %s: %s", layer, reason)
		}
	}

	s.onNodeSeen(v5, time.Now())
	requesterIdentity := &identity{localNode: mustV5Node(t), servesEL: true, servesCL: true}
	got := s.onFindNodeV5(
		requesterIdentity,
		&v5protocol.FindNode{Distances: []uint{256}},
		v5,
		&net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 30303},
	)
	if len(got) != 1 || got[0].ID() != v5.ID() {
		t.Fatalf("configured generic requester received %d nodes, want its configured peer", len(got))
	}
}

func TestConfiguredBootnodeValidatesAdvertisedForkFields(t *testing.T) {
	s := newDualLayerService(t)
	record := storedENRWith(t, mustKey(t), map[string][]byte{
		"eth":  {0x01},
		"eth2": {0x02},
	})
	encoded, err := record.EncodeBase64()
	if err != nil {
		t.Fatal(err)
	}
	s.config.ELBootnodes = []string{encoded}
	s.config.CLBootnodes = []string{encoded}
	s.indexConfiguredBootnodes()
	id, ok := configuredBootnodeID(encoded, false)
	if !ok {
		t.Fatal("configured node ID was not indexed")
	}

	if accepted, _ := s.admitELNode(id, record); accepted {
		t.Error("configured bootnode bypassed its advertised EL fork field")
	}
	if s.admitCLNode(id, record) {
		t.Error("configured bootnode bypassed its advertised CL fork field")
	}
}

func TestConfiguredGenericBootnodeStaysInDeclaredLayer(t *testing.T) {
	for _, layer := range []db.NodeLayer{db.LayerEL, db.LayerCL} {
		t.Run(string(layer), func(t *testing.T) {
			s := newDualLayerService(t)
			record := storedENRWith(t, mustKey(t), nil)
			encoded, err := record.EncodeBase64()
			if err != nil {
				t.Fatal(err)
			}
			if layer == db.LayerEL {
				s.config.ELBootnodes = []string{encoded}
			} else {
				s.config.CLBootnodes = []string{encoded}
			}
			s.indexConfiguredBootnodes()

			v5, err := v5node.New(record)
			if err != nil {
				t.Fatal(err)
			}
			if !s.checkAndAddNode(v5) {
				t.Fatal("configured generic bootnode was not admitted")
			}

			if got := s.elTable.Get(v5.ID()); (got != nil) != (layer == db.LayerEL) {
				t.Errorf("EL membership = %v for configured %s bootnode", got != nil, layer)
			}
			if got := s.clTable.Get(v5.ID()); (got != nil) != (layer == db.LayerCL) {
				t.Errorf("CL membership = %v for configured %s bootnode", got != nil, layer)
			}
		})
	}
}

// elNodeWithFork builds a v5 node whose eth field carries the given fork hash.
func elNodeWithFork(t *testing.T, ip net.IP, hash [4]byte, next uint64) *v5node.Node {
	return v5NodeWithForkFields(t, ip, hash, next, nil)
}

// persistELNode writes a node to the EL database and waits for the row.
func persistELNode(t *testing.T, s *Service, n *nodes.Node, wantCount int) {
	t.Helper()

	n.SetLastSeen(time.Now())
	n.MarkDirty(nodes.DirtyFull)
	if err := s.elNodeDB.QueueUpdate(n); err != nil {
		t.Fatal(err)
	}
	waitForRows(t, s.config.Database, wantCount)
}

// A discv4 packet from a peer that exists only as a DB row must not promote it
// past the fork filter: Get falls back to the DB, and the not-newer-seq branch
// used to re-add without any classification.
func TestOnNodeSeenV4DoesNotResurrectRejectedNode(t *testing.T) {
	s := newDualLayerService(t)

	rejected := elNodeWithFork(t, net.IPv4(10, 7, 0, 1), [4]byte{0xde, 0xad, 0xbe, 0xef}, 0)
	persistELNode(t, s, nodes.NewFromV5(rejected, s.elNodeDB), 1)
	if s.elTable.Get(rejected.ID()) == nil {
		t.Fatal("rejected node not reachable via DB fallback")
	}

	v4Node, err := v4node.FromENR(rejected.Record(), &net.UDPAddr{IP: net.IPv4(10, 7, 0, 1), Port: 9000})
	if err != nil {
		t.Fatalf("v4 node: %v", err)
	}
	s.onNodeSeenV4(v4Node, time.Now())

	for _, active := range s.elTable.GetActiveNodes() {
		if active.ID() == rejected.ID() {
			t.Fatal("fork-rejected DB node was promoted into the active pool")
		}
	}
}

// Restart must apply the same fork classification to persisted rows that live
// traffic gets: a fork rotation can invalidate rows admitted before it.
func TestStartDoesNotLoadRejectedNodes(t *testing.T) {
	s := newDualLayerService(t)

	forkID := s.enrManager.GetELFilter().GetCurrentForkID(StaticHead())
	accepted := elNodeWithFork(t, net.IPv4(10, 8, 0, 1), forkID.Hash, forkID.Next)
	rejected := elNodeWithFork(t, net.IPv4(10, 8, 0, 2), [4]byte{0xde, 0xad, 0xbe, 0xef}, 0)
	persistELNode(t, s, nodes.NewFromV5(accepted, s.elNodeDB), 1)
	persistELNode(t, s, nodes.NewFromV5(rejected, s.elNodeDB), 2)

	if err := s.loadInitialNodes(); err != nil {
		t.Fatal(err)
	}

	active := s.elTable.GetActiveNodes()
	if len(active) != 1 {
		t.Fatalf("active pool holds %d nodes, want 1", len(active))
	}
	if active[0].ID() != accepted.ID() {
		t.Fatal("the loaded node is not the fork-accepted one")
	}
}

// acceptedForkFields returns the eth fork ID and encoded eth2 field this
// service currently accepts.
func acceptedForkFields(t *testing.T, s *Service) (elconfig.ForkID, []byte) {
	t.Helper()

	forkID := s.enrManager.GetELFilter().GetCurrentForkID(StaticHead())
	digest := s.enrManager.GetCLFilter().GetCurrentForkDigest()
	return forkID, clconfig.EncodeETH2Field(digest, [4]byte{}, ^uint64(0))
}

func activeInTable(table *nodes.FlatTable, nodeID [32]byte) bool {
	for _, n := range table.GetActiveNodes() {
		if n.ID() == nodeID {
			return true
		}
	}
	return false
}

// A peer that publishes a record with a foreign fork hash left our chain: the
// async discv5 update path must evict it from the EL table, keep its still
// valid CL entry, and the persisted record must keep it out of sweep
// promotion and restart loads.
func TestOnNodeUpdateEvictsWrongChainELPeerAndDoesNotReturn(t *testing.T) {
	s := newDualLayerService(t)
	forkID, eth2 := acceptedForkFields(t, s)

	key := mustKey(t)
	ip := net.IPv4(10, 11, 0, 1)
	good, err := v5node.New(forkRecord(t, key, 1, ip, forkID.Hash, forkID.Next, eth2))
	if err != nil {
		t.Fatalf("v5node.New: %v", err)
	}
	nodeID := [32]byte(good.ID())
	if !s.checkAndAddNode(good) {
		t.Fatal("compatible node was not admitted")
	}
	if !activeInTable(s.elTable, nodeID) || !activeInTable(s.clTable, nodeID) {
		t.Fatal("node not active in both tables")
	}

	wrong, err := v5node.New(forkRecord(t, key, 2, ip, [4]byte{0xde, 0xad, 0xbe, 0xef}, 0, eth2))
	if err != nil {
		t.Fatalf("v5node.New: %v", err)
	}
	s.onNodeUpdate(wrong)

	if activeInTable(s.elTable, nodeID) {
		t.Fatal("wrong-chain peer stayed in the EL table")
	}
	if !activeInTable(s.clTable, nodeID) {
		t.Fatal("still-valid CL entry was evicted alongside the EL one")
	}
	isBad, _, reason, err := s.config.Database.IsBadNode(nodeID[:], db.LayerEL, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !isBad || reason != "invalid_fork_id" {
		t.Fatalf("bad-node record = (%v, %q), want (true, invalid_fork_id)", isBad, reason)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		stored, loadErr := s.elNodeDB.Load(nodeID)
		if loadErr == nil && stored.Record() != nil && stored.Record().Seq() == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failing record was not persisted")
		}
		time.Sleep(20 * time.Millisecond)
	}

	s.elTable.PerformSweep()
	if activeInTable(s.elTable, nodeID) {
		t.Fatal("sweep re-promoted the evicted wrong-chain peer")
	}

	var localID [32]byte
	restored, err := s.createTable(localID, s.elNodeDB, "EL")
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.LoadInitialNodesFromDB(); err != nil {
		t.Fatal(err)
	}
	if activeInTable(restored, nodeID) {
		t.Fatal("restart reloaded the evicted wrong-chain peer")
	}
}

// The discv4 newer-record path must evict too: the peer proved the
// wrong-chain record with a fresh signature.
func TestOnNodeSeenV4EvictsWrongChainPeer(t *testing.T) {
	s := newDualLayerService(t)
	forkID, eth2 := acceptedForkFields(t, s)

	key := mustKey(t)
	ip := net.IPv4(10, 11, 0, 2)
	good, err := v5node.New(forkRecord(t, key, 1, ip, forkID.Hash, forkID.Next, eth2))
	if err != nil {
		t.Fatalf("v5node.New: %v", err)
	}
	nodeID := [32]byte(good.ID())
	if !s.checkAndAddNode(good) {
		t.Fatal("compatible node was not admitted")
	}

	wrongRec := forkRecord(t, key, 2, ip, [4]byte{0xde, 0xad, 0xbe, 0xef}, 0, eth2)
	v4Node, err := v4node.FromENR(wrongRec, &net.UDPAddr{IP: ip, Port: 9000})
	if err != nil {
		t.Fatalf("v4 node: %v", err)
	}
	s.onNodeSeenV4(v4Node, time.Now())

	if activeInTable(s.elTable, nodeID) {
		t.Fatal("wrong-chain peer stayed in the EL table")
	}
}

// A peer with a foreign eth2 digest left the CL chain; its valid EL entry
// must stay.
func TestOnNodeUpdateEvictsWrongChainCLPeer(t *testing.T) {
	s := newDualLayerService(t)
	forkID, eth2 := acceptedForkFields(t, s)

	key := mustKey(t)
	ip := net.IPv4(10, 11, 0, 3)
	good, err := v5node.New(forkRecord(t, key, 1, ip, forkID.Hash, forkID.Next, eth2))
	if err != nil {
		t.Fatalf("v5node.New: %v", err)
	}
	nodeID := [32]byte(good.ID())
	if !s.checkAndAddNode(good) {
		t.Fatal("compatible node was not admitted")
	}

	foreignEth2 := clconfig.EncodeETH2Field(clconfig.ForkDigest{0xde, 0xad, 0xbe, 0xef}, [4]byte{}, ^uint64(0))
	wrong, err := v5node.New(forkRecord(t, key, 2, ip, forkID.Hash, forkID.Next, foreignEth2))
	if err != nil {
		t.Fatalf("v5node.New: %v", err)
	}
	s.onNodeUpdate(wrong)

	if activeInTable(s.clTable, nodeID) {
		t.Fatal("wrong-chain peer stayed in the CL table")
	}
	if !activeInTable(s.elTable, nodeID) {
		t.Fatal("still-valid EL entry was evicted alongside the CL one")
	}
	isBad, _, reason, err := s.config.Database.IsBadNode(nodeID[:], db.LayerCL, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !isBad || reason != "invalid_fork_digest" {
		t.Fatalf("bad-node record = (%v, %q), want (true, invalid_fork_digest)", isBad, reason)
	}
}

// A record that classification accepts must never trigger an eviction, no
// matter which failure path called the helper.
func TestEvictWrongChainKeepsCompatiblePeer(t *testing.T) {
	s := newDualLayerService(t)
	n := dualLayerNode(t, s)
	nodeID := [32]byte(n.ID())
	if !s.checkAndAddNode(n) {
		t.Fatal("compatible node was not admitted")
	}

	s.evictWrongChain(s.elTable, s.elNodeDB, nodeID, n.Record(), db.LayerEL)
	s.evictWrongChain(s.clTable, s.clNodeDB, nodeID, n.Record(), db.LayerCL)

	if !activeInTable(s.elTable, nodeID) || !activeInTable(s.clTable, nodeID) {
		t.Fatal("compatible peer was evicted")
	}
}

func TestEvictWrongChainSkipsConfiguredBootnode(t *testing.T) {
	s := newDualLayerService(t)

	wrongRec := forkRecord(t, mustKey(t), 1, net.IPv4(10, 11, 0, 4), [4]byte{0xde, 0xad, 0xbe, 0xef}, 0, nil)
	encoded, err := wrongRec.EncodeBase64()
	if err != nil {
		t.Fatal(err)
	}
	s.config.ELBootnodes = []string{encoded}
	s.indexConfiguredBootnodes()

	v5, err := v5node.New(wrongRec)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := [32]byte(v5.ID())
	if !s.elTable.Add(nodes.NewFromV5(v5, s.elNodeDB)) {
		t.Fatal("bootnode was not added")
	}

	s.evictWrongChain(s.elTable, s.elNodeDB, nodeID, wrongRec, db.LayerEL)

	if !activeInTable(s.elTable, nodeID) {
		t.Fatal("configured bootnode was evicted")
	}
}
