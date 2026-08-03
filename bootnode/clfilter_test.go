package bootnode

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/db"
	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/nodes"
)

// newCLTestService mirrors newServeAllTestService but wires the CL layer, so the
// CL fork-digest filter and its counters are reachable.
func newCLTestService(t *testing.T) *Service {
	t.Helper()

	logger := quietLogger()
	database := newTestDatabase(t)

	cfg := &Config{
		Logger:   logger,
		Database: database,
		CLConfig: &clconfig.Config{},
	}

	key := mustKey(t)
	ln, err := createLocalNode(cfg, key, net.ParseIP("1.2.3.4"), nil, 9000, nil)
	if err != nil {
		t.Fatalf("createLocalNode: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	s := &Service{config: cfg, ctx: ctx, enrManager: NewENRManager(cfg, key, ln, false, true)}
	s.clNodeDB = nodes.NewNodeDB(ctx, database, db.LayerCL, logger)
	s.clTable, err = s.createTable(ln.ID(), s.clNodeDB, "CL")
	if err != nil {
		t.Fatalf("createTable: %v", err)
	}

	return s
}

// clNodeOnCurrentDigest builds a v5 node whose eth2 entry carries the digest the
// filter currently accepts, so it exercises the accepted path.
func clNodeOnCurrentDigest(t *testing.T, s *Service) *v5node.Node {
	t.Helper()

	digest := s.enrManager.GetCLFilter().GetCurrentForkDigest()
	eth2 := clconfig.EncodeETH2Field(digest, [4]byte{}, ^uint64(0))

	key := mustKey(t)
	rec := enr.New()
	if err := rec.Set("ip", net.IPv4(9, 9, 9, 9)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := rec.Set("udp", uint16(9000)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	if err := rec.Set("eth2", eth2); err != nil {
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

// onNodeSeen runs once per decoded discv5 message, so it must classify without
// counting: otherwise the Fork Filter card reports packet traffic rather than
// admission decisions.
func TestOnNodeSeen_LeavesCLFilterCountersUntouched(t *testing.T) {
	s := newCLTestService(t)
	n := clNodeOnCurrentDigest(t, s)

	for i := 0; i < 3; i++ {
		s.onNodeSeen(n, time.Now())
	}

	if got := s.enrManager.GetCLFilter().GetStats().TotalChecks; got != 0 {
		t.Fatalf("TotalChecks = %d after 3 onNodeSeen calls, want 0", got)
	}
}

// The counterpart guard: admission must still count, or the fix would just zero
// the UI permanently while the classification tests passed.
func TestCheckAndAddNode_RecordsCLAdmissionOnce(t *testing.T) {
	s := newCLTestService(t)
	n := clNodeOnCurrentDigest(t, s)

	if !s.checkAndAddNode(n) {
		t.Fatal("current-digest node was not admitted to the CL table")
	}

	stats := s.enrManager.GetCLFilter().GetStats()
	if stats.TotalChecks != 1 || stats.AcceptedCurrent != 1 {
		t.Fatalf("stats = %+v after one admission, want 1 check / 1 accepted-current", stats)
	}
}
