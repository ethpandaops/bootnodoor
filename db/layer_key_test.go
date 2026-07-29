package db

import (
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
)

func testDB(t *testing.T) *Database {
	t.Helper()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	database := NewDatabase(&SqliteDatabaseConfig{File: ":memory:"}, logger)
	if err := database.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.ApplyEmbeddedDbSchema(-2); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return database
}

// A dual-layer peer occupies one row per layer. With nodeid as the sole primary
// key both upserts collide, so the second layer overwrites the first's
// layer-specific fork digest while the row keeps the first layer's tag — and
// every read filters on (nodeid, layer), so one layer silently disappears.
func TestUpsertKeepsBothLayers(t *testing.T) {
	database := testDB(t)

	id := []byte("0123456789abcdef0123456789abcdef")
	elDigest := []byte{0xaa, 0xaa, 0xaa, 0xaa}
	clDigest := []byte{0xbb, 0xbb, 0xbb, 0xbb}

	for _, tc := range []struct {
		layer  NodeLayer
		digest []byte
	}{{LayerEL, elDigest}, {LayerCL, clDigest}} {
		n := &Node{
			NodeID: id, Layer: string(tc.layer), Port: 30303, Seq: 1,
			ForkDigest: tc.digest, FirstSeen: time.Now().Unix(), ENR: []byte("enr"),
		}
		if err := database.RunDBTransaction(func(tx *sqlx.Tx) error {
			return database.UpsertNode(tx, n)
		}); err != nil {
			t.Fatalf("upsert %s: %v", tc.layer, err)
		}
	}

	el, err := database.GetNode(LayerEL, id)
	if err != nil {
		t.Fatalf("EL row missing after the CL upsert: %v", err)
	}
	cl, err := database.GetNode(LayerCL, id)
	if err != nil {
		t.Fatalf("CL row missing after the EL upsert: %v", err)
	}
	if string(el.ForkDigest) != string(elDigest) {
		t.Errorf("EL fork digest = %x, want %x", el.ForkDigest, elDigest)
	}
	if string(cl.ForkDigest) != string(clDigest) {
		t.Errorf("CL fork digest = %x, want %x", cl.ForkDigest, clDigest)
	}
}

// Same collision on the ENR-update path, which is the one admission uses.
func TestUpdateNodeENRKeepsBothLayers(t *testing.T) {
	database := testDB(t)

	id := []byte("fedcba9876543210fedcba9876543210")

	for _, tc := range []struct {
		layer  NodeLayer
		digest []byte
	}{{LayerEL, []byte{1, 1, 1, 1}}, {LayerCL, []byte{2, 2, 2, 2}}} {
		if err := database.RunDBTransaction(func(tx *sqlx.Tx) error {
			return database.UpdateNodeENR(tx, tc.layer, id, nil, nil, 30303, 1, tc.digest, []byte("enr"), true, true)
		}); err != nil {
			t.Fatalf("update %s: %v", tc.layer, err)
		}
	}

	if _, err := database.GetNode(LayerEL, id); err != nil {
		t.Errorf("EL row missing: %v", err)
	}
	if _, err := database.GetNode(LayerCL, id); err != nil {
		t.Errorf("CL row missing: %v", err)
	}
	got, err := database.CountAllNodes()
	if err != nil {
		t.Fatalf("CountAllNodes: %v", err)
	}
	if got != 2 {
		t.Errorf("total rows across layers = %d, want 2", got)
	}
}

// markBadNode is called per layer, and INSERT OR REPLACE keyed on nodeid alone
// drops the other layer's entry — so a peer rejected on both layers stays
// suppressed on only whichever was written last, defeating the cache that
// exists to stop repeated ENR requests.
func TestBadNodeSuppressionSurvivesBothLayers(t *testing.T) {
	database := testDB(t)

	id := []byte("badbadbadbadbadbadbadbadbadbadba")

	if err := database.StoreBadNode(id, LayerEL, "invalid_fork_id"); err != nil {
		t.Fatalf("store EL: %v", err)
	}
	if err := database.StoreBadNode(id, LayerCL, "invalid_fork_digest"); err != nil {
		t.Fatalf("store CL: %v", err)
	}

	elBad, _, elReason, err := database.IsBadNode(id, LayerEL, time.Hour)
	if err != nil {
		t.Fatalf("IsBadNode EL: %v", err)
	}
	clBad, _, clReason, err := database.IsBadNode(id, LayerCL, time.Hour)
	if err != nil {
		t.Fatalf("IsBadNode CL: %v", err)
	}

	if !elBad {
		t.Error("EL rejection was forgotten after the CL rejection was recorded")
	}
	if !clBad {
		t.Error("CL rejection was forgotten after the EL rejection was recorded")
	}
	if elBad && elReason != "invalid_fork_id" {
		t.Errorf("EL reason = %q, want invalid_fork_id", elReason)
	}
	if clBad && clReason != "invalid_fork_digest" {
		t.Errorf("CL reason = %q, want invalid_fork_digest", clReason)
	}
}
