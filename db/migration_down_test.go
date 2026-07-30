package db

import (
	"path/filepath"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
)

// The down migration collapses two rows into a nodeid primary key, so it has to
// actually run and has to pick a row deterministically rather than erroring on
// the constraint.
func TestLayerKeyDownMigrationCollapsesDeterministically(t *testing.T) {
	file := filepath.Join(t.TempDir(), "down.db")

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	database := NewDatabase(&SqliteDatabaseConfig{File: file}, logger)
	if err := database.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer database.Close()
	if err := database.ApplyEmbeddedDbSchema(-2); err != nil {
		t.Fatalf("schema: %v", err)
	}

	dualID := []byte("dddddddddddddddddddddddddddddddd")
	clOnlyID := []byte("11111111111111111111111111111111")

	for _, tc := range []struct {
		id    []byte
		layer NodeLayer
	}{{dualID, LayerEL}, {dualID, LayerCL}, {clOnlyID, LayerCL}} {
		n := &Node{
			NodeID: tc.id, Layer: string(tc.layer), Port: 30303, Seq: 1,
			ForkDigest: []byte{1, 2, 3, 4}, FirstSeen: 1000, ENR: []byte("enr-" + string(tc.layer)),
		}
		if err := database.RunDBTransaction(func(tx *sqlx.Tx) error {
			return database.UpsertNode(tx, n)
		}); err != nil {
			t.Fatalf("seed %s: %v", tc.layer, err)
		}
	}

	goose.SetLogger(&gooseLogger{logger: logger})
	goose.SetBaseFS(embedSchema)
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.Down(database.writerDb.DB, "schema"); err != nil {
		t.Fatalf("down migration failed to run: %v", err)
	}

	var rows []struct {
		NodeID []byte `db:"nodeid"`
		Layer  string `db:"layer"`
	}
	if err := database.ReaderDb.Select(&rows, "SELECT nodeid, layer FROM nodes ORDER BY layer"); err != nil {
		t.Fatalf("select after down: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows after collapse = %d, want 2", len(rows))
	}

	byID := map[string]string{}
	for _, r := range rows {
		byID[string(r.NodeID)] = r.Layer
	}
	if got := byID[string(dualID)]; got != string(LayerEL) {
		t.Errorf("dual-layer node collapsed to layer %q, want el", got)
	}
	if got := byID[string(clOnlyID)]; got != string(LayerCL) {
		t.Errorf("cl-only node collapsed to layer %q, want cl", got)
	}
}
