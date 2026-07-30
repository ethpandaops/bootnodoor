package db

import (
	"path/filepath"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
)

const schemaBeforeLayerKey = 20251106015541

func openAt(t *testing.T, file string, version int64) *Database {
	t.Helper()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	database := NewDatabase(&SqliteDatabaseConfig{File: file}, logger)
	if err := database.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := database.ApplyEmbeddedDbSchema(version); err != nil {
		t.Fatalf("schema %d: %v", version, err)
	}
	return database
}

// The up migration rebuilds both tables, so it must carry existing rows across
// rather than silently starting empty.
func TestLayerKeyMigrationPreservesExistingRows(t *testing.T) {
	file := filepath.Join(t.TempDir(), "nodes.db")

	elID := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	clID := []byte("cccccccccccccccccccccccccccccccc")

	// Seeded with raw SQL: the Go upserts now target the composite key and
	// cannot write the pre-migration schema.
	old := openAt(t, file, schemaBeforeLayerKey)
	if err := old.RunDBTransaction(func(tx *sqlx.Tx) error {
		for _, tc := range []struct {
			id    []byte
			layer NodeLayer
		}{{elID, LayerEL}, {clID, LayerCL}} {
			if _, err := tx.Exec(
				`INSERT INTO nodes (nodeid, layer, port, seq, fork_digest, first_seen, enr, has_v4, has_v5)
				 VALUES (?, ?, 30303, 7, ?, 1000, ?, 1, 1)`,
				tc.id, string(tc.layer), []byte{9, 9, 9, 9}, []byte("enr-"+string(tc.layer))); err != nil {
				return err
			}
		}
		_, err := tx.Exec(
			`INSERT INTO bad_nodes (nodeid, layer, rejected_at, reason) VALUES (?, ?, ?, ?)`,
			elID, string(LayerEL), 1000, "invalid_fork_id")
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	old.Close()

	migrated := openAt(t, file, -2)
	defer migrated.Close()

	el, err := migrated.GetNode(LayerEL, elID)
	if err != nil {
		t.Fatalf("EL row lost by the migration: %v", err)
	}
	if el.Seq != 7 || string(el.ENR) != "enr-el" {
		t.Errorf("EL row mangled: seq=%d enr=%q", el.Seq, el.ENR)
	}
	if _, err := migrated.GetNode(LayerCL, clID); err != nil {
		t.Errorf("CL row lost by the migration: %v", err)
	}
	if isBad, _, reason, err := migrated.IsBadNode(elID, LayerEL, 0); err != nil {
		t.Errorf("IsBadNode: %v", err)
	} else if !isBad || reason != "invalid_fork_id" {
		t.Errorf("bad node lost by the migration: isBad=%v reason=%q", isBad, reason)
	}

	// The point of the migration: both layers now coexist for one ID.
	for _, layer := range []NodeLayer{LayerEL, LayerCL} {
		n := &Node{
			NodeID: elID, Layer: string(layer), Port: 30303, Seq: 8,
			ForkDigest: []byte{1, 2, 3, 4}, FirstSeen: 1000, ENR: []byte("enr"),
		}
		if err := migrated.RunDBTransaction(func(tx *sqlx.Tx) error {
			return migrated.UpsertNode(tx, n)
		}); err != nil {
			t.Fatalf("post-migration upsert %s: %v", layer, err)
		}
	}
	if _, err := migrated.GetNode(LayerEL, elID); err != nil {
		t.Errorf("EL row missing after dual-layer upsert: %v", err)
	}
	if _, err := migrated.GetNode(LayerCL, elID); err != nil {
		t.Errorf("CL row missing after dual-layer upsert: %v", err)
	}
}
