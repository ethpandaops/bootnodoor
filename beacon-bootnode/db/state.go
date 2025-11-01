package db

import (
	"github.com/jmoiron/sqlx"
)

/*
CREATE TABLE IF NOT EXISTS "state" (
    "key" TEXT PRIMARY KEY,
    "value" BLOB
);
*/

// State represents a key-value pair for storing runtime state.
type State struct {
	Key   string `db:"key"`   // State key identifier
	Value []byte `db:"value"` // State value (raw bytes)
}

// GetState retrieves a state value by key.
func (d *Database) GetState(key string) ([]byte, error) {
	var value []byte
	err := d.ReaderDb.Get(&value, "SELECT value FROM state WHERE key = $1", key)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// SetState stores a state value by key.
// If tx is nil, creates and manages its own transaction automatically.
func (d *Database) SetState(tx *sqlx.Tx, key string, value []byte) error {
	if tx == nil {
		return d.RunDBTransaction(func(tx *sqlx.Tx) error {
			return d.SetState(tx, key, value)
		})
	}

	_, err := tx.Exec(`
		INSERT INTO state (key, value) VALUES ($1, $2)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// DeleteState removes a state entry by key.
func (d *Database) DeleteState(tx *sqlx.Tx, key string) error {
	if tx == nil {
		return d.RunDBTransaction(func(tx *sqlx.Tx) error {
			return d.DeleteState(tx, key)
		})
	}

	_, err := tx.Exec("DELETE FROM state WHERE key = $1", key)
	return err
}
