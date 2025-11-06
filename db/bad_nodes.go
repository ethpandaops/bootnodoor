package db

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
)

// BadNodeRecheckInterval is the default time to wait before rechecking a bad node.
const BadNodeRecheckInterval = 7 * 24 * time.Hour // 7 days

// StoreBadNode stores a node that failed admission checks.
// This prevents repeatedly requesting ENRs from nodes that won't pass filters.
func (d *Database) StoreBadNode(nodeID []byte, layer NodeLayer, reason string) error {
	return d.RunDBTransaction(func(tx *sqlx.Tx) error {
		_, err := tx.Exec(`
			INSERT OR REPLACE INTO bad_nodes (nodeid, layer, rejected_at, reason)
			VALUES (?, ?, ?, ?)
		`, nodeID, layer, time.Now().Unix(), reason)
		return err
	})
}

// IsBadNode checks if a node is marked as bad and whether it should be rechecked.
// Returns:
//   - isBad: true if the node is in the bad nodes list
//   - shouldRecheck: true if enough time has passed since rejection (> recheckInterval)
//   - reason: the reason the node was rejected
func (d *Database) IsBadNode(nodeID []byte, layer NodeLayer, recheckInterval time.Duration) (isBad bool, shouldRecheck bool, reason string, err error) {
	if recheckInterval == 0 {
		recheckInterval = BadNodeRecheckInterval
	}

	var rejectedAt int64
	var storedReason sql.NullString

	err = d.ReaderDb.QueryRow(`
		SELECT rejected_at, reason
		FROM bad_nodes
		WHERE nodeid = ? AND layer = ?
	`, nodeID, layer).Scan(&rejectedAt, &storedReason)

	if err == sql.ErrNoRows {
		// Not a bad node
		return false, false, "", nil
	}

	if err != nil {
		// Database error
		return false, false, "", err
	}

	// Node is marked as bad
	isBad = true
	if storedReason.Valid {
		reason = storedReason.String
	}

	// Check if enough time has passed to recheck
	timeSinceRejection := time.Since(time.Unix(rejectedAt, 0))
	shouldRecheck = timeSinceRejection > recheckInterval

	return isBad, shouldRecheck, reason, nil
}

// RemoveBadNode removes a node from the bad nodes list.
// This is called when a previously bad node passes admission checks.
func (d *Database) RemoveBadNode(nodeID []byte, layer NodeLayer) error {
	return d.RunDBTransaction(func(tx *sqlx.Tx) error {
		_, err := tx.Exec(`
			DELETE FROM bad_nodes
			WHERE nodeid = ? AND layer = ?
		`, nodeID, layer)
		return err
	})
}

// CleanupOldBadNodes removes bad node entries older than the given age.
// This should be called periodically (e.g., once per day) to prevent unbounded growth.
func (d *Database) CleanupOldBadNodes(maxAge time.Duration) (int64, error) {
	if maxAge == 0 {
		maxAge = BadNodeRecheckInterval
	}

	cutoffTime := time.Now().Add(-maxAge).Unix()

	var deletedCount int64
	err := d.RunDBTransaction(func(tx *sqlx.Tx) error {
		result, err := tx.Exec(`
			DELETE FROM bad_nodes
			WHERE rejected_at < ?
		`, cutoffTime)
		if err != nil {
			return err
		}

		deletedCount, err = result.RowsAffected()
		return err
	})

	return deletedCount, err
}

// GetBadNodesCount returns the total number of bad nodes per layer.
func (d *Database) GetBadNodesCount() (map[NodeLayer]int, error) {
	rows, err := d.ReaderDb.Query(`
		SELECT layer, COUNT(*) as count
		FROM bad_nodes
		GROUP BY layer
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[NodeLayer]int)
	for rows.Next() {
		var layer NodeLayer
		var count int
		if err := rows.Scan(&layer, &count); err != nil {
			return nil, err
		}
		counts[layer] = count
	}

	return counts, rows.Err()
}
