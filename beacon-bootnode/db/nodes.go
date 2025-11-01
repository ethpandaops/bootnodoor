package db

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
)

/*
CREATE TABLE IF NOT EXISTS "nodes" (
    "nodeid" BLOB PRIMARY KEY,
    "ip" BLOB,
    "ipv6" BLOB,
    "port" INTEGER,
    "seq" INTEGER,
    "fork_digest" BLOB,
    "first_seen" INTEGER,
    "last_seen" INTEGER,
    "last_active" INTEGER,
    "enr" BLOB,
    "success_count" INTEGER DEFAULT 0,
    "failure_count" INTEGER DEFAULT 0,
    "avg_rtt" INTEGER DEFAULT 0
);
*/

// Node represents a discovered bootnode peer stored in the database.
type Node struct {
	NodeID       []byte        `db:"nodeid"`        // 32-byte node ID
	IP           []byte        `db:"ip"`            // IPv4 address (4 bytes)
	IPv6         []byte        `db:"ipv6"`          // IPv6 address (16 bytes)
	Port         int           `db:"port"`          // UDP port
	Seq          uint64        `db:"seq"`           // ENR sequence number
	ForkDigest   []byte        `db:"fork_digest"`   // 4-byte fork digest
	FirstSeen    int64         `db:"first_seen"`    // Unix timestamp
	LastSeen     sql.NullInt64 `db:"last_seen"`     // Unix timestamp (nullable)
	LastActive   sql.NullInt64 `db:"last_active"`   // Unix timestamp (nullable)
	ENR          []byte        `db:"enr"`           // RLP-encoded ENR
	SuccessCount int           `db:"success_count"` // Successful pings
	FailureCount int           `db:"failure_count"` // Failed pings
	AvgRTT       int           `db:"avg_rtt"`       // Average RTT in milliseconds
}

// GetNode retrieves a single node by ID from the database.
func (d *Database) GetNode(nodeID []byte) (*Node, error) {
	node := &Node{}
	err := d.ReaderDb.Get(node, `
		SELECT nodeid, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active,
		       enr, success_count, failure_count, avg_rtt
		FROM nodes WHERE nodeid = $1`, nodeID)
	if err != nil {
		return nil, err
	}
	return node, nil
}

// GetNodes retrieves all nodes from the database.
func (d *Database) GetNodes() ([]*Node, error) {
	nodes := []*Node{}
	err := d.ReaderDb.Select(&nodes, `
		SELECT nodeid, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active,
		       enr, success_count, failure_count, avg_rtt
		FROM nodes`)
	return nodes, err
}

// GetRandomNodes retrieves N random nodes from the database.
func (d *Database) GetRandomNodes(n int) ([]*Node, error) {
	nodes := []*Node{}
	err := d.ReaderDb.Select(&nodes, `
		SELECT nodeid, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active,
		       enr, success_count, failure_count, avg_rtt
		FROM nodes
		ORDER BY RANDOM()
		LIMIT $1`, n)
	return nodes, err
}

// GetInactiveNodes retrieves N nodes ordered by oldest last_active time.
// Nodes with NULL last_active (never active) are returned first.
func (d *Database) GetInactiveNodes(n int) ([]*Node, error) {
	nodes := []*Node{}
	err := d.ReaderDb.Select(&nodes, `
		SELECT nodeid, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active,
		       enr, success_count, failure_count, avg_rtt
		FROM nodes
		ORDER BY last_active ASC NULLS FIRST
		LIMIT $1`, n)
	return nodes, err
}

// CountNodes returns the total number of nodes.
func (d *Database) CountNodes() (int, error) {
	var count int
	err := d.ReaderDb.Get(&count, "SELECT COUNT(*) FROM nodes")
	return count, err
}

// NodeExists checks if a node exists in the database.
func (d *Database) NodeExists(nodeID []byte) (bool, uint64, error) {
	var seq uint64
	err := d.ReaderDb.Get(&seq, "SELECT seq FROM nodes WHERE nodeid = $1", nodeID)
	if err != nil {
		return false, 0, err
	}
	return true, seq, nil
}

// InsertNode creates a new node record in the database within a transaction.
func (d *Database) InsertNode(tx *sqlx.Tx, node *Node) error {
	_, err := tx.Exec(`
		INSERT INTO nodes (nodeid, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active, enr, success_count, failure_count, avg_rtt)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		node.NodeID,
		node.IP,
		node.IPv6,
		node.Port,
		node.Seq,
		node.ForkDigest,
		node.FirstSeen,
		node.LastSeen,
		node.LastActive,
		node.ENR,
		node.SuccessCount,
		node.FailureCount,
		node.AvgRTT,
	)
	return err
}

// UpsertNode inserts or updates a node record in the database within a transaction.
// Note: last_active is NOT updated by this method - use UpdateNodeLastActive() instead.
func (d *Database) UpsertNode(tx *sqlx.Tx, node *Node) error {
	_, err := tx.Exec(`
		INSERT INTO nodes (nodeid, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active, enr, success_count, failure_count, avg_rtt)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT(nodeid) DO UPDATE SET
			ip = excluded.ip,
			ipv6 = excluded.ipv6,
			port = excluded.port,
			seq = excluded.seq,
			fork_digest = excluded.fork_digest,
			last_seen = excluded.last_seen,
			enr = excluded.enr,
			success_count = excluded.success_count,
			failure_count = excluded.failure_count,
			avg_rtt = excluded.avg_rtt`,
		node.NodeID,
		node.IP,
		node.IPv6,
		node.Port,
		node.Seq,
		node.ForkDigest,
		node.FirstSeen,
		node.LastSeen,
		node.LastActive,
		node.ENR,
		node.SuccessCount,
		node.FailureCount,
		node.AvgRTT,
	)
	return err
}

// UpdateNodeSeq updates just the sequence number and ENR of a node.
func (d *Database) UpdateNodeSeq(tx *sqlx.Tx, nodeID []byte, seq uint64, enr []byte) error {
	_, err := tx.Exec("UPDATE nodes SET seq = $1, enr = $2 WHERE nodeid = $3", seq, enr, nodeID)
	return err
}

// UpdateNodeENR performs an ENR update that preserves stats and timestamps.
// On insert: creates node with ENR info and default stats (first_seen = now, others NULL/0)
// On update: updates only seq, enr, ip, ipv6, port, fork_digest (preserves all stats and timestamps)
func (d *Database) UpdateNodeENR(tx *sqlx.Tx, nodeID []byte, ip []byte, ipv6 []byte, port int, seq uint64, forkDigest []byte, enr []byte) error {
	now := time.Now().Unix()
	_, err := tx.Exec(`
		INSERT INTO nodes (nodeid, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active, enr, success_count, failure_count, avg_rtt)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, $8, 0, 0, 0)
		ON CONFLICT(nodeid) DO UPDATE SET
			ip = excluded.ip,
			ipv6 = excluded.ipv6,
			port = excluded.port,
			seq = excluded.seq,
			fork_digest = excluded.fork_digest,
			enr = excluded.enr`,
		nodeID,
		ip,
		ipv6,
		port,
		seq,
		forkDigest,
		now,
		enr,
	)
	return err
}

// UpdateNodeLastSeen updates only the last_seen timestamp.
func (d *Database) UpdateNodeLastSeen(tx *sqlx.Tx, nodeID []byte, timestamp int64) error {
	_, err := tx.Exec("UPDATE nodes SET last_seen = $1 WHERE nodeid = $2", timestamp, nodeID)
	return err
}

// UpdateNodeLastActive updates the last_active timestamp of a node.
// If active is true, sets last_active to current time. If false, sets to NULL (inactive).
func (d *Database) UpdateNodeLastActive(tx *sqlx.Tx, nodeID []byte, active bool) error {
	if active {
		_, err := tx.Exec("UPDATE nodes SET last_active = $1 WHERE nodeid = $2", time.Now().Unix(), nodeID)
		return err
	}
	_, err := tx.Exec("UPDATE nodes SET last_active = NULL WHERE nodeid = $1", nodeID)
	return err
}

// DeleteNode removes a node from the database within a transaction.
func (d *Database) DeleteNode(tx *sqlx.Tx, nodeID []byte) error {
	_, err := tx.Exec("DELETE FROM nodes WHERE nodeid = $1", nodeID)
	return err
}

// DeleteNodesBefore removes nodes with last_active older than the given timestamp.
func (d *Database) DeleteNodesBefore(tx *sqlx.Tx, timestamp int64) (int64, error) {
	result, err := tx.Exec("DELETE FROM nodes WHERE last_active IS NOT NULL AND last_active < $1", timestamp)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
