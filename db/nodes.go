package db

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
)

// NodeLayer represents whether a node belongs to EL or CL.
type NodeLayer string

const (
	LayerEL NodeLayer = "el"
	LayerCL NodeLayer = "cl"
)

// Node represents a node stored in the database (EL or CL).
type Node struct {
	NodeID       []byte        `db:"nodeid"`        // 32-byte node ID
	Layer        string        `db:"layer"`         // 'el' or 'cl'
	IP           []byte        `db:"ip"`            // IPv4 address (4 bytes)
	IPv6         []byte        `db:"ipv6"`          // IPv6 address (16 bytes)
	Port         int           `db:"port"`          // UDP port
	Seq          uint64        `db:"seq"`           // ENR sequence number
	ForkDigest   []byte        `db:"fork_digest"`   // Fork digest from 'eth' or 'eth2'
	FirstSeen    int64         `db:"first_seen"`    // Unix timestamp
	LastSeen     sql.NullInt64 `db:"last_seen"`     // Unix timestamp (nullable)
	LastActive   sql.NullInt64 `db:"last_active"`   // Unix timestamp (nullable)
	ENR          []byte        `db:"enr"`           // RLP-encoded ENR
	HasV4        bool          `db:"has_v4"`        // Supports discv4 (EL only)
	HasV5        bool          `db:"has_v5"`        // Supports discv5
	SuccessCount int           `db:"success_count"` // Successful pings
	FailureCount int           `db:"failure_count"` // Failed pings
	AvgRTT       int           `db:"avg_rtt"`       // Average RTT in milliseconds
}

// GetNode retrieves a single node by ID and layer.
func (d *Database) GetNode(layer NodeLayer, nodeID []byte) (*Node, error) {
	d.trackQuery()
	node := &Node{}
	err := d.ReaderDb.Get(node, `
		SELECT nodeid, layer, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active,
		       enr, has_v4, has_v5, success_count, failure_count, avg_rtt
		FROM nodes WHERE nodeid = $1 AND layer = $2`, nodeID, string(layer))
	if err != nil {
		return nil, err
	}
	return node, nil
}

// GetNodes retrieves all nodes for a specific layer.
func (d *Database) GetNodes(layer NodeLayer) ([]*Node, error) {
	d.trackQuery()
	nodes := []*Node{}
	err := d.ReaderDb.Select(&nodes, `
		SELECT nodeid, layer, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active,
		       enr, has_v4, has_v5, success_count, failure_count, avg_rtt
		FROM nodes WHERE layer = $1`, string(layer))
	return nodes, err
}

// GetAllNodes retrieves all nodes (both EL and CL).
func (d *Database) GetAllNodes() ([]*Node, error) {
	d.trackQuery()
	nodes := []*Node{}
	err := d.ReaderDb.Select(&nodes, `
		SELECT nodeid, layer, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active,
		       enr, has_v4, has_v5, success_count, failure_count, avg_rtt
		FROM nodes`)
	return nodes, err
}

// GetRandomNodes retrieves N random nodes for a specific layer.
func (d *Database) GetRandomNodes(layer NodeLayer, n int) ([]*Node, error) {
	d.trackQuery()
	nodes := []*Node{}
	err := d.ReaderDb.Select(&nodes, `
		SELECT nodeid, layer, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active,
		       enr, has_v4, has_v5, success_count, failure_count, avg_rtt
		FROM nodes
		WHERE layer = $1
		ORDER BY RANDOM()
		LIMIT $2`, string(layer), n)
	return nodes, err
}

// GetInactiveNodes retrieves N nodes ordered by oldest last_active time for a specific layer.
func (d *Database) GetInactiveNodes(layer NodeLayer, n int) ([]*Node, error) {
	d.trackQuery()
	nodes := []*Node{}
	err := d.ReaderDb.Select(&nodes, `
		SELECT nodeid, layer, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active,
		       enr, has_v4, has_v5, success_count, failure_count, avg_rtt
		FROM nodes
		WHERE layer = $1
		ORDER BY last_active ASC NULLS FIRST
		LIMIT $2`, string(layer), n)
	return nodes, err
}

// CountNodes returns the total number of nodes for a specific layer.
func (d *Database) CountNodes(layer NodeLayer) (int, error) {
	d.trackQuery()
	var count int
	err := d.ReaderDb.Get(&count, "SELECT COUNT(*) FROM nodes WHERE layer = $1", string(layer))
	return count, err
}

// CountAllNodes returns the total number of nodes (all layers).
func (d *Database) CountAllNodes() (int, error) {
	d.trackQuery()
	var count int
	err := d.ReaderDb.Get(&count, "SELECT COUNT(*) FROM nodes")
	return count, err
}

// NodeExists checks if a node exists for a specific layer.
func (d *Database) NodeExists(layer NodeLayer, nodeID []byte) (bool, uint64, error) {
	d.trackQuery()
	var seq uint64
	err := d.ReaderDb.Get(&seq, "SELECT seq FROM nodes WHERE nodeid = $1 AND layer = $2", nodeID, string(layer))
	if err == sql.ErrNoRows {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	return true, seq, nil
}

// UpsertNode inserts or updates a node.
func (d *Database) UpsertNode(tx *sqlx.Tx, node *Node) error {
	_, err := tx.Exec(`
		INSERT INTO nodes (nodeid, layer, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active, enr, has_v4, has_v5, success_count, failure_count, avg_rtt)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT(nodeid) DO UPDATE SET
			ip = excluded.ip,
			ipv6 = excluded.ipv6,
			port = excluded.port,
			seq = excluded.seq,
			fork_digest = excluded.fork_digest,
			last_seen = excluded.last_seen,
			enr = excluded.enr,
			has_v4 = excluded.has_v4,
			has_v5 = excluded.has_v5,
			success_count = excluded.success_count,
			failure_count = excluded.failure_count,
			avg_rtt = excluded.avg_rtt`,
		node.NodeID, node.Layer, node.IP, node.IPv6, node.Port, node.Seq, node.ForkDigest,
		node.FirstSeen, node.LastSeen, node.LastActive, node.ENR,
		node.HasV4, node.HasV5, node.SuccessCount, node.FailureCount, node.AvgRTT)
	return err
}

// UpdateNodeENR updates only ENR-related fields.
func (d *Database) UpdateNodeENR(tx *sqlx.Tx, layer NodeLayer, nodeID []byte, ip []byte, ipv6 []byte, port int, seq uint64, forkDigest []byte, enr []byte, hasV4 bool, hasV5 bool) error {
	now := time.Now().Unix()
	_, err := tx.Exec(`
		INSERT INTO nodes (nodeid, layer, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active, enr, has_v4, has_v5, success_count, failure_count, avg_rtt)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, $9, $10, $11, 0, 0, 0)
		ON CONFLICT(nodeid) DO UPDATE SET
			ip = excluded.ip,
			ipv6 = excluded.ipv6,
			port = excluded.port,
			seq = excluded.seq,
			fork_digest = excluded.fork_digest,
			enr = excluded.enr,
			has_v4 = excluded.has_v4,
			has_v5 = excluded.has_v5`,
		nodeID, string(layer), ip, ipv6, port, seq, forkDigest, now, enr, hasV4, hasV5)
	return err
}

// UpdateNodeLastActive updates the last_active timestamp.
func (d *Database) UpdateNodeLastActive(tx *sqlx.Tx, layer NodeLayer, nodeID []byte, timestamp int64) error {
	_, err := tx.Exec("UPDATE nodes SET last_active = $1 WHERE nodeid = $2 AND layer = $3", timestamp, nodeID, string(layer))
	return err
}

// UpdateNodeLastSeen updates the last_seen timestamp.
func (d *Database) UpdateNodeLastSeen(tx *sqlx.Tx, layer NodeLayer, nodeID []byte, timestamp int64) error {
	_, err := tx.Exec("UPDATE nodes SET last_seen = $1 WHERE nodeid = $2 AND layer = $3", timestamp, nodeID, string(layer))
	return err
}

// DeleteNode removes a node.
func (d *Database) DeleteNode(tx *sqlx.Tx, layer NodeLayer, nodeID []byte) error {
	_, err := tx.Exec("DELETE FROM nodes WHERE nodeid = $1 AND layer = $2", nodeID, string(layer))
	return err
}

// DeleteNodesBefore removes nodes with last_active older than the given timestamp for a specific layer.
func (d *Database) DeleteNodesBefore(tx *sqlx.Tx, layer NodeLayer, timestamp int64) (int64, error) {
	result, err := tx.Exec("DELETE FROM nodes WHERE layer = $1 AND last_active IS NOT NULL AND last_active < $2", string(layer), timestamp)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetNodesByForkDigest retrieves nodes filtered by fork digest for a specific layer.
func (d *Database) GetNodesByForkDigest(layer NodeLayer, forkDigest []byte, limit int) ([]*Node, error) {
	d.trackQuery()
	nodes := []*Node{}
	query := `
		SELECT nodeid, layer, ip, ipv6, port, seq, fork_digest, first_seen, last_seen, last_active,
		       enr, has_v4, has_v5, success_count, failure_count, avg_rtt
		FROM nodes
		WHERE layer = $1 AND fork_digest = $2
		ORDER BY last_active DESC NULLS LAST
		LIMIT $3`
	err := d.ReaderDb.Select(&nodes, query, string(layer), forkDigest, limit)
	return nodes, err
}

// GetNodeStats returns statistics about nodes.
func (d *Database) GetNodeStats() (map[NodeLayer]int, error) {
	d.trackQuery()
	stats := make(map[NodeLayer]int)

	rows, err := d.ReaderDb.Query("SELECT layer, COUNT(*) FROM nodes GROUP BY layer")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var layer string
		var count int
		if err := rows.Scan(&layer, &count); err != nil {
			return nil, err
		}
		stats[NodeLayer(layer)] = count
	}

	return stats, nil
}
