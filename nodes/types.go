package nodes

import (
	"time"

)

// DefaultPingInterval is how often we PING nodes to check liveness.
const DefaultPingInterval = 30 * time.Second

// DefaultMaxNodeAge is the maximum time since last seen before considering a node dead.
const DefaultMaxNodeAge = 24 * time.Hour

// DefaultMaxFailures is the maximum consecutive failures before considering a node dead.
const DefaultMaxFailures = 3

// RejectionLogTTL is how long we remember that we logged a rejection for a node.
const RejectionLogTTL = 12 * time.Hour

// Rejection reason flags
const (
	RejectionIPLimit   uint8 = 0x01
	RejectionAdmission uint8 = 0x02
)

// DB is the interface for node database that supports rejection tracking.
type DB interface {
	StoreRejection(id [32]byte, reason uint8, timestamp time.Time) error
	LoadRejection(id [32]byte) (flags uint8, timestamp time.Time, found bool, err error)
	ExpireRejections(ttl time.Duration) (int, error)
}

// NodeChangedCallback is called when a node is added or updated in the table.
type NodeChangedCallback func(*Node)

// TableStats contains statistics about the routing table.
type TableStats struct {
	TotalNodes          int
	ActiveNodes         int
	BucketsFilled       int
	AdmissionRejections int
	IPLimitRejections   int
	DeadNodesRemoved    int
	IPStats             IPStats
}

// Helper functions for node slices

// nodesToIDs converts a slice of nodes to a slice of node IDs.
func nodesToIDs(nodes []*Node) [][32]byte {
	ids := make([][32]byte, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID()
	}
	return ids
}

// nodesMap creates a map from node ID to node from a slice of nodes.
func nodesMap(nodes []*Node) map[[32]byte]*Node {
	m := make(map[[32]byte]*Node)
	for _, n := range nodes {
		m[n.ID()] = n
	}
	return m
}
