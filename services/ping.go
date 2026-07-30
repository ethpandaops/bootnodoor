package services

import (
	"fmt"
	"sync"
	"time"

	"github.com/ethpandaops/bootnodoor/discv4"
	discv4node "github.com/ethpandaops/bootnodoor/discv4/node"
	discv5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/discv5/protocol"
	"github.com/ethpandaops/bootnodoor/enr"
	nodedb "github.com/ethpandaops/bootnodoor/nodes"
	"github.com/sirupsen/logrus"
)

// PingService handles PING/PONG operations for liveness checks.
// Supports both discv5 and discv4 protocols (prefers v5, falls back to v4).
type PingService struct {
	// v5Handler is the discv5 protocol handler (may be nil)
	v5Handler *protocol.Handler

	// v4Service is the discv4 service (may be nil)
	v4Service *discv4.Service

	// logger for debug messages
	logger logrus.FieldLogger

	// mu guards the counters: PingMultiple fans pings out across goroutines
	// while GetStats is read from the web UI handler.
	mu sync.Mutex

	// Stats
	pingsSent      int
	pongsReceived  int
	pingTimeouts   int
	pingsV5        int // Pings sent via v5
	pingsV4        int // Pings sent via v4
	avgRTT         time.Duration
	totalRTT       time.Duration
	rttSampleCount int
}

// NewPingService creates a new ping service with dual protocol support.
// At least one of v5Handler or v4Service must be provided.
func NewPingService(v5Handler *protocol.Handler, v4Service *discv4.Service, logger logrus.FieldLogger) *PingService {
	return &PingService{
		v5Handler: v5Handler,
		v4Service: v4Service,
		logger:    logger,
	}
}

// Ping sends a PING to a node and waits for PONG.
//
// Prefers discv5 if available, falls back to discv4.
// Returns true if the node responded, false on timeout.
// Also updates the node's RTT statistics.
func (ps *PingService) Ping(n *nodedb.Node) (bool, time.Duration, error) {
	ps.countPingSent()

	ps.logger.WithFields(logrus.Fields{
		"peerID": n.PeerID(),
		"addr":   n.Addr(),
	}).Trace("discover: sending PING")

	start := time.Now()

	// Try discv5 first if available
	if v5Node := n.V5(); v5Node != nil && ps.v5Handler != nil {
		ps.countV5Ping()
		respChan, err := ps.v5Handler.SendPing(v5Node)
		if err != nil {
			// Failed to send ping - only increment failure if no v4 fallback available
			if n.V4() == nil || ps.v4Service == nil {
				// No v4 fallback - this is a final failure
				ps.countTimeout()
				n.IncrementFailureCount()
				ps.logger.WithFields(logrus.Fields{
					"peerID":   n.PeerID(),
					"addr":     n.Addr(),
					"protocol": "v5",
					"error":    err,
				}).Debug("discover: failed to send PING v5, no v4 fallback")
				return false, 0, err
			}

			ps.logger.WithFields(logrus.Fields{
				"peerID":   n.PeerID(),
				"addr":     n.Addr(),
				"protocol": "v5",
				"error":    err,
			}).Debug("discover: failed to send PING v5, trying v4 fallback")
			// Don't return error - try v4 fallback
		} else {
			// Wait for PONG
			resp := <-respChan
			rtt := time.Since(start)

			if resp.Error == nil {
				// Success
				ps.countPong(rtt)
				n.UpdateRTT(rtt)
				n.ResetFailureCount()

				ps.logger.WithFields(logrus.Fields{
					"peerID":   n.PeerID(),
					"addr":     n.Addr(),
					"protocol": "v5",
					"rtt":      rtt,
				}).Trace("discover: PING v5 successful")

				return true, rtt, nil
			}

			// V5 ping failed - only increment failure if no v4 fallback available
			if n.V4() == nil || ps.v4Service == nil {
				// No v4 fallback - this is a final failure
				ps.countTimeout()
				n.IncrementFailureCount()
				ps.logger.WithFields(logrus.Fields{
					"peerID":   n.PeerID(),
					"addr":     n.Addr(),
					"protocol": "v5",
					"error":    resp.Error,
				}).Debug("discover: PING v5 failed, no v4 fallback")
				return false, 0, resp.Error
			}

			ps.logger.WithFields(logrus.Fields{
				"peerID":   n.PeerID(),
				"addr":     n.Addr(),
				"protocol": "v5",
				"error":    resp.Error,
			}).Debug("discover: PING v5 timeout or error, trying v4 fallback")
			// Continue to v4 fallback
		}
	}

	// Try discv4 fallback if available
	if v4Node := n.V4(); v4Node != nil && ps.v4Service != nil {
		ps.countV4Ping()
		pong, err := ps.v4Service.Ping(v4Node)
		rtt := time.Since(start)

		if err != nil {
			ps.countTimeout()
			n.IncrementFailureCount()
			ps.logger.WithFields(logrus.Fields{
				"peerID":   n.PeerID(),
				"addr":     n.Addr(),
				"protocol": "v4",
				"error":    err,
				"rtt":      rtt,
			}).Debug("discover: PING v4 timeout or error")
			return false, 0, err
		}

		// Success
		ps.countPong(rtt)
		n.UpdateRTT(rtt)
		n.ResetFailureCount()

		ps.logger.WithFields(logrus.Fields{
			"peerID":   n.PeerID(),
			"addr":     n.Addr(),
			"protocol": "v4",
			"rtt":      rtt,
			"pong":     pong,
		}).Trace("discover: PING v4 successful")

		return true, rtt, nil
	}

	// No protocol available
	ps.countTimeout()
	n.IncrementFailureCount()
	ps.logger.WithFields(logrus.Fields{
		"peerID": n.PeerID(),
		"addr":   n.Addr(),
	}).Debug("discover: node has no supported protocol (v5 or v4)")
	return false, 0, fmt.Errorf("no supported protocol")
}

// PingMultiple sends PINGs to multiple nodes in parallel.
//
// Returns a map of node ID to ping result (success/failure).
func (ps *PingService) PingMultiple(nodes []*nodedb.Node) map[[32]byte]bool {
	ps.logger.WithField("count", len(nodes)).Trace("discover: pinging multiple nodes in parallel")

	results := make(map[[32]byte]bool)
	resultChan := make(chan struct {
		id      [32]byte
		success bool
	}, len(nodes))

	// Send PINGs in parallel
	for _, n := range nodes {
		go func(n *nodedb.Node) {
			success, _, _ := ps.Ping(n)
			resultChan <- struct {
				id      [32]byte
				success bool
			}{n.ID(), success}
		}(n)
	}

	// Collect results
	for i := 0; i < len(nodes); i++ {
		result := <-resultChan
		results[result.id] = result.success
	}

	successCount := 0
	for _, success := range results {
		if success {
			successCount++
		}
	}

	ps.logger.WithFields(logrus.Fields{
		"total":   len(nodes),
		"success": successCount,
		"failed":  len(nodes) - successCount,
	}).Trace("discover: ping batch complete")

	return results
}

// CheckProtocolSupport checks which protocols (v4 and/or v5) a node supports.
//
// This pings the node on BOTH discv4 and discv5 to determine actual protocol support.
// The node's V4/V5 fields are updated based on which protocols respond successfully.
//
// This should be called at a lower frequency than regular aliveness checks (e.g., every 30 minutes)
// to discover protocol capabilities without excessive overhead.
//
// Returns (v4Supported, v5Supported, error)
func (ps *PingService) CheckProtocolSupport(n *nodedb.Node) (bool, bool, error) {
	addr := n.Addr()
	if addr == nil {
		return false, false, fmt.Errorf("node has no address")
	}

	record := n.Record()
	if record == nil {
		return false, false, fmt.Errorf("node has no ENR")
	}
	// Left alone until after the install, so the sequence the install is gated on
	// cannot move underneath it.
	probedSeq := record.Seq()

	ps.logger.WithFields(logrus.Fields{
		"peerID": n.PeerID(),
		"addr":   addr,
	}).Debug("checking protocol support")

	var v4Supported, v5Supported bool
	var v4RTT, v5RTT time.Duration

	// Probe objects are kept for the install: the v4 one is refreshed in place by
	// the ENR fetch below, and rebuilding from the pre-probe snapshot would discard
	// exactly that refresh.
	var probedV4 *discv4node.Node
	var probedV5 *discv5node.Node
	var refreshedRecord *enr.Record

	// Test discv5 support
	if ps.v5Handler != nil {
		// Create or get v5 node
		v5Node := n.V5()
		if v5Node == nil {
			// Try to create v5 node from ENR
			var err error
			v5Node, err = nodedb.NewV5NodeFromRecord(record)
			if err != nil {
				ps.logger.WithError(err).Debug("failed to create v5 node for support check")
			}
		}

		probedV5 = v5Node

		if v5Node != nil {
			start := time.Now()
			respChan, err := ps.v5Handler.SendPing(v5Node)
			if err == nil {
				resp := <-respChan
				v5RTT = time.Since(start)
				if resp.Error == nil {
					v5Supported = true
					ps.logger.WithFields(logrus.Fields{
						"peerID": n.PeerID(),
						"addr":   addr,
						"rtt":    v5RTT,
					}).Debug("v5 support confirmed")
				}
			}
		}
	}

	// Test discv4 support
	if ps.v4Service != nil {
		// Create or get v4 node
		v4Node := n.V4()
		if v4Node == nil {
			// Try to create v4 node from ENR
			var err error
			v4Node, err = nodedb.NewV4NodeFromRecord(record, addr)
			if err != nil {
				ps.logger.WithError(err).Debug("failed to create v4 node for support check")
			}
		}

		probedV4 = v4Node

		if v4Node != nil {
			start := time.Now()
			_, err := ps.v4Service.Ping(v4Node)
			v4RTT = time.Since(start)
			if err == nil {
				v4Supported = true
				ps.logger.WithFields(logrus.Fields{
					"peerID": n.PeerID(),
					"addr":   addr,
					"rtt":    v4RTT,
				}).Debug("v4 support confirmed")

				// Fetched here but applied after the install: advancing the record
				// mid-probe would move the very sequence the install is gated on.
				if enrRecord, err := ps.v4Service.RequestENR(v4Node); err == nil {
					refreshedRecord = enrRecord
				}
			}
		}
	}

	// Apply both outcomes together, and only while the record they describe is
	// still the node's current one. A probe that started before a newer record
	// arrived knows nothing about it, so it must neither install a superseded
	// endpoint nor clear a pointer that newer record brought in.
	applied := n.ApplyProbeResult(probedSeq, probedV4, v4Supported, probedV5, v5Supported)

	// Only now advance the record. Attaching it to the v4 node deliberately leaves
	// that node's proven address alone, so its label keeps describing the endpoint
	// the ping actually reached — which is what lets a correctly addressed pointer
	// for this same record replace it later.
	// Attach to the object that was probed, not to whatever V4() returns now: a
	// concurrent admission may have replaced the pointer, and overwriting its ENR
	// with this older response would leave that pointer's record disagreeing with
	// both the node's record and its label.
	if refreshedRecord != nil {
		if probedV4 != nil {
			probedV4.SetENR(refreshedRecord)
		}
		n.UpdateENR(refreshedRecord)
	}

	if applied {
		ps.logger.WithFields(logrus.Fields{
			"peerID": n.PeerID(),
			"v4":     v4Supported,
			"v5":     v5Supported,
		}).Info("updated protocol support from probe")
	}

	// Update RTT with best available
	if v5Supported && v4Supported {
		// Use the better RTT
		if v5RTT < v4RTT {
			n.UpdateRTT(v5RTT)
		} else {
			n.UpdateRTT(v4RTT)
		}
	} else if v5Supported {
		n.UpdateRTT(v5RTT)
	} else if v4Supported {
		n.UpdateRTT(v4RTT)
	}

	if !v4Supported && !v5Supported {
		ps.logger.WithFields(logrus.Fields{
			"peerID": n.PeerID(),
			"addr":   addr,
		}).Debug("node does not support v4 or v5")
		return false, false, fmt.Errorf("node does not support any protocol")
	}

	ps.logger.WithFields(logrus.Fields{
		"peerID":      n.PeerID(),
		"addr":        addr,
		"v4Supported": v4Supported,
		"v5Supported": v5Supported,
	}).Info("protocol support check complete")

	return v4Supported, v5Supported, nil
}

// CheckProtocolSupportMultiple checks protocol support for multiple nodes in parallel.
//
// This is useful for periodically verifying protocol capabilities across the table.
func (ps *PingService) CheckProtocolSupportMultiple(nodes []*nodedb.Node) {
	ps.logger.WithField("count", len(nodes)).Debug("checking protocol support for multiple nodes")

	type result struct {
		peerID      string
		v4Supported bool
		v5Supported bool
		err         error
	}

	resultChan := make(chan result, len(nodes))

	// Check in parallel
	for _, n := range nodes {
		go func(n *nodedb.Node) {
			v4, v5, err := ps.CheckProtocolSupport(n)
			resultChan <- result{
				peerID:      n.PeerID(),
				v4Supported: v4,
				v5Supported: v5,
				err:         err,
			}
		}(n)
	}

	// Collect results
	var v4Count, v5Count, bothCount, noneCount int
	for i := 0; i < len(nodes); i++ {
		res := <-resultChan
		if res.err != nil {
			noneCount++
			continue
		}

		if res.v4Supported && res.v5Supported {
			bothCount++
		} else if res.v5Supported {
			v5Count++
		} else if res.v4Supported {
			v4Count++
		}
	}

	ps.logger.WithFields(logrus.Fields{
		"total":  len(nodes),
		"v4Only": v4Count,
		"v5Only": v5Count,
		"both":   bothCount,
		"none":   noneCount,
	}).Info("protocol support check batch complete")
}

func (ps *PingService) countPingSent() {
	ps.mu.Lock()
	ps.pingsSent++
	ps.mu.Unlock()
}

func (ps *PingService) countV5Ping() {
	ps.mu.Lock()
	ps.pingsV5++
	ps.mu.Unlock()
}

func (ps *PingService) countV4Ping() {
	ps.mu.Lock()
	ps.pingsV4++
	ps.mu.Unlock()
}

func (ps *PingService) countTimeout() {
	ps.mu.Lock()
	ps.pingTimeouts++
	ps.mu.Unlock()
}

func (ps *PingService) countPong(rtt time.Duration) {
	ps.mu.Lock()
	ps.pongsReceived++
	ps.totalRTT += rtt
	ps.rttSampleCount++
	ps.avgRTT = ps.totalRTT / time.Duration(ps.rttSampleCount)
	ps.mu.Unlock()
}

// PingStats returns statistics about PING operations.
type PingStats struct {
	PingsSent     int
	PongsReceived int
	PingTimeouts  int
	PingsV5       int // Pings sent via discv5
	PingsV4       int // Pings sent via discv4
	AverageRTT    time.Duration
	SuccessRate   float64
}

// GetStats returns PING statistics.
func (ps *PingService) GetStats() PingStats {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	successRate := 0.0
	if ps.pingsSent > 0 {
		successRate = float64(ps.pongsReceived) / float64(ps.pingsSent) * 100
	}

	return PingStats{
		PingsSent:     ps.pingsSent,
		PongsReceived: ps.pongsReceived,
		PingTimeouts:  ps.pingTimeouts,
		PingsV5:       ps.pingsV5,
		PingsV4:       ps.pingsV4,
		AverageRTT:    ps.avgRTT,
		SuccessRate:   successRate,
	}
}
