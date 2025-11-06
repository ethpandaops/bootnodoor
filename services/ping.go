package services

import (
	"fmt"
	"time"

	nodedb "github.com/ethpandaops/bootnodoor/nodes"
	"github.com/ethpandaops/bootnodoor/discv4"
	"github.com/ethpandaops/bootnodoor/discv5/protocol"
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
	ps.pingsSent++

	ps.logger.WithFields(logrus.Fields{
		"peerID": n.PeerID(),
		"addr":   n.Addr(),
	}).Trace("discover: sending PING")

	start := time.Now()

	// Try discv5 first if available
	if v5Node := n.V5(); v5Node != nil && ps.v5Handler != nil {
		ps.pingsV5++
		respChan, err := ps.v5Handler.SendPing(v5Node)
		if err != nil {
			// Failed to send ping - only increment failure if no v4 fallback available
			if n.V4() == nil || ps.v4Service == nil {
				// No v4 fallback - this is a final failure
				ps.pingTimeouts++
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
				ps.pongsReceived++
				ps.totalRTT += rtt
				ps.rttSampleCount++
				ps.avgRTT = ps.totalRTT / time.Duration(ps.rttSampleCount)
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
				ps.pingTimeouts++
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
		ps.pingsV4++
		pong, err := ps.v4Service.Ping(v4Node)
		rtt := time.Since(start)

		if err != nil {
			ps.pingTimeouts++
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
		ps.pongsReceived++
		ps.totalRTT += rtt
		ps.rttSampleCount++
		ps.avgRTT = ps.totalRTT / time.Duration(ps.rttSampleCount)
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
	ps.pingTimeouts++
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

	ps.logger.WithFields(logrus.Fields{
		"peerID": n.PeerID(),
		"addr":   addr,
	}).Debug("checking protocol support")

	var v4Supported, v5Supported bool
	var v4RTT, v5RTT time.Duration

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

				// If v4 ping succeeded, request ENR to ensure we have latest record
				if enrRecord, err := ps.v4Service.RequestENR(v4Node); err == nil {
					v4Node.SetENR(enrRecord)
					n.UpdateENR(enrRecord)
				}
			}
		}
	}

	// Update node with discovered protocol support
	// Add v5 support if confirmed and not present
	if v5Supported && n.V5() == nil {
		// Create and set v5 node
		if v5Node, err := nodedb.NewV5NodeFromRecord(record); err == nil {
			n.SetV5(v5Node)
			ps.logger.WithField("peerID", n.PeerID()).Info("added v5 support to node")
		}
	}

	// Remove v5 support if not confirmed but present
	if !v5Supported && n.V5() != nil {
		n.SetV5(nil)
		ps.logger.WithField("peerID", n.PeerID()).Warn("removed v5 support from node (no longer responding)")
	}

	// Add v4 support if confirmed and not present
	if v4Supported && n.V4() == nil {
		// Create and set v4 node
		if v4Node, err := nodedb.NewV4NodeFromRecord(record, addr); err == nil {
			n.SetV4(v4Node)
			ps.logger.WithField("peerID", n.PeerID()).Info("added v4 support to node")
		}
	}

	// Remove v4 support if not confirmed but present
	if !v4Supported && n.V4() != nil {
		n.SetV4(nil)
		ps.logger.WithField("peerID", n.PeerID()).Warn("removed v4 support from node (no longer responding)")
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
		peerID       string
		v4Supported  bool
		v5Supported  bool
		err          error
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
		"total":    len(nodes),
		"v4Only":   v4Count,
		"v5Only":   v5Count,
		"both":     bothCount,
		"none":     noneCount,
	}).Info("protocol support check batch complete")
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
