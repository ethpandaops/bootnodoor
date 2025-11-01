package discover

import (
	"time"

	"github.com/pk910/bootoor/discv5/node"
	"github.com/pk910/bootoor/discv5/protocol"
	"github.com/sirupsen/logrus"
)

// PingService handles PING/PONG operations for liveness checks.
type PingService struct {
	// handler is the protocol handler for sending messages
	handler *protocol.Handler

	// logger for debug messages
	logger logrus.FieldLogger

	// Stats
	pingsSent      int
	pongsReceived  int
	pingTimeouts   int
	avgRTT         time.Duration
	totalRTT       time.Duration
	rttSampleCount int
}

// NewPingService creates a new ping service.
func NewPingService(handler *protocol.Handler, logger logrus.FieldLogger) *PingService {
	return &PingService{
		handler: handler,
		logger:  logger,
	}
}

// Ping sends a PING to a node and waits for PONG.
//
// Returns true if the node responded, false on timeout.
// Also updates the node's RTT statistics.
func (ps *PingService) Ping(n *node.Node) (bool, time.Duration, error) {
	ps.pingsSent++

	ps.logger.WithFields(logrus.Fields{
		"peerID": n.PeerID(),
		"addr":   n.Addr(),
	}).Trace("discover: sending PING")

	start := time.Now()

	// Send PING
	respChan, err := ps.handler.SendPing(n)
	if err != nil {
		ps.logger.WithFields(logrus.Fields{
			"peerID": n.PeerID(),
			"addr":   n.Addr(),
			"error":  err,
		}).Debug("discover: failed to send PING")
		return false, 0, err
	}

	// Wait for PONG
	resp := <-respChan

	rtt := time.Since(start)

	if resp.Error != nil {
		ps.pingTimeouts++
		// Record failure on the node
		n.IncrementFailureCount()
		ps.logger.WithFields(logrus.Fields{
			"peerID": n.PeerID(),
			"addr":   n.Addr(),
			"error":  resp.Error,
			"rtt":    rtt,
		}).Debug("discover: PING timeout or error")
		return false, 0, resp.Error
	}

	// Update statistics
	ps.pongsReceived++
	ps.totalRTT += rtt
	ps.rttSampleCount++
	ps.avgRTT = ps.totalRTT / time.Duration(ps.rttSampleCount)

	// Update node's RTT and success count
	n.UpdateRTT(rtt)
	n.ResetFailureCount() // This also increments success count

	ps.logger.WithFields(logrus.Fields{
		"peerID": n.PeerID(),
		"addr":   n.Addr(),
		"rtt":    rtt,
	}).Trace("discover: PING successful")

	return true, rtt, nil
}

// PingMultiple sends PINGs to multiple nodes in parallel.
//
// Returns a map of node ID to ping result (success/failure).
func (ps *PingService) PingMultiple(nodes []*node.Node) map[node.ID]bool {
	ps.logger.WithField("count", len(nodes)).Trace("discover: pinging multiple nodes in parallel")

	results := make(map[node.ID]bool)
	resultChan := make(chan struct {
		id      node.ID
		success bool
	}, len(nodes))

	// Send PINGs in parallel
	for _, n := range nodes {
		go func(n *node.Node) {
			success, _, _ := ps.Ping(n)
			resultChan <- struct {
				id      node.ID
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

// PingStats returns statistics about PING operations.
type PingStats struct {
	PingsSent     int
	PongsReceived int
	PingTimeouts  int
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
		AverageRTT:    ps.avgRTT,
		SuccessRate:   successRate,
	}
}
