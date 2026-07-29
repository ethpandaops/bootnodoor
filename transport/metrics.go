package transport

import (
	"sync/atomic"
)

// Metrics tracks statistics for the UDP transport.
//
// All operations are atomic and thread-safe.
type Metrics struct {
	// Packet counts
	packetsSent     atomic.Uint64
	packetsReceived atomic.Uint64
	packetsDropped  atomic.Uint64

	// Byte counts
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64

	// Error counts
	sendErrors    atomic.Uint64
	receiveErrors atomic.Uint64
	rateLimited   atomic.Uint64

	// Dispatch outcomes. A packet the first handler declines but a later one
	// accepts is normal traffic for the other protocol on a shared socket; only
	// a packet no handler accepts is unrecognised.
	packetsFellThrough atomic.Uint64
	packetsUnhandled   atomic.Uint64
}

// RecordFellThrough records a packet accepted by a handler other than the first.
func (m *Metrics) RecordFellThrough() {
	m.packetsFellThrough.Add(1)
}

// RecordUnhandled records a packet no handler accepted.
func (m *Metrics) RecordUnhandled() {
	m.packetsUnhandled.Add(1)
}

// NewMetrics creates a new metrics tracker.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// RecordSent records a sent packet.
func (m *Metrics) RecordSent(bytes uint64) {
	m.packetsSent.Add(1)
	m.bytesSent.Add(bytes)
}

// RecordReceived records a received packet.
func (m *Metrics) RecordReceived(bytes uint64) {
	m.packetsReceived.Add(1)
	m.bytesReceived.Add(bytes)
}

// IncrementSendErrors increments the send error counter.
func (m *Metrics) IncrementSendErrors() {
	m.sendErrors.Add(1)
}

// IncrementReceiveErrors increments the receive error counter.
func (m *Metrics) IncrementReceiveErrors() {
	m.receiveErrors.Add(1)
}

// IncrementRateLimited increments the rate-limited packet counter.
func (m *Metrics) IncrementRateLimited() {
	m.rateLimited.Add(1)
}

// IncrementDropped increments the dropped packet counter.
func (m *Metrics) IncrementDropped() {
	m.packetsDropped.Add(1)
}

// Snapshot returns a snapshot of the current metrics.
type MetricsSnapshot struct {
	PacketsSent        uint64
	PacketsReceived    uint64
	PacketsDropped     uint64
	BytesSent          uint64
	BytesReceived      uint64
	SendErrors         uint64
	ReceiveErrors      uint64
	RateLimited        uint64
	PacketsFellThrough uint64
	PacketsUnhandled   uint64
}

// Snapshot returns a snapshot of the current metrics.
//
// Example:
//
//	snapshot := transport.Metrics().Snapshot()
//	fmt.Printf("Packets sent: %d, received: %d\n",
//	    snapshot.PacketsSent, snapshot.PacketsReceived)
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		PacketsSent:        m.packetsSent.Load(),
		PacketsReceived:    m.packetsReceived.Load(),
		PacketsDropped:     m.packetsDropped.Load(),
		BytesSent:          m.bytesSent.Load(),
		BytesReceived:      m.bytesReceived.Load(),
		SendErrors:         m.sendErrors.Load(),
		ReceiveErrors:      m.receiveErrors.Load(),
		RateLimited:        m.rateLimited.Load(),
		PacketsFellThrough: m.packetsFellThrough.Load(),
		PacketsUnhandled:   m.packetsUnhandled.Load(),
	}
}

// Reset resets all metrics to zero.
func (m *Metrics) Reset() {
	m.packetsSent.Store(0)
	m.packetsReceived.Store(0)
	m.packetsDropped.Store(0)
	m.bytesSent.Store(0)
	m.bytesReceived.Store(0)
	m.sendErrors.Store(0)
	m.receiveErrors.Store(0)
	m.rateLimited.Store(0)
}

// PacketsSent returns the number of packets sent.
func (m *Metrics) PacketsSent() uint64 {
	return m.packetsSent.Load()
}

// PacketsReceived returns the number of packets received.
func (m *Metrics) PacketsReceived() uint64 {
	return m.packetsReceived.Load()
}

// BytesSent returns the number of bytes sent.
func (m *Metrics) BytesSent() uint64 {
	return m.bytesSent.Load()
}

// BytesReceived returns the number of bytes received.
func (m *Metrics) BytesReceived() uint64 {
	return m.bytesReceived.Load()
}

// SendErrors returns the number of send errors.
func (m *Metrics) SendErrors() uint64 {
	return m.sendErrors.Load()
}

// ReceiveErrors returns the number of receive errors.
func (m *Metrics) ReceiveErrors() uint64 {
	return m.receiveErrors.Load()
}

// RateLimited returns the number of rate-limited packets.
func (m *Metrics) RateLimited() uint64 {
	return m.rateLimited.Load()
}
