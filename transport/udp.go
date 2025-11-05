// Package transport provides the UDP transport layer for discv5.
//
// The transport handles:
//   - UDP socket management (IPv4 and IPv6)
//   - Packet sending and receiving
//   - Per-IP rate limiting
//   - Metrics collection
//   - Graceful shutdown
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/sirupsen/logrus"
)

const (
	// MaxPacketSize is the maximum size of a UDP packet (1280 bytes for IPv6 MTU)
	MaxPacketSize = 1280

	// DefaultReadBuffer is the default size for the UDP read buffer
	DefaultReadBuffer = 2 * 1024 * 1024 // 2 MB

	// DefaultWriteBuffer is the default size for the UDP write buffer
	DefaultWriteBuffer = 2 * 1024 * 1024 // 2 MB
)

// PacketHandler is called when a packet is received.
//
// The handler should process the packet and return quickly.
// Long-running operations should be done in a separate goroutine.
// Returns true if the packet was handled, false if not recognized.
type PacketHandler func(data []byte, from *net.UDPAddr) bool

// UDPTransport manages UDP socket I/O for the discv5 protocol.
//
// It provides:
//   - Concurrent packet sending and receiving
//   - Per-IP rate limiting
//   - Metrics collection
//   - Graceful shutdown
//   - Multiple protocol handler support
type UDPTransport struct {
	// conn is the UDP connection
	conn *net.UDPConn

	// handlers is a list of packet handlers (tried in order)
	handlers []PacketHandler
	handlersMu sync.RWMutex

	// logger for debug and error messages
	logger logrus.FieldLogger

	// rateLimiter controls per-IP packet rates
	rateLimiter *RateLimiter

	// metrics tracks transport statistics
	metrics *Metrics

	// ctx and cancel for shutdown coordination
	ctx    context.Context
	cancel context.CancelFunc

	// wg tracks active goroutines for graceful shutdown
	wg sync.WaitGroup

	// closed indicates if the transport is closed
	closed atomic.Bool
}

// Config contains configuration for the UDP transport.
type Config struct {
	// ListenAddr is the address to bind to (e.g., "0.0.0.0:9000")
	// Ignored if Conn is provided.
	ListenAddr string

	// Conn is an optional existing UDP connection to use instead of creating a new one.
	// When provided, ListenAddr, ReadBuffer, and WriteBuffer are ignored.
	Conn *net.UDPConn

	// Logger for debug and error messages (optional)
	Logger logrus.FieldLogger

	// RateLimitPerIP is the maximum packets per second per IP (0 = no limit)
	RateLimitPerIP int

	// ReadBuffer size in bytes (0 = use default)
	// Ignored if Conn is provided.
	ReadBuffer int

	// WriteBuffer size in bytes (0 = use default)
	// Ignored if Conn is provided.
	WriteBuffer int
}

// NewUDPTransport creates a new UDP transport.
//
// The transport starts listening immediately and spawns goroutines
// for packet reception. Use AddHandler() to register protocol handlers.
// Call Close() to shut down gracefully.
//
// Example:
//
//	transport, err := NewUDPTransport(&Config{
//	    ListenAddr: "0.0.0.0:9000",
//	})
//	if err != nil {
//	    return err
//	}
//	defer transport.Close()
//
//	// Register handlers
//	transport.AddHandler(myHandler)
func NewUDPTransport(cfg *Config) (*UDPTransport, error) {
	if cfg == nil {
		return nil, fmt.Errorf("transport: nil config")
	}

	// Default logger
	logger := cfg.Logger
	if logger == nil {
		// Create a default logger if none provided
		logger = logrus.StandardLogger()
	}

	var conn *net.UDPConn

	// Use provided connection or create a new one
	if cfg.Conn != nil {
		// Use provided connection (for multiplexing)
		conn = cfg.Conn
		logger.WithField("addr", conn.LocalAddr()).Debug("transport: using provided connection")
	} else {
		// Create new connection
		if cfg.ListenAddr == "" {
			return nil, fmt.Errorf("transport: ListenAddr required when Conn is not provided")
		}

		// Resolve listen address
		addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf("transport: failed to resolve address: %w", err)
		}

		// Create UDP socket
		conn, err = net.ListenUDP("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("transport: failed to listen: %w", err)
		}

		// Set buffer sizes
		readBuf := cfg.ReadBuffer
		if readBuf == 0 {
			readBuf = DefaultReadBuffer
		}
		writeBuf := cfg.WriteBuffer
		if writeBuf == 0 {
			writeBuf = DefaultWriteBuffer
		}

		if err := conn.SetReadBuffer(readBuf); err != nil {
			logger.Warn("transport: failed to set read buffer", "error", err)
		}
		if err := conn.SetWriteBuffer(writeBuf); err != nil {
			logger.Warn("transport: failed to set write buffer", "error", err)
		}
	}

	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Create rate limiter
	var rateLimiter *RateLimiter
	if cfg.RateLimitPerIP > 0 {
		rateLimiter = NewRateLimiter(cfg.RateLimitPerIP)
	}

	t := &UDPTransport{
		conn:        conn,
		handlers:    make([]PacketHandler, 0),
		logger:      logger,
		rateLimiter: rateLimiter,
		metrics:     NewMetrics(),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Start receive goroutines
	// Use multiple goroutines for better concurrency
	numWorkers := 4
	for i := 0; i < numWorkers; i++ {
		t.wg.Add(1)
		go t.receiveLoop()
	}

	logger.WithFields(logrus.Fields{
		"addr":    conn.LocalAddr(),
		"workers": numWorkers,
	}).Debug("transport: UDP transport started and listening")

	// Give receive loops a moment to start
	time.Sleep(10 * time.Millisecond)

	return t, nil
}

// LocalAddr returns the local UDP address being listened on.
func (t *UDPTransport) LocalAddr() *net.UDPAddr {
	return t.conn.LocalAddr().(*net.UDPAddr)
}

// Conn returns the underlying UDP connection.
func (t *UDPTransport) Conn() *net.UDPConn {
	return t.conn
}

// AddHandler registers a packet handler.
//
// Handlers are called in the order they are registered.
// The first handler to return true stops the handler chain.
// If a handler returns false, the next handler in the chain is tried.
//
// For optimal performance, register handlers in order of likelihood:
//   - Register discv5 before discv4 (discv5 has magic string, faster to validate)
//   - Each handler should quickly validate and return false if not their protocol
//
// This is thread-safe and can be called while the transport is running.
//
// Example:
//
//	transport.AddHandler(func(data []byte, from *net.UDPAddr) bool {
//	    // Try to handle packet, return true if successful
//	    err := myProtocol.HandlePacket(data, from)
//	    return err == nil
//	})
func (t *UDPTransport) AddHandler(handler func(data []byte, from *net.UDPAddr) bool) {
	t.handlersMu.Lock()
	defer t.handlersMu.Unlock()
	t.handlers = append(t.handlers, PacketHandler(handler))
	t.logger.Debug("transport: handler registered")
}

// SendTo sends a packet to the specified address.
// This is the interface method required by protocol.Transport.
func (t *UDPTransport) SendTo(data []byte, to *net.UDPAddr) error {
	return t.Send(data, to)
}

// Send sends a packet to the specified address.
//
// This is thread-safe and can be called concurrently.
// Returns an error if the transport is closed or if sending fails.
//
// Example:
//
//	err := transport.Send(packetData, remoteAddr)
//	if err != nil {
//	    log.Printf("Failed to send: %v", err)
//	}
func (t *UDPTransport) Send(data []byte, to *net.UDPAddr) error {
	if t.closed.Load() {
		t.logger.Debug("transport: attempted to send on closed transport")
		return fmt.Errorf("transport: closed")
	}

	if len(data) > MaxPacketSize {
		t.logger.WithFields(logrus.Fields{
			"size":    len(data),
			"maxSize": MaxPacketSize,
		}).Warn("transport: packet too large")
		return fmt.Errorf("transport: packet too large (%d > %d)", len(data), MaxPacketSize)
	}

	if err := node.ValidateUDPAddr(to); err != nil {
		t.logger.WithField("addr", to).Warn("transport: invalid destination address")
		return fmt.Errorf("transport: invalid destination: %w", err)
	}

	// Set write deadline to prevent hanging
	deadline := time.Now().Add(5 * time.Second)
	if err := t.conn.SetWriteDeadline(deadline); err != nil {
		t.logger.WithError(err).Warn("transport: failed to set write deadline")
	}

	n, err := t.conn.WriteToUDP(data, to)
	if err != nil {
		t.metrics.IncrementSendErrors()
		t.logger.WithFields(logrus.Fields{
			"to":    to,
			"error": err,
		}).Error("transport: write failed")
		return fmt.Errorf("transport: write failed: %w", err)
	}

	if n != len(data) {
		t.metrics.IncrementSendErrors()
		t.logger.WithFields(logrus.Fields{
			"sent":     n,
			"expected": len(data),
		}).Error("transport: incomplete write")
		return fmt.Errorf("transport: incomplete write (%d/%d bytes)", n, len(data))
	}

	t.metrics.RecordSent(uint64(n))
	t.logger.WithFields(logrus.Fields{
		"to":   to,
		"size": n,
	}).Trace("transport: packet sent successfully")
	return nil
}

// dispatchPacket routes a packet to the registered handlers.
//
// Handlers are tried in order until one returns true.
func (t *UDPTransport) dispatchPacket(data []byte, from *net.UDPAddr) {
	t.handlersMu.RLock()
	handlers := t.handlers
	t.handlersMu.RUnlock()

	// Try each handler in order
	for _, handler := range handlers {
		if handler(data, from) {
			// Handler accepted the packet
			return
		}
	}

	// No handler recognized the packet
	t.logger.WithFields(logrus.Fields{
		"from": from,
		"size": len(data),
	}).Debug("transport: unrecognized packet (no handler accepted it)")
}

// receiveLoop receives packets from the UDP socket.
//
// This runs in multiple goroutines for better concurrency.
// It continues until the transport is closed.
func (t *UDPTransport) receiveLoop() {
	defer t.wg.Done()

	buffer := make([]byte, MaxPacketSize)

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Set read deadline to allow periodic checking of context
		deadline := time.Now().Add(1 * time.Second)
		if err := t.conn.SetReadDeadline(deadline); err != nil {
			t.logger.WithError(err).Error("transport: failed to set read deadline")
			return
		}

		// Try to read packet (this blocks until packet arrives or timeout)
		n, from, err := t.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout is expected, continue
				continue
			}

			// Check if we're shutting down
			select {
			case <-t.ctx.Done():
				return
			default:
			}

			t.logger.WithError(err).Error("transport: read failed")
			t.metrics.IncrementReceiveErrors()
			continue
		}

		t.logger.WithFields(logrus.Fields{
			"from": from,
			"size": n,
		}).Trace("transport: received packet")

		// Validate source address
		if err := node.ValidateUDPAddr(from); err != nil {
			t.logger.WithFields(logrus.Fields{
				"from":  from,
				"error": err,
			}).Debug("transport: invalid source address")
			t.metrics.IncrementReceiveErrors()
			continue
		}

		// Check rate limit
		if t.rateLimiter != nil && !t.rateLimiter.Allow(from.IP) {
			t.metrics.IncrementRateLimited()
			t.logger.WithField("from", from).Debug("transport: rate limited")
			continue
		}

		// Record received bytes
		t.metrics.RecordReceived(uint64(n))

		// Make a copy of the data for the handler
		dataCopy := make([]byte, n)
		copy(dataCopy, buffer[:n])

		// Call handlers (non-blocking)
		go t.dispatchPacket(dataCopy, from)
	}
}

// Close gracefully shuts down the transport.
//
// It stops accepting new packets, waits for active handlers to complete
// (with a timeout), and closes the UDP socket.
//
// Example:
//
//	if err := transport.Close(); err != nil {
//	    log.Printf("Error closing transport: %v", err)
//	}
func (t *UDPTransport) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return fmt.Errorf("transport: already closed")
	}

	// Signal shutdown to all goroutines
	t.cancel()

	// Close the UDP socket
	if err := t.conn.Close(); err != nil {
		t.logger.Warn("transport: error closing socket", "error", err)
	}

	// Wait for goroutines to finish (with timeout)
	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.logger.Info("transport: shutdown complete")
	case <-time.After(5 * time.Second):
		t.logger.Warn("transport: shutdown timeout, some goroutines may be stuck")
	}

	return nil
}

// Metrics returns the current transport metrics.
func (t *UDPTransport) Metrics() *Metrics {
	return t.metrics
}
