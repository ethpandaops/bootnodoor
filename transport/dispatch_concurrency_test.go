package transport

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestDispatchConcurrencyIsBounded sends a burst of packets from a single
// source and verifies that the number of dispatch handlers running at once
// never exceeds the configured limit. Without a cap, each packet spawns its
// own goroutine with no ceiling.
func TestDispatchConcurrencyIsBounded(t *testing.T) {
	listenerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listenerConn.Close()

	const limit = 8
	tr, err := NewUDPTransport(&Config{Conn: listenerConn, MaxConcurrentDispatch: limit})
	if err != nil {
		t.Fatalf("NewUDPTransport: %v", err)
	}
	defer tr.Close()

	var inFlight int32
	var peak int32
	release := make(chan struct{})

	tr.AddHandler(func(data []byte, from, localAddr *net.UDPAddr) bool {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if cur <= old || atomic.CompareAndSwapInt32(&peak, old, cur) {
				break
			}
		}
		<-release
		atomic.AddInt32(&inFlight, -1)
		return true
	})

	sender, err := net.DialUDP("udp4", nil, listenerConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()

	const burst = 100
	for i := 0; i < burst; i++ {
		if _, err := sender.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&peak) < limit {
		time.Sleep(10 * time.Millisecond)
	}
	// Give any handler beyond the limit a chance to start, if the cap is broken.
	time.Sleep(200 * time.Millisecond)
	close(release)

	if got := atomic.LoadInt32(&peak); got > limit {
		t.Fatalf("peak concurrent handlers = %d, want <= %d", got, limit)
	}
	if got := atomic.LoadInt32(&peak); got != limit {
		t.Fatalf("peak concurrent handlers = %d, want exactly %d for a burst well above the limit", got, limit)
	}
}

// TestDispatchDropsPacketsBeyondLimit verifies that packets beyond the
// concurrency limit are dropped and counted, rather than queued or blocking
// the receive loop.
func TestDispatchDropsPacketsBeyondLimit(t *testing.T) {
	listenerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listenerConn.Close()

	const limit = 4
	tr, err := NewUDPTransport(&Config{Conn: listenerConn, MaxConcurrentDispatch: limit})
	if err != nil {
		t.Fatalf("NewUDPTransport: %v", err)
	}
	defer tr.Close()

	release := make(chan struct{})
	tr.AddHandler(func(data []byte, from, localAddr *net.UDPAddr) bool {
		<-release
		return true
	})

	sender, err := net.DialUDP("udp4", nil, listenerConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()

	const burst = 50
	for i := 0; i < burst; i++ {
		if _, err := sender.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && tr.Metrics().Snapshot().PacketsDropped < burst-limit {
		time.Sleep(10 * time.Millisecond)
	}
	close(release)

	dropped := tr.Metrics().Snapshot().PacketsDropped
	if dropped < uint64(burst-limit) {
		t.Fatalf("PacketsDropped = %d, want at least %d", dropped, burst-limit)
	}
}

// TestDispatchProcessesBurstWithinLimit is the regression check: ordinary
// traffic that never exceeds the concurrency limit must still be delivered to
// handlers and not dropped.
func TestDispatchProcessesBurstWithinLimit(t *testing.T) {
	listenerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listenerConn.Close()

	tr, err := NewUDPTransport(&Config{Conn: listenerConn, MaxConcurrentDispatch: DefaultMaxConcurrentDispatch})
	if err != nil {
		t.Fatalf("NewUDPTransport: %v", err)
	}
	defer tr.Close()

	var handled int32
	tr.AddHandler(func(data []byte, from, localAddr *net.UDPAddr) bool {
		atomic.AddInt32(&handled, 1)
		return true
	})

	sender, err := net.DialUDP("udp4", nil, listenerConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()

	const count = 20
	for i := 0; i < count; i++ {
		if _, err := sender.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&handled) < count {
		time.Sleep(10 * time.Millisecond)
	}

	if got := atomic.LoadInt32(&handled); got != count {
		t.Fatalf("handled = %d, want %d", got, count)
	}
	if dropped := tr.Metrics().Snapshot().PacketsDropped; dropped != 0 {
		t.Fatalf("PacketsDropped = %d, want 0 for a burst within the limit", dropped)
	}
}
