package transport

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
)

func dispatchTestTransport(t *testing.T, handlers ...PacketHandler) *UDPTransport {
	t.Helper()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	return &UDPTransport{logger: logger, metrics: NewMetrics(), handlers: handlers}
}

// discv5 registers first and rejects anything it cannot decode, so a normal
// discv4 packet is only recognised on the second attempt. Counting the first
// handler's rejection as "invalid" made 84% of ordinary traffic look invalid, so
// the distinction has to be made here, where the final outcome is known.
func TestDispatchDistinguishesFallthroughFromUnhandled(t *testing.T) {
	accept := func(_ []byte, _ *net.UDPAddr, _ *net.UDPAddr) bool { return true }
	reject := func(_ []byte, _ *net.UDPAddr, _ *net.UDPAddr) bool { return false }

	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 30303}
	local := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 9000}

	t.Run("first handler accepts", func(t *testing.T) {
		tr := dispatchTestTransport(t, accept, reject)
		tr.dispatchPacket([]byte("packet"), from, local)

		got := tr.Metrics().Snapshot()
		if got.PacketsFellThrough != 0 {
			t.Errorf("PacketsFellThrough = %d, want 0", got.PacketsFellThrough)
		}
		if got.PacketsUnhandled != 0 {
			t.Errorf("PacketsUnhandled = %d, want 0", got.PacketsUnhandled)
		}
	})

	t.Run("second handler accepts", func(t *testing.T) {
		tr := dispatchTestTransport(t, reject, accept)
		tr.dispatchPacket([]byte("packet"), from, local)

		got := tr.Metrics().Snapshot()
		if got.PacketsFellThrough != 1 {
			t.Errorf("PacketsFellThrough = %d, want 1", got.PacketsFellThrough)
		}
		if got.PacketsUnhandled != 0 {
			t.Errorf("PacketsUnhandled = %d, want 0", got.PacketsUnhandled)
		}
	})

	t.Run("nobody accepts", func(t *testing.T) {
		tr := dispatchTestTransport(t, reject, reject)
		tr.dispatchPacket([]byte("packet"), from, local)

		got := tr.Metrics().Snapshot()
		if got.PacketsFellThrough != 0 {
			t.Errorf("PacketsFellThrough = %d, want 0", got.PacketsFellThrough)
		}
		if got.PacketsUnhandled != 1 {
			t.Errorf("PacketsUnhandled = %d, want 1", got.PacketsUnhandled)
		}
	})
}

// Two discv5 identities share a socket, and the first rejects packets addressed
// to the second. That is identity demultiplexing, not other-protocol traffic, so
// it must not inflate the fallthrough counter.
func TestDispatchDoesNotCountSameProtocolDemux(t *testing.T) {
	accept := func(_ []byte, _ *net.UDPAddr, _ *net.UDPAddr) bool { return true }
	reject := func(_ []byte, _ *net.UDPAddr, _ *net.UDPAddr) bool { return false }

	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 30303}
	local := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 9000}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Run("second discv5 identity accepts", func(t *testing.T) {
		tr := &UDPTransport{logger: logger, metrics: NewMetrics()}
		tr.AddHandlerFor("discv5", reject)
		tr.AddHandlerFor("discv5", accept)
		tr.AddHandlerFor("discv4", reject)
		tr.dispatchPacket([]byte("packet"), from, local)

		if got := tr.Metrics().Snapshot().PacketsFellThrough; got != 0 {
			t.Errorf("PacketsFellThrough = %d, want 0 for same-protocol demux", got)
		}
	})

	t.Run("discv4 accepts after discv5 identities", func(t *testing.T) {
		tr := &UDPTransport{logger: logger, metrics: NewMetrics()}
		tr.AddHandlerFor("discv5", reject)
		tr.AddHandlerFor("discv5", reject)
		tr.AddHandlerFor("discv4", accept)
		tr.dispatchPacket([]byte("packet"), from, local)

		if got := tr.Metrics().Snapshot().PacketsFellThrough; got != 1 {
			t.Errorf("PacketsFellThrough = %d, want 1 when the protocol changed", got)
		}
	})
}

// Reset must clear the dispatch counters too, or a caller sees stale values.
func TestResetClearsDispatchCounters(t *testing.T) {
	m := NewMetrics()
	m.RecordFellThrough()
	m.RecordUnhandled()
	m.Reset()

	got := m.Snapshot()
	if got.PacketsFellThrough != 0 || got.PacketsUnhandled != 0 {
		t.Errorf("after Reset: fellThrough=%d unhandled=%d, want 0/0", got.PacketsFellThrough, got.PacketsUnhandled)
	}
}
