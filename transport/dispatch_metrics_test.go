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
