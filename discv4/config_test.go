package discv4

import (
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv4/protocol"
)

type stubTransport struct{}

func (stubTransport) SendTo([]byte, *net.UDPAddr) error             { return nil }
func (stubTransport) Send([]byte, *net.UDPAddr, *net.UDPAddr) error { return nil }
func (stubTransport) LocalAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30303}
}
func (stubTransport) AddHandler(func([]byte, *net.UDPAddr, *net.UDPAddr) bool) {}
func (stubTransport) AddHandlerFor(string, func([]byte, *net.UDPAddr, *net.UDPAddr) bool) {
}

func TestValidateRejectsNegativeMaxNodes(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.PrivateKey = key
	cfg.MaxNodes = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("negative MaxNodes passed validation")
	}
}

// TestMaxNodesReachesHandler: distinct senders beyond MaxNodes are not tracked.
func TestMaxNodesReachesHandler(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.PrivateKey = key
	cfg.MaxNodes = 2
	s, err := New(cfg, stubTransport{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	from := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 30303}
	for range 5 {
		peer, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		data, _, err := protocol.Encode(peer, &protocol.Ping{
			Version:    4,
			From:       protocol.NewEndpoint(from, 0),
			To:         protocol.NewEndpoint(from, 0),
			Expiration: protocol.MakeExpiration(20 * time.Second),
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Handler().HandlePacket(data, from, from)
	}

	if got := s.Handler().GetStats().KnownNodes; got != 2 {
		t.Fatalf("known nodes = %d, want 2", got)
	}
}
