package discv5

import (
	"context"
	"crypto/ecdsa"
	"net"
	"time"

	"github.com/pk910/bootoor/discv5/protocol"
	"github.com/sirupsen/logrus"
)

// Config contains configuration for the discv5 service.
type Config struct {
	// Service context
	Context context.Context

	// PrivateKey is the node's private key
	PrivateKey *ecdsa.PrivateKey

	// BindIP is the IP address to bind to
	BindIP net.IP

	// BindPort is the UDP port to bind to
	BindPort int

	// ENRIP is the IPv4 address to advertise in the ENR (optional, uses BindIP if nil)
	ENRIP net.IP

	// ENRIP6 is the IPv6 address to advertise in the ENR (optional)
	ENRIP6 net.IP

	// ENRPort is the UDP port to advertise in the ENR (0 = use BindPort)
	ENRPort int

	// ETH2Data is the eth2 field to include in the ENR (optional)
	// This should be the 16-byte encoded eth2 field containing fork digest and next fork info
	ETH2Data []byte

	// Callbacks (all optional, can be nil)

	// OnHandshakeComplete is called when a handshake completes successfully
	OnHandshakeComplete protocol.OnHandshakeCompleteCallback

	// OnNodeUpdate is called when a node's ENR is updated
	OnNodeUpdate protocol.OnNodeUpdateCallback

	// OnFindNode is called when a FINDNODE request is received
	OnFindNode protocol.OnFindNodeCallback

	// OnTalkReq is called when a TALKREQ request is received
	OnTalkReq protocol.OnTalkReqCallback

	// ResponseFilter is applied when serving FINDNODE responses (Stage 2)
	ResponseFilter protocol.ResponseFilter

	// SessionLifetime is how long sessions remain valid (default 12 hours)
	SessionLifetime time.Duration

	// MaxSessions is the maximum number of cached sessions (default 1000)
	MaxSessions int

	// Logger for debug messages
	Logger logrus.FieldLogger
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		BindIP:          net.IPv4zero,
		BindPort:        9000,
		SessionLifetime: 12 * time.Hour,
		MaxSessions:     1000,
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.PrivateKey == nil {
		return ErrMissingPrivateKey
	}

	if c.BindPort <= 0 || c.BindPort > 65535 {
		return ErrInvalidPort
	}

	return nil
}
