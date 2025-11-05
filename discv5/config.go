package discv5

import (
	"context"
	"crypto/ecdsa"
	"net"
	"time"

	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/discv5/protocol"
	"github.com/sirupsen/logrus"
)

// Config contains configuration for the discv5 service.
type Config struct {
	// Service context
	Context context.Context

	// PrivateKey is the node's private key
	PrivateKey *ecdsa.PrivateKey

	// ENRIP is the IPv4 address to advertise in the ENR (optional)
	ENRIP net.IP

	// ENRIP6 is the IPv6 address to advertise in the ENR (optional)
	ENRIP6 net.IP

	// ENRPort is the UDP port to advertise in the ENR (optional)
	// If not specified, the port will be obtained from the transport layer
	ENRPort int

	// ETH2Data is the eth2 field to include in the ENR (optional)
	// This should be the 16-byte encoded eth2 field containing fork digest and next fork info
	ETH2Data []byte

	// LocalENR is an already-initialized ENR to use for this node (optional)
	// If provided, this ENR will be used instead of creating a new one.
	// The higher-level service is responsible for loading, creating, and persisting this ENR.
	LocalENR *enr.Record

	// Callbacks (all optional, can be nil)

	// OnHandshakeComplete is called when a handshake completes successfully
	OnHandshakeComplete protocol.OnHandshakeCompleteCallback

	// OnNodeUpdate is called when a node's ENR is updated
	OnNodeUpdate protocol.OnNodeUpdateCallback

	// OnNodeSeen is called when a node is seen (receives a message)
	OnNodeSeen protocol.OnNodeSeenCallback

	// OnFindNode is called when a FINDNODE request is received
	OnFindNode protocol.OnFindNodeCallback

	// OnTalkReq is called when a TALKREQ request is received
	OnTalkReq protocol.OnTalkReqCallback

	// OnPongReceived is called when a PONG response is received
	OnPongReceived protocol.OnPongReceivedCallback

	// SessionLifetime is how long sessions remain valid (default 30 minutes)
	SessionLifetime time.Duration

	// MaxSessions is the maximum number of cached sessions (default 1000)
	MaxSessions int

	// Logger for debug messages
	Logger logrus.FieldLogger
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		SessionLifetime: 30 * time.Minute,
		MaxSessions:     1000,
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.PrivateKey == nil {
		return ErrMissingPrivateKey
	}

	// ENRPort is optional - will be obtained from transport if not set
	if c.ENRPort != 0 && (c.ENRPort < 0 || c.ENRPort > 65535) {
		return ErrInvalidPort
	}

	return nil
}
