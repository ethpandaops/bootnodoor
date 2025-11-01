// Package bootnode implements an Ethereum beacon chain bootnode.
//
// This package provides a specialized discv5 bootnode implementation with:
//   - Fork digest filtering for Ethereum consensus layer
//   - Node database and persistence
//   - Routing table management with IP limits
//   - Discovery and ping services
package bootnode

import (
	"crypto/ecdsa"
	"net"
	"time"

	"github.com/pk910/bootoor/beacon-bootnode/config"
	"github.com/pk910/bootoor/beacon-bootnode/nodedb"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/sirupsen/logrus"
)

// Config contains configuration for the beacon bootnode.
type Config struct {
	// PrivateKey is the node's private key (required)
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

	// CLConfig is the consensus layer configuration for fork digest filtering
	CLConfig *config.Config

	// GracePeriod is how long to accept old fork digests (default 60 minutes)
	GracePeriod time.Duration

	// BootNodes are the initial nodes to connect to
	BootNodes []*node.Node

	// NodeDB is the database for storing discovered nodes (required)
	NodeDB *nodedb.NodeDB

	// MaxNodesPerIP is the maximum nodes allowed per IP address (default 100)
	MaxNodesPerIP int

	// SessionLifetime is how long sessions remain valid (default 12 hours)
	SessionLifetime time.Duration

	// MaxSessions is the maximum number of cached sessions (default 1000)
	MaxSessions int

	// PingInterval is how often to ping nodes (default 30 seconds)
	PingInterval time.Duration

	// MaxNodeAge is the maximum time since last seen (default 24 hours)
	MaxNodeAge time.Duration

	// MaxFailures is the maximum consecutive failures (default 3)
	MaxFailures int

	// Logger for debug messages
	Logger logrus.FieldLogger
}

// DefaultConfig returns a default bootnode configuration.
func DefaultConfig() *Config {
	return &Config{
		BindIP:          net.IPv4zero,
		BindPort:        9000,
		MaxNodesPerIP:   100,
		GracePeriod:     60 * time.Minute,
		SessionLifetime: 12 * time.Hour,
		MaxSessions:     1000,
		PingInterval:    30 * time.Second,
		MaxNodeAge:      24 * time.Hour,
		MaxFailures:     3,
	}
}
