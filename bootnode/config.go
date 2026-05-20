// Package bootnode implements a universal Ethereum bootnode supporting both
// Execution Layer (EL) and Consensus Layer (CL) discovery.
//
// The bootnode supports:
//   - Discovery v4 (discv4) for EL nodes
//   - Discovery v5 (discv5) for both EL and CL nodes
//   - Dual routing tables (separate for EL and CL)
//   - Fork-aware filtering
//   - Separate ports for EL and CL (each with its own ENR)
package bootnode

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"time"

	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	"github.com/ethpandaops/bootnodoor/db"
	"github.com/sirupsen/logrus"
)

// Config contains configuration for the universal bootnode.
type Config struct {
	// PrivateKey is the node's secp256k1 private key (required)
	PrivateKey *ecdsa.PrivateKey

	// Database is the shared database for both EL and CL nodes (required)
	Database *db.Database

	// Network configuration

	// BindIP is the IP address to bind to (default: 0.0.0.0)
	BindIP net.IP

	// ELBindPort is the UDP port for EL discovery (discv4 + discv5) (default: 30303)
	ELBindPort uint16

	// CLBindPort is the UDP port for CL discovery (discv5 only) (default: 9000)
	CLBindPort uint16

	// ENR configuration

	// ENRIP is the IP address to advertise in ENR (optional, auto-detected if nil)
	ENRIP net.IP

	// ENRIP6 is the IPv6 address to advertise in ENR (optional)
	ENRIP6 net.IP

	// ELENRPort is the UDP port to advertise in EL ENR (default: same as ELBindPort)
	ELENRPort uint16

	// CLENRPort is the UDP port to advertise in CL ENR (default: same as CLBindPort)
	CLENRPort uint16

	// Execution Layer configuration

	// ELConfig is the EL chain configuration (optional, nil disables EL support)
	ELConfig *elconfig.ChainConfig

	// ELGenesisHash is the EL genesis block hash (required if ELConfig is set)
	ELGenesisHash [32]byte

	// ELGenesisTime is the EL genesis block timestamp (required if ELConfig is set)
	ELGenesisTime uint64

	// ELBootnodes is the list of initial EL bootnodes (ENR or enode format)
	ELBootnodes []string

	// Consensus Layer configuration

	// CLConfig is the CL beacon chain configuration (optional, nil disables CL support)
	CLConfig *clconfig.Config

	// CLBootnodes is the list of initial CL bootnodes (ENR format only)
	CLBootnodes []string

	// Routing table configuration

	// MaxActiveNodes is the maximum active nodes per table (default: 500)
	MaxActiveNodes int

	// MaxNodesPerIP is the maximum nodes allowed per IP address (default: 10)
	MaxNodesPerIP int

	// PingInterval is how often to ping nodes (default: 30s)
	PingInterval time.Duration

	// MaxNodeAge is the maximum age before considering a node dead (default: 24h)
	MaxNodeAge time.Duration

	// MaxFailures is the maximum consecutive failures before removing a node (default: 3)
	MaxFailures int

	// Protocol configuration

	// SessionLifetime is the discv5 session lifetime (default: 12 hours)
	SessionLifetime time.Duration

	// MaxSessions is the maximum number of discv5 sessions (default: 1024)
	MaxSessions int

	// Discovery configuration

	// EnableIPDiscovery enables automatic IP discovery from PONG responses (default: false)
	EnableIPDiscovery bool

	// GracePeriod is the grace period for accepting old fork digests (default: 60 minutes)
	GracePeriod time.Duration

	// Logging

	// Logger is the logger instance (optional)
	Logger logrus.FieldLogger
}

// DefaultConfig returns a configuration with sensible defaults.
//
// You must set at least:
//   - PrivateKey
//   - Database
//   - One of: ELConfig or CLConfig (or both)
func DefaultConfig() *Config {
	return &Config{
		BindIP:          net.IPv4zero,
		ELBindPort:      30303,
		CLBindPort:      9000,
		MaxActiveNodes:  500,
		MaxNodesPerIP:   10,
		PingInterval:    30 * time.Second,
		MaxNodeAge:      24 * time.Hour,
		MaxFailures:     3,
		SessionLifetime: 12 * time.Hour,
		MaxSessions:     1024,
		GracePeriod:     60 * time.Minute,
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.PrivateKey == nil {
		return fmt.Errorf("private key is required")
	}

	if c.Database == nil {
		return fmt.Errorf("database is required")
	}

	// Must have at least one layer enabled
	if c.ELConfig == nil && c.CLConfig == nil {
		return fmt.Errorf("at least one of ELConfig or CLConfig must be set")
	}

	// Validate EL config if provided
	if c.ELConfig != nil {
		if c.ELGenesisHash == [32]byte{} {
			return fmt.Errorf("ELGenesisHash is required when ELConfig is set")
		}
		if c.ELGenesisTime == 0 {
			return fmt.Errorf("ELGenesisTime is required when ELConfig is set")
		}
		if c.ELBindPort == 0 {
			return fmt.Errorf("ELBindPort is required when ELConfig is set")
		}
	}

	// Validate CL config if provided
	if c.CLConfig != nil && c.CLBindPort == 0 {
		return fmt.Errorf("CLBindPort is required when CLConfig is set")
	}

	// Ensure ports don't collide when both layers are enabled
	if c.ELConfig != nil && c.CLConfig != nil && c.ELBindPort == c.CLBindPort {
		return fmt.Errorf("ELBindPort and CLBindPort must be different when both layers are enabled (both set to %d)", c.ELBindPort)
	}

	if c.MaxActiveNodes <= 0 {
		return fmt.Errorf("max active nodes must be positive")
	}

	if c.MaxNodesPerIP <= 0 {
		return fmt.Errorf("max nodes per IP must be positive")
	}

	return nil
}

// ApplyDefaults fills in default values for unset fields.
func (c *Config) ApplyDefaults() {
	if c.BindIP == nil {
		c.BindIP = net.IPv4zero
	}

	if c.ELBindPort == 0 {
		c.ELBindPort = 30303
	}

	if c.CLBindPort == 0 {
		c.CLBindPort = 9000
	}

	if c.ELENRPort == 0 {
		c.ELENRPort = c.ELBindPort
	}

	if c.CLENRPort == 0 {
		c.CLENRPort = c.CLBindPort
	}

	if c.MaxActiveNodes == 0 {
		c.MaxActiveNodes = 500
	}

	if c.MaxNodesPerIP == 0 {
		c.MaxNodesPerIP = 10
	}

	if c.PingInterval == 0 {
		c.PingInterval = 30 * time.Second
	}

	if c.MaxNodeAge == 0 {
		c.MaxNodeAge = 24 * time.Hour
	}

	if c.MaxFailures == 0 {
		c.MaxFailures = 3
	}

	if c.SessionLifetime == 0 {
		c.SessionLifetime = 12 * time.Hour
	}

	if c.MaxSessions == 0 {
		c.MaxSessions = 1024
	}

	if c.GracePeriod == 0 {
		c.GracePeriod = 60 * time.Minute
	}

	if c.Logger == nil {
		c.Logger = logrus.New()
	}
}

// HasEL returns true if EL support is enabled.
func (c *Config) HasEL() bool {
	return c.ELConfig != nil
}

// HasCL returns true if CL support is enabled.
func (c *Config) HasCL() bool {
	return c.CLConfig != nil
}
