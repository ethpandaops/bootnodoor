// Package bootnode implements a universal Ethereum bootnode supporting both
// Execution Layer (EL) and Consensus Layer (CL) discovery.
//
// The bootnode supports:
//   - Discovery v4 (discv4) for EL nodes
//   - Discovery v5 (discv5) for both EL and CL nodes
//   - Dual routing tables (separate for EL and CL)
//   - Fork-aware filtering
//   - Protocol multiplexing (both protocols on same UDP port)
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

	// BindPort is the UDP port to bind to (default: 30303)
	BindPort uint16

	// ENR configuration

	// ENRIP is the IP address to advertise in ENR (optional, auto-detected if nil)
	ENRIP net.IP

	// ENRIP6 is the IPv6 address to advertise in ENR (optional)
	ENRIP6 net.IP

	// ENRPort is the UDP port to advertise in ENR (default: same as BindPort)
	ENRPort uint16

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

	// EnableDiscv4 enables Discovery v4 protocol (default: true)
	EnableDiscv4 bool

	// EnableDiscv5 enables Discovery v5 protocol (default: true)
	EnableDiscv5 bool

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
		BindIP:            net.IPv4zero,
		BindPort:          30303,
		MaxActiveNodes:    500,
		MaxNodesPerIP:     10,
		PingInterval:      30 * time.Second,
		MaxNodeAge:        24 * time.Hour,
		MaxFailures:       3,
		EnableDiscv4:      true,
		EnableDiscv5:      true,
		SessionLifetime:   12 * time.Hour,
		MaxSessions:       1024,
		EnableIPDiscovery: false,
		GracePeriod:       60 * time.Minute,
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
	}

	// Must have at least one protocol enabled
	if !c.EnableDiscv4 && !c.EnableDiscv5 {
		return fmt.Errorf("at least one of EnableDiscv4 or EnableDiscv5 must be true")
	}

	// Discv4 requires EL config (CL nodes don't use discv4)
	if c.EnableDiscv4 && c.ELConfig == nil {
		return fmt.Errorf("EnableDiscv4 requires ELConfig to be set (discv4 is EL-only)")
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

	if c.BindPort == 0 {
		c.BindPort = 30303
	}

	if c.ENRPort == 0 {
		c.ENRPort = c.BindPort
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
