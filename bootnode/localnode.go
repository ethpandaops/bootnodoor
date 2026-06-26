package bootnode

import (
	"fmt"

	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
)

// createLocalNode creates the local node with ENR.
//
// This generates the local node that will be shared across both discv4 and discv5.
// The ENR will contain all network information and will be updated with eth/eth2 fields later.
func createLocalNode(cfg *Config, storedENR *enr.Record) (*v5node.Node, error) {
	var localENR *enr.Record
	var err error

	if storedENR != nil {
		// Use stored ENR as baseline, but verify it matches our private key
		pubKey := storedENR.PublicKey()
		if pubKey != nil && pubKey.Equal(&cfg.PrivateKey.PublicKey) {
			localENR = storedENR
			cfg.Logger.Debug("using stored ENR as baseline")
		} else {
			cfg.Logger.Warn("stored ENR doesn't match private key, creating new one")
		}
	}

	// Create new ENR if we don't have a valid one
	if localENR == nil {
		localENR, err = buildENR(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to build ENR: %w", err)
		}
	}

	// Create node from ENR
	node, err := v5node.New(localENR)
	if err != nil {
		return nil, fmt.Errorf("failed to create local node: %w", err)
	}

	cfg.Logger.WithField("nodeID", node.ID().String()[:16]+"...").Info("created local node")

	return node, nil
}

// buildENR builds a new ENR record from configuration.
func buildENR(cfg *Config) (*enr.Record, error) {
	record := enr.New()

	// Set identity scheme (v4) and public key
	record.Set(enr.WithIdentityScheme("v4"))
	record.Set(enr.WithPublicKey(&cfg.PrivateKey.PublicKey))

	// Set IP addresses
	if cfg.ENRIP != nil {
		if ipv4 := cfg.ENRIP.To4(); ipv4 != nil {
			record.Set("ip", ipv4)
		}
	}
	if cfg.ENRIP6 != nil {
		if ipv6 := cfg.ENRIP6.To16(); ipv6 != nil {
			record.Set("ip6", ipv6)
		}
	}

	// Set UDP/TCP ports
	port := cfg.ENRPort
	if port == 0 {
		port = cfg.BindPort
	}
	if port > 0 {
		record.Set("udp", port)
		record.Set("tcp", port)
		// ip6 needs udp6/tcp6 to be a usable endpoint.
		if cfg.ENRIP6 != nil && cfg.ENRIP6.To16() != nil {
			record.Set("udp6", port)
			record.Set("tcp6", port)
		}
	}

	// Set sequence number to 1
	record.SetSeq(1)

	// Sign the record
	if err := record.Sign(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign ENR: %w", err)
	}

	return record, nil
}
