package bootnode

import (
	"fmt"

	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
)

// createLocalNode creates a local node with the given UDP port.
//
// The storedENR is used as a baseline if it matches the private key and port.
// Otherwise a fresh ENR is built from the config.
func createLocalNode(cfg *Config, storedENR *enr.Record, udpPort uint16) (*v5node.Node, error) {
	var localENR *enr.Record
	var err error

	if storedENR != nil {
		// Use stored ENR as baseline, but verify it matches our private key and port
		pubKey := storedENR.PublicKey()
		if pubKey != nil && pubKey.Equal(&cfg.PrivateKey.PublicKey) && storedENR.UDP() == udpPort {
			localENR = storedENR
			cfg.Logger.WithField("udpPort", udpPort).Debug("using stored ENR as baseline")
		} else {
			cfg.Logger.WithField("udpPort", udpPort).Warn("stored ENR doesn't match private key or port, creating new one")
		}
	}

	// Create new ENR if we don't have a valid one
	if localENR == nil {
		localENR, err = buildENR(cfg, udpPort)
		if err != nil {
			return nil, fmt.Errorf("failed to build ENR: %w", err)
		}
	}

	// Create node from ENR
	node, err := v5node.New(localENR)
	if err != nil {
		return nil, fmt.Errorf("failed to create local node: %w", err)
	}

	cfg.Logger.WithField("nodeID", node.ID().String()[:16]+"...").WithField("udpPort", udpPort).Info("created local node")

	return node, nil
}

// buildENR builds a new ENR record from configuration with the specified port.
func buildENR(cfg *Config, udpPort uint16) (*enr.Record, error) {
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

	// Set UDP port
	if udpPort > 0 {
		record.Set("udp", udpPort)
	}

	// Set TCP port (same as UDP)
	if udpPort > 0 {
		record.Set("tcp", udpPort)
	}

	// Set sequence number to 1
	record.SetSeq(1)

	// Sign the record
	if err := record.Sign(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign ENR: %w", err)
	}

	return record, nil
}
