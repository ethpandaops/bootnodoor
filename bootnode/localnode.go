package bootnode

import (
	"crypto/ecdsa"
	"fmt"
	"net"

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

	// Set UDP port
	if cfg.ENRPort > 0 {
		record.Set("udp", cfg.ENRPort)
	} else if cfg.BindPort > 0 {
		record.Set("udp", cfg.BindPort)
	}

	// Set TCP port (same as UDP for now)
	if cfg.ENRPort > 0 {
		record.Set("tcp", cfg.ENRPort)
	} else if cfg.BindPort > 0 {
		record.Set("tcp", cfg.BindPort)
	}

	// Set sequence number to 1
	record.SetSeq(1)

	// Sign the record
	if err := record.Sign(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign ENR: %w", err)
	}

	return record, nil
}

// updateENRAddresses updates the ENR with network addresses if needed.
//
// This is called when we want to update just the IP/port without changing other fields.
func updateENRAddresses(node *v5node.Node, privKey *ecdsa.PrivateKey, ip net.IP, ip6 net.IP, port uint16) (*v5node.Node, error) {
	currentRecord := node.Record()

	// Check if update is needed
	needsUpdate := false

	currentIP := currentRecord.IP()
	if ip != nil && (currentIP == nil || !currentIP.Equal(ip)) {
		needsUpdate = true
	}

	currentIP6 := currentRecord.IP6()
	if ip6 != nil && (currentIP6 == nil || !currentIP6.Equal(ip6)) {
		needsUpdate = true
	}

	currentPort := currentRecord.UDP()
	if port > 0 && currentPort != port {
		needsUpdate = true
	}

	if !needsUpdate {
		return node, nil
	}

	// Clone and update
	newRecord, err := currentRecord.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone ENR: %w", err)
	}

	if ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			newRecord.Set("ip", ipv4)
		}
	}
	if ip6 != nil {
		if ipv6 := ip6.To16(); ipv6 != nil {
			newRecord.Set("ip6", ipv6)
		}
	}
	if port > 0 {
		newRecord.Set("udp", port)
		newRecord.Set("tcp", port)
	}

	// Increment sequence
	newRecord.SetSeq(currentRecord.Seq() + 1)

	// Re-sign
	if err := newRecord.Sign(privKey); err != nil {
		return nil, fmt.Errorf("failed to sign updated ENR: %w", err)
	}

	// Create new node
	return v5node.New(newRecord)
}
