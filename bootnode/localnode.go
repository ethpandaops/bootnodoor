package bootnode

import (
	"crypto/ecdsa"
	"fmt"
	"net"

	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
)

// createLocalNode creates a local node with ENR for one identity.
func createLocalNode(cfg *Config, key *ecdsa.PrivateKey, enrIP, enrIP6 net.IP, enrPort uint16, storedENR *enr.Record) (*v5node.Node, error) {
	var localENR *enr.Record
	var err error

	if storedENR != nil {
		pubKey := storedENR.PublicKey()
		if pubKey != nil && pubKey.Equal(&key.PublicKey) {
			localENR = storedENR
			cfg.Logger.Debug("using stored ENR as baseline")
		} else {
			cfg.Logger.Warn("stored ENR doesn't match private key, creating new one")
		}
	}

	switch {
	case localENR == nil:
		localENR, err = buildENR(key, enrIP, enrIP6, enrPort)
		if err != nil {
			return nil, fmt.Errorf("failed to build ENR: %w", err)
		}

	case !cfg.EnableIPDiscovery:
		// With IP discovery off there is no learned address to preserve, so config
		// is the single source of truth for the advertised endpoint: rebuild from
		// it (carrying the stored sequence forward) so a changed --enr-ip/--enr-ip6
		// or port takes effect on restart with a persistent node database.
		seq := localENR.Seq()
		localENR, err = buildENR(key, enrIP, enrIP6, enrPort)
		if err != nil {
			return nil, fmt.Errorf("failed to build ENR: %w", err)
		}
		localENR.SetSeq(seq)
		if err := localENR.Sign(key); err != nil {
			return nil, fmt.Errorf("failed to re-sign ENR: %w", err)
		}

	case enrPort > 0 && localENR.UDP() != enrPort:
		// IP discovery is on, so the stored IP may be a learned external address
		// worth keeping; config still wins on the port.
		localENR.Set("udp", enrPort)
		if localENR.IP6() != nil {
			localENR.Set("udp6", enrPort)
		}
		localENR.SetSeq(localENR.Seq() + 1)
		if err := localENR.Sign(key); err != nil {
			return nil, fmt.Errorf("failed to re-sign ENR after port change: %w", err)
		}
		cfg.Logger.WithField("udp", enrPort).Info("updated stored ENR port from config")
	}

	// Create node from ENR
	node, err := v5node.New(localENR)
	if err != nil {
		return nil, fmt.Errorf("failed to create local node: %w", err)
	}

	cfg.Logger.WithField("nodeID", node.ID().String()[:16]+"...").Info("created local node")

	return node, nil
}

// buildENR builds a new ENR record for one identity.
func buildENR(key *ecdsa.PrivateKey, enrIP, enrIP6 net.IP, enrPort uint16) (*enr.Record, error) {
	record := enr.New()

	// Set identity scheme (v4) and public key
	record.Set(enr.WithIdentityScheme("v4"))
	record.Set(enr.WithPublicKey(&key.PublicKey))

	// Set IP addresses
	if enrIP != nil {
		if ipv4 := enrIP.To4(); ipv4 != nil {
			record.Set("ip", ipv4)
		}
	}
	if enrIP6 != nil {
		if ipv6 := enrIP6.To16(); ipv6 != nil {
			record.Set("ip6", ipv6)
		}
	}

	// A bootnode only serves discovery (UDP); it accepts no RLPx/libp2p, so it
	// advertises udp/udp6 and omits tcp/tcp6 rather than inviting failed dials.
	if enrPort > 0 {
		record.Set("udp", enrPort)
		if enrIP6 != nil && enrIP6.To16() != nil {
			record.Set("udp6", enrPort)
		}
	}

	// Set sequence number to 1
	record.SetSeq(1)

	// Sign the record
	if err := record.Sign(key); err != nil {
		return nil, fmt.Errorf("failed to sign ENR: %w", err)
	}

	return record, nil
}
