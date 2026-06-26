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

	if localENR == nil {
		localENR, err = buildENR(key, enrIP, enrIP6, enrPort)
		if err != nil {
			return nil, fmt.Errorf("failed to build ENR: %w", err)
		}
	} else if reconcileStoredENR(cfg, localENR, enrIP, enrIP6, enrPort) {
		// An explicitly-configured field (or the port) changed, so the record was
		// updated; bump the sequence and re-sign so peers pick it up.
		localENR.SetSeq(localENR.Seq() + 1)
		if err := localENR.Sign(key); err != nil {
			return nil, fmt.Errorf("failed to re-sign ENR: %w", err)
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

// reconcileStoredENR applies authoritative config to a reused stored ENR:
// explicitly-configured advertised IPs override the stored value and the port is
// always config-authoritative, so a changed --enr-ip/--enr-ip6/port takes effect
// on restart. An auto-detected IP is left untouched so an address learned via IP
// discovery survives. Reports whether the record changed.
func reconcileStoredENR(cfg *Config, rec *enr.Record, enrIP, enrIP6 net.IP, enrPort uint16) bool {
	changed := false

	if cfg.ENRIPProvided && enrIP != nil {
		if cur := rec.IP(); cur == nil || !cur.Equal(enrIP) {
			rec.Set("ip", enrIP.To4())
			changed = true
		}
	}
	if cfg.ENRIP6Provided && enrIP6 != nil {
		if cur := rec.IP6(); cur == nil || !cur.Equal(enrIP6) {
			rec.Set("ip6", enrIP6.To16())
			changed = true
		}
	}

	// A udp/udp6 port is only meaningful alongside the matching IP family.
	if enrPort > 0 && rec.IP() != nil && rec.UDP() != enrPort {
		rec.Set("udp", enrPort)
		changed = true
	}
	if enrPort > 0 && rec.IP6() != nil && rec.UDP6() != enrPort {
		rec.Set("udp6", enrPort)
		changed = true
	}

	return changed
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
