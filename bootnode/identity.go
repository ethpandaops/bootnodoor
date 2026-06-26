package bootnode

import (
	"bytes"
	"crypto/ecdsa"
	"net"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv5"
	v5node "github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/services"
	"github.com/ethpandaops/bootnodoor/transport"
)

// localENRKey is the db state key for the primary identity's ENR, kept stable
// for backward compatibility with single-key deployments.
const localENRKey = "local_enr"

// identity is one local discovery persona. A single-key bootnode has one
// identity serving both layers; separate EL and CL keys yield two, letting
// operators keep the distinct node IDs their existing bootnodes advertise.
type identity struct {
	key      *ecdsa.PrivateKey
	servesEL bool
	servesCL bool

	enrIP    net.IP
	enrIP6   net.IP
	bindPort uint16
	enrPort  uint16
	storeKey string

	localNode     *v5node.Node
	enrManager    *ENRManager
	transport     *transport.UDPTransport
	discv5Service *discv5.Service
	pingService   *services.PingService
}

// resolveIdentities collapses EL and CL into one identity when they share a key
// (a key uniquely determines the node ID; Validate rejects same-key-different-port).
func resolveIdentities(cfg *Config) []*identity {
	elKey, clKey := cfg.elKey(), cfg.clKey()

	shared := cfg.HasEL() && cfg.HasCL() && sameKey(elKey, clKey)

	if shared {
		return []*identity{newIdentity(cfg, elKey, true, true, cfg.elBindPort(), cfg.elENRPort(), localENRKey)}
	}

	var ids []*identity
	if cfg.HasEL() {
		ids = append(ids, newIdentity(cfg, elKey, true, false, cfg.elBindPort(), cfg.elENRPort(), localENRKey))
	}
	if cfg.HasCL() {
		// Keep the legacy key for CL-only deployments; namespace it only when an
		// EL identity is also persisting under localENRKey.
		clStore := localENRKey
		if cfg.HasEL() {
			clStore = localENRKey + "_cl"
		}
		ids = append(ids, newIdentity(cfg, clKey, false, true, cfg.clBindPort(), cfg.clENRPort(), clStore))
	}
	return ids
}

func newIdentity(cfg *Config, key *ecdsa.PrivateKey, servesEL, servesCL bool, bindPort, enrPort uint16, storeKey string) *identity {
	return &identity{
		key:      key,
		servesEL: servesEL,
		servesCL: servesCL,
		enrIP:    cfg.ENRIP,
		enrIP6:   cfg.ENRIP6,
		bindPort: bindPort,
		enrPort:  enrPort,
		storeKey: storeKey,
	}
}

func sameKey(a, b *ecdsa.PrivateKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(ethcrypto.FromECDSA(a), ethcrypto.FromECDSA(b))
}
