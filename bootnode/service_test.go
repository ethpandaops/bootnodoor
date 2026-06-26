package bootnode

import (
	"crypto/ecdsa"
	"net"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/db"
	"github.com/sirupsen/logrus"
)

// newTestService builds a minimal Service with the given identities and an
// in-memory database, enough to exercise updateENRWithDiscoveredIP.
func newTestService(t *testing.T, ids []*identity) *Service {
	t.Helper()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	database := db.NewDatabase(&db.SqliteDatabaseConfig{File: ":memory:", MaxOpenConns: 5, MaxIdleConns: 2}, logger)
	if err := database.Init(); err != nil {
		t.Fatalf("db init: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.ApplyEmbeddedDbSchema(-2); err != nil {
		t.Fatalf("db schema: %v", err)
	}

	cfg := &Config{Logger: logger, Database: database}
	for _, id := range ids {
		ln, err := createLocalNode(cfg, id.key, net.ParseIP("1.2.3.4"), nil, id.enrPort, nil)
		if err != nil {
			t.Fatalf("createLocalNode: %v", err)
		}
		id.localNode = ln
		id.enrManager = NewENRManager(cfg, id.key, ln, id.servesEL, id.servesCL)
	}
	return &Service{config: cfg, identities: ids}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// updateENRWithDiscoveredIP should advertise the externally-observed port on
// every identity when they share one socket — the default dual-key migration
// path — so a NAT port remap is reflected in both ENRs.
func TestUpdateENRWithDiscoveredIP_SharedSocketDualKey(t *testing.T) {
	el := &identity{key: mustKey(t), servesEL: true, bindPort: 9000, enrPort: 9000, storeKey: "local_enr"}
	cl := &identity{key: mustKey(t), servesCL: true, bindPort: 9000, enrPort: 9000, storeKey: "local_enr_cl"}
	s := newTestService(t, []*identity{el, cl})

	s.updateENRWithDiscoveredIP(net.ParseIP("9.9.9.9"), 31000, false)

	for _, id := range s.identities {
		rec := id.localNode.Record()
		if ip := rec.IP(); ip == nil || !ip.Equal(net.ParseIP("9.9.9.9")) {
			t.Errorf("identity (EL=%v): ENR IP = %v, want 9.9.9.9", id.servesEL, rec.IP())
		}
		if rec.UDP() != 31000 {
			t.Errorf("identity (EL=%v): ENR udp = %d, want 31000 (discovered port)", id.servesEL, rec.UDP())
		}
	}
}

// With identities on separate bind ports the discovered port can't be
// attributed to a layer, so each identity keeps its configured port while still
// adopting the discovered IP.
func TestUpdateENRWithDiscoveredIP_SplitSocketKeepsConfiguredPort(t *testing.T) {
	el := &identity{key: mustKey(t), servesEL: true, bindPort: 30303, enrPort: 30303, storeKey: "local_enr"}
	cl := &identity{key: mustKey(t), servesCL: true, bindPort: 9000, enrPort: 9000, storeKey: "local_enr_cl"}
	s := newTestService(t, []*identity{el, cl})

	s.updateENRWithDiscoveredIP(net.ParseIP("9.9.9.9"), 31000, false)

	want := map[bool]uint16{true: 30303, false: 9000} // servesEL -> configured port
	for _, id := range s.identities {
		rec := id.localNode.Record()
		if ip := rec.IP(); ip == nil || !ip.Equal(net.ParseIP("9.9.9.9")) {
			t.Errorf("identity (EL=%v): ENR IP = %v, want 9.9.9.9", id.servesEL, rec.IP())
		}
		if rec.UDP() != want[id.servesEL] {
			t.Errorf("identity (EL=%v): ENR udp = %d, want %d (configured port, not discovered)", id.servesEL, rec.UDP(), want[id.servesEL])
		}
	}
}
