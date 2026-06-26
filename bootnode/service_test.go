package bootnode

import (
	"crypto/ecdsa"
	"net"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	"github.com/ethpandaops/bootnodoor/db"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/sirupsen/logrus"
)

func quietLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

// storedENRWith builds a signed ENR carrying the given extra fields, simulating
// a record persisted by an earlier (e.g. shared single-key) deployment.
func storedENRWith(t *testing.T, key *ecdsa.PrivateKey, fields map[string][]byte) *enr.Record {
	t.Helper()
	rec, err := buildENR(key, net.ParseIP("1.2.3.4"), nil, 9000)
	if err != nil {
		t.Fatalf("buildENR: %v", err)
	}
	for k, v := range fields {
		_ = rec.Set(k, v)
	}
	rec.SetSeq(rec.Seq() + 1)
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return rec
}

// A reused shared ENR carries both eth and eth2; an EL-only identity must drop
// the inherited eth2 so peers don't classify it as serving CL.
func TestUpdateENR_ELOnlyDropsInheritedEth2(t *testing.T) {
	cfg := &Config{Logger: quietLogger(), ELConfig: &elconfig.ChainConfig{}, ELGenesisHash: [32]byte{1, 2, 3}, ELGenesisTime: 1000}
	key := mustKey(t)
	stored := storedENRWith(t, key, map[string][]byte{"eth2": {0xaa, 0xbb, 0xcc, 0xdd}})
	ln, err := createLocalNode(cfg, key, net.ParseIP("1.2.3.4"), nil, 9000, stored)
	if err != nil {
		t.Fatalf("createLocalNode: %v", err)
	}

	if err := NewENRManager(cfg, key, ln, true, false).UpdateENR(0, 0); err != nil {
		t.Fatalf("UpdateENR: %v", err)
	}

	rec := ln.Record()
	if _, ok := rec.Eth(); !ok {
		t.Error("EL identity should advertise eth")
	}
	var eth2 []byte
	if err := rec.Get("eth2", &eth2); err == nil {
		t.Error("EL-only identity should not advertise eth2")
	}
}

// An identity that serves neither layer (no chain config) must drop both fields
// inherited from a reused record — covering the eth-removal branch.
func TestUpdateENR_DropsUnservedFields(t *testing.T) {
	cfg := &Config{Logger: quietLogger()}
	key := mustKey(t)
	stored := storedENRWith(t, key, map[string][]byte{"eth": {0x01, 0x02, 0x03, 0x04}, "eth2": {0xaa, 0xbb, 0xcc, 0xdd}})
	ln, err := createLocalNode(cfg, key, net.ParseIP("1.2.3.4"), nil, 9000, stored)
	if err != nil {
		t.Fatalf("createLocalNode: %v", err)
	}

	if err := NewENRManager(cfg, key, ln, false, false).UpdateENR(0, 0); err != nil {
		t.Fatalf("UpdateENR: %v", err)
	}

	rec := ln.Record()
	var v []byte
	if err := rec.Get("eth", &v); err == nil {
		t.Error("unserved eth field should be removed")
	}
	if err := rec.Get("eth2", &v); err == nil {
		t.Error("unserved eth2 field should be removed")
	}
}

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
