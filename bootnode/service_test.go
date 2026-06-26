package bootnode

import (
	"crypto/ecdsa"
	"net"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	"github.com/ethpandaops/bootnodoor/db"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/services"
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

	logger := quietLogger()
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

func TestResolveIdentities_SharedKeyCollapses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrivateKey = mustKey(t)
	cfg.ELConfig = &elconfig.ChainConfig{}
	cfg.CLConfig = &clconfig.Config{}
	cfg.ApplyDefaults()

	ids := resolveIdentities(cfg)
	if len(ids) != 1 {
		t.Fatalf("shared key should collapse to 1 identity, got %d", len(ids))
	}
	if !ids[0].servesEL || !ids[0].servesCL {
		t.Errorf("shared identity should serve both layers, got EL=%v CL=%v", ids[0].servesEL, ids[0].servesCL)
	}
	if ids[0].storeKey != localENRKey {
		t.Errorf("shared identity storeKey = %q, want %q", ids[0].storeKey, localENRKey)
	}
}

func TestResolveIdentities_SeparateKeysSplit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ELPrivateKey = mustKey(t)
	cfg.CLPrivateKey = mustKey(t)
	cfg.ELConfig = &elconfig.ChainConfig{}
	cfg.CLConfig = &clconfig.Config{}
	cfg.ApplyDefaults()

	ids := resolveIdentities(cfg)
	if len(ids) != 2 {
		t.Fatalf("distinct keys should yield 2 identities, got %d", len(ids))
	}
	var el, cl *identity
	for _, id := range ids {
		if id.servesEL {
			el = id
		}
		if id.servesCL {
			cl = id
		}
	}
	if el == nil || cl == nil || el == cl {
		t.Fatalf("expected one EL and one distinct CL identity")
	}
	if el.servesCL || cl.servesEL {
		t.Error("split identities should each serve a single layer")
	}
	if el.storeKey != localENRKey || cl.storeKey != localENRKey+"_cl" {
		t.Errorf("storeKeys: EL=%q CL=%q", el.storeKey, cl.storeKey)
	}
}

func TestResolveIdentities_CLOnlyKeepsLegacyStoreKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrivateKey = mustKey(t)
	cfg.CLConfig = &clconfig.Config{} // no ELConfig
	cfg.ApplyDefaults()

	ids := resolveIdentities(cfg)
	if len(ids) != 1 || ids[0].servesEL || !ids[0].servesCL {
		t.Fatalf("CL-only should yield one CL identity, got %+v", ids)
	}
	if ids[0].storeKey != localENRKey {
		t.Errorf("CL-only storeKey = %q, want legacy %q", ids[0].storeKey, localENRKey)
	}
}

// validatableConfig returns a config that passes Validate, ready for a test to
// mutate one aspect. Database is a non-nil placeholder (Validate only nil-checks it).
func validatableConfig(t *testing.T) *Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Logger = quietLogger()
	cfg.Database = &db.Database{}
	cfg.ELConfig = &elconfig.ChainConfig{}
	cfg.ELGenesisHash = [32]byte{1}
	cfg.ELGenesisTime = 1
	cfg.CLConfig = &clconfig.Config{}
	cfg.ApplyDefaults()
	return cfg
}

func TestValidate_SameKeyDifferentPortRejected(t *testing.T) {
	cfg := validatableConfig(t)
	cfg.PrivateKey = mustKey(t) // both layers share this key
	cfg.ELBindPort = 30303
	cfg.CLBindPort = 9000
	if err := cfg.Validate(); err == nil {
		t.Fatal("same key with different ports should be rejected")
	}
}

func TestValidate_SharedKeyDefaultPortsOK(t *testing.T) {
	cfg := validatableConfig(t)
	cfg.PrivateKey = mustKey(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("shared key + default ports should validate: %v", err)
	}
}

func TestValidate_PerLayerKeysOK(t *testing.T) {
	cfg := validatableConfig(t)
	cfg.PrivateKey = nil
	cfg.ELPrivateKey = mustKey(t)
	cfg.CLPrivateKey = mustKey(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("distinct per-layer keys should validate: %v", err)
	}
}

func TestValidate_MissingKeyForEnabledLayerRejected(t *testing.T) {
	cfg := validatableConfig(t)
	cfg.PrivateKey = nil // no key for either layer
	if err := cfg.Validate(); err == nil {
		t.Fatal("an enabled layer without a key should be rejected")
	}
}

// ipDiscoveryService wires an IPDiscovery that signals the consensus port on a
// channel, plus a Service holding the given identities.
func ipDiscoveryService(t *testing.T, ids []*identity) (*Service, <-chan uint16) {
	t.Helper()
	consensus := make(chan uint16, 1)
	ipd := services.NewIPDiscovery(services.IPDiscoveryConfig{
		MinReports:     3,
		MinDistinctIPs: 3,
		Logger:         quietLogger(),
		OnConsensusReached: func(_ net.IP, port uint16, _ bool) {
			select {
			case consensus <- port:
			default:
			}
		},
	})
	return &Service{config: &Config{Logger: quietLogger()}, identities: ids, ipDiscovery: ipd}, consensus
}

// Split sockets observe different external ports; onPongReceived must bucket
// them so IP-discovery consensus is reachable (the bug fixed in 6ff551f).
func TestOnPongReceived_SplitSocketReachesConsensus(t *testing.T) {
	s, consensus := ipDiscoveryService(t, []*identity{
		{key: mustKey(t), servesEL: true, bindPort: 30303, enrPort: 30303},
		{key: mustKey(t), servesCL: true, bindPort: 9000, enrPort: 9000},
	})

	// Same external IP, different observed ports (one per socket), distinct reporters.
	s.onPongReceived([]byte("reporter-a-1"), net.ParseIP("10.0.0.1"), net.ParseIP("9.9.9.9"), 30303)
	s.onPongReceived([]byte("reporter-b-2"), net.ParseIP("10.0.0.2"), net.ParseIP("9.9.9.9"), 9000)
	s.onPongReceived([]byte("reporter-c-3"), net.ParseIP("10.0.0.3"), net.ParseIP("9.9.9.9"), 40404)

	select {
	case <-consensus:
	case <-time.After(2 * time.Second):
		t.Fatal("split-socket PONGs never reached IP-discovery consensus")
	}
}

// A single shared socket must keep the externally-observed port so a NAT port
// remap still self-corrects.
func TestOnPongReceived_SingleSocketKeepsObservedPort(t *testing.T) {
	s, consensus := ipDiscoveryService(t, []*identity{
		{key: mustKey(t), servesEL: true, servesCL: true, bindPort: 9000, enrPort: 9000},
	})

	for i, reporter := range []string{"reporter-a-1", "reporter-b-2", "reporter-c-3"} {
		s.onPongReceived([]byte(reporter), net.IPv4(10, 0, 0, byte(i+1)), net.ParseIP("9.9.9.9"), 31000)
	}

	select {
	case port := <-consensus:
		if port != 31000 {
			t.Errorf("single-socket consensus port = %d, want observed 31000", port)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("single-socket PONGs never reached IP-discovery consensus")
	}
}

// A bootnode serves discovery only, so it advertises udp/udp6 and never
// tcp/tcp6 (which would invite RLPx/libp2p dials it can't answer).
func TestBuildENR_AdvertisesUDPNotTCP(t *testing.T) {
	rec, err := buildENR(mustKey(t), net.ParseIP("203.0.113.1"), net.ParseIP("2001:db8::1"), 9000)
	if err != nil {
		t.Fatalf("buildENR: %v", err)
	}
	if rec.IP6() == nil || rec.UDP6() != 9000 {
		t.Errorf("v6 endpoint: ip6=%v udp6=%d, want set and 9000", rec.IP6(), rec.UDP6())
	}
	if rec.UDP() != 9000 {
		t.Errorf("udp = %d, want 9000", rec.UDP())
	}
	var p uint16
	if err := rec.Get("tcp", &p); err == nil {
		t.Error("tcp must not be advertised by a discovery-only bootnode")
	}
	if err := rec.Get("tcp6", &p); err == nil {
		t.Error("tcp6 must not be advertised by a discovery-only bootnode")
	}
}

// A v4-only node must not advertise any v6 fields.
func TestBuildENR_NoIPv6OmitsV6Fields(t *testing.T) {
	rec, err := buildENR(mustKey(t), net.ParseIP("203.0.113.1"), nil, 9000)
	if err != nil {
		t.Fatalf("buildENR: %v", err)
	}
	if rec.IP6() != nil {
		t.Error("ip6 should be absent for a v4-only node")
	}
	if rec.UDP6() != 0 {
		t.Errorf("udp6 = %d, want absent for a v4-only node", rec.UDP6())
	}
}

// With IP discovery off, a changed advertised IP in config must take effect on
// restart even when a matching ENR is already persisted.
func TestCreateLocalNode_DiscoveryOffConfigIPWins(t *testing.T) {
	key := mustKey(t)
	stored := storedENRWith(t, key, nil) // advertises 1.2.3.4
	cfg := &Config{Logger: quietLogger(), EnableIPDiscovery: false}

	ln, err := createLocalNode(cfg, key, net.ParseIP("5.6.7.8"), net.ParseIP("2001:db8::9"), 9000, stored)
	if err != nil {
		t.Fatalf("createLocalNode: %v", err)
	}
	if ip := ln.Record().IP(); ip == nil || !ip.Equal(net.ParseIP("5.6.7.8")) {
		t.Errorf("discovery off: ENR ip = %v, want config 5.6.7.8", ip)
	}
	if ip6 := ln.Record().IP6(); ip6 == nil || !ip6.Equal(net.ParseIP("2001:db8::9")) {
		t.Errorf("discovery off: ENR ip6 = %v, want config 2001:db8::9", ip6)
	}
}

// With IP discovery on, the stored (possibly learned) IP is preserved over a
// config value so a restart doesn't clobber a discovered external address.
func TestCreateLocalNode_DiscoveryOnPreservesStoredIP(t *testing.T) {
	key := mustKey(t)
	stored := storedENRWith(t, key, nil) // advertises 1.2.3.4
	cfg := &Config{Logger: quietLogger(), EnableIPDiscovery: true}

	ln, err := createLocalNode(cfg, key, net.ParseIP("5.6.7.8"), nil, 9000, stored)
	if err != nil {
		t.Fatalf("createLocalNode: %v", err)
	}
	if ip := ln.Record().IP(); ip == nil || !ip.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("discovery on: ENR ip = %v, want preserved 1.2.3.4", ip)
	}
}
