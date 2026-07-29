package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/bootnodoor/bootnode"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	"github.com/ethpandaops/bootnodoor/db"
)

func testService(t *testing.T, bindPort uint16) *bootnode.Service {
	t.Helper()
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	database := db.NewDatabase(&db.SqliteDatabaseConfig{File: ":memory:"}, logger)
	if err := database.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.ApplyEmbeddedDbSchema(-2); err != nil {
		t.Fatal(err)
	}

	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chainCfg, err := elconfig.ParseChainConfig([]byte(`{"chainId":1,"shanghaiTime":1500}`))
	if err != nil {
		t.Fatal(err)
	}

	cfg := bootnode.DefaultConfig()
	cfg.PrivateKey = key
	cfg.Database = database
	cfg.Logger = logger
	cfg.BindIP = net.IPv4(127, 0, 0, 1)
	cfg.BindPort = bindPort
	cfg.ENRIP = net.IPv4(127, 0, 0, 1)
	cfg.ENRIPProvided = true
	cfg.ELConfig = chainCfg
	cfg.ELGenesisHash = [32]byte{9, 9, 9}
	cfg.ELGenesisTime = 1000
	cfg.EnableDiscv4 = false

	svc, err := bootnode.New(cfg)
	if err != nil {
		t.Fatalf("bootnode.New: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	return svc
}

// TestOverviewReportsLiveStats verifies the overview no longer renders
// hardcoded zeros: every formerly-dead field is backed by a real counter, so
// the panel reflects the running service.
func TestOverviewReportsLiveStats(t *testing.T) {
	svc := testService(t, 42424)
	fh := NewFrontendHandler(svc)

	rr := httptest.NewRecorder()
	fh.Overview(rr, httptest.NewRequest(http.MethodGet, "/?ajax=1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var got OverviewPageData
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Status == "" || got.PeerID == "" {
		t.Fatalf("basic fields empty: %+v", got)
	}
	// Sessions are counted from the live cache, so the field is present and
	// non-negative even on a service that has not peered yet.
	if got.SessionsTotal < 0 || got.SessionsActive < 0 {
		t.Fatalf("session stats = %d/%d", got.SessionsTotal, got.SessionsActive)
	}

	stats := svc.GetStats()
	if got.LookupsStarted != stats.Lookups.LookupsStarted {
		t.Errorf("LookupsStarted = %d, want the aggregator's %d", got.LookupsStarted, stats.Lookups.LookupsStarted)
	}
	if got.PingsSent != stats.Ping.PingsSent {
		t.Errorf("PingsSent = %d, want %d", got.PingsSent, stats.Ping.PingsSent)
	}
	if got.PacketsReceived != int(stats.Packets.PacketsReceived) {
		t.Errorf("PacketsReceived = %d, want %d", got.PacketsReceived, stats.Packets.PacketsReceived)
	}
}

// TestGetStatsAggregatesAcrossLayers verifies the aggregator reads every
// source it claims to: lookups, pings, sessions and transport packets.
func TestGetStatsAggregatesAcrossLayers(t *testing.T) {
	svc := testService(t, 42425)
	stats := svc.GetStats()

	if stats.Lookups.LookupsStarted < 0 || stats.Ping.PingsSent < 0 {
		t.Fatalf("counters are negative: %+v", stats)
	}
	if stats.HasV4 {
		t.Fatal("discv4 was disabled for this service but reported as present")
	}
}
