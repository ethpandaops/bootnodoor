package nodes

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ethpandaops/bootnodoor/db"
	"github.com/ethpandaops/bootnodoor/enr"
)

// TestBuildNodeFromDBRestoresV4EndpointWhenENRHasNone verifies a persisted v4
// row loads from its stored endpoint columns when its ENR omits ip/udp.
func TestBuildNodeFromDBRestoresV4EndpointWhenENRHasNone(t *testing.T) {
	database := persistTestDB(t, filepath.Join(t.TempDir(), "v4-endpoint.db"))
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ndb := NewNodeDB(ctx, database, db.LayerEL, quietTableLogger())

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rec := enr.New()
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	enrBytes, err := rec.EncodeRLPBytes()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	ip := net.IPv4(10, 12, 0, 1).To4()
	n, err := ndb.buildNodeFromDB(&db.Node{
		NodeID:    make([]byte, 32),
		ENR:       enrBytes,
		IP:        ip,
		Port:      9000,
		FirstSeen: time.Now().Unix(),
		HasV4:     true,
	})
	if err != nil {
		t.Fatalf("buildNodeFromDB: %v", err)
	}
	if got := n.Addr(); !got.IP.Equal(ip) || got.Port != 9000 {
		t.Fatalf("addr = %v, want %v:9000 from the stored columns", got, ip)
	}
	if !n.HasV4() {
		t.Error("v4 pointer was not restored")
	}
}
