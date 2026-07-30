package protocol

import (
	"crypto/ecdsa"
	"net"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/sirupsen/logrus"
)

// TestResolveHandshakeSender covers the optional-record rule from discv5 v5.1:
// a peer may answer our WHOAREYOU without repeating its ENR, and rejecting that
// would break bonding with exactly the peers whose records we already hold.
func TestResolveHandshakeSender(t *testing.T) {
	key := generateKey(t)
	record := signedRecord(t, key, 4, nil)
	known, err := node.New(record)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	encoded, err := record.EncodeRLPBytes()
	if err != nil {
		t.Fatalf("encode record: %v", err)
	}

	otherKey := generateKey(t)
	otherNode, err := node.New(signedRecord(t, otherKey, 1, nil))
	if err != nil {
		t.Fatalf("create other node: %v", err)
	}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tests := []struct {
		name      string
		enrBytes  []byte
		challenge *PendingChallenge
		source    node.ID
		wantErr   bool
	}{
		{
			name:     "record in handshake is used",
			enrBytes: encoded,
			source:   known.ID(),
		},
		{
			name:      "record omitted falls back to the challenge",
			challenge: &PendingChallenge{KnownNode: known},
			source:    known.ID(),
		},
		{
			name:      "record omitted with nothing to fall back to",
			challenge: &PendingChallenge{},
			source:    known.ID(),
			wantErr:   true,
		},
		{
			name:     "record belongs to a different node than claimed",
			enrBytes: encoded,
			source:   otherNode.ID(),
			wantErr:  true,
		},
		{
			name:      "fallback belongs to a different node than claimed",
			challenge: &PendingChallenge{KnownNode: known},
			source:    otherNode.ID(),
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, pubKey, err := resolveHandshakeSender(tc.enrBytes, tc.challenge, tc.source, logger)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got a resolved sender")
				}
				return
			}

			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got == nil {
				t.Fatal("resolved a key but no node; the session would have nothing to refresh")
			}
			if node.PubkeyToID(pubKey) != tc.source {
				t.Fatal("resolved key does not derive the claimed source ID")
			}
		})
	}
}

func TestApplyENRUpdateInstallsNewestMatchingRecord(t *testing.T) {
	key := generateKey(t)
	currentRecord := signedRecord(t, key, 1, nil)
	remoteNode, err := node.New(currentRecord)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	staleRecord := signedRecord(t, key, 1, nil)
	newRecord := signedRecord(t, key, 2, map[string]interface{}{
		"eth": []struct {
			Hash []byte
			Next uint64
		}{{Hash: []byte{0xde, 0xad, 0xbe, 0xef}}},
	})
	newestRecord := signedRecord(t, key, 3, map[string]interface{}{
		"eth": []struct {
			Hash []byte
			Next uint64
		}{{Hash: []byte{0xca, 0xfe, 0xba, 0xbe}}},
	})

	callbackCount := 0
	handler := testHandler(func(updated *node.Node) {
		callbackCount++
		if updated != remoteNode {
			t.Error("callback received a different node")
		}
	})

	if !handler.applyENRUpdate(remoteNode, []*enr.Record{staleRecord, newestRecord, newRecord}) {
		t.Fatal("expected ENR to be updated")
	}
	if got := remoteNode.Record().Seq(); got != 3 {
		t.Fatalf("record sequence = %d, want 3", got)
	}
	eth, ok := remoteNode.Record().Eth()
	if !ok {
		t.Fatal("updated record is missing eth fork ID")
	}
	if got, want := eth[0].ForkID, [4]byte{0xca, 0xfe, 0xba, 0xbe}; got != want {
		t.Fatalf("fork hash = %x, want %x", got, want)
	}
	if callbackCount != 1 {
		t.Fatalf("callback count = %d, want 1", callbackCount)
	}
}

func TestApplyENRUpdateRejectsDifferentNode(t *testing.T) {
	remoteNode, err := node.New(signedRecord(t, generateKey(t), 1, nil))
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	differentRecord := signedRecord(t, generateKey(t), 99, nil)

	callbackCount := 0
	handler := testHandler(func(*node.Node) { callbackCount++ })
	if handler.applyENRUpdate(remoteNode, []*enr.Record{differentRecord}) {
		t.Fatal("different node's ENR was accepted")
	}
	if got := remoteNode.Record().Seq(); got != 1 {
		t.Fatalf("record sequence = %d, want 1", got)
	}
	if callbackCount != 0 {
		t.Fatalf("callback count = %d, want 0", callbackCount)
	}
}

func TestApplyENRUpdateRejectsStaleRecord(t *testing.T) {
	key := generateKey(t)
	remoteNode, err := node.New(signedRecord(t, key, 2, nil))
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	callbackCount := 0
	handler := testHandler(func(*node.Node) { callbackCount++ })
	if handler.applyENRUpdate(remoteNode, []*enr.Record{signedRecord(t, key, 1, nil)}) {
		t.Fatal("stale ENR was accepted")
	}
	if got := remoteNode.Record().Seq(); got != 2 {
		t.Fatalf("record sequence = %d, want 2", got)
	}
	if callbackCount != 0 {
		t.Fatalf("callback count = %d, want 0", callbackCount)
	}
}

func testHandler(onNodeUpdate OnNodeUpdateCallback) *Handler {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	return &Handler{config: HandlerConfig{
		Logger:       logger,
		OnNodeUpdate: onNodeUpdate,
	}}
}

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func signedRecord(t *testing.T, key *ecdsa.PrivateKey, seq uint64, fields map[string]interface{}) *enr.Record {
	t.Helper()
	record := enr.New()
	if err := record.Set("ip", net.IPv4(203, 0, 113, 1)); err != nil {
		t.Fatalf("set ip: %v", err)
	}
	if err := record.Set("udp", uint16(30303)); err != nil {
		t.Fatalf("set udp: %v", err)
	}
	for name, value := range fields {
		if err := record.Set(name, value); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}
	record.SetSeq(seq)
	if err := record.Sign(key); err != nil {
		t.Fatalf("sign record: %v", err)
	}
	return record
}
