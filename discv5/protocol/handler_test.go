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
