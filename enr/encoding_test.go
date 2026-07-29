package enr

import (
	"bytes"
	"crypto/ecdsa"
	"net"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	gethenr "github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

// enrResponse mirrors discv4's ENRRESPONSE layout: a Record nested in a struct
// alongside other fields, which is the shape that encoded as an empty list.
type enrResponse struct {
	ReplyTok []byte
	Record   *Record
}

func signedRecord(t *testing.T) (*Record, *ecdsa.PrivateKey) {
	t.Helper()

	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	record := New()
	record.Set("ip", net.IPv4(192, 168, 1, 1))
	record.Set("udp", uint16(9000))

	if err := record.Sign(privKey); err != nil {
		t.Fatalf("Failed to sign record: %v", err)
	}

	return record, privKey
}

// TestNestedRecordEncoding tests that a Record nested in a struct serializes as
// its own record encoding rather than an empty list.
func TestNestedRecordEncoding(t *testing.T) {
	record, _ := signedRecord(t)

	want, err := record.EncodeRLPBytes()
	if err != nil {
		t.Fatalf("Failed to encode record: %v", err)
	}

	encoded, err := rlp.EncodeToBytes(&enrResponse{ReplyTok: []byte{0xaa}, Record: record})
	if err != nil {
		t.Fatalf("Failed to encode response: %v", err)
	}

	if !bytes.Contains(encoded, want) {
		t.Fatalf("Nested record not present in encoding: got %x, want it to contain %x", encoded, want)
	}

	var decoded enrResponse
	if err := rlp.DecodeBytes(encoded, &decoded); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if decoded.Record.UDP() != record.UDP() {
		t.Errorf("UDP port mismatch: got %d, want %d", decoded.Record.UDP(), record.UDP())
	}

	if decoded.Record.Seq() != record.Seq() {
		t.Errorf("Sequence mismatch: got %d, want %d", decoded.Record.Seq(), record.Seq())
	}
}

// TestRecordSliceEncoding tests that records in a slice each carry their own
// encoding.
func TestRecordSliceEncoding(t *testing.T) {
	record, _ := signedRecord(t)

	want, err := record.EncodeRLPBytes()
	if err != nil {
		t.Fatalf("Failed to encode record: %v", err)
	}

	encoded, err := rlp.EncodeToBytes([]*Record{record})
	if err != nil {
		t.Fatalf("Failed to encode slice: %v", err)
	}

	if !bytes.Contains(encoded, want) {
		t.Fatalf("Record not present in slice encoding: got %x, want it to contain %x", encoded, want)
	}
}

// TestNestedRecordDecodesInGoEthereum tests that a nested record survives
// go-ethereum's decoder, which rejected our ENRRESPONSE with "record contains
// less than two list elements".
func TestNestedRecordDecodesInGoEthereum(t *testing.T) {
	record, privKey := signedRecord(t)

	encoded, err := rlp.EncodeToBytes(&enrResponse{ReplyTok: []byte{0xaa}, Record: record})
	if err != nil {
		t.Fatalf("Failed to encode response: %v", err)
	}

	var decoded struct {
		ReplyTok []byte
		Record   gethenr.Record
	}
	if err := rlp.DecodeBytes(encoded, &decoded); err != nil {
		t.Fatalf("go-ethereum failed to decode response: %v", err)
	}

	n, err := enode.New(enode.ValidSchemes, &decoded.Record)
	if err != nil {
		t.Fatalf("go-ethereum failed to build node from record: %v", err)
	}

	if n.ID() != enode.PubkeyToIDV4(&privKey.PublicKey) {
		t.Errorf("Node ID mismatch: got %v, want %v", n.ID(), enode.PubkeyToIDV4(&privKey.PublicKey))
	}

	if n.UDP() != int(record.UDP()) {
		t.Errorf("UDP port mismatch: got %d, want %d", n.UDP(), record.UDP())
	}
}

// TestDecodeRejectsOversizedRecord tests that the 300-byte limit is enforced on
// ingest, not just on encode.
func TestDecodeRejectsOversizedRecord(t *testing.T) {
	oversized, err := rlp.EncodeToBytes([]interface{}{
		make([]byte, 64),
		uint64(1),
		"padding",
		make([]byte, MaxRecordSize),
	})
	if err != nil {
		t.Fatalf("Failed to build oversized payload: %v", err)
	}

	if len(oversized) <= MaxRecordSize {
		t.Fatalf("Payload is %d bytes, expected more than %d", len(oversized), MaxRecordSize)
	}

	if err := New().DecodeRLPBytes(oversized); err != ErrRecordTooLarge {
		t.Errorf("DecodeRLPBytes error = %v, want %v", err, ErrRecordTooLarge)
	}

	if _, err := Load(oversized); err != ErrRecordTooLarge {
		t.Errorf("Load error = %v, want %v", err, ErrRecordTooLarge)
	}
}

// TestDecodeAcceptsRecordAtSizeLimit tests that the size check does not reject
// compliant records.
func TestDecodeAcceptsRecordAtSizeLimit(t *testing.T) {
	record, _ := signedRecord(t)

	encoded, err := record.EncodeRLPBytes()
	if err != nil {
		t.Fatalf("Failed to encode record: %v", err)
	}

	if len(encoded) > MaxRecordSize {
		t.Fatalf("Record is %d bytes, expected at most %d", len(encoded), MaxRecordSize)
	}

	if err := New().DecodeRLPBytes(encoded); err != nil {
		t.Errorf("DecodeRLPBytes error = %v, want nil", err)
	}
}
