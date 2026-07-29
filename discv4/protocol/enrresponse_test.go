package protocol

import (
	"bytes"
	"net"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover/v4wire"
	gethenode "github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethpandaops/bootnodoor/enr"
)

// TestENRResponseEncodesRecord verifies that a discv4 ENRRESPONSE serializes the
// embedded ENR record correctly (regression for the empty-record bug where
// enr.Record was encoded as c0 because it does not satisfy rlp.Encoder).
func TestENRResponseEncodesRecord(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	rec := enr.New()
	_ = rec.Set("id", "v4")
	_ = rec.Set("ip", net.IPv4(127, 0, 0, 1).To4())
	_ = rec.Set("udp", uint16(30303))
	if err := rec.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := &ENRResponse{ReplyTok: []byte{1, 2, 3}, Record: rec}

	packet, _, err := Encode(key, resp)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Decode as geth would: parse packet, then decode the ENR via geth's enode.
	decoded, err := DecodePacket(packet)
	if err != nil {
		t.Fatalf("self-decode: %v", err)
	}
	got, ok := decoded.(*ENRResponse)
	if !ok {
		t.Fatalf("wrong type: %T", decoded)
	}

	// The embedded record must match the original record's canonical encoding.
	want, _ := rec.EncodeRLP()
	gotRLP, _ := got.Record.EncodeRLP()
	if !bytes.Equal(want, gotRLP) {
		t.Fatalf("record mismatch:\n got %x\nwant %x", gotRLP, want)
	}

	// And geth's own v4wire decoder must accept it (this is what fails on the wire:
	// "record contains less than two list elements").
	sigdata := packet[headSize:] // type || rlp
	var gethResp v4wire.ENRResponse
	if err := rlp.DecodeBytes(sigdata[1:], &gethResp); err != nil {
		t.Fatalf("geth v4wire decode rejected the response: %v", err)
	}
	gethNode, err := gethenode.New(gethenode.ValidSchemes, &gethResp.Record)
	if err != nil {
		t.Fatalf("geth could not build node from record: %v", err)
	}
	if gethNode.Seq() != rec.Seq() {
		t.Fatalf("geth decoded seq %d, want %d", gethNode.Seq(), rec.Seq())
	}
	if !gethNode.IP().Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("geth decoded ip %s, want 127.0.0.1", gethNode.IP())
	}
}
