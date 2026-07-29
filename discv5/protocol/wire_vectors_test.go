package protocol

// Official discv5 wire test vectors from
// https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
//
// These tests verify bootnodoor's wire-level decoding and handshake crypto against
// the specification test vectors.

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/discv5/session"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.ReplaceAll(strings.TrimPrefix(s, "0x"), "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func nodeID(t *testing.T, s string) node.ID {
	t.Helper()
	var id node.ID
	copy(id[:], mustHex(t, s))
	return id
}

func privKey(t *testing.T, s string) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ethcrypto.ToECDSA(mustHex(t, s))
	if err != nil {
		t.Fatalf("bad key: %v", err)
	}
	return k
}

const (
	srcNodeIDHex  = "0xaaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
	destNodeIDHex = "0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"
	nodeAKeyHex   = "0xeef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"
	nodeBKeyHex   = "0x66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
)

// --- Packet decoding vectors ---

func TestVectorPingMessagePacket(t *testing.T) {
	packetBytes := mustHex(t, `
00000000000000000000000000000000088b3d4342774649325f313964a39e55
ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3
4c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc`)

	destID := nodeID(t, destNodeIDHex)
	srcID := nodeID(t, srcNodeIDHex)

	p, err := DecodePacket(packetBytes, destID)
	if err != nil {
		t.Fatalf("DecodePacket failed: %v", err)
	}
	if p.PacketType != OrdinaryPacket {
		t.Fatalf("wrong packet type: %d", p.PacketType)
	}
	if !bytes.Equal(p.SrcID, srcID[:]) {
		t.Fatalf("wrong src id: %x", p.SrcID)
	}
	wantNonce := mustHex(t, "0xffffffffffffffffffffffff")
	if !bytes.Equal(p.Header.Nonce, wantNonce) {
		t.Fatalf("wrong nonce: %x", p.Header.Nonce)
	}

	// Decrypt with the vector read-key
	readKey := mustHex(t, "0x00000000000000000000000000000000")
	pt, err := session.DecryptMessage(readKey, p.Header.Nonce, p.HeaderData, p.Message)
	if err != nil {
		t.Fatalf("decrypt failed (GCM AAD construction mismatch?): %v", err)
	}
	// plaintext = message-type (0x01 ping) || rlp([req-id, enr-seq])
	if pt[0] != PingMsg {
		t.Fatalf("wrong message type: %x", pt[0])
	}
	// Verify the decoded RLP fields (req-id, enr-seq) rather than exact bytes.
	msg := &Ping{}
	if err := decodeRLP(pt[1:], msg); err != nil {
		t.Fatalf("rlp decode: %v", err)
	}
	if !bytes.Equal(msg.RequestID, mustHex(t, "0x00000001")) {
		t.Fatalf("wrong req-id: %x", msg.RequestID)
	}
	if msg.ENRSeq != 2 {
		t.Fatalf("wrong enr-seq: %d", msg.ENRSeq)
	}
}

func TestVectorWhoareyouPacket(t *testing.T) {
	packetBytes := mustHex(t, `
00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad
1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d`)

	destID := nodeID(t, destNodeIDHex)

	p, err := DecodePacket(packetBytes, destID)
	if err != nil {
		t.Fatalf("DecodePacket failed: %v", err)
	}
	if p.PacketType != WHOAREYOUPacket {
		t.Fatalf("wrong packet type: %d", p.PacketType)
	}
	if !bytes.Equal(p.Header.Nonce, mustHex(t, "0x0102030405060708090a0b0c")) {
		t.Fatalf("wrong request-nonce: %x", p.Header.Nonce)
	}
	if !bytes.Equal(p.Challenge.IDNonce, mustHex(t, "0x0102030405060708090a0b0c0d0e0f10")) {
		t.Fatalf("wrong id-nonce: %x", p.Challenge.IDNonce)
	}
	if p.Challenge.ENRSeq != 0 {
		t.Fatalf("wrong enr-seq: %d", p.Challenge.ENRSeq)
	}
	// The challenge-data (HeaderData) must match the spec value exactly —
	// this is the id-signature input and HKDF salt.
	wantChallengeData := mustHex(t, "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000")
	if !bytes.Equal(p.HeaderData, wantChallengeData) {
		t.Fatalf("challenge-data mismatch:\n got %x\nwant %x", p.HeaderData, wantChallengeData)
	}
}

func TestVectorWhoareyouChallengeDataBuilder(t *testing.T) {
	// BuildWHOAREYOUChallengeData must reproduce the same challenge-data the remote
	// peer extracts from the raw packet.
	maskingIV := mustHex(t, "0x00000000000000000000000000000000")
	nonce := mustHex(t, "0x0102030405060708090a0b0c")
	challenge := &WHOAREYOUChallenge{
		IDNonce: mustHex(t, "0x0102030405060708090a0b0c0d0e0f10"),
		ENRSeq:  0,
	}
	got := BuildWHOAREYOUChallengeData(maskingIV, nonce, challenge)
	want := mustHex(t, "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000")
	if !bytes.Equal(got, want) {
		t.Fatalf("challenge-data mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestVectorHandshakePacket(t *testing.T) {
	packetBytes := mustHex(t, `
00000000000000000000000000000000088b3d4342774649305f313964a39e55
ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3
4c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef
268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfb
a776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1
f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d83
9cf8`)

	destID := nodeID(t, destNodeIDHex)
	srcID := nodeID(t, srcNodeIDHex)

	p, err := DecodePacket(packetBytes, destID)
	if err != nil {
		t.Fatalf("DecodePacket failed: %v", err)
	}
	if p.PacketType != HandshakePacket {
		t.Fatalf("wrong packet type: %d", p.PacketType)
	}
	if !bytes.Equal(p.Handshake.SourceNodeID, srcID[:]) {
		t.Fatalf("wrong src id: %x", p.Handshake.SourceNodeID)
	}
	if len(p.Handshake.Signature) != 64 {
		t.Fatalf("wrong sig size: %d", len(p.Handshake.Signature))
	}
	wantEph := mustHex(t, "0x039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5")
	if !bytes.Equal(p.Handshake.EphemeralPubKey, wantEph) {
		t.Fatalf("wrong ephemeral pubkey: %x", p.Handshake.EphemeralPubKey)
	}
	if len(p.Handshake.ENR) != 0 {
		t.Fatalf("unexpected ENR in handshake: %x", p.Handshake.ENR)
	}

	// Verify the id-signature against node A's static key using the vector's
	// challenge-data (from the WHOAREYOU with enr-seq=1).
	challengeData := mustHex(t, "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000001")
	nodeAKey := privKey(t, nodeAKeyHex)
	if !verifyIDSignature(&nodeAKey.PublicKey, p.Handshake.Signature, challengeData, p.Handshake.EphemeralPubKey, destID) {
		t.Fatal("id-signature verification failed")
	}

	// Decrypt the message with the vector read-key.
	readKey := mustHex(t, "0x4f9fac6de7567d1e3b1241dffe90f662")
	pt, err := session.DecryptMessage(readKey, p.Header.Nonce, p.HeaderData, p.Message)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if pt[0] != PingMsg {
		t.Fatalf("wrong message type: %x", pt[0])
	}
}

func TestVectorHandshakePacketWithENR(t *testing.T) {
	packetBytes := mustHex(t, `
00000000000000000000000000000000088b3d4342774649305f313964a39e55
ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3
4c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be9856
2fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b2
1481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1
f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6
cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb1
2a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a
80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e
4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b1394
71`)

	destID := nodeID(t, destNodeIDHex)

	p, err := DecodePacket(packetBytes, destID)
	if err != nil {
		t.Fatalf("DecodePacket failed: %v", err)
	}
	if p.PacketType != HandshakePacket {
		t.Fatalf("wrong packet type: %d", p.PacketType)
	}
	if len(p.Handshake.ENR) == 0 {
		t.Fatal("expected ENR in handshake packet")
	}

	readKey := mustHex(t, "0x53b1c075f41876423154e157470c2f48")
	pt, err := session.DecryptMessage(readKey, p.Header.Nonce, p.HeaderData, p.Message)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if pt[0] != PingMsg {
		t.Fatalf("wrong message type: %x", pt[0])
	}
}

// --- Crypto primitive vectors ---

func TestVectorECDH(t *testing.T) {
	pub := mustHex(t, "0x039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231")
	secKey := privKey(t, "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")

	pubKey, err := ethcrypto.DecompressPubkey(pub)
	if err != nil {
		t.Fatalf("bad pubkey: %v", err)
	}

	shared := ecdh(secKey, pubKey)
	want := mustHex(t, "0x033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e")
	if !bytes.Equal(shared, want) {
		t.Fatalf("ECDH mismatch:\n got %x\nwant %x", shared, want)
	}
}

func TestVectorKeyDerivation(t *testing.T) {
	ephKey := privKey(t, "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")
	destPub := mustHex(t, "0x0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91")
	nodeIDA := nodeID(t, srcNodeIDHex)
	nodeIDB := nodeID(t, destNodeIDHex)
	challengeData := mustHex(t, "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000")

	destPubKey, err := ethcrypto.DecompressPubkey(destPub)
	if err != nil {
		t.Fatalf("bad pubkey: %v", err)
	}

	keys, err := deriveKeys(ephKey, destPubKey, nodeIDA, nodeIDB, challengeData)
	if err != nil {
		t.Fatalf("deriveKeys failed: %v", err)
	}

	wantInitiator := mustHex(t, "0xdccc82d81bd610f4f76d3ebe97a40571")
	wantRecipient := mustHex(t, "0xac74bb8773749920b0d3a8881c173ec5")
	if !bytes.Equal(keys.InitiatorKey, wantInitiator) {
		t.Fatalf("initiator-key mismatch:\n got %x\nwant %x", keys.InitiatorKey, wantInitiator)
	}
	if !bytes.Equal(keys.RecipientKey, wantRecipient) {
		t.Fatalf("recipient-key mismatch:\n got %x\nwant %x", keys.RecipientKey, wantRecipient)
	}
}

func TestVectorIDNonceSigning(t *testing.T) {
	staticKey := privKey(t, "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")
	challengeData := mustHex(t, "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000")
	ephPub := mustHex(t, "0x039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231")
	nodeIDB := nodeID(t, destNodeIDHex)

	sig, err := makeIDSignature(staticKey, challengeData, ephPub, nodeIDB)
	if err != nil {
		t.Fatalf("makeIDSignature failed: %v", err)
	}
	want := mustHex(t, "0x94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6")
	if !bytes.Equal(sig, want) {
		t.Fatalf("id-signature mismatch:\n got %x\nwant %x", sig, want)
	}

	// And verify direction
	if !verifyIDSignature(&staticKey.PublicKey, want, challengeData, ephPub, nodeIDB) {
		t.Fatal("verifyIDSignature rejected the spec vector signature")
	}
}

// decodeRLP is a tiny helper wrapping geth's rlp for the tests.
func decodeRLP(data []byte, val interface{}) error {
	return rlp.DecodeBytes(data, val)
}
