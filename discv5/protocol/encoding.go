package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/pk910/bootoor/discv5/crypto"
	"github.com/pk910/bootoor/discv5/node"
)

// EncodeRandomPacket encodes a random packet to trigger WHOAREYOU (go-ethereum style).
//
// Random packet format (no session):
//
//	packet = masking-iv (16) || masked-header (23) || masked-authdata (32) || random-message (20)
//	masking-key = dest-node-id[:16]
//	mask = AES-CTR(masking-key, masking-iv)
//
// The authdata for random packets contains: srcID (32 bytes)
// The message is 20 bytes of random data
func EncodeRandomPacket(localNodeID, destNodeID node.ID) ([]byte, error) {
	// Generate random masking IV (16 bytes)
	maskingIV, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate masking IV: %w", err)
	}

	// Generate random nonce (12 bytes)
	nonce, err := crypto.GenerateRandomBytes(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Build static header (23 bytes)
	// protocol-id (6) || version (2) || flag (1) || nonce (12) || authsize (2)
	staticHeader := make([]byte, 23)
	copy(staticHeader[0:6], []byte("discv5"))
	binary.BigEndian.PutUint16(staticHeader[6:8], 1) // version
	staticHeader[8] = OrdinaryPacket                 // flag = ordinary message (0x00)
	copy(staticHeader[9:21], nonce)
	binary.BigEndian.PutUint16(staticHeader[21:23], 32) // authsize = 32 bytes (srcID)

	// Build authdata (32 bytes)
	// For random packets: just the source node ID
	authdata := localNodeID[:]

	// Generate random message (20 bytes)
	randomMessage, err := crypto.GenerateRandomBytes(20)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random message: %w", err)
	}

	// Create AES cipher with dest node ID as key
	maskingKey := destNodeID[:16]
	block, err := aes.NewCipher(maskingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create CTR stream cipher
	stream := cipher.NewCTR(block, maskingIV)

	// Mask static header
	maskedHeader := make([]byte, 23)
	copy(maskedHeader, staticHeader)
	stream.XORKeyStream(maskedHeader, maskedHeader)

	// Mask authdata (continue with same cipher stream)
	maskedAuthdata := make([]byte, 32)
	copy(maskedAuthdata, authdata)
	stream.XORKeyStream(maskedAuthdata, maskedAuthdata)

	// Build final packet: IV || masked-header || masked-authdata || random-message
	packet := make([]byte, 0, 16+23+32+20)
	packet = append(packet, maskingIV...)
	packet = append(packet, maskedHeader...)
	packet = append(packet, maskedAuthdata...)
	packet = append(packet, randomMessage...)

	return packet, nil
}

// BuildOrdinaryHeaderData builds unmasked header data for GCM encryption of ordinary packets.
//
// Returns IV || unmasked-header || unmasked-authdata
// This is used as additional authenticated data for AES-GCM.
func BuildOrdinaryHeaderData(localNodeID node.ID, nonce, authdata []byte) ([]byte, []byte, error) {
	// Generate random masking IV (16 bytes)
	maskingIV, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate masking IV: %w", err)
	}

	// Build static header (23 bytes) - UNMASKED
	staticHeader := make([]byte, 23)
	copy(staticHeader[0:6], []byte("discv5"))
	binary.BigEndian.PutUint16(staticHeader[6:8], 1) // version
	staticHeader[8] = OrdinaryPacket                 // flag = ordinary message (0x00)
	copy(staticHeader[9:21], nonce)
	binary.BigEndian.PutUint16(staticHeader[21:23], uint16(len(authdata)))

	// Build unmasked header data: IV || unmasked-header || unmasked-authdata
	headerData := make([]byte, 0, 16+23+len(authdata))
	headerData = append(headerData, maskingIV...)
	headerData = append(headerData, staticHeader...)
	headerData = append(headerData, authdata...)

	return maskingIV, headerData, nil
}

// EncodeOrdinaryPacket encodes an ordinary packet with an established session.
//
// Packet format (with session):
//
//	packet = masking-iv (16) || masked-header (23) || masked-authdata (32) || message-ciphertext
//	authdata = srcID (32 bytes)
func EncodeOrdinaryPacket(localNodeID, destNodeID node.ID, maskingIV, nonce []byte, authdata []byte, message []byte) ([]byte, error) {
	if len(maskingIV) != 16 {
		return nil, fmt.Errorf("invalid masking IV length: %d (expected 16)", len(maskingIV))
	}

	// Build static header (23 bytes)
	staticHeader := make([]byte, 23)
	copy(staticHeader[0:6], []byte("discv5"))
	binary.BigEndian.PutUint16(staticHeader[6:8], 1) // version
	staticHeader[8] = OrdinaryPacket                 // flag = ordinary message (0x00)
	copy(staticHeader[9:21], nonce)
	binary.BigEndian.PutUint16(staticHeader[21:23], uint16(len(authdata)))

	// Create AES cipher with dest node ID as key
	maskingKey := destNodeID[:16]
	block, err := aes.NewCipher(maskingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create CTR stream cipher
	stream := cipher.NewCTR(block, maskingIV)

	// Mask static header
	maskedHeader := make([]byte, 23)
	copy(maskedHeader, staticHeader)
	stream.XORKeyStream(maskedHeader, maskedHeader)

	// Mask authdata
	maskedAuthdata := make([]byte, len(authdata))
	copy(maskedAuthdata, authdata)
	stream.XORKeyStream(maskedAuthdata, maskedAuthdata)

	// Build final packet
	packet := make([]byte, 0, 16+23+len(authdata)+len(message))
	packet = append(packet, maskingIV...)
	packet = append(packet, maskedHeader...)
	packet = append(packet, maskedAuthdata...)
	packet = append(packet, message...)

	return packet, nil
}

// EncodeHandshakePacket encodes a handshake message packet.
//
// Handshake packet format:
//
//	packet = masking-iv (16) || masked-header (23) || masked-authdata || message-ciphertext
//	authdata = src-id (32) || sig-size (1) || eph-key-size (1) || id-signature || eph-pubkey || record
//
// The minimal authdata is 34 bytes (src-id + sig-size + eph-key-size).
// Plus variable-length signature (~64 bytes), ephemeral pubkey (33 bytes), and optional ENR.
func EncodeHandshakePacket(localNodeID, destNodeID node.ID, maskingIV, nonce []byte, signature, ephPubkey, enrBytes, messageCiphertext []byte) ([]byte, error) {
	if len(maskingIV) != 16 {
		return nil, fmt.Errorf("invalid masking IV length: %d (expected 16)", len(maskingIV))
	}

	// Build authdata: src-id || sig-size || eph-key-size || signature || eph-pubkey || enr
	authdata := make([]byte, 0, 34+len(signature)+len(ephPubkey)+len(enrBytes))
	authdata = append(authdata, localNodeID[:]...)    // 32 bytes
	authdata = append(authdata, byte(len(signature))) // 1 byte
	authdata = append(authdata, byte(len(ephPubkey))) // 1 byte
	authdata = append(authdata, signature...)         // variable
	authdata = append(authdata, ephPubkey...)         // variable
	authdata = append(authdata, enrBytes...)          // variable (optional)

	authsize := len(authdata)

	// Build static header (23 bytes)
	staticHeader := make([]byte, 23)
	copy(staticHeader[0:6], []byte("discv5"))
	binary.BigEndian.PutUint16(staticHeader[6:8], 1) // version
	staticHeader[8] = HandshakePacket                // flag = handshake (0x02)
	copy(staticHeader[9:21], nonce)
	binary.BigEndian.PutUint16(staticHeader[21:23], uint16(authsize))

	// Create AES cipher with dest node ID as key
	maskingKey := destNodeID[:16]
	block, err := aes.NewCipher(maskingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create CTR stream cipher
	stream := cipher.NewCTR(block, maskingIV)

	// Mask static header
	maskedHeader := make([]byte, 23)
	copy(maskedHeader, staticHeader)
	stream.XORKeyStream(maskedHeader, maskedHeader)

	// Mask authdata (continue with same cipher stream)
	maskedAuthdata := make([]byte, len(authdata))
	copy(maskedAuthdata, authdata)
	stream.XORKeyStream(maskedAuthdata, maskedAuthdata)

	// Build final packet: IV || masked-header || masked-authdata || message-ciphertext
	packet := make([]byte, 0, 16+23+len(authdata)+len(messageCiphertext))
	packet = append(packet, maskingIV...)
	packet = append(packet, maskedHeader...)
	packet = append(packet, maskedAuthdata...)
	packet = append(packet, messageCiphertext...)

	return packet, nil
}

// BuildHandshakeHeaderData builds unmasked header data for GCM encryption.
//
// Returns IV || unmasked-header || unmasked-authdata
// This is used as additional authenticated data for AES-GCM.
func BuildHandshakeHeaderData(localNodeID node.ID, nonce []byte, signature, ephPubkey, enrBytes []byte) ([]byte, []byte, error) {
	// Generate random masking IV (16 bytes)
	maskingIV, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate masking IV: %w", err)
	}

	// Build authdata: src-id || sig-size || eph-key-size || signature || eph-pubkey || enr
	authdata := make([]byte, 0, 34+len(signature)+len(ephPubkey)+len(enrBytes))
	authdata = append(authdata, localNodeID[:]...)    // 32 bytes
	authdata = append(authdata, byte(len(signature))) // 1 byte
	authdata = append(authdata, byte(len(ephPubkey))) // 1 byte
	authdata = append(authdata, signature...)         // variable
	authdata = append(authdata, ephPubkey...)         // variable
	authdata = append(authdata, enrBytes...)          // variable (optional)

	authsize := len(authdata)

	// Build static header (23 bytes) - UNMASKED
	staticHeader := make([]byte, 23)
	copy(staticHeader[0:6], []byte("discv5"))
	binary.BigEndian.PutUint16(staticHeader[6:8], 1) // version
	staticHeader[8] = HandshakePacket                // flag = handshake (0x02)
	copy(staticHeader[9:21], nonce)
	binary.BigEndian.PutUint16(staticHeader[21:23], uint16(authsize))

	// Build unmasked header data: IV || unmasked-header || unmasked-authdata
	headerData := make([]byte, 0, 16+23+len(authdata))
	headerData = append(headerData, maskingIV...)
	headerData = append(headerData, staticHeader...)
	headerData = append(headerData, authdata...)

	return maskingIV, headerData, nil
}

// EncodeWHOAREYOUPacket encodes a WHOAREYOU packet and returns both the packet and the masking IV.
//
// WHOAREYOU packet format:
//
//	whoareyou-packet = masking-iv (16) || masked-header (23) || masked-authdata (24)
//	authdata = id-nonce (16) || enr-seq (8)
//
// Returns: (packet bytes, masking IV, error)
func EncodeWHOAREYOUPacket(destNodeID node.ID, nonce []byte, challenge *WHOAREYOUChallenge) ([]byte, []byte, error) {
	// Generate random masking IV (16 bytes)
	maskingIV, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate masking IV: %w", err)
	}

	// Build static header (23 bytes)
	staticHeader := make([]byte, 23)
	copy(staticHeader[0:6], []byte("discv5"))
	binary.BigEndian.PutUint16(staticHeader[6:8], 1) // version
	staticHeader[8] = WHOAREYOUPacket                // flag = WHOAREYOU (0x01)
	copy(staticHeader[9:21], nonce)
	binary.BigEndian.PutUint16(staticHeader[21:23], 24) // authsize = 24 bytes

	// Build authdata (24 bytes)
	// id-nonce (16) || enr-seq (8)
	authdata := make([]byte, 24)
	copy(authdata[0:16], challenge.IDNonce[:16]) // Use first 16 bytes of IDNonce
	binary.BigEndian.PutUint64(authdata[16:24], challenge.ENRSeq)

	// Create AES cipher with dest node ID as key
	maskingKey := destNodeID[:16]
	block, err := aes.NewCipher(maskingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create CTR stream cipher
	stream := cipher.NewCTR(block, maskingIV)

	// Mask static header
	maskedHeader := make([]byte, 23)
	copy(maskedHeader, staticHeader)
	stream.XORKeyStream(maskedHeader, maskedHeader)

	// Mask authdata
	maskedAuthdata := make([]byte, 24)
	copy(maskedAuthdata, authdata)
	stream.XORKeyStream(maskedAuthdata, maskedAuthdata)

	// Build final packet: IV || masked-header || masked-authdata
	packet := make([]byte, 0, 16+23+24)
	packet = append(packet, maskingIV...)
	packet = append(packet, maskedHeader...)
	packet = append(packet, maskedAuthdata...)

	return packet, maskingIV, nil
}
