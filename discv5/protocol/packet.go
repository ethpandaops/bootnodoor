package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/ethpandaops/bootnodoor/discv5/crypto"
	"github.com/ethpandaops/bootnodoor/discv5/node"
)

// Packet types for discv5 protocol (matches go-ethereum v5wire flags)
const (
	// OrdinaryPacket is an encrypted message with an established session
	OrdinaryPacket byte = 0x00

	// WHOAREYOUPacket is a challenge sent when no session exists
	WHOAREYOUPacket byte = 0x01

	// HandshakePacket is sent in response to WHOAREYOU to establish a session
	HandshakePacket byte = 0x02
)

const (
	// ProtocolID is the protocol identifier for discv5
	// Format: "discv5" as bytes
	ProtocolID = "discv5"

	// MinPacketSize is the minimum size of a valid packet
	MinPacketSize = 63

	// MaxPacketSize is the maximum size of a UDP packet
	// This is 1280 bytes - the minimum IPv6 MTU to ensure packets aren't fragmented
	MaxPacketSize = 1280

	// HeaderSize is the size of the packet header
	HeaderSize = 32
)

// Packet represents a discv5 protocol packet.
//
// All communication in discv5 happens through packets sent over UDP.
// There are three packet types:
//   - Ordinary: Regular encrypted message (most common)
//   - WHOAREYOU: Challenge for session establishment
//   - Handshake: Response to WHOAREYOU challenge
type Packet struct {
	// PacketType is the type of packet (Ordinary, WHOAREYOU, or Handshake)
	PacketType byte

	// Header contains packet metadata (nonce, auth data, etc.)
	Header *PacketHeader

	// HeaderData is the raw packet data from start to end of authdata (IV + masked header + masked authdata)
	// This is used as additional data (AD) for AES-GCM encryption/decryption
	HeaderData []byte

	// SrcID is the source node ID (extracted from authdata for ordinary/random packets)
	SrcID []byte

	// Message is the encrypted message payload (for Ordinary packets)
	Message []byte

	// Challenge is the challenge data (for WHOAREYOU packets)
	Challenge *WHOAREYOUChallenge

	// Handshake is the handshake data (for Handshake packets)
	Handshake *HandshakeData
}

// PacketHeader contains metadata for all packet types.
//
// Format:
//   - ProtocolID: 6 bytes - "discv5"
//   - Version: 2 bytes - protocol version (currently 0x0001)
//   - Flag: 1 byte - packet type (Ordinary, WHOAREYOU, Handshake)
//   - Nonce: 12 bytes - random nonce for encryption
//   - AuthDataSize: 2 bytes - size of authentication data
type PacketHeader struct {
	// ProtocolID should always be "discv5"
	ProtocolID []byte

	// Version is the protocol version (currently 0x0001)
	Version uint16

	// Flag indicates the packet type
	Flag byte

	// Nonce is used for encryption (12 bytes)
	Nonce []byte

	// AuthDataSize is the size of the authentication data in bytes
	AuthDataSize uint16
}

// WHOAREYOUChallenge is sent when a node receives a packet from an unknown source.
//
// It challenges the sender to prove their identity before establishing a session.
//
// Format:
//   - IDNonce: Random challenge nonce (16 bytes)
//   - ENRSeq: Highest ENR sequence number we have for this node
type WHOAREYOUChallenge struct {
	// IDNonce is a random challenge value (16 bytes)
	IDNonce []byte

	// ENRSeq is the highest ENR sequence number we have
	// The peer should send their ENR if their sequence is higher
	ENRSeq uint64
}

// HandshakeData is sent in response to a WHOAREYOU challenge.
//
// It proves the sender's identity and optionally provides an updated ENR.
//
// Format:
//   - SourceNodeID: Sender's node ID (32 bytes)
//   - Signature: Signature proving ownership of node ID
//   - EphemeralPubKey: Ephemeral public key for ECDH
//   - ENR: Optional updated ENR record (if sequence number changed)
type HandshakeData struct {
	// SourceNodeID is the sender's node ID (32 bytes)
	SourceNodeID []byte

	// Signature proves ownership of the node ID
	Signature []byte

	// EphemeralPubKey is the ephemeral public key for session establishment
	EphemeralPubKey []byte

	// ENR is the sender's ENR record (optional, only if seq changed)
	ENR []byte
}

// NewPacketHeader creates a new packet header with default values.
//
// The header is initialized with:
//   - ProtocolID: "discv5"
//   - Version: 0x0001
//   - Flag: Set to provided packet type
//   - Nonce: Random 12-byte nonce
//   - AuthDataSize: 0 (set later based on auth data)
func NewPacketHeader(packetType byte) (*PacketHeader, error) {
	nonce, err := crypto.GenerateRandomBytes(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return &PacketHeader{
		ProtocolID:   []byte(ProtocolID),
		Version:      0x0001,
		Flag:         packetType,
		Nonce:        nonce,
		AuthDataSize: 0,
	}, nil
}

// Encode encodes the packet header to bytes.
//
// Format (total 32 bytes):
//   - ProtocolID: 6 bytes
//   - Version: 2 bytes (big-endian)
//   - Flag: 1 byte
//   - Nonce: 12 bytes
//   - AuthDataSize: 2 bytes (big-endian)
func (h *PacketHeader) Encode() ([]byte, error) {
	if len(h.ProtocolID) != 6 {
		return nil, fmt.Errorf("invalid protocol ID length: %d", len(h.ProtocolID))
	}

	if len(h.Nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length: %d", len(h.Nonce))
	}

	header := make([]byte, 32)

	// Protocol ID (6 bytes)
	copy(header[0:6], h.ProtocolID)

	// Version (2 bytes, big-endian)
	header[6] = byte(h.Version >> 8)
	header[7] = byte(h.Version & 0xFF)

	// Flag (1 byte)
	header[8] = h.Flag

	// Nonce (12 bytes)
	copy(header[9:21], h.Nonce)

	// AuthDataSize (2 bytes, big-endian)
	header[21] = byte(h.AuthDataSize >> 8)
	header[22] = byte(h.AuthDataSize & 0xFF)

	// Remaining bytes (23-31) are reserved and set to zero

	return header, nil
}

// DecodePacketHeader decodes a packet header from bytes.
//
// The input must be at least 32 bytes (the header size).
func DecodePacketHeader(data []byte) (*PacketHeader, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	header := &PacketHeader{
		ProtocolID: make([]byte, 6),
		Nonce:      make([]byte, 12),
	}

	// Protocol ID (6 bytes)
	copy(header.ProtocolID, data[0:6])

	// Verify protocol ID
	if string(header.ProtocolID) != ProtocolID {
		return nil, fmt.Errorf("invalid protocol ID: %s", header.ProtocolID)
	}

	// Version (2 bytes, big-endian)
	header.Version = uint16(data[6])<<8 | uint16(data[7])

	// Flag (1 byte)
	header.Flag = data[8]

	// Nonce (12 bytes)
	copy(header.Nonce, data[9:21])

	// AuthDataSize (2 bytes, big-endian)
	header.AuthDataSize = uint16(data[21])<<8 | uint16(data[22])

	return header, nil
}

// EncodePacket encodes a complete packet to bytes.
//
// Format:
//   - Header (32 bytes)
//   - Auth data (variable, size specified in header)
//   - Message data (remaining bytes)
func EncodePacket(packet *Packet) ([]byte, error) {
	// Encode header
	headerBytes, err := packet.Header.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode header: %w", err)
	}

	// Build packet based on type
	result := headerBytes

	switch packet.PacketType {
	case OrdinaryPacket:
		// Ordinary packet: header + encrypted message
		result = append(result, packet.Message...)

	case WHOAREYOUPacket:
		// WHOAREYOU packet: header + challenge data
		if packet.Challenge == nil {
			return nil, fmt.Errorf("WHOAREYOU packet missing challenge data")
		}
		challengeBytes := encodeChallenge(packet.Challenge)
		result = append(result, challengeBytes...)

	case HandshakePacket:
		// Handshake packet: header + handshake data + encrypted message
		if packet.Handshake == nil {
			return nil, fmt.Errorf("handshake packet missing handshake data")
		}
		handshakeBytes := encodeHandshake(packet.Handshake)
		result = append(result, handshakeBytes...)
		result = append(result, packet.Message...)

	default:
		return nil, fmt.Errorf("unknown packet type: %d", packet.PacketType)
	}

	// Verify packet size
	if len(result) > MaxPacketSize {
		return nil, fmt.Errorf("packet too large: %d bytes (max %d)", len(result), MaxPacketSize)
	}

	return result, nil
}

// encodeChallenge encodes a WHOAREYOU challenge to bytes.
func encodeChallenge(challenge *WHOAREYOUChallenge) []byte {
	// IDNonce (32 bytes) + ENRSeq (8 bytes)
	result := make([]byte, 40)
	copy(result[0:32], challenge.IDNonce)

	// ENR sequence (8 bytes, big-endian)
	for i := 0; i < 8; i++ {
		result[32+i] = byte(challenge.ENRSeq >> (56 - uint(i)*8))
	}

	return result
}

// encodeHandshake encodes handshake data to bytes.
func encodeHandshake(handshake *HandshakeData) []byte {
	// SourceNodeID (32 bytes) + Signature (65 bytes) + EphemeralPubKey (33 bytes) + ENR (variable)
	result := make([]byte, 0, 130+len(handshake.ENR))

	result = append(result, handshake.SourceNodeID...)
	result = append(result, handshake.Signature...)
	result = append(result, handshake.EphemeralPubKey...)
	result = append(result, handshake.ENR...)

	return result
}

// DecodePacket decodes a packet from bytes according to go-ethereum discv5 format.
//
// Packet format:
//
//	masking-iv (16) || masked-header (23) || masked-authdata || message-data
//
// The header and authdata are masked using AES-CTR with:
//
//	masking-key = localNodeID[:16]
//	stream = AES-CTR(masking-key, masking-iv)
//
// This performs initial unmasking and parsing of the packet structure.
// The message payload is not decrypted at this stage.
func DecodePacket(data []byte, localNodeID node.ID) (*Packet, error) {
	// Minimum packet size: 16 (IV) + 23 (header) + 24 (min authdata for WHOAREYOU) = 63
	if len(data) < MinPacketSize {
		return nil, fmt.Errorf("packet too short: %d bytes (min %d)", len(data), MinPacketSize)
	}

	// Extract masking IV (first 16 bytes)
	maskingIV := data[0:16]

	// Create AES cipher with local node ID as key (first 16 bytes)
	maskingKey := localNodeID[:16]
	block, err := aes.NewCipher(maskingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create CTR stream cipher
	stream := cipher.NewCTR(block, maskingIV)

	// Unmask header (23 bytes starting at offset 16)
	if len(data) < 16+23 {
		return nil, fmt.Errorf("packet too short for header: %d bytes", len(data))
	}

	maskedHeader := data[16:39]
	staticHeader := make([]byte, 23)
	stream.XORKeyStream(staticHeader, maskedHeader)

	// Decode static header
	// Format: protocol-id(6) || version(2) || flag(1) || nonce(12) || authsize(2)
	if string(staticHeader[0:6]) != ProtocolID {
		return nil, fmt.Errorf("invalid protocol ID: %s", string(staticHeader[0:6]))
	}

	version := binary.BigEndian.Uint16(staticHeader[6:8])
	flag := staticHeader[8]
	nonce := make([]byte, 12)
	copy(nonce, staticHeader[9:21])
	authsize := binary.BigEndian.Uint16(staticHeader[21:23])

	// Create packet header
	header := &PacketHeader{
		ProtocolID:   []byte(ProtocolID),
		Version:      version,
		Flag:         flag,
		Nonce:        nonce,
		AuthDataSize: authsize,
	}

	// Verify we have enough data for authdata
	authDataStart := 39 // 16 (IV) + 23 (header)
	authDataEnd := authDataStart + int(authsize)
	if len(data) < authDataEnd {
		return nil, fmt.Errorf("packet too short for authdata: need %d bytes, have %d", authDataEnd, len(data))
	}

	// Unmask authdata (continue with same cipher stream)
	maskedAuthdata := data[authDataStart:authDataEnd]
	authdata := make([]byte, authsize)
	stream.XORKeyStream(authdata, maskedAuthdata)

	// Build header data with UNMASKED header and authdata (for GCM/signatures)
	// Format: IV (16) + unmasked-header (23) + unmasked-authdata (variable)
	headerData := make([]byte, 0, authDataEnd)
	headerData = append(headerData, data[0:16]...)   // IV
	headerData = append(headerData, staticHeader...) // unmasked header
	headerData = append(headerData, authdata...)     // unmasked authdata

	packet := &Packet{
		PacketType: flag,
		Header:     header,
		HeaderData: headerData,
	}

	// Parse packet based on type
	switch flag {
	case OrdinaryPacket: // flag = 0x00 for ordinary/random packets
		// For ordinary/random packets: authdata = srcID (32 bytes)
		if authsize == 32 {
			// This is a random packet or ordinary packet with srcID
			packet.SrcID = make([]byte, 32)
			copy(packet.SrcID, authdata)
		}
		// Message data is everything after authdata
		packet.Message = data[authDataEnd:]

	case WHOAREYOUPacket: // flag = 0x01 for WHOAREYOU
		// WHOAREYOU packet: authdata = id-nonce(16) || enr-seq(8) = 24 bytes
		if authsize != 24 {
			return nil, fmt.Errorf("invalid WHOAREYOU authsize: %d (expected 24)", authsize)
		}
		packet.Challenge = &WHOAREYOUChallenge{
			IDNonce: make([]byte, 16), // ID nonce is 16 bytes
			ENRSeq:  binary.BigEndian.Uint64(authdata[16:24]),
		}
		copy(packet.Challenge.IDNonce, authdata[0:16])
		// WHOAREYOU has no message data

	case HandshakePacket: // flag = 0x02 for handshake
		// Handshake packet authdata format:
		// src-id (32) || sig-size (1) || eph-key-size (1) || signature (sig-size) || eph-pubkey (eph-key-size) || enr (optional)

		if authsize < 34 { // Minimum: 32 + 1 + 1
			return nil, fmt.Errorf("invalid handshake authsize: %d (minimum 34)", authsize)
		}

		// Extract source node ID (32 bytes)
		sourceID := make([]byte, 32)
		copy(sourceID, authdata[0:32])

		// Extract sizes
		sigSize := int(authdata[32])
		ephKeySize := int(authdata[33])

		// Verify we have enough data
		minSize := 34 + sigSize + ephKeySize
		if int(authsize) < minSize {
			return nil, fmt.Errorf("invalid handshake authsize: %d (expected at least %d)", authsize, minSize)
		}

		// Extract signature
		signature := make([]byte, sigSize)
		copy(signature, authdata[34:34+sigSize])

		// Extract ephemeral public key
		ephPubkey := make([]byte, ephKeySize)
		copy(ephPubkey, authdata[34+sigSize:34+sigSize+ephKeySize])

		// Extract optional ENR (if any remaining bytes)
		var enrBytes []byte
		if int(authsize) > minSize {
			enrBytes = make([]byte, int(authsize)-minSize)
			copy(enrBytes, authdata[minSize:])
		}

		// Store handshake data
		packet.Handshake = &HandshakeData{
			SourceNodeID:    sourceID,
			Signature:       signature,
			EphemeralPubKey: ephPubkey,
			ENR:             enrBytes,
		}

		// Message data is everything after authdata
		packet.Message = data[authDataEnd:]

	default:
		return nil, fmt.Errorf("unknown packet type: %d", flag)
	}

	return packet, nil
}
