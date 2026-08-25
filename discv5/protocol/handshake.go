package protocol

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/discv5/session"
	"golang.org/x/crypto/hkdf"
)

// makeIDSignature creates the ID nonce signature for handshake.
//
// The signature proves that we own the node ID (private key) and is computed over:
//
//	"discovery v5 identity proof" || challenge-data || ephemeral-pubkey || dest-node-id
//
// This matches go-ethereum's makeIDSignature function.
func makeIDSignature(privKey *ecdsa.PrivateKey, challenge, ephPubkey []byte, destID node.ID) ([]byte, error) {
	// Create hash input: "discovery v5 identity proof" || challenge || ephkey || destID
	hash := sha256.New()
	hash.Write([]byte("discovery v5 identity proof"))
	hash.Write(challenge)
	hash.Write(ephPubkey)
	hash.Write(destID[:])

	sigHash := hash.Sum(nil)

	// Sign the hash
	sig, err := ethcrypto.Sign(sigHash, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign ID nonce: %w", err)
	}

	// Remove recovery ID (last byte) - discv5 doesn't use it
	return sig[:len(sig)-1], nil
}

// verifyIDSignature verifies the ID nonce signature in a handshake.
//
// Returns true if the signature is valid, false otherwise.
func verifyIDSignature(pubKey *ecdsa.PublicKey, signature, challenge, ephPubkey []byte, destID node.ID) bool {
	// Create hash input: "discovery v5 identity proof" || challenge || ephkey || destID
	hash := sha256.New()
	hash.Write([]byte("discovery v5 identity proof"))
	hash.Write(challenge)
	hash.Write(ephPubkey)
	hash.Write(destID[:])

	sigHash := hash.Sum(nil)

	// Add recovery ID (0) to signature for verification - go-ethereum expects 65 bytes
	sigWithRecovery := make([]byte, 65)
	copy(sigWithRecovery, signature)
	sigWithRecovery[64] = 0 // recovery ID

	// Verify signature
	return ethcrypto.VerifySignature(
		ethcrypto.FromECDSAPub(pubKey),
		sigHash,
		sigWithRecovery[:64], // Verify without recovery ID
	)
}

// ecdh performs ECDH key agreement and returns the shared secret in compressed form.
//
// This matches go-ethereum's ecdh function which returns a 33-byte compressed point.
func ecdh(privkey *ecdsa.PrivateKey, pubkey *ecdsa.PublicKey) []byte {
	// Perform scalar multiplication: shared = pubkey * privkey.D
	//lint:ignore SA1019 stdlib replacement does not support secp256k1
	secX, secY := pubkey.ScalarMult(pubkey.X, pubkey.Y, privkey.D.Bytes())
	if secX == nil {
		return nil
	}

	// Compress the point: 0x02 or 0x03 prefix + X coordinate (32 bytes)
	sec := make([]byte, 33)
	sec[0] = 0x02 | byte(secY.Bit(0))
	// Use ReadBits to match go-ethereum exactly
	// ReadBits encodes the absolute value of x as big-endian bytes
	secX.FillBytes(sec[1:33])

	return sec
}

// deriveKeys derives session keys using HKDF-SHA256.
//
// This implements the discv5 key derivation:
//
//	info = "discovery v5 key agreement" || initiator-id || recipient-id
//	kdf = HKDF-SHA256(secret, challenge, info)
//	write-key = kdf[0:16]
//	read-key = kdf[16:32]
//
// The keys are swapped depending on who initiated the handshake.
func deriveKeys(ephPrivKey *ecdsa.PrivateKey, remotePubKey *ecdsa.PublicKey,
	initiatorID, recipientID node.ID, challenge []byte) (*session.SessionKeys, error) {

	// Perform ECDH to get shared secret
	secret := ecdh(ephPrivKey, remotePubKey)
	if secret == nil {
		return nil, fmt.Errorf("ECDH failed")
	}

	// Build info: "discovery v5 key agreement" || initiator-id || recipient-id
	info := make([]byte, 0, 26+32+32) // text + 2 node IDs
	info = append(info, []byte("discovery v5 key agreement")...)
	info = append(info, initiatorID[:]...)
	info = append(info, recipientID[:]...)

	// Use HKDF to derive keys
	// Extract: HMAC-SHA256(salt=challenge, ikm=secret)
	// Expand: HMAC-SHA256(prk, info)
	kdf := hkdf.New(sha256.New, secret, challenge, info)

	// Read write-key (16 bytes) and read-key (16 bytes)
	keys := &session.SessionKeys{
		InitiatorKey: make([]byte, 16),
		RecipientKey: make([]byte, 16),
	}

	if _, err := kdf.Read(keys.InitiatorKey); err != nil {
		return nil, fmt.Errorf("failed to derive initiator key: %w", err)
	}

	if _, err := kdf.Read(keys.RecipientKey); err != nil {
		return nil, fmt.Errorf("failed to derive recipient key: %w", err)
	}

	return keys, nil
}

// encodePublicKey encodes a public key in compressed form (33 bytes).
func encodePublicKey(pubKey *ecdsa.PublicKey) []byte {
	return ethcrypto.CompressPubkey(pubKey)
}

// decodePublicKey decodes a compressed public key.
func decodePublicKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) != 33 {
		return nil, fmt.Errorf("invalid compressed public key length: %d", len(data))
	}
	return ethcrypto.DecompressPubkey(data)
}

// generateEphemeralKey generates a new ephemeral ECDSA key pair for ECDH.
func generateEphemeralKey() (*ecdsa.PrivateKey, error) {
	return ethcrypto.GenerateKey()
}
