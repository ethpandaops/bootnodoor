package crypto

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto"
)

// ECDH performs Elliptic Curve Diffie-Hellman key agreement.
//
// Given a private key and a peer's public key, it computes a shared secret
// that both parties can derive independently. The shared secret is the
// X coordinate of the point: privKey * pubKey.
//
// The discv5 protocol uses ECDH for session key establishment during
// the handshake process. The shared secret is then used as input to
// HKDF for deriving encryption keys.
//
// Returns a 32-byte shared secret.
//
// Example:
//
//	// Alice's side
//	alicePriv, _ := crypto.GenerateKey()
//	bobPub := // ... received from Bob ...
//	sharedSecret1, err := ECDH(alicePriv, bobPub)
//
//	// Bob's side
//	bobPriv, _ := crypto.GenerateKey()
//	alicePub := // ... received from Alice ...
//	sharedSecret2, err := ECDH(bobPriv, alicePub)
//
//	// sharedSecret1 == sharedSecret2
func ECDH(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	if privKey == nil {
		return nil, fmt.Errorf("crypto: nil private key")
	}

	if pubKey == nil {
		return nil, fmt.Errorf("crypto: nil public key")
	}

	// Convert to secp256k1 types for scalar multiplication
	var scalar secp256k1.ModNScalar
	scalar.SetByteSlice(privKey.D.Bytes())

	pubBytes := crypto.CompressPubkey(pubKey)

	pubKeyS, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid public key: %w", err)
	}

	var point, result secp256k1.JacobianPoint

	pubKeyS.AsJacobian(&point)
	secp256k1.ScalarMultNonConst(&scalar, &point, &result)
	result.ToAffine()

	// Return the X coordinate as the shared secret
	secret := make([]byte, 32)
	result.X.PutBytesUnchecked(secret)

	return secret, nil
}

// ValidatePublicKey validates that a public key is on the secp256k1 curve.
//
// This should be called when receiving public keys from untrusted sources
// to prevent invalid point attacks.
//
// Returns nil if the key is valid, error otherwise.
func ValidatePublicKey(pubKey *ecdsa.PublicKey) error {
	if pubKey == nil {
		return fmt.Errorf("crypto: nil public key")
	}

	// Build uncompressed representation manually to avoid panic from
	// CompressPubkey on invalid points. Format: 0x04 || X (32 bytes) || Y (32 bytes)
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	pubKey.X.FillBytes(uncompressed[1:33])
	pubKey.Y.FillBytes(uncompressed[33:65])

	// ParsePubKey performs on-curve and infinity checks.
	if _, err := secp256k1.ParsePubKey(uncompressed); err != nil {
		return fmt.Errorf("crypto: invalid public key: %w", err)
	}

	return nil
}

// DeriveKeyMaterial derives key material from an ECDH shared secret.
//
// This is a convenience function that combines ECDH and HKDF.
// It's the recommended way to derive session keys in discv5.
//
// Parameters:
//   - privKey: Local private key (static or ephemeral)
//   - pubKey: Remote public key (static or ephemeral)
//   - info: Context string for key derivation (e.g., "discovery v5 key agreement")
//   - keyLen: Desired output key length in bytes
//
// Example:
//
//	sessionKey, err := DeriveKeyMaterial(
//	    localPriv,
//	    remotePub,
//	    []byte("discovery v5 session key"),
//	    16, // 128-bit AES key
//	)
func DeriveKeyMaterial(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey, info []byte, keyLen int) ([]byte, error) {
	// Validate the public key
	if err := ValidatePublicKey(pubKey); err != nil {
		return nil, err
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := ECDH(privKey, pubKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: ECDH failed: %w", err)
	}

	// Derive key material using HKDF
	// No salt is used (nil) as per discv5 spec
	keyMaterial, err := HKDFExtract(nil, sharedSecret, info, keyLen)
	if err != nil {
		return nil, fmt.Errorf("crypto: HKDF failed: %w", err)
	}

	return keyMaterial, nil
}

// SharedSecretToKey derives a fixed-length key from a shared secret.
//
// This is a simple wrapper around Keccak256 for backward compatibility.
// For new code, prefer using HKDF via DeriveKeyMaterial.
func SharedSecretToKey(secret []byte) []byte {
	return crypto.Keccak256(secret)
}
