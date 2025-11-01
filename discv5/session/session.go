package session

import (
	"net"
	"sync"
	"time"

	"github.com/pk910/bootoor/discv5/node"
)

// Session represents an active encrypted session with a peer.
//
// Each session has:
//   - Unique session keys derived from ECDH
//   - Creation and expiration timestamps
//   - Role (initiator or recipient)
//   - Nonce tracking for replay protection
//   - Node reference for protocol operations
type Session struct {
	// RemoteID is the node ID of the remote peer
	RemoteID node.ID

	// RemoteAddr is the network address of the remote peer
	RemoteAddr *net.UDPAddr

	// Node is the full node information (ENR, etc.)
	// This allows protocol operations to access node data without a separate table lookup
	Node *node.Node

	// Keys contains the encryption keys for this session
	Keys *SessionKeys

	// IsInitiator indicates if we initiated this session
	IsInitiator bool

	// CreatedAt is when the session was established
	CreatedAt time.Time

	// ExpiresAt is when the session expires
	ExpiresAt time.Time

	// LastUsed is the last time this session was used
	LastUsed time.Time

	// mu protects mutable fields
	mu sync.RWMutex
}

// NewSession creates a new session.
//
// Parameters:
//   - remoteID: Node ID of the remote peer
//   - remoteAddr: Network address of the remote peer
//   - keys: Derived session keys
//   - isInitiator: True if we initiated the session
//   - lifetime: How long the session is valid (default 12 hours)
//
// Example:
//
//	session := NewSession(remoteID, remoteAddr, keys, true, 12*time.Hour)
func NewSession(
	remoteID node.ID,
	remoteAddr *net.UDPAddr,
	keys *SessionKeys,
	isInitiator bool,
	lifetime time.Duration,
) *Session {
	now := time.Now()

	return &Session{
		RemoteID:    remoteID,
		RemoteAddr:  remoteAddr,
		Keys:        keys,
		IsInitiator: isInitiator,
		CreatedAt:   now,
		ExpiresAt:   now.Add(lifetime),
		LastUsed:    now,
	}
}

// IsExpired checks if the session has expired.
//
// Sessions expire after their lifetime (default 12 hours) or can be
// manually expired by the session manager.
func (s *Session) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return time.Now().After(s.ExpiresAt)
}

// Touch updates the last used timestamp.
//
// This is called whenever the session is used for encryption or decryption.
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LastUsed = time.Now()
}

// SetNode updates the node reference for this session.
//
// This is typically called after a handshake when we receive the remote node's ENR.
func (s *Session) SetNode(n *node.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Node = n
}

// GetNode returns the node reference for this session.
//
// Returns nil if no node has been set.
func (s *Session) GetNode() *node.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.Node
}

// EncryptionKey returns the key to use for encrypting outgoing messages.
//
// The key depends on whether we are the session initiator or recipient.
func (s *Session) EncryptionKey() []byte {
	if s.IsInitiator {
		return s.Keys.InitiatorKey
	}
	return s.Keys.RecipientKey
}

// DecryptionKey returns the key to use for decrypting incoming messages.
//
// The key is the opposite of the encryption key.
func (s *Session) DecryptionKey() []byte {
	if s.IsInitiator {
		return s.Keys.RecipientKey
	}
	return s.Keys.InitiatorKey
}

// Age returns how long ago the session was created.
func (s *Session) Age() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return time.Since(s.CreatedAt)
}

// IdleTime returns how long ago the session was last used.
func (s *Session) IdleTime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return time.Since(s.LastUsed)
}

// TimeUntilExpiry returns how long until the session expires.
//
// Returns 0 if already expired.
func (s *Session) TimeUntilExpiry() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	remaining := time.Until(s.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// String returns a human-readable representation of the session.
func (s *Session) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role := "recipient"
	if s.IsInitiator {
		role = "initiator"
	}

	return "Session{" +
		"RemoteID: " + s.RemoteID.String() +
		", Role: " + role +
		", Age: " + s.Age().String() +
		", Idle: " + s.IdleTime().String() +
		"}"
}
