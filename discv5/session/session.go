package session

import (
	"net"
	"slices"
	"sync"
	"time"

	"github.com/ethpandaops/bootnodoor/discv5/node"
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

	// remoteAddr is the network address of the remote peer. Unexported because it
	// is mutated by UpdateAddr under mu while packets are handled concurrently;
	// read it through Addr().
	remoteAddr *net.UDPAddr

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

	// sentNonces holds the nonces of recent ordinary packets we sent, oldest first.
	sentNonces []string

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
//   - lifetime: How long the session is valid (default 30 minutes)
//
// Example:
//
//	session := NewSession(remoteID, remoteAddr, keys, true, 30*time.Minute)
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
		remoteAddr:  remoteAddr,
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

// maxSentNonces bounds the remembered nonces. A WHOAREYOU answers a packet we
// sent moments ago, so the window only has to cover the traffic we can send to
// one peer within a request lifetime; sized well above that, because being too
// small silently drops a legitimate peer's restart recovery until its next
// packet, while being generous costs a few hundred bytes per session.
const maxSentNonces = 64

// RecordSentNonce remembers the nonce of an ordinary packet we sent on this
// session, so a WHOAREYOU claiming to answer it can be verified.
func (s *Session) RecordSentNonce(nonce []byte) {
	if len(nonce) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sentNonces = append(s.sentNonces, string(nonce))
	if len(s.sentNonces) > maxSentNonces {
		s.sentNonces = s.sentNonces[len(s.sentNonces)-maxSentNonces:]
	}
}

// SentNonce reports whether nonce belongs to a packet we sent on this session.
//
// WHOAREYOU is unauthenticated, and answering one replaces this session's keys,
// so a forged challenge must not be able to reach that path. Only a peer that
// actually received one of our packets can quote its nonce back.
func (s *Session) SentNonce(nonce []byte) bool {
	if len(nonce) == 0 {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return slices.Contains(s.sentNonces, string(nonce))
}

// Addr returns the remote address for this session.
func (s *Session) Addr() *net.UDPAddr {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.remoteAddr
}

// UpdateAddr updates the remote address for this session.
//
// Only call this once the sender is authenticated: an unauthenticated packet
// naming this node ID must not be able to steer where the session points.
func (s *Session) UpdateAddr(addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.remoteAddr = addr
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
	role := "recipient"
	if s.IsInitiator {
		role = "initiator"
	}

	// Age and IdleTime take the read lock themselves; holding it here as well
	// would be a recursive RLock, which deadlocks if a writer queues in between.
	return "Session{" +
		"RemoteID: " + s.RemoteID.String() +
		", Role: " + role +
		", Age: " + s.Age().String() +
		", Idle: " + s.IdleTime().String() +
		"}"
}
