package protocol

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethpandaops/bootnodoor/crypto"
	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/discv5/session"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/sirupsen/logrus"
)

// Transport interface for sending packets.
type Transport interface {
	SendTo(data []byte, to *net.UDPAddr) error
	Send(data []byte, to *net.UDPAddr, from *net.UDPAddr) error
}

// PendingHandshake tracks a message waiting for handshake completion
type PendingHandshake struct {
	Message    Message
	ToNode     *node.Node
	ToAddr     *net.UDPAddr
	ToNodeID   node.ID
	CreatedAt  time.Time
	LastRetry  time.Time // When we last sent a retry
	RetryCount int       // Number of retries attempted
	MaxRetries int       // Maximum number of retries (default 3)
}

// PendingChallenge tracks WHOAREYOU challenges we've sent.
type PendingChallenge struct {
	ToAddr        *net.UDPAddr
	ToNodeID      node.ID
	ChallengeData []byte
	PacketBytes   []byte // Raw WHOAREYOU packet bytes for resending
	CreatedAt     time.Time

	// KnownNode is the record our advertised ENRSeq came from, if any. A peer
	// may legally answer a non-zero ENRSeq without repeating its record, so
	// this is the only copy left to verify that handshake against.
	KnownNode *node.Node
}

// OnHandshakeCompleteCallback is called when a handshake completes successfully.
type OnHandshakeCompleteCallback func(n *node.Node, incoming bool)

// OnNodeUpdateCallback is called when a node's ENR is updated.
type OnNodeUpdateCallback func(n *node.Node)

// OnNodeSeenCallback is called when a node is seen (receives a message).
// This is useful for tracking last_seen timestamps in the database.
type OnNodeSeenCallback func(n *node.Node, timestamp time.Time)

// OnFindNodeCallback is called when a FINDNODE request is received.
// The sourceNode parameter is the node that sent the request (may be nil if unknown).
// The requester parameter provides the requesting node's address for context-aware filtering (e.g., LAN-aware filtering).
type OnFindNodeCallback func(msg *FindNode, sourceNode *node.Node, requester *net.UDPAddr) []*node.Node

// OnTalkReqCallback is called when a TALKREQ request is received.
type OnTalkReqCallback func(msg *TalkReq) []byte

// OnPongReceivedCallback is called when a PONG response is received.
// Parameters: remoteNodeID, sourceIP (remote peer's IP), reportedIP (our IP as seen by the remote peer), reportedPort (our port as seen by the remote peer)
type OnPongReceivedCallback func(remoteNodeID node.ID, sourceIP net.IP, reportedIP net.IP, reportedPort uint16)

// Handler handles incoming and outgoing protocol messages.
//
// The handler is responsible for:
//   - Processing incoming packets (PING, FINDNODE, TALKREQ)
//   - Sending responses with appropriate filtering
//   - Managing request/response matching
//   - Applying response filters (LAN/WAN awareness)
type Handler struct {
	// config holds the handler configuration
	config HandlerConfig

	// ctx is the context for cancellation
	ctx context.Context

	// requests tracks pending requests
	requests *RequestTracker

	// pendingHandshakes tracks messages waiting for handshake completion (key: nodeID+addr)
	pendingHandshakes map[string]*PendingHandshake

	// pendingChallenges tracks WHOAREYOU challenges we've sent (key: nodeID+addr)
	pendingChallenges map[string]*PendingChallenge

	// pendingPerIP tracks the number of pending entries per IP address
	pendingPerIP map[string]int

	// transport is used to send UDP packets
	transport Transport

	// mu protects handler state
	mu sync.RWMutex

	// Stats
	packetsReceived    int
	packetsSent        int
	invalidPackets     int
	filteredResponses  int
	findNodeReceived   int
	rejectedHandshakes int
	rejectedChallenges int
	evictedHandshakes  int
	evictedChallenges  int
}

const (
	// pendingHandshakeTimeout is how long we keep pending handshakes before cleanup
	pendingHandshakeTimeout = 10 * time.Second

	// pendingChallengeTimeout is how long we keep pending challenges before cleanup
	pendingChallengeTimeout = 10 * time.Second

	// cleanupInterval is how often we run the cleanup routine
	cleanupInterval = 5 * time.Second

	// handshakeRetryInterval is how long to wait before retrying a handshake
	handshakeRetryInterval = 2 * time.Second

	// defaultMaxPendingHandshakes is the default maximum number of pending outgoing handshakes
	defaultMaxPendingHandshakes = 2000

	// defaultMaxPendingChallenges is the default maximum number of pending incoming challenges
	defaultMaxPendingChallenges = 500

	// defaultMaxPendingPerIP is the default maximum number of pending entries per IP
	defaultMaxPendingPerIP = 10
)

// HandlerConfig contains configuration for the protocol handler.
type HandlerConfig struct {
	// LocalNode is our node information
	LocalNode *node.Node

	// Sessions is the session cache
	Sessions *session.Cache

	// PrivateKey is the node's private key (for handshake signatures)
	PrivateKey *ecdsa.PrivateKey

	// Callbacks (all optional, can be nil)
	OnHandshakeComplete OnHandshakeCompleteCallback
	OnNodeUpdate        OnNodeUpdateCallback
	OnNodeSeen          OnNodeSeenCallback
	OnFindNode          OnFindNodeCallback
	OnTalkReq           OnTalkReqCallback
	OnPongReceived      OnPongReceivedCallback

	// RequestTimeout is the timeout for requests
	RequestTimeout time.Duration

	// MaxPendingHandshakes is the maximum number of pending outgoing handshakes (0 = 2000)
	MaxPendingHandshakes int

	// MaxPendingChallenges is the maximum number of pending incoming challenges (0 = 500)
	MaxPendingChallenges int

	// MaxPendingPerIP is the maximum number of pending entries per IP address (0 = 10)
	MaxPendingPerIP int

	// Logger for debug messages
	Logger logrus.FieldLogger
}

// NewHandler creates a new protocol handler.
//
// Example:
//
//	handler := NewHandler(HandlerConfig{
//	    LocalNode: myNode,
//	    Sessions: sessionCache,
//	    OnFindNode: func(msg *FindNode, sourceNode *node.Node, requester *net.UDPAddr) []*node.Node { ... },
//	})
func NewHandler(ctx context.Context, cfg HandlerConfig) *Handler {
	// Apply defaults for limits
	if cfg.MaxPendingHandshakes <= 0 {
		cfg.MaxPendingHandshakes = defaultMaxPendingHandshakes
	}
	if cfg.MaxPendingChallenges <= 0 {
		cfg.MaxPendingChallenges = defaultMaxPendingChallenges
	}
	if cfg.MaxPendingPerIP <= 0 {
		cfg.MaxPendingPerIP = defaultMaxPendingPerIP
	}

	h := &Handler{
		config:            cfg,
		ctx:               ctx,
		requests:          NewRequestTracker(cfg.RequestTimeout),
		pendingHandshakes: make(map[string]*PendingHandshake),
		pendingChallenges: make(map[string]*PendingChallenge),
		pendingPerIP:      make(map[string]int),
	}

	// Start cleanup routine for expired pending entries
	go h.cleanupLoop()

	return h
}

// SetTransport sets the transport for sending packets.
func (h *Handler) SetTransport(transport Transport) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.transport = transport
}

// addPendingHandshake adds a pending handshake with limit checking and LRU eviction.
// Must be called with h.mu locked.
func (h *Handler) addPendingHandshake(key string, pending *PendingHandshake) bool {
	ipKey := pending.ToAddr.IP.String()

	// Check per-IP limit
	if h.pendingPerIP[ipKey] >= h.config.MaxPendingPerIP {
		h.rejectedHandshakes++
		h.config.Logger.WithFields(logrus.Fields{
			"ip":    ipKey,
			"count": h.pendingPerIP[ipKey],
			"limit": h.config.MaxPendingPerIP,
		}).Debug("handler: rejected pending handshake, per-IP limit reached")
		return false
	}

	// Check global limit
	if len(h.pendingHandshakes) >= h.config.MaxPendingHandshakes {
		// Evict oldest
		h.evictOldestHandshake()
	}

	// Add the entry
	h.pendingHandshakes[key] = pending
	h.pendingPerIP[ipKey]++

	return true
}

// removePendingHandshake removes a pending handshake and updates counters.
// Must be called with h.mu locked.
func (h *Handler) removePendingHandshake(key string, pending *PendingHandshake) {
	delete(h.pendingHandshakes, key)
	if pending != nil {
		ipKey := pending.ToAddr.IP.String()
		h.pendingPerIP[ipKey]--
		if h.pendingPerIP[ipKey] <= 0 {
			delete(h.pendingPerIP, ipKey)
		}
	}
}

// evictOldestHandshake removes the oldest pending handshake (LRU).
// Must be called with h.mu locked.
func (h *Handler) evictOldestHandshake() {
	if len(h.pendingHandshakes) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	var oldestPending *PendingHandshake
	first := true

	for key, pending := range h.pendingHandshakes {
		if first || pending.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = pending.CreatedAt
			oldestPending = pending
			first = false
		}
	}

	h.removePendingHandshake(oldestKey, oldestPending)
	h.evictedHandshakes++

	h.config.Logger.WithFields(logrus.Fields{
		"nodeID": oldestPending.ToNodeID.String()[:16],
		"age":    time.Since(oldestTime),
	}).Debug("handler: evicted oldest pending handshake")
}

// addPendingChallenge adds a pending challenge with limit checking and LRU eviction.
// Must be called with h.mu locked.
// Returns false if the challenge was rejected or if one already exists.
func (h *Handler) addPendingChallenge(key string, pending *PendingChallenge) bool {
	// Check if a challenge already exists for this key
	if existing := h.pendingChallenges[key]; existing != nil {
		// Don't overwrite - client might already be responding to the existing challenge
		h.config.Logger.WithFields(logrus.Fields{
			"nodeID": pending.ToNodeID.String()[:16],
			"addr":   pending.ToAddr,
			"age":    time.Since(existing.CreatedAt),
		}).Debug("handler: pending challenge already exists, not overwriting")
		return false
	}

	ipKey := pending.ToAddr.IP.String()

	// Check per-IP limit
	if h.pendingPerIP[ipKey] >= h.config.MaxPendingPerIP {
		h.rejectedChallenges++
		h.config.Logger.WithFields(logrus.Fields{
			"ip":    ipKey,
			"count": h.pendingPerIP[ipKey],
			"limit": h.config.MaxPendingPerIP,
		}).Debug("handler: rejected pending challenge, per-IP limit reached")
		return false
	}

	// Check global limit
	if len(h.pendingChallenges) >= h.config.MaxPendingChallenges {
		// Evict oldest
		h.evictOldestChallenge()
	}

	// Add the entry
	h.pendingChallenges[key] = pending
	h.pendingPerIP[ipKey]++

	return true
}

// removePendingChallenge removes a pending challenge and updates counters.
// Must be called with h.mu locked.
func (h *Handler) removePendingChallenge(key string, pending *PendingChallenge) {
	delete(h.pendingChallenges, key)
	if pending != nil {
		ipKey := pending.ToAddr.IP.String()
		h.pendingPerIP[ipKey]--
		if h.pendingPerIP[ipKey] <= 0 {
			delete(h.pendingPerIP, ipKey)
		}
	}
}

// evictOldestChallenge removes the oldest pending challenge (LRU).
// Must be called with h.mu locked.
func (h *Handler) evictOldestChallenge() {
	if len(h.pendingChallenges) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	var oldestPending *PendingChallenge
	first := true

	for key, pending := range h.pendingChallenges {
		if first || pending.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = pending.CreatedAt
			oldestPending = pending
			first = false
		}
	}

	h.removePendingChallenge(oldestKey, oldestPending)
	h.evictedChallenges++

	h.config.Logger.WithFields(logrus.Fields{
		"nodeID": oldestPending.ToNodeID.String()[:16],
		"age":    time.Since(oldestTime),
	}).Debug("handler: evicted oldest pending challenge")
}

// HandleIncomingPacket processes an incoming UDP packet.
//
// This is called by the UDP transport layer when a packet arrives.
// The localAddr parameter is the local address that received the packet.
func (h *Handler) HandleIncomingPacket(data []byte, from *net.UDPAddr, localAddr *net.UDPAddr) error {
	h.mu.Lock()
	h.packetsReceived++
	h.mu.Unlock()

	h.config.Logger.WithFields(logrus.Fields{
		"from":      from,
		"localAddr": localAddr,
		"size":      len(data),
		"packetHex": fmt.Sprintf("%x", data[:min(100, len(data))]),
	}).Trace("handler: incoming packet")

	// Decode packet (unmask header and authdata using our local node ID)
	packet, err := DecodePacket(data, h.config.LocalNode.ID())
	if err != nil {
		h.mu.Lock()
		h.invalidPackets++
		h.mu.Unlock()

		h.config.Logger.WithFields(logrus.Fields{
			"from":  from,
			"error": err,
		}).Trace("handler: invalid packet")
		return fmt.Errorf("invalid packet: %w", err)
	}

	// Handle based on packet type
	switch packet.PacketType {
	case OrdinaryPacket:
		return h.handleOrdinaryPacket(packet, from, localAddr)
	case WHOAREYOUPacket:
		return h.handleWHOAREYOUPacket(packet, from, localAddr)
	case HandshakePacket:
		return h.handleHandshakePacket(packet, from, localAddr)
	default:
		h.mu.Lock()
		h.invalidPackets++
		h.mu.Unlock()
		h.config.Logger.WithFields(logrus.Fields{
			"from": from,
			"type": packet.PacketType,
		}).Warn("handler: unknown packet type")
		return fmt.Errorf("unknown packet type: %d", packet.PacketType)
	}
}

// handleOrdinaryPacket handles an ordinary encrypted packet.
func (h *Handler) handleOrdinaryPacket(packet *Packet, from *net.UDPAddr, localAddr *net.UDPAddr) error {
	// Extract source node ID from packet
	if len(packet.SrcID) != 32 {
		return fmt.Errorf("no source node ID in packet")
	}
	var srcNodeID node.ID
	copy(srcNodeID[:], packet.SrcID)

	// Sessions are keyed by the sender's node ID and every creation site uses the
	// correct ID, so this always hits when a session exists. There is deliberately
	// no address fallback: srcID is unauthenticated, so matching a session by
	// source address alone let anyone who could guess a peer's IP:port reach the
	// failure path below and tear that peer's session down.
	sess := h.config.Sessions.Get(srcNodeID)
	if sess == nil {
		// No session exists, send WHOAREYOU challenge
		h.config.Logger.WithFields(logrus.Fields{
			"from":   from,
			"nodeID": srcNodeID.String()[:16],
		}).Debug("handler: no session, sending WHOAREYOU")
		return h.sendWHOAREYOU(from, srcNodeID, packet.Header.Nonce, localAddr)
	}

	// Decrypt message using session key
	// HeaderData contains: IV + masked header + masked authdata (used as GCM additional data)
	plaintext, err := session.DecryptMessage(
		sess.DecryptionKey(),
		packet.Header.Nonce,
		packet.HeaderData,
		packet.Message,
	)
	if err != nil {
		// Keep the session. Anyone can send an undecryptable packet naming this
		// node ID, so deleting here let an attacker who knows only a peer's public
		// ID destroy that peer's session at will. A peer that genuinely lost its
		// keys recovers via the handshake, and Cache.Put replaces this entry by
		// node ID when it lands, so deletion buys nothing.
		//
		// The challenge still goes to the packet source: the legitimate "restarted
		// and lost my keys" case is a random packet, which by definition fails to
		// decrypt, and the source is the only address such a peer is reachable at.
		// Answering at sess.Addr() instead would be a reflection primitive.
		h.config.Logger.WithFields(logrus.Fields{
			"nodeID": sess.RemoteID.String()[:16],
			"addr":   from,
			"error":  err,
		}).Debug("handler: decryption failed, keeping session and sending WHOAREYOU")

		return h.sendWHOAREYOU(from, srcNodeID, packet.Header.Nonce, localAddr)
	}

	// Only now is the sender proven: AES-GCM over the header authenticates
	// possession of the session key, and the source address is not part of the
	// AAD, so a NAT-rebound peer decrypts fine from its new address.
	// Zone is part of the comparison because Cache.GetByAddr matches on the full
	// address string; ignoring it here would let the two disagree for scoped IPv6
	// and strand a peer that changed interface.
	if cur := sess.Addr(); cur == nil || cur.Port != from.Port || cur.Zone != from.Zone || !cur.IP.Equal(from.IP) {
		h.config.Logger.WithFields(logrus.Fields{
			"nodeID":  srcNodeID.String()[:16],
			"oldAddr": sess.Addr(),
			"newAddr": from,
		}).Info("handler: node address changed, updating session")

		sess.UpdateAddr(from)
	}

	// Decode message from plaintext
	// Plaintext format: message-type (1 byte) + RLP-encoded message
	if len(plaintext) < 1 {
		h.config.Logger.WithField("from", from).Debug("handler: message too short")
		return fmt.Errorf("message too short")
	}

	msgType := plaintext[0]
	msgData := plaintext[1:]

	// Convert to Message interface and decode RLP data into it
	msg := h.createMessage(msgType)
	if msg == nil {
		h.config.Logger.WithFields(logrus.Fields{
			"from":    from,
			"msgType": msgType,
		}).Warn("handler: unknown message type")
		return fmt.Errorf("unknown message type: %d", msgType)
	}

	// Decode RLP message data into the message struct
	// ENR records in NODES messages will be properly decoded via the rlp.Decoder interface
	if err := rlp.DecodeBytes(msgData, msg); err != nil {
		h.config.Logger.WithFields(logrus.Fields{
			"from":  from,
			"error": err,
		}).Debug("handler: failed to decode message")
		return fmt.Errorf("failed to decode message: %w", err)
	}

	// Handle message based on type
	return h.handleMessage(msg, sess.RemoteID, from, sess.GetNode(), localAddr)
}

// handleWHOAREYOUPacket handles a WHOAREYOU challenge.
func (h *Handler) handleWHOAREYOUPacket(packet *Packet, from *net.UDPAddr, localAddr *net.UDPAddr) error {
	// We need to find which node this is for - extract from pending handshakes
	// Since we don't know the nodeID yet from WHOAREYOU, we need to match by address
	// and find the pending handshake
	var pending *PendingHandshake
	var pendingKey string

	h.mu.Lock()
	for key, p := range h.pendingHandshakes {
		if p.ToAddr.String() == from.String() {
			pending = p
			pendingKey = key
			break
		}
	}
	h.mu.Unlock()

	if pending == nil {
		// No pending handshake - this WHOAREYOU is unexpected
		// This can happen when:
		// 1. Remote's session expired but ours didn't (asymmetric expiry)
		// 2. Remote restarted and lost their session
		// 3. Remote had a decryption failure and deleted their session
		//
		// We sent an encrypted packet with our stale session, but they don't have one.
		// Solution: Look up the pending request, create a handshake with its stored message,
		// complete the handshake, and replay the request with the same request ID.
		sess := h.config.Sessions.GetByAddr(from)
		if sess == nil {
			// No session at all - truly unexpected WHOAREYOU
			return fmt.Errorf("no pending handshake for %s", from)
		}

		// Answering this challenge derives fresh keys and replaces the session, so
		// a WHOAREYOU nobody authenticated must not reach that path: otherwise
		// anyone able to reach us from this address could swap a working session
		// for keys the real peer never agreed to. Only a peer that actually
		// received one of our packets can quote its nonce.
		if !sess.SentNonce(packet.Header.Nonce) {
			h.config.Logger.WithFields(logrus.Fields{
				"nodeID": sess.RemoteID.String()[:16],
				"addr":   from,
			}).Debug("handler: ignoring WHOAREYOU referencing a nonce we never sent")
			return fmt.Errorf("unsolicited WHOAREYOU from %s", from)
		}

		// Look up pending request for this node to get the message to replay
		pendingReq := h.requests.GetPendingRequestForNode(sess.RemoteID)
		if pendingReq == nil {
			// Keep the session: the handshake replaces it by node ID if the peer
			// really did lose its keys, so deleting here only helps an attacker.
			h.config.Logger.WithFields(logrus.Fields{
				"nodeID": sess.RemoteID.String()[:16],
				"addr":   from,
				"age":    sess.Age(),
			}).Debug("handler: received unexpected WHOAREYOU with no pending request")
			return fmt.Errorf("no pending handshake or request for %s", from)
		}

		// Create pending handshake with the stored message from the pending request
		// This will be sent after handshake completes, matching the existing pending request
		pendingKey = makeHandshakeKey(sess.RemoteID, from)
		pending = &PendingHandshake{
			Message:    pendingReq.Message, // Use the original message with same request ID!
			ToNode:     pendingReq.Node,    // Use node from pending request (not stale session)
			ToAddr:     from,
			ToNodeID:   sess.RemoteID,
			CreatedAt:  time.Now(),
			LastRetry:  time.Now(),
			RetryCount: 0,
			MaxRetries: 3,
		}

		h.mu.Lock()
		h.pendingHandshakes[pendingKey] = pending
		h.mu.Unlock()

		// The stale session is not deleted here: sendHandshakePacket's Put replaces
		// it by node ID once the new keys exist, so deleting first only widens the
		// window in which the peer has no session at all.

		// Continue processing the WHOAREYOU with our pending handshake
		// After handshake completes, the message will be sent with the SAME request ID,
		// and will match the existing pending request
		h.config.Logger.WithFields(logrus.Fields{
			"nodeID":  sess.RemoteID.String()[:16],
			"addr":    from,
			"age":     sess.Age(),
			"msgType": pendingReq.Message.Type(),
		}).Debug("handler: processing unexpected WHOAREYOU, will replay request after handshake")
	}

	remoteNodeID := pending.ToNodeID
	remoteNode := pending.ToNode

	// Get remote node's public key from the stored node
	var remotePubKey *ecdsa.PublicKey
	if remoteNode != nil {
		remotePubKey = remoteNode.PublicKey()
	}

	// If we don't have the node info, we can't complete handshake
	if remotePubKey == nil {
		h.config.Logger.WithField("remoteID", remoteNodeID).Warn("handler: no node information available for handshake")
		return fmt.Errorf("no node information available for handshake: %s", remoteNodeID)
	}

	// Generate ephemeral ECDH key pair
	ephKey, err := generateEphemeralKey()
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	ephPubkey := encodePublicKey(&ephKey.PublicKey)

	// The challenge data is the WHOAREYOU packet header (IV + unmasked header + unmasked authdata)
	// This is stored in packet.HeaderData
	challengeData := packet.HeaderData

	// Create ID nonce signature
	signature, err := makeIDSignature(h.config.PrivateKey, challengeData, ephPubkey, remoteNodeID)
	if err != nil {
		return fmt.Errorf("failed to create ID signature: %w", err)
	}

	// Derive session keys using HKDF
	// We are the initiator (we sent the random packet first)
	sessionKeys, err := deriveKeys(ephKey, remotePubKey, h.config.LocalNode.ID(), remoteNodeID, challengeData)
	if err != nil {
		h.config.Logger.WithError(err).Error("handler: failed to derive session keys")
		return fmt.Errorf("failed to derive session keys: %w", err)
	}

	// Check if we should send our ENR
	// - If ENRSeq is 0, they don't have our ENR, so always send it
	// - If ENRSeq > 0, only send if our seq is higher
	var enrBytes []byte
	localENR := h.config.LocalNode.Record()
	if packet.Challenge.ENRSeq == 0 || packet.Challenge.ENRSeq < localENR.Seq() {
		enrBytes, err = localENR.EncodeRLPBytes()
		if err != nil {
			h.config.Logger.WithError(err).Warn("handler: failed to encode ENR")
		} else {
		}
	}

	// Encode the message plaintext: message-type (1 byte) + RLP-encoded message
	msgBytes, err := pending.Message.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	plaintext := make([]byte, 1+len(msgBytes))
	plaintext[0] = pending.Message.Type()
	copy(plaintext[1:], msgBytes)

	// Generate nonce for the handshake packet
	nonce, err := crypto.GenerateRandomBytes(12)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Build unmasked header data for GCM authentication
	// This returns: maskingIV, unmasked headerData (IV || header || authdata)
	maskingIV, headerData, err := BuildHandshakeHeaderData(h.config.LocalNode.ID(), nonce,
		signature, ephPubkey, enrBytes)
	if err != nil {
		return fmt.Errorf("failed to build header data: %w", err)
	}

	// Encrypt the message with GCM using headerData as additional authenticated data
	ciphertext, err := session.EncryptMessage(sessionKeys.InitiatorKey, nonce, headerData, plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt handshake message: %w", err)
	}

	// Encode final handshake packet with encrypted message
	// This uses the same maskingIV to ensure consistency
	packetBytes, err := EncodeHandshakePacket(h.config.LocalNode.ID(), remoteNodeID, maskingIV, nonce,
		signature, ephPubkey, enrBytes, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to encode handshake packet: %w", err)
	}

	// Store session keys
	sess := session.NewSession(
		remoteNodeID,
		from,
		sessionKeys,
		true, // we are the initiator
		h.config.Sessions.Lifetime(),
	)

	// Try to get the node from a previous session to set it
	if existingSess := h.config.Sessions.Get(remoteNodeID); existingSess != nil {
		if existingNode := existingSess.GetNode(); existingNode != nil {
			sess.SetNode(existingNode)
		}
	}

	if sess.GetNode() == nil && remoteNode != nil {
		sess.SetNode(remoteNode)
	}

	h.config.Sessions.Put(sess)

	// Call OnHandshakeComplete callback for outgoing handshake
	if sess.GetNode() != nil && h.config.OnHandshakeComplete != nil {
		h.config.OnHandshakeComplete(sess.GetNode(), false) // incoming = false
	}

	// Remove pending handshake
	h.mu.Lock()
	h.removePendingHandshake(pendingKey, pending)
	h.mu.Unlock()

	// Send handshake packet
	h.mu.RLock()
	transport := h.transport
	h.mu.RUnlock()

	if transport == nil {
		return fmt.Errorf("transport not initialized")
	}

	if err := transport.Send(packetBytes, from, localAddr); err != nil {
		return fmt.Errorf("failed to send handshake packet: %w", err)
	}

	h.mu.Lock()
	h.packetsSent++
	h.mu.Unlock()

	return nil
}

// makeHandshakeKey creates a unique key for tracking pending handshakes
func makeHandshakeKey(nodeID node.ID, addr *net.UDPAddr) string {
	return fmt.Sprintf("%s@%s", nodeID.String(), addr.String())
}

// BuildWHOAREYOUChallengeData builds the unmasked challenge data for signature verification.
// This matches the headerData that the remote node will extract when decoding the WHOAREYOU packet.
// Format: IV (16) || unmasked-header (23) || unmasked-authdata (24)
func BuildWHOAREYOUChallengeData(maskingIV, nonce []byte, challenge *WHOAREYOUChallenge) []byte {
	// Build unmasked static header (23 bytes)
	// Format: protocol-id(6) || version(2) || flag(1) || nonce(12) || authsize(2)
	staticHeader := make([]byte, 23)
	copy(staticHeader[0:6], []byte("discv5"))
	binary.BigEndian.PutUint16(staticHeader[6:8], 1) // version
	staticHeader[8] = WHOAREYOUPacket                // flag = 0x01
	copy(staticHeader[9:21], nonce)
	binary.BigEndian.PutUint16(staticHeader[21:23], 24) // authsize

	// Build unmasked authdata (24 bytes): id-nonce (16) || enr-seq (8)
	authdata := make([]byte, 24)
	copy(authdata[0:16], challenge.IDNonce[:16])
	binary.BigEndian.PutUint64(authdata[16:24], challenge.ENRSeq)

	// Build complete challenge data: IV || unmasked-header || unmasked-authdata
	challengeData := make([]byte, 0, 16+23+24)
	challengeData = append(challengeData, maskingIV...)
	challengeData = append(challengeData, staticHeader...)
	challengeData = append(challengeData, authdata...)

	return challengeData
}

// handleHandshakePacket handles a handshake packet.
func (h *Handler) handleHandshakePacket(packet *Packet, from *net.UDPAddr, localAddr *net.UDPAddr) error {
	h.config.Logger.WithFields(logrus.Fields{
		"from": from,
	}).Debug("handler: received HANDSHAKE packet")
	// This is a response to our WHOAREYOU challenge

	if packet.Handshake == nil {
		return fmt.Errorf("handshake packet has no handshake data")
	}

	// Convert source node ID
	var sourceNodeID node.ID
	if len(packet.Handshake.SourceNodeID) != 32 {
		return fmt.Errorf("invalid source node ID length: %d", len(packet.Handshake.SourceNodeID))
	}
	copy(sourceNodeID[:], packet.Handshake.SourceNodeID)

	// Look up the pending challenge we sent
	challengeKey := makeHandshakeKey(sourceNodeID, from)
	h.mu.Lock()
	pendingChallenge, exists := h.pendingChallenges[challengeKey]
	if !exists {
		h.mu.Unlock()
		h.config.Logger.WithField("from", from).Debug("handler: no pending challenge found for handshake")
		return fmt.Errorf("no pending challenge for handshake from %s", from)
	}
	h.removePendingChallenge(challengeKey, pendingChallenge)
	h.mu.Unlock()

	remoteNodeFromENR, senderPubKey, err := resolveHandshakeSender(
		packet.Handshake.ENR, pendingChallenge, sourceNodeID, h.config.Logger)
	if err != nil {
		h.config.Logger.WithError(err).WithField("sourceNodeID", sourceNodeID.String()[:16]).
			Warn("handler: cannot resolve handshake sender")
		return err
	}

	// Decode ephemeral public key (for ECDH)
	ephPubKey, err := decodePublicKey(packet.Handshake.EphemeralPubKey)
	if err != nil {
		return fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	// Verify the ID signature using the sender's STATIC public key
	// The signature is over: "discovery v5 identity proof" || challenge-data || ephemeral-pubkey || dest-id
	// where challenge-data is the WHOAREYOU packet bytes and dest-id is our local node ID
	if !verifyIDSignature(senderPubKey, packet.Handshake.Signature, pendingChallenge.ChallengeData,
		packet.Handshake.EphemeralPubKey, h.config.LocalNode.ID()) {
		h.config.Logger.WithField("from", from).Warn("handler: invalid handshake signature")
		return fmt.Errorf("invalid handshake signature")
	}

	// Derive session keys
	// We are the recipient (we sent the WHOAREYOU), they are the initiator
	sessionKeys, err := deriveKeys(
		h.config.PrivateKey,            // Our private key
		ephPubKey,                      // Their ephemeral public key
		sourceNodeID,                   // Initiator ID (them)
		h.config.LocalNode.ID(),        // Recipient ID (us)
		pendingChallenge.ChallengeData, // Challenge data as salt
	)
	if err != nil {
		h.config.Logger.WithError(err).Error("handler: failed to derive session keys")
		return fmt.Errorf("failed to derive session keys: %w", err)
	}

	// Decrypt the message
	// The message was encrypted with the initiator key
	plaintext, err := session.DecryptMessage(
		sessionKeys.InitiatorKey,
		packet.Header.Nonce,
		packet.HeaderData, // IV + header + authdata used as GCM additional data
		packet.Message,
	)
	if err != nil {
		h.config.Logger.WithError(err).Error("handler: failed to decrypt handshake message")
		return fmt.Errorf("failed to decrypt handshake message: %w", err)
	}

	// Establish the session
	sess := session.NewSession(
		sourceNodeID,
		from,
		sessionKeys,
		false, // we are the recipient, not the initiator
		h.config.Sessions.Lifetime(),
	)
	h.config.Sessions.Put(sess)

	h.config.Logger.WithFields(logrus.Fields{
		"sourceNodeID": sourceNodeID.String()[:16],
		"from":         from,
	}).Debug("handler: session established successfully")

	// Store node in session and call OnHandshakeComplete callback
	if remoteNodeFromENR != nil {
		sess.SetNode(remoteNodeFromENR)
		if h.config.OnHandshakeComplete != nil {
			h.config.OnHandshakeComplete(remoteNodeFromENR, true) // incoming = true
		}
	}

	// Decode and process the message
	if len(plaintext) < 1 {
		return fmt.Errorf("handshake message too short")
	}

	msgType := plaintext[0]
	msgData := plaintext[1:]

	// Convert to Message interface and decode
	msg := h.createMessage(msgType)
	if msg == nil {
		h.config.Logger.WithField("msgType", msgType).Warn("handler: unknown message type in handshake")
		return fmt.Errorf("unknown message type: %d", msgType)
	}

	if err := rlp.DecodeBytes(msgData, msg); err != nil {
		h.config.Logger.WithError(err).Error("handler: failed to decode handshake message")
		return fmt.Errorf("failed to decode message: %w", err)
	}

	// Handle the message
	return h.handleMessage(msg, sourceNodeID, from, sess.GetNode(), localAddr)
}

// handleMessage dispatches a decoded message to the appropriate handler.
func (h *Handler) handleMessage(msg Message, remoteID node.ID, from *net.UDPAddr, remoteNode *node.Node, localAddr *net.UDPAddr) error {
	if remoteNode != nil {
		now := time.Now()
		remoteNode.SetLastSeen(now)
		remoteNode.ResetFailureCount()

		// Call OnNodeSeen callback for persistence
		if h.config.OnNodeSeen != nil {
			h.config.OnNodeSeen(remoteNode, now)
		}
	}

	switch msg.Type() {
	case PingMsg:
		return h.handlePing(msg.(*Ping), remoteID, from, remoteNode, localAddr)
	case PongMsg:
		return h.handlePong(msg.(*Pong), remoteID, from, remoteNode)
	case FindNodeMsg:
		return h.handleFindNode(msg.(*FindNode), remoteID, from, remoteNode, localAddr)
	case NodesMsg:
		return h.handleNodes(msg.(*Nodes), remoteID, from)
	case TalkReqMsg:
		return h.handleTalkReq(msg.(*TalkReq), remoteID, from, remoteNode, localAddr)
	case TalkRespMsg:
		return h.handleTalkResp(msg.(*TalkResp), remoteID, from)
	default:
		h.config.Logger.Debug("handler: unknown message type",
			"type", msg.Type(),
			"from", from,
		)
		return fmt.Errorf("unknown message type: %d", msg.Type())
	}
}

// handlePing handles a PING message.
func (h *Handler) handlePing(msg *Ping, remoteID node.ID, from *net.UDPAddr, remoteNode *node.Node, localAddr *net.UDPAddr) error {
	h.config.Logger.WithFields(logrus.Fields{
		"from":   from,
		"nodeID": remoteID,
	}).Debug("handler: received PING")

	// Check if remote has a higher ENR sequence than what we have
	if remoteNode != nil {
		if msg.ENRSeq > remoteNode.Record().Seq() {
			h.config.Logger.WithFields(logrus.Fields{
				"nodeID":   remoteID.String()[:16],
				"ourSeq":   remoteNode.Record().Seq(),
				"theirSeq": msg.ENRSeq,
			}).Debug("handler: remote has newer ENR, requesting update")
			h.requestENRUpdate(remoteNode)
		}
	}

	// Create PONG response
	pong := &Pong{
		RequestID: msg.RequestID,
		ENRSeq:    h.config.LocalNode.Record().Seq(),
		IP:        from.IP,
		Port:      uint16(from.Port),
	}

	// Send PONG
	return h.SendMessageFrom(pong, remoteID, from, nil, localAddr)
}

// handlePong handles a PONG message.
func (h *Handler) handlePong(msg *Pong, remoteID node.ID, from *net.UDPAddr, remoteNode *node.Node) error {
	h.config.Logger.WithFields(logrus.Fields{
		"from":   from,
		"nodeID": remoteID,
	}).Debug("handler: received PONG")

	// An unsolicited PONG must not reach the side effects below: OnPongReceived
	// casts a vote in the external-IP election that rewrites our published ENR,
	// and the ENR branch triggers outbound traffic.
	req := h.requests.MatchResponse(msg.RequestID, remoteID, msg)
	if req == nil {
		return nil
	}

	// The IP-discovery vote additionally requires the PONG to come from the address
	// we pinged. A session peer can send an authenticated PONG from a forged source,
	// and from.IP is what feeds the distinct-reporter threshold. Delivery above
	// stays source-agnostic so NAT rebinding and mobile peers keep working; only
	// this vote needs the endpoint proven.
	if h.config.OnPongReceived != nil && len(msg.IP) > 0 && msg.Port > 0 &&
		req.DestAddr != nil && req.DestAddr.IP.Equal(from.IP) {
		reportedIP := net.IP(msg.IP)
		h.config.OnPongReceived(remoteID, from.IP, reportedIP, msg.Port)
	}

	// Update node's last seen time
	if remoteNode != nil {
		// Check if remote has a higher ENR sequence than what we have
		if msg.ENRSeq > remoteNode.Record().Seq() {
			h.config.Logger.WithFields(logrus.Fields{
				"nodeID":   remoteID.String()[:16],
				"ourSeq":   remoteNode.Record().Seq(),
				"theirSeq": msg.ENRSeq,
			}).Debug("handler: remote has newer ENR, requesting update")
			// Request the updated ENR immediately via FINDNODE distance 0
			h.requestENRUpdate(remoteNode)
		}
	}

	return nil
}

// handleFindNode handles a FINDNODE message.
func (h *Handler) handleFindNode(msg *FindNode, remoteID node.ID, from *net.UDPAddr, remoteNode *node.Node, localAddr *net.UDPAddr) error {
	h.mu.Lock()
	h.findNodeReceived++
	h.mu.Unlock()

	h.config.Logger.WithFields(logrus.Fields{
		"from":      from,
		"nodeID":    remoteID,
		"distances": msg.Distances,
	}).Debug("handler: received FINDNODE")

	// Find closest nodes based on requested distances
	var nodes []*node.Node

	if len(msg.Distances) == 1 && msg.Distances[0] == 0 {
		// Special case: distance 0 means "return your own ENR"
		nodes = []*node.Node{h.config.LocalNode}
		h.config.Logger.WithFields(logrus.Fields{
			"from":   from,
			"nodeID": remoteID.String()[:16],
		}).Debug("handler: FINDNODE distance 0, returning our ENR")
	} else {
		// Use OnFindNode callback to get nodes (callback handles filtering)
		if h.config.OnFindNode != nil {
			nodes = h.config.OnFindNode(msg, remoteNode, from)
		}

		h.config.Logger.WithFields(logrus.Fields{
			"from":      from,
			"nodeID":    remoteID.String()[:16],
			"distances": msg.Distances,
			"found":     len(nodes),
		}).Debug("handler: FINDNODE lookup completed via callback")
	}

	// Split nodes into multiple packets if needed to stay under max packet size.
	// Each ENR is typically 200-400 bytes, so we limit to 3 nodes per packet to be safe.
	const maxNodesPerPacket = 3

	// Cap the total response so it never exceeds what real clients consume. go-ethereum
	// honours only the first packet's `total` and reads at most 5 NODES packets
	// (totalNodesResponseLimit); anything beyond that is dropped as unsolicited. sigp/discv5
	// caps at 16 nodes. Keep to <=5 packets / <=15 nodes so no served node is silently lost.
	const maxNodesPerResponse = 15
	if len(nodes) > maxNodesPerResponse {
		nodes = nodes[:maxNodesPerResponse]
	}

	// Calculate total number of packets needed
	totalPackets := (len(nodes) + maxNodesPerPacket - 1) / maxNodesPerPacket
	if totalPackets == 0 {
		totalPackets = 1 // Always send at least one response, even if empty
	}

	// Send NODES responses in chunks
	for i := 0; i < totalPackets; i++ {
		start := i * maxNodesPerPacket
		end := start + maxNodesPerPacket
		if end > len(nodes) {
			end = len(nodes)
		}

		chunk := nodes[start:end]
		records := make([]*enr.Record, len(chunk))
		for j, n := range chunk {
			records[j] = n.Record()
		}

		nodesMsg := &Nodes{
			RequestID: msg.RequestID,
			Total:     uint(totalPackets),
			Records:   records,
		}

		if err := h.SendMessageFrom(nodesMsg, remoteID, from, remoteNode, localAddr); err != nil {
			return err
		}
	}

	return nil
}

// handleNodes handles a NODES message.
func (h *Handler) handleNodes(msg *Nodes, remoteID node.ID, from *net.UDPAddr) error {
	h.config.Logger.WithFields(logrus.Fields{
		"from":   from,
		"nodeID": remoteID,
		"count":  len(msg.Records),
	}).Debug("handler: received NODES")

	// Match with pending request
	h.requests.MatchResponse(msg.RequestID, remoteID, msg)

	// Note: discovered nodes are handled by the application via the response channel
	// The bootnode service will receive these nodes and decide what to do with them
	// (add to table, filter, etc.)

	return nil
}

// handleTalkReq handles a TALKREQ message.
func (h *Handler) handleTalkReq(msg *TalkReq, remoteID node.ID, from *net.UDPAddr, remoteNode *node.Node, localAddr *net.UDPAddr) error {
	h.config.Logger.WithFields(logrus.Fields{
		"from":     from,
		"nodeID":   remoteID,
		"protocol": string(msg.Protocol),
	}).Debug("handler: received TALKREQ")

	// Use OnTalkReq callback to handle the request
	var respData []byte
	if h.config.OnTalkReq != nil {
		respData = h.config.OnTalkReq(msg)
	}

	resp := &TalkResp{
		RequestID: msg.RequestID,
		Response:  respData,
	}

	return h.SendMessageFrom(resp, remoteID, from, remoteNode, localAddr)
}

// handleTalkResp handles a TALKRESP message.
func (h *Handler) handleTalkResp(msg *TalkResp, remoteID node.ID, from *net.UDPAddr) error {
	h.config.Logger.WithFields(logrus.Fields{
		"from":   from,
		"nodeID": remoteID,
	}).Debug("handler: received TALKRESP")

	// Match with pending request
	h.requests.MatchResponse(msg.RequestID, remoteID, msg)

	return nil
}

// SendMessage sends a message to a remote node.
//
// This is a public method that can be used by higher-level services
// to send arbitrary messages through the protocol handler.
// remoteNode is optional - if provided, it will be stored in pending handshakes for WHOAREYOU responses.
func (h *Handler) SendMessage(msg Message, remoteID node.ID, to *net.UDPAddr, remoteNode *node.Node) error {
	return h.SendMessageFrom(msg, remoteID, to, remoteNode, nil)
}

// SendMessageFrom sends a message to a remote node from a specific local address.
//
// This is similar to SendMessage but allows specifying the local address to send from.
// This ensures IP address consistency when binding to 0.0.0.0 - the response is sent
// from the same address that received the request.
// remoteNode is optional - if provided, it will be stored in pending handshakes for WHOAREYOU responses.
func (h *Handler) SendMessageFrom(msg Message, remoteID node.ID, to *net.UDPAddr, remoteNode *node.Node, from *net.UDPAddr) error {
	// Look up session
	sess := h.config.Sessions.Get(remoteID)

	var packetBytes []byte
	var err error

	if sess == nil {
		// No session - send random packet to trigger WHOAREYOU from receiver

		// Store pending message for handshake completion
		// Include the node object if we have it (needed for handshake)
		handshakeKey := makeHandshakeKey(remoteID, to)
		now := time.Now()
		pending := &PendingHandshake{
			Message:    msg,
			ToNode:     remoteNode,
			ToAddr:     to,
			ToNodeID:   remoteID,
			CreatedAt:  now,
			LastRetry:  now,
			RetryCount: 0,
			MaxRetries: 3, // Retry up to 3 times before giving up
		}

		h.mu.Lock()
		accepted := h.addPendingHandshake(handshakeKey, pending)
		h.mu.Unlock()

		if !accepted {
			return fmt.Errorf("pending handshake limit reached")
		}

		// Log if we don't have node info for potential handshake
		if remoteNode == nil {
			h.config.Logger.WithField("remoteID", remoteID).Debug("handler: sending random packet without node info, may fail handshake if WHOAREYOU received")
		}

		// Encode random packet (go-ethereum style)
		// This will be 91 bytes: IV(16) + header(23) + authdata(32) + random(20)
		packetBytes, err = EncodeRandomPacket(h.config.LocalNode.ID(), remoteID)
		if err != nil {
			return fmt.Errorf("failed to encode random packet: %w", err)
		}
	} else {
		// Have session - encrypt and send normally

		// Encode message plaintext: message-type (1 byte) + RLP-encoded message
		msgBytes, err := msg.Encode()
		if err != nil {
			return fmt.Errorf("failed to encode message: %w", err)
		}

		// Build plaintext: message type + message data
		plaintext := make([]byte, 1+len(msgBytes))
		plaintext[0] = msg.Type()
		copy(plaintext[1:], msgBytes)

		// Generate nonce
		nonce, err := crypto.GenerateRandomBytes(12)
		if err != nil {
			return fmt.Errorf("failed to generate nonce: %w", err)
		}

		// Get local node ID
		localNodeID := h.config.LocalNode.ID()

		// Authdata for ordinary message with session: srcID (32 bytes)
		authdata := localNodeID[:]

		// Build unmasked header data for GCM authentication
		// This returns: maskingIV, unmasked headerData (IV || header || authdata)
		maskingIV, headerData, err := BuildOrdinaryHeaderData(localNodeID, nonce, authdata)
		if err != nil {
			return fmt.Errorf("failed to build header data: %w", err)
		}

		// Encrypt message using session key
		// GCM uses unmasked headerData as additional authenticated data
		ciphertext, err := session.EncryptMessage(sess.EncryptionKey(), nonce, headerData, plaintext)
		if err != nil {
			return fmt.Errorf("failed to encrypt message: %w", err)
		}

		// Now encode the full packet with the encrypted message
		// This uses the same maskingIV to ensure consistency
		packetBytes, err = EncodeOrdinaryPacket(localNodeID, remoteID, maskingIV, nonce, authdata, ciphertext)
		if err != nil {
			return fmt.Errorf("failed to encode ordinary packet: %w", err)
		}

		// Remembered so a WHOAREYOU quoting this nonce can be told apart from a
		// forged one; answering a forged challenge would replace the session keys.
		sess.RecordSentNonce(nonce)
	}

	// Send via UDP transport from the specified local address
	h.mu.RLock()
	transport := h.transport
	h.mu.RUnlock()

	if transport == nil {
		return fmt.Errorf("transport not initialized")
	}

	if err := transport.Send(packetBytes, to, from); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	h.mu.Lock()
	h.packetsSent++
	h.mu.Unlock()

	h.config.Logger.WithFields(logrus.Fields{
		"type":   msg.Type(),
		"to":     to,
		"from":   from,
		"nodeID": remoteID,
		"size":   len(packetBytes),
	}).Trace("sent message from specific local address")

	return nil
}

// sendWHOAREYOU sends a WHOAREYOU challenge.
// The nonce parameter must be the nonce from the client's original packet.
func (h *Handler) sendWHOAREYOU(to *net.UDPAddr, destNodeID node.ID, nonce []byte, localAddr *net.UDPAddr) error {
	// Generate random ID nonce for the challenge (16 bytes)
	idNonce, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return fmt.Errorf("failed to generate ID nonce: %w", err)
	}

	// Get the current ENR sequence we have for this node
	enrSeq := uint64(0)
	var knownNode *node.Node
	if sess := h.config.Sessions.Get(destNodeID); sess != nil {
		if existingNode := sess.GetNode(); existingNode != nil {
			knownNode = existingNode
			enrSeq = existingNode.Record().Seq()
		}
	}

	// Create WHOAREYOU challenge
	challenge := &WHOAREYOUChallenge{
		IDNonce: idNonce,
		ENRSeq:  enrSeq, // Send the ENR seq we have, so they know if we need an update
	}

	// Encode WHOAREYOU packet (go-ethereum style)
	// This will be 63 bytes: IV(16) + header(23) + authdata(24)
	packetBytes, maskingIV, err := EncodeWHOAREYOUPacket(destNodeID, nonce, challenge)
	if err != nil {
		return fmt.Errorf("failed to encode WHOAREYOU packet: %w", err)
	}

	// Build unmasked challenge data for signature verification
	// Format: IV || unmasked-header || unmasked-authdata
	// This is what the remote node will use when creating their handshake signature
	challengeData := BuildWHOAREYOUChallengeData(maskingIV, nonce, challenge)

	// Store the challenge so we can verify the handshake response
	challengeKey := makeHandshakeKey(destNodeID, to)
	pendingChallenge := &PendingChallenge{
		ToAddr:        to,
		ToNodeID:      destNodeID,
		ChallengeData: challengeData,
		PacketBytes:   packetBytes, // Store for resending
		CreatedAt:     time.Now(),
		KnownNode:     knownNode,
	}

	h.mu.Lock()
	existing := h.pendingChallenges[challengeKey]
	accepted := h.addPendingChallenge(challengeKey, pendingChallenge)
	h.mu.Unlock()

	if !accepted {
		if existing != nil {
			// Challenge already exists - resend the exact same WHOAREYOU packet
			// This handles the case where the client sent multiple concurrent requests
			// or the WHOAREYOU was lost in transit
			h.config.Logger.WithFields(logrus.Fields{
				"to":     to,
				"nodeID": destNodeID.String()[:16],
				"age":    time.Since(existing.CreatedAt),
			}).Debug("handler: resending existing WHOAREYOU challenge")

			// Get transport and resend the exact same packet
			h.mu.RLock()
			transport := h.transport
			h.mu.RUnlock()

			if transport == nil {
				return fmt.Errorf("transport not initialized")
			}

			if err := transport.Send(existing.PacketBytes, to, localAddr); err != nil {
				return fmt.Errorf("failed to resend WHOAREYOU packet: %w", err)
			}

			return nil
		}
		// Challenge rejected due to limits - still send it but won't be able to verify handshake
		h.config.Logger.WithFields(logrus.Fields{
			"to":     to,
			"nodeID": destNodeID.String()[:16],
		}).Debug("handler: pending challenge limit reached, sending WHOAREYOU anyway")
		// Continue anyway - they might retry and succeed later
	}

	// Send via UDP transport
	h.mu.RLock()
	transport := h.transport
	h.mu.RUnlock()

	if transport == nil {
		return fmt.Errorf("transport not initialized")
	}

	if err := transport.Send(packetBytes, to, localAddr); err != nil {
		return fmt.Errorf("failed to send WHOAREYOU packet: %w", err)
	}

	h.config.Logger.WithFields(logrus.Fields{
		"to":        to,
		"nodeID":    destNodeID.String()[:16],
		"enrSeq":    enrSeq,
		"idNonce":   fmt.Sprintf("%x", idNonce),
		"packetHex": fmt.Sprintf("%x", packetBytes),
		"maskingIV": fmt.Sprintf("%x", maskingIV),
		"nonce":     fmt.Sprintf("%x", nonce),
	}).Debug("handler: sent WHOAREYOU challenge")

	return nil
}

// cleanupLoop runs periodically to remove expired pending entries.
func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.cleanupExpiredEntries()
		case <-h.ctx.Done():
			return
		}
	}
}

// cleanupExpiredEntries removes expired pending handshakes and challenges.
// It also retries handshakes that haven't received a response.
func (h *Handler) cleanupExpiredEntries() {
	now := time.Now()

	h.mu.Lock()

	// Process pending handshakes - retry or remove expired
	var toRemoveHandshakes []string
	var toRetryHandshakes []*PendingHandshake
	for key, pending := range h.pendingHandshakes {
		// Check if handshake is truly expired (timeout or exceeded retries)
		if now.Sub(pending.CreatedAt) > pendingHandshakeTimeout {
			toRemoveHandshakes = append(toRemoveHandshakes, key)
		} else if pending.RetryCount < pending.MaxRetries && now.Sub(pending.LastRetry) > handshakeRetryInterval {
			// Handshake needs retry - not yet expired but no response
			toRetryHandshakes = append(toRetryHandshakes, pending)
		}
	}

	// Remove truly expired handshakes
	for _, key := range toRemoveHandshakes {
		pending := h.pendingHandshakes[key]
		h.removePendingHandshake(key, pending)
	}
	expiredHandshakes := len(toRemoveHandshakes)

	// Clean up expired pending challenges
	var toRemoveChallenges []string
	for key, pending := range h.pendingChallenges {
		if now.Sub(pending.CreatedAt) > pendingChallengeTimeout {
			toRemoveChallenges = append(toRemoveChallenges, key)
		}
	}
	for _, key := range toRemoveChallenges {
		pending := h.pendingChallenges[key]
		h.removePendingChallenge(key, pending)
	}
	expiredChallenges := len(toRemoveChallenges)

	transport := h.transport
	h.mu.Unlock()

	// Retry handshakes that need it (outside the lock to avoid blocking)
	retriedHandshakes := 0
	if transport != nil {
		for _, pending := range toRetryHandshakes {
			// Encode and resend random packet
			packetBytes, err := EncodeRandomPacket(h.config.LocalNode.ID(), pending.ToNodeID)
			if err != nil {
				h.config.Logger.WithFields(logrus.Fields{
					"nodeID": pending.ToNodeID.String()[:16],
					"error":  err,
				}).Debug("handler: failed to encode retry random packet")
				continue
			}

			if err := transport.SendTo(packetBytes, pending.ToAddr); err != nil {
				h.config.Logger.WithFields(logrus.Fields{
					"nodeID": pending.ToNodeID.String()[:16],
					"addr":   pending.ToAddr,
					"error":  err,
				}).Debug("handler: failed to send retry random packet")
				continue
			}

			// Update retry state
			h.mu.Lock()
			pending.LastRetry = now
			pending.RetryCount++
			h.packetsSent++
			h.mu.Unlock()

			retriedHandshakes++

			h.config.Logger.WithFields(logrus.Fields{
				"nodeID":     pending.ToNodeID.String()[:16],
				"addr":       pending.ToAddr,
				"retryCount": pending.RetryCount,
				"maxRetries": pending.MaxRetries,
			}).Debug("handler: retried handshake random packet")
		}
	}

	// Clean up expired sessions
	expiredSessions := h.config.Sessions.CleanupExpired()

	if expiredHandshakes > 0 || expiredChallenges > 0 || expiredSessions > 0 || retriedHandshakes > 0 {
		h.config.Logger.WithFields(logrus.Fields{
			"expiredHandshakes": expiredHandshakes,
			"expiredChallenges": expiredChallenges,
			"expiredSessions":   expiredSessions,
			"retriedHandshakes": retriedHandshakes,
		}).Debug("handler: cleaned up expired entries")
	}
}

// Requests returns the request tracker.
//
// This allows higher-level services to track pending requests.
func (h *Handler) Requests() *RequestTracker {
	return h.requests
}

// SendPing sends a PING to a remote node.
//
// Returns a channel that will receive the PONG response.
func (h *Handler) SendPing(n *node.Node) (<-chan *Response, error) {
	requestID, err := NewRequestID()
	if err != nil {
		return nil, err
	}

	ping := &Ping{
		RequestID: requestID,
		ENRSeq:    h.config.LocalNode.Record().Seq(),
	}

	// One read of the address for both the record and the send: a newer ENR can
	// move it in between, and the endpoint proof needs them to agree.
	destAddr := n.Addr()

	// Register pending request (store message and node for replay if session becomes stale)
	respChan := h.requests.AddRequest(requestID, n, ping, destAddr)

	// Send PING (pass node object so it's available for handshake if needed)
	if err := h.SendMessage(ping, n.ID(), destAddr, n); err != nil {
		h.config.Logger.WithFields(logrus.Fields{
			"to":     n.Addr(),
			"nodeID": n.ID(),
			"error":  err,
		}).Debug("handler: failed to send PING")
		h.requests.CancelRequest(requestID)
		return nil, err
	}

	h.config.Logger.WithFields(logrus.Fields{
		"to":     n.Addr(),
		"nodeID": n.ID(),
	}).Debug("handler: PING sent successfully")

	return respChan, nil
}

// requestENRUpdate sends a FINDNODE request with distance 0 to fetch the node's updated ENR.
//
// This is called when we detect that a remote node has a newer ENR sequence.
// The request is sent asynchronously and the response is handled in a goroutine.
func (h *Handler) requestENRUpdate(n *node.Node) {
	go func() {
		h.config.Logger.WithFields(logrus.Fields{
			"nodeID": n.ID().String()[:16],
			"addr":   n.Addr(),
		}).Debug("handler: requesting ENR update via FINDNODE distance 0")

		// Send FINDNODE with distance 0 (requests the node's own ENR)
		respChan, err := h.SendFindNode(n, []uint{0})
		if err != nil {
			h.config.Logger.WithFields(logrus.Fields{
				"nodeID": n.ID().String()[:16],
				"error":  err,
			}).Debug("handler: failed to request ENR update")
			return
		}

		// Wait for response with timeout
		select {
		case resp := <-respChan:
			if resp.Error != nil {
				h.config.Logger.WithFields(logrus.Fields{
					"nodeID": n.ID().String()[:16],
					"error":  resp.Error,
				}).Debug("handler: ENR update request failed")
				return
			}

			nodesMsg, ok := resp.Message.(*Nodes)
			if !ok {
				h.config.Logger.WithFields(logrus.Fields{
					"nodeID": n.ID().String()[:16],
					"type":   fmt.Sprintf("%T", resp.Message),
				}).Debug("handler: ENR update returned unexpected response")
				return
			}

			if h.applyENRUpdate(n, nodesMsg.Records) {
				h.config.Logger.WithFields(logrus.Fields{
					"nodeID": n.ID().String()[:16],
					"seq":    n.Record().Seq(),
				}).Debug("handler: installed ENR update")
			}

		case <-time.After(5 * time.Second):
			h.config.Logger.WithFields(logrus.Fields{
				"nodeID": n.ID().String()[:16],
			}).Debug("handler: ENR update request timed out")
		}
	}()
}

// resolveHandshakeSender determines which node, and therefore which static key,
// a handshake must be verified against.
//
// The record is optional in the handshake message: a peer may legally omit it
// when our WHOAREYOU advertised an ENRSeq it has nothing newer than, in which
// case the challenge's own copy is the only one left. The whole node is
// returned rather than a bare key because the session and the handshake
// callback both hang off it, and a node-less session can never refresh its ENR.
func resolveHandshakeSender(enrBytes []byte, challenge *PendingChallenge, sourceNodeID node.ID,
	logger logrus.FieldLogger,
) (*node.Node, *ecdsa.PublicKey, error) {
	var remoteNode *node.Node

	if len(enrBytes) > 0 {
		record := &enr.Record{}
		if err := record.DecodeRLPBytes(enrBytes); err != nil {
			logger.WithError(err).Warn("handler: failed to decode ENR from handshake")
		} else if n, err := node.New(record); err != nil {
			logger.WithError(err).Warn("handler: failed to create node from ENR")
		} else {
			remoteNode = n
		}
	}

	if remoteNode == nil && challenge != nil {
		remoteNode = challenge.KnownNode
	}

	if remoteNode == nil {
		return nil, nil, fmt.Errorf("no ENR provided in handshake packet")
	}

	pubKey := remoteNode.PublicKey()
	if pubKey == nil {
		return nil, nil, fmt.Errorf("handshake record carries no public key")
	}

	// The session is keyed by the claimed source ID while the signature only
	// proves possession of this key, so without binding the two a peer could
	// authenticate as itself and be filed under another node's identity.
	if node.PubkeyToID(pubKey) != sourceNodeID {
		return nil, nil, fmt.Errorf("handshake key does not match source node ID")
	}

	return remoteNode, pubKey, nil
}

// applyENRUpdate installs the newest valid record returned by a distance-zero
// FINDNODE request. A peer must not be able to replace its session record with
// another node's ENR, even though the response itself matched the pending request.
func (h *Handler) applyENRUpdate(n *node.Node, records []*enr.Record) bool {
	var newest *enr.Record

	for _, record := range records {
		candidate, err := node.New(record)
		if err != nil {
			h.config.Logger.WithError(err).Debug("handler: ignoring invalid ENR update")
			continue
		}
		if candidate.ID() != n.ID() {
			h.config.Logger.WithFields(logrus.Fields{
				"nodeID":   n.ID().String()[:16],
				"recordID": candidate.ID().String()[:16],
			}).Debug("handler: ignoring ENR update for a different node")
			continue
		}
		if newest == nil || record.Seq() > newest.Seq() {
			newest = record
		}
	}

	if newest == nil || !n.UpdateENR(newest) {
		return false
	}

	if h.config.OnNodeUpdate != nil {
		h.config.OnNodeUpdate(n)
	}
	return true
}

// SendFindNode sends a FINDNODE request.
//
// Returns a channel that will receive the NODES response.
func (h *Handler) SendFindNode(n *node.Node, distances []uint) (<-chan *Response, error) {
	requestID, err := NewRequestID()
	if err != nil {
		return nil, err
	}

	findNode := &FindNode{
		RequestID: requestID,
		Distances: distances,
	}

	destAddr := n.Addr()

	// Register pending request (store message and node for replay if session becomes stale)
	respChan := h.requests.AddRequest(requestID, n, findNode, destAddr)

	// Send FINDNODE (pass node object so it's available for handshake if needed)
	if err := h.SendMessage(findNode, n.ID(), destAddr, n); err != nil {
		h.config.Logger.WithFields(logrus.Fields{
			"to":        n.Addr(),
			"nodeID":    n.ID(),
			"distances": distances,
			"error":     err,
		}).Debug("handler: failed to send FINDNODE")
		h.requests.CancelRequest(requestID)
		return nil, err
	}

	h.config.Logger.WithFields(logrus.Fields{
		"to":        n.Addr(),
		"nodeID":    n.ID(),
		"distances": distances,
	}).Debug("handler: FINDNODE sent successfully")

	return respChan, nil
}

// GetStats returns handler statistics.
type HandlerStats struct {
	PacketsReceived    int
	PacketsSent        int
	InvalidPackets     int
	FilteredResponses  int
	FindNodeReceived   int
	PendingHandshakes  int
	PendingChallenges  int
	RejectedHandshakes int
	RejectedChallenges int
	EvictedHandshakes  int
	EvictedChallenges  int
	PendingPerIPCount  int
	RequestStats       RequestStats
}

// GetStats returns statistics about the handler.
func (h *Handler) GetStats() HandlerStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return HandlerStats{
		PacketsReceived:    h.packetsReceived,
		PacketsSent:        h.packetsSent,
		InvalidPackets:     h.invalidPackets,
		FilteredResponses:  h.filteredResponses,
		FindNodeReceived:   h.findNodeReceived,
		PendingHandshakes:  len(h.pendingHandshakes),
		PendingChallenges:  len(h.pendingChallenges),
		RejectedHandshakes: h.rejectedHandshakes,
		RejectedChallenges: h.rejectedChallenges,
		EvictedHandshakes:  h.evictedHandshakes,
		EvictedChallenges:  h.evictedChallenges,
		PendingPerIPCount:  len(h.pendingPerIP),
		RequestStats:       h.requests.GetStats(),
	}
}

// createMessage creates a Message instance based on message type.
//
// This is a simple factory that returns empty message structs.
// Full decoding would need RLP parsing of the message content.
func (h *Handler) createMessage(msgType byte) Message {
	switch msgType {
	case PingMsg:
		return &Ping{}
	case PongMsg:
		return &Pong{}
	case FindNodeMsg:
		return &FindNode{}
	case NodesMsg:
		return &Nodes{}
	case TalkReqMsg:
		return &TalkReq{}
	case TalkRespMsg:
		return &TalkResp{}
	default:
		return nil
	}
}
