package protocol

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/discv4/node"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/sirupsen/logrus"
)

// Transport interface for sending packets.
type Transport interface {
	SendTo(data []byte, to *net.UDPAddr) error
}

// Callbacks

// OnPingCallback is called when a PING request is received.
type OnPingCallback func(from *node.Node, ping *Ping) error

// OnFindnodeCallback is called when a FINDNODE request is received.
// Returns the list of nodes to include in the response.
type OnFindnodeCallback func(from *node.Node, target []byte, requester *net.UDPAddr) []*node.Node

// OnENRRequestCallback is called when an ENRREQUEST is received.
type OnENRRequestCallback func(from *node.Node) error

// OnNodeSeenCallback is called when we receive any valid packet from a node.
type OnNodeSeenCallback func(n *node.Node, timestamp time.Time)

// OnPongReceivedCallback is called when a PONG response is received.
// The ip and port parameters contain our external address as seen by the remote peer.
type OnPongReceivedCallback func(from *node.Node, ip net.IP, port uint16)

// Handler handles incoming and outgoing discv4 protocol messages.
//
// The handler is responsible for:
//   - Encoding/decoding packets
//   - Processing PING, PONG, FINDNODE, NEIGHBORS, ENRREQUEST, ENRRESPONSE
//   - Bond tracking and validation
//   - Request/response matching
//   - Callbacks for application logic
type Handler struct {
	// Configuration
	config HandlerConfig

	// Context for cancellation
	ctx context.Context

	// Transport layer
	transport Transport

	// Nodes map (node ID -> Node)
	nodesMu sync.RWMutex
	nodes   map[node.ID]*node.Node

	// Pending requests (hash -> PendingRequest)
	requestsMu sync.RWMutex
	requests   map[string]*PendingRequest

	// Pending multi-packet FINDNODE responses
	pendingNeighborsMu sync.RWMutex
	pendingNeighbors   map[string]*PendingNeighborsResponse

	// Statistics
	statsMu               sync.RWMutex
	packetsReceived       uint64
	packetsSent           uint64
	invalidPackets        uint64
	expiredPackets        uint64
	unbondedFindnode      uint64
	findnodeRequestsRecv  uint64
	findnodeResponsesRecv uint64
}

// HandlerConfig contains configuration for the protocol handler.
type HandlerConfig struct {
	// PrivateKey is our node's private key
	PrivateKey *ecdsa.PrivateKey

	// LocalENR is our node's ENR record (optional)
	LocalENR *enr.Record

	// LocalAddr is our listening address
	LocalAddr *net.UDPAddr

	// BondExpiration is how long bonds last (default 24 hours)
	BondExpiration time.Duration

	// RequestTimeout is how long to wait for responses (default 500ms)
	RequestTimeout time.Duration

	// ExpirationWindow is the acceptable time range for packet expiration (default 20s)
	ExpirationWindow time.Duration

	// Callbacks (all optional)
	OnPing         OnPingCallback
	OnPongReceived OnPongReceivedCallback
	OnFindnode     OnFindnodeCallback
	OnENRRequest   OnENRRequestCallback
	OnNodeSeen     OnNodeSeenCallback
}

// PendingRequest tracks an outgoing request waiting for a response.
type PendingRequest struct {
	// RequestHash is the hash of the outgoing packet (used as reply token)
	RequestHash []byte

	// ToNode is the destination node
	ToNode *node.Node

	// PacketType is the type of request
	PacketType byte

	// CreatedAt is when the request was created
	CreatedAt time.Time

	// Timeout is when the request expires
	Timeout time.Time

	// ResponseChan receives the response (or nil on timeout)
	ResponseChan chan interface{}
}

// PendingNeighborsResponse tracks a multi-packet NEIGHBORS response.
type PendingNeighborsResponse struct {
	// Nodes accumulated so far
	Nodes []*node.Node

	// CreatedAt is when we received the first packet
	CreatedAt time.Time

	// LastRecv is when we received the last packet
	LastRecv time.Time
}

const (
	// defaultBondExpiration is the default bond duration (24 hours)
	defaultBondExpiration = 24 * time.Hour

	// defaultRequestTimeout is the default request timeout (500ms)
	defaultRequestTimeout = 500 * time.Millisecond

	// defaultExpirationWindow is the default expiration window (20 seconds)
	defaultExpirationWindow = 20 * time.Second

	// cleanupInterval is how often we run cleanup
	cleanupInterval = 5 * time.Second

	// neighborsTimeout is how long to wait for additional NEIGHBORS packets
	neighborsTimeout = 2 * time.Second
)

// NewHandler creates a new protocol handler.
func NewHandler(ctx context.Context, config HandlerConfig, transport Transport) *Handler {
	// Set defaults
	if config.BondExpiration == 0 {
		config.BondExpiration = defaultBondExpiration
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultRequestTimeout
	}
	if config.ExpirationWindow == 0 {
		config.ExpirationWindow = defaultExpirationWindow
	}

	h := &Handler{
		config:           config,
		ctx:              ctx,
		transport:        transport,
		nodes:            make(map[node.ID]*node.Node),
		requests:         make(map[string]*PendingRequest),
		pendingNeighbors: make(map[string]*PendingNeighborsResponse),
	}

	// Start cleanup goroutine
	go h.cleanupLoop()

	return h
}

// HandlePacket processes an incoming UDP packet.
//
// This is called by the transport layer when a packet is received.
func (h *Handler) HandlePacket(data []byte, from *net.UDPAddr) error {
	h.incrementPacketsReceived()

	// Decode packet
	packet, fromKey, hash, err := Decode(data)
	if err != nil {
		h.incrementInvalidPackets()
		logrus.WithError(err).Debug("Failed to decode packet")
		return fmt.Errorf("decode error: %w", err)
	}

	// Convert public key to Node ID
	pubkey, err := DecodePubkey(crypto.S256(), fromKey)
	if err != nil {
		h.incrementInvalidPackets()
		return fmt.Errorf("invalid public key: %w", err)
	}

	fromNodeID := node.PubkeyToID(pubkey)

	// Get or create node
	fromNode := h.getOrCreateNode(fromNodeID, pubkey, from)

	// Update last seen
	fromNode.UpdateLastSeen()
	fromNode.IncrementPacketsReceived()

	// Call OnNodeSeen callback
	if h.config.OnNodeSeen != nil {
		h.config.OnNodeSeen(fromNode, time.Now())
	}

	// Dispatch by packet type
	switch p := packet.(type) {
	case *Ping:
		return h.handlePing(fromNode, from, p, hash)
	case *Pong:
		return h.handlePong(fromNode, from, p)
	case *Findnode:
		return h.handleFindnode(fromNode, from, p)
	case *Neighbors:
		return h.handleNeighbors(fromNode, from, p)
	case *ENRRequest:
		return h.handleENRRequest(fromNode, from, p, hash)
	case *ENRResponse:
		return h.handleENRResponse(fromNode, from, p)
	default:
		h.incrementInvalidPackets()
		return fmt.Errorf("unknown packet type")
	}
}

// handlePing processes a PING request.
func (h *Handler) handlePing(fromNode *node.Node, from *net.UDPAddr, ping *Ping, hash []byte) error {
	logrus.WithFields(logrus.Fields{
		"from":    from.String(),
		"node_id": fmt.Sprintf("%x", fromNode.IDBytes()[:8]),
		"version": ping.Version,
		"enr_seq": ping.ENRSeq,
	}).Debug("Received PING")

	// Check expiration
	if Expired(ping.Expiration) {
		h.incrementExpiredPackets()
		return ErrExpired
	}

	// Mark ping received
	fromNode.MarkPingReceived()

	// Call callback
	if h.config.OnPing != nil {
		if err := h.config.OnPing(fromNode, ping); err != nil {
			return err
		}
	}

	// Send PONG response
	return h.sendPong(fromNode, from, hash)
}

// handlePong processes a PONG response.
func (h *Handler) handlePong(fromNode *node.Node, from *net.UDPAddr, pong *Pong) error {
	logrus.WithFields(logrus.Fields{
		"from":    from.String(),
		"node_id": fmt.Sprintf("%x", fromNode.IDBytes()[:8]),
		"enr_seq": pong.ENRSeq,
	}).Debug("Received PONG")

	// Check expiration
	if Expired(pong.Expiration) {
		h.incrementExpiredPackets()
		return ErrExpired
	}

	// Mark pong received (establishes bond)
	fromNode.MarkPongReceived(h.config.BondExpiration)

	// Call OnPongReceived callback with the IP and port reported in the PONG
	// The To field in PONG contains our address as seen by the remote peer
	if h.config.OnPongReceived != nil && pong.To.IP != nil && pong.To.UDP > 0 {
		h.config.OnPongReceived(fromNode, pong.To.IP, pong.To.UDP)
	}

	// Match to pending request
	req := h.getPendingRequest(string(pong.ReplyTok))
	if req != nil {
		req.ResponseChan <- pong
	}

	// Check if remote node has newer ENR
	if pong.ENRSeq > 0 && fromNode.ENR() != nil {
		if pong.ENRSeq > fromNode.ENR().Seq() {
			// Request updated ENR
			go h.RequestENR(fromNode)
		}
	}

	return nil
}

// handleFindnode processes a FINDNODE request.
func (h *Handler) handleFindnode(fromNode *node.Node, from *net.UDPAddr, findnode *Findnode) error {
	logrus.WithFields(logrus.Fields{
		"from":    from.String(),
		"node_id": fmt.Sprintf("%x", fromNode.IDBytes()[:8]),
		"target":  fmt.Sprintf("%x", findnode.Target[:8]),
	}).Debug("Received FINDNODE")

	// Check expiration
	if Expired(findnode.Expiration) {
		h.incrementExpiredPackets()
		return ErrExpired
	}

	// Check if node is bonded
	if !fromNode.IsBonded() {
		h.incrementUnbondedFindnode()
		logrus.WithField("node_id", fmt.Sprintf("%x", fromNode.IDBytes()[:8])).
			Debug("Rejected FINDNODE from unbonded node")
		return fmt.Errorf("node not bonded")
	}

	h.incrementFindnodeRequestsRecv()

	// Call callback to get nodes
	var nodes []*node.Node
	if h.config.OnFindnode != nil {
		targetID := findnode.Target.ID()
		nodes = h.config.OnFindnode(fromNode, targetID, from)
	}

	// Send NEIGHBORS response(s)
	return h.sendNeighbors(fromNode, from, nodes)
}

// handleNeighbors processes a NEIGHBORS response.
func (h *Handler) handleNeighbors(fromNode *node.Node, from *net.UDPAddr, neighbors *Neighbors) error {
	logrus.WithFields(logrus.Fields{
		"from":       from.String(),
		"node_id":    fmt.Sprintf("%x", fromNode.IDBytes()[:8]),
		"node_count": len(neighbors.Nodes),
	}).Debug("Received NEIGHBORS")

	// Check expiration
	if Expired(neighbors.Expiration) {
		h.incrementExpiredPackets()
		return ErrExpired
	}

	h.incrementFindnodeResponsesRecv()

	// Convert nodes
	nodes := make([]*node.Node, 0, len(neighbors.Nodes))
	for _, n := range neighbors.Nodes {
		pubkey, err := DecodePubkey(crypto.S256(), n.ID)
		if err != nil {
			logrus.WithError(err).Debug("Invalid node public key in NEIGHBORS")
			continue
		}

		addr := &net.UDPAddr{
			IP:   n.IP,
			Port: int(n.UDP),
		}

		nodeID := node.PubkeyToID(pubkey)
		discoveredNode := h.getOrCreateNode(nodeID, pubkey, addr)
		nodes = append(nodes, discoveredNode)
	}

	// Try to match to pending request
	// We use the sender's node ID as the key for pending FINDNODE requests
	key := string(fromNode.IDBytes())

	h.pendingNeighborsMu.Lock()
	pending := h.pendingNeighbors[key]
	if pending == nil {
		pending = &PendingNeighborsResponse{
			Nodes:     nodes,
			CreatedAt: time.Now(),
			LastRecv:  time.Now(),
		}
		h.pendingNeighbors[key] = pending
	} else {
		pending.Nodes = append(pending.Nodes, nodes...)
		pending.LastRecv = time.Now()
	}
	h.pendingNeighborsMu.Unlock()

	// Check if we have a pending request waiting for this
	h.requestsMu.RLock()
	var matchedReq *PendingRequest
	for _, req := range h.requests {
		if req.PacketType == FindnodePacket && req.ToNode.ID() == fromNode.ID() {
			matchedReq = req
			break
		}
	}
	h.requestsMu.RUnlock()

	if matchedReq != nil {
		// Deliver accumulated nodes after a short delay
		// (in case more NEIGHBORS packets arrive)
		go func() {
			time.Sleep(100 * time.Millisecond)

			h.pendingNeighborsMu.Lock()
			finalPending := h.pendingNeighbors[key]
			delete(h.pendingNeighbors, key)
			h.pendingNeighborsMu.Unlock()

			if finalPending != nil {
				matchedReq.ResponseChan <- finalPending.Nodes
			}
		}()
	}

	return nil
}

// handleENRRequest processes an ENRREQUEST.
func (h *Handler) handleENRRequest(fromNode *node.Node, from *net.UDPAddr, req *ENRRequest, hash []byte) error {
	logrus.WithFields(logrus.Fields{
		"from":    from.String(),
		"node_id": fmt.Sprintf("%x", fromNode.IDBytes()[:8]),
	}).Debug("Received ENRREQUEST")

	// Check expiration
	if Expired(req.Expiration) {
		h.incrementExpiredPackets()
		return ErrExpired
	}

	// Call callback
	if h.config.OnENRRequest != nil {
		if err := h.config.OnENRRequest(fromNode); err != nil {
			return err
		}
	}

	// Send ENRResponse
	return h.sendENRResponse(fromNode, from, hash)
}

// handleENRResponse processes an ENRRESPONSE.
func (h *Handler) handleENRResponse(fromNode *node.Node, from *net.UDPAddr, resp *ENRResponse) error {
	logrus.WithFields(logrus.Fields{
		"from":    from.String(),
		"node_id": fmt.Sprintf("%x", fromNode.IDBytes()[:8]),
		"enr_seq": resp.Record.Seq(),
	}).Debug("Received ENRRESPONSE")

	// Update node's ENR
	fromNode.SetENR(resp.Record)

	// Match to pending request
	req := h.getPendingRequest(string(resp.ReplyTok))
	if req != nil {
		req.ResponseChan <- resp.Record
	}

	return nil
}

// Sending Methods

// Ping sends a PING request to a node.
func (h *Handler) Ping(n *node.Node) (*Pong, error) {
	// Build PING message
	ping := &Ping{
		Version:    4,
		From:       NewEndpoint(h.config.LocalAddr, uint16(h.config.LocalAddr.Port)),
		To:         NewEndpoint(n.Addr(), uint16(n.Addr().Port)),
		Expiration: MakeExpiration(h.config.ExpirationWindow),
	}

	// Add ENR sequence if we have an ENR
	if h.config.LocalENR != nil {
		ping.ENRSeq = h.config.LocalENR.Seq()
	}

	// Encode packet
	packet, hash, err := Encode(h.config.PrivateKey, ping)
	if err != nil {
		return nil, fmt.Errorf("encode error: %w", err)
	}

	// Register pending request
	req := h.addPendingRequest(hash, n, PingPacket)

	// Send packet
	if err := h.transport.SendTo(packet, n.Addr()); err != nil {
		h.removePendingRequest(string(hash))
		return nil, err
	}

	h.incrementPacketsSent()
	n.IncrementPacketsSent()
	n.MarkPingSent()

	// Wait for response
	select {
	case resp := <-req.ResponseChan:
		if pong, ok := resp.(*Pong); ok {
			// Wait for the remote node to ping us back and process our PONG response.
			// This is critical for the bond handshake to complete on the remote side.
			// Without this wait, subsequent FINDNODE/ENRREQUEST may be rejected as unbonded.
			// Match go-ethereum's ensureBond behavior (respTimeout = 500ms).
			time.Sleep(500 * time.Millisecond)
			return pong, nil
		}
		return nil, fmt.Errorf("unexpected response type")
	case <-time.After(h.config.RequestTimeout):
		h.removePendingRequest(string(hash))
		n.MarkTimeout()
		return nil, fmt.Errorf("timeout")
	case <-h.ctx.Done():
		h.removePendingRequest(string(hash))
		return nil, h.ctx.Err()
	}
}

// Findnode sends a FINDNODE request to a node.
func (h *Handler) Findnode(n *node.Node, target []byte) ([]*node.Node, error) {
	// Check if node is bonded
	if !n.IsBonded() {
		// Establish bond first
		if _, err := h.Ping(n); err != nil {
			return nil, fmt.Errorf("failed to establish bond: %w", err)
		}
	}

	// Build FINDNODE message
	var targetPubkey Pubkey
	copy(targetPubkey[:], target)

	findnode := &Findnode{
		Target:     targetPubkey,
		Expiration: MakeExpiration(h.config.ExpirationWindow),
	}

	// Encode packet
	packet, hash, err := Encode(h.config.PrivateKey, findnode)
	if err != nil {
		return nil, fmt.Errorf("encode error: %w", err)
	}

	// Register pending request
	req := h.addPendingRequest(hash, n, FindnodePacket)

	// Send packet
	if err := h.transport.SendTo(packet, n.Addr()); err != nil {
		h.removePendingRequest(string(hash))
		return nil, err
	}

	h.incrementPacketsSent()
	n.IncrementPacketsSent()

	// Wait for response (NEIGHBORS may arrive in multiple packets)
	select {
	case resp := <-req.ResponseChan:
		if nodes, ok := resp.([]*node.Node); ok {
			return nodes, nil
		}
		return nil, fmt.Errorf("unexpected response type")
	case <-time.After(h.config.RequestTimeout * 3): // Longer timeout for multi-packet responses
		h.removePendingRequest(string(hash))
		n.MarkTimeout()
		return nil, fmt.Errorf("timeout")
	case <-h.ctx.Done():
		h.removePendingRequest(string(hash))
		return nil, h.ctx.Err()
	}
}

// RequestENR sends an ENRREQUEST to a node.
func (h *Handler) RequestENR(n *node.Node) (*enr.Record, error) {
	// Check if node is bonded
	if !n.IsBonded() {
		// Establish bond first
		if _, err := h.Ping(n); err != nil {
			return nil, fmt.Errorf("failed to establish bond: %w", err)
		}
	}

	// Build ENRREQUEST message
	req := &ENRRequest{
		Expiration: MakeExpiration(h.config.ExpirationWindow),
	}

	// Encode packet
	packet, hash, err := Encode(h.config.PrivateKey, req)
	if err != nil {
		return nil, fmt.Errorf("encode error: %w", err)
	}

	// Register pending request
	pendingReq := h.addPendingRequest(hash, n, ENRRequestPacket)

	// Send packet
	if err := h.transport.SendTo(packet, n.Addr()); err != nil {
		h.removePendingRequest(string(hash))
		return nil, err
	}

	h.incrementPacketsSent()
	n.IncrementPacketsSent()

	// Wait for response
	select {
	case resp := <-pendingReq.ResponseChan:
		if record, ok := resp.(*enr.Record); ok {
			return record, nil
		}
		return nil, fmt.Errorf("unexpected response type")
	case <-time.After(h.config.RequestTimeout):
		h.removePendingRequest(string(hash))
		n.MarkTimeout()
		return nil, fmt.Errorf("timeout")
	case <-h.ctx.Done():
		h.removePendingRequest(string(hash))
		return nil, h.ctx.Err()
	}
}

// sendPong sends a PONG response.
func (h *Handler) sendPong(to *node.Node, addr *net.UDPAddr, replyTok []byte) error {
	pong := &Pong{
		To:         NewEndpoint(addr, uint16(addr.Port)),
		ReplyTok:   replyTok,
		Expiration: MakeExpiration(h.config.ExpirationWindow),
	}

	// Add ENR sequence if we have an ENR
	if h.config.LocalENR != nil {
		pong.ENRSeq = h.config.LocalENR.Seq()
	}

	packet, _, err := Encode(h.config.PrivateKey, pong)
	if err != nil {
		return err
	}

	if err := h.transport.SendTo(packet, addr); err != nil {
		return err
	}

	h.incrementPacketsSent()
	to.IncrementPacketsSent()
	to.MarkPongSent()

	return nil
}

// sendNeighbors sends NEIGHBORS response(s).
func (h *Handler) sendNeighbors(to *node.Node, addr *net.UDPAddr, nodes []*node.Node) error {
	// Split nodes into packets of MaxNeighbors
	for i := 0; i < len(nodes); i += MaxNeighbors {
		end := i + MaxNeighbors
		if end > len(nodes) {
			end = len(nodes)
		}

		batch := nodes[i:end]
		nodeRecords := make([]NodeRecord, len(batch))

		for j, n := range batch {
			nodeRecords[j] = NodeRecord{
				IP:  n.Addr().IP,
				UDP: uint16(n.Addr().Port),
				TCP: uint16(n.Addr().Port),
				ID:  EncodePubkey(n.PublicKey()),
			}
		}

		neighbors := &Neighbors{
			Nodes:      nodeRecords,
			Expiration: MakeExpiration(h.config.ExpirationWindow),
		}

		packet, _, err := Encode(h.config.PrivateKey, neighbors)
		if err != nil {
			return err
		}

		if err := h.transport.SendTo(packet, addr); err != nil {
			return err
		}

		h.incrementPacketsSent()
		to.IncrementPacketsSent()
	}

	return nil
}

// sendENRResponse sends an ENRRESPONSE.
func (h *Handler) sendENRResponse(to *node.Node, addr *net.UDPAddr, replyTok []byte) error {
	if h.config.LocalENR == nil {
		return fmt.Errorf("no local ENR configured")
	}

	resp := &ENRResponse{
		ReplyTok: replyTok,
		Record:   h.config.LocalENR,
	}

	packet, _, err := Encode(h.config.PrivateKey, resp)
	if err != nil {
		return err
	}

	if err := h.transport.SendTo(packet, addr); err != nil {
		return err
	}

	h.incrementPacketsSent()
	to.IncrementPacketsSent()

	return nil
}

// Node Management

// getOrCreateNode gets an existing node or creates a new one.
func (h *Handler) getOrCreateNode(id node.ID, pubkey *ecdsa.PublicKey, addr *net.UDPAddr) *node.Node {
	h.nodesMu.Lock()
	defer h.nodesMu.Unlock()

	n, exists := h.nodes[id]
	if exists {
		// Update address if changed
		if n.Addr().String() != addr.String() {
			n.SetAddr(addr)
		}
		return n
	}

	// Create new node
	n = node.New(pubkey, addr)
	h.nodes[id] = n
	return n
}

// GetNode returns a node by ID.
func (h *Handler) GetNode(id node.ID) *node.Node {
	h.nodesMu.RLock()
	defer h.nodesMu.RUnlock()
	return h.nodes[id]
}

// AllNodes returns all known nodes.
func (h *Handler) AllNodes() []*node.Node {
	h.nodesMu.RLock()
	defer h.nodesMu.RUnlock()

	nodes := make([]*node.Node, 0, len(h.nodes))
	for _, n := range h.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// Request Tracking

// addPendingRequest registers a new pending request.
func (h *Handler) addPendingRequest(hash []byte, toNode *node.Node, packetType byte) *PendingRequest {
	req := &PendingRequest{
		RequestHash:  hash,
		ToNode:       toNode,
		PacketType:   packetType,
		CreatedAt:    time.Now(),
		Timeout:      time.Now().Add(h.config.RequestTimeout),
		ResponseChan: make(chan interface{}, 1),
	}

	h.requestsMu.Lock()
	h.requests[string(hash)] = req
	h.requestsMu.Unlock()

	return req
}

// getPendingRequest retrieves a pending request by hash.
func (h *Handler) getPendingRequest(hash string) *PendingRequest {
	h.requestsMu.RLock()
	defer h.requestsMu.RUnlock()
	return h.requests[hash]
}

// removePendingRequest removes a pending request.
func (h *Handler) removePendingRequest(hash string) {
	h.requestsMu.Lock()
	delete(h.requests, hash)
	h.requestsMu.Unlock()
}

// Cleanup

// cleanupLoop periodically cleans up expired requests and neighbors.
func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.cleanup()
		case <-h.ctx.Done():
			return
		}
	}
}

// cleanup removes expired entries.
func (h *Handler) cleanup() {
	now := time.Now()

	// Clean up expired requests
	h.requestsMu.Lock()
	for hash, req := range h.requests {
		if now.After(req.Timeout) {
			delete(h.requests, hash)
		}
	}
	h.requestsMu.Unlock()

	// Clean up old pending neighbors
	h.pendingNeighborsMu.Lock()
	for key, pending := range h.pendingNeighbors {
		if now.Sub(pending.LastRecv) > neighborsTimeout {
			delete(h.pendingNeighbors, key)
		}
	}
	h.pendingNeighborsMu.Unlock()
}

// Statistics

func (h *Handler) incrementPacketsReceived() {
	h.statsMu.Lock()
	h.packetsReceived++
	h.statsMu.Unlock()
}

func (h *Handler) incrementPacketsSent() {
	h.statsMu.Lock()
	h.packetsSent++
	h.statsMu.Unlock()
}

func (h *Handler) incrementInvalidPackets() {
	h.statsMu.Lock()
	h.invalidPackets++
	h.statsMu.Unlock()
}

func (h *Handler) incrementExpiredPackets() {
	h.statsMu.Lock()
	h.expiredPackets++
	h.statsMu.Unlock()
}

func (h *Handler) incrementUnbondedFindnode() {
	h.statsMu.Lock()
	h.unbondedFindnode++
	h.statsMu.Unlock()
}

func (h *Handler) incrementFindnodeRequestsRecv() {
	h.statsMu.Lock()
	h.findnodeRequestsRecv++
	h.statsMu.Unlock()
}

func (h *Handler) incrementFindnodeResponsesRecv() {
	h.statsMu.Lock()
	h.findnodeResponsesRecv++
	h.statsMu.Unlock()
}

// Stats returns current statistics.
func (h *Handler) Stats() map[string]interface{} {
	h.statsMu.RLock()
	defer h.statsMu.RUnlock()

	return map[string]interface{}{
		"packets_received":        h.packetsReceived,
		"packets_sent":            h.packetsSent,
		"invalid_packets":         h.invalidPackets,
		"expired_packets":         h.expiredPackets,
		"unbonded_findnode":       h.unbondedFindnode,
		"findnode_requests_recv":  h.findnodeRequestsRecv,
		"findnode_responses_recv": h.findnodeResponsesRecv,
		"known_nodes":             len(h.nodes),
		"pending_requests":        len(h.requests),
		"pending_neighbors":       len(h.pendingNeighbors),
	}
}
