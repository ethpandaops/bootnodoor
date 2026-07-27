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
	Send(data []byte, to *net.UDPAddr, from *net.UDPAddr) error
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

	// MaxNodes is the maximum number of nodes to track (default 50000).
	// Once reached, new nodes are handled but not retained until a slot frees up,
	// keeping memory bounded under floods of distinct node IDs.
	MaxNodes int

	// NodeTTL is how long an unbonded node is retained since it was last seen
	// before it becomes eligible for eviction (default 5 minutes). Bonded nodes
	// are kept until their bond expires.
	NodeTTL time.Duration

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

	// Reserved counts nodes a handler has claimed room for but may not have
	// appended yet. Reserving before decoding makes the persistence cap exact
	// even when packets are dispatched concurrently.
	Reserved int

	// Closed marks a delivered entry. Packets processed after delivery must
	// not reserve against it; cleanup evicts the tombstone by CreatedAt.
	Closed bool

	// CreatedAt is when we received the first packet
	CreatedAt time.Time
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

	// neighborsTimeout is how long a pending NEIGHBORS entry may live before
	// cleanup evicts it as a backstop.
	neighborsTimeout = 2 * time.Second

	// defaultMaxNodes is the default cap on tracked nodes. It bounds memory
	// against floods of distinct node IDs (for example fabricated NEIGHBORS
	// records) that would otherwise grow the map without limit.
	defaultMaxNodes = 50000

	// defaultNodeTTL is how long an unbonded node is retained since it was last
	// seen before it becomes eligible for eviction.
	defaultNodeTTL = 5 * time.Minute

	// neighborsCollectWindow is how long we accumulate multi-packet NEIGHBORS
	// before delivering the collected nodes to the waiting FINDNODE.
	neighborsCollectWindow = 100 * time.Millisecond

	// maxNeighborsPerResponse caps the nodes accumulated for one FINDNODE. A
	// discv4 FINDNODE returns at most one k-bucket, so anything beyond this is a
	// flood and is dropped.
	maxNeighborsPerResponse = 16
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
	if config.MaxNodes == 0 {
		config.MaxNodes = defaultMaxNodes
	}
	if config.NodeTTL == 0 {
		config.NodeTTL = defaultNodeTTL
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
// The localAddr parameter is the local address that received the packet.
func (h *Handler) HandlePacket(data []byte, from *net.UDPAddr, localAddr *net.UDPAddr) (err error) {
	// Recover from panics
	defer func() {
		if r := recover(); r != nil {
			logrus.WithFields(logrus.Fields{
				"from":  from,
				"panic": r,
			}).Error("discv4: PANIC in HandlePacket!")
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	h.incrementPacketsReceived()

	// Decode packet
	packet, fromKey, hash, err := Decode(data)
	if err != nil {
		h.incrementInvalidPackets()
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
		return h.handlePing(fromNode, from, localAddr, p, hash)
	case *Pong:
		return h.handlePong(fromNode, from, p)
	case *Findnode:
		return h.handleFindnode(fromNode, from, localAddr, p)
	case *Neighbors:
		return h.handleNeighbors(fromNode, from, p)
	case *ENRRequest:
		return h.handleENRRequest(fromNode, from, localAddr, p, hash)
	case *ENRResponse:
		return h.handleENRResponse(fromNode, from, p)
	default:
		h.incrementInvalidPackets()
		return fmt.Errorf("unknown packet type")
	}
}

// handlePing processes a PING request.
func (h *Handler) handlePing(fromNode *node.Node, from *net.UDPAddr, localAddr *net.UDPAddr, ping *Ping, hash []byte) error {
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
	if err := h.sendPong(fromNode, from, localAddr, hash); err != nil {
		return err
	}

	// Mark node as bonded: they pinged us, we ponged them.
	// This allows THEM to query US with FINDNODE immediately.
	fromNode.MarkPongReceived(h.config.BondExpiration)

	// IMPORTANT: For bidirectional bonding (required by strict clients like reth for ENRRequest),
	// we also need to establish that WE can reach THEM, not just that they can reach us.
	// Send a PING back to them to establish bidirectional bond.
	//
	// RATE LIMITING: Only send PING back if we haven't pinged them in the last 100ms.
	// This prevents ping-pong loops (max 10 pings/sec per node).
	lastPingSent := fromNode.LastPingSent()
	timeSinceLastPing := time.Since(lastPingSent)

	// Only spawn goroutine if we're actually going to ping (don't create unnecessary goroutines)
	if timeSinceLastPing > 100*time.Millisecond {
		// Send PING back in goroutine to establish bidirectional bond
		go func() {
			if _, err := h.Ping(fromNode); err != nil {
				logrus.WithFields(logrus.Fields{
					"node_id": fmt.Sprintf("%x", fromNode.IDBytes()[:8]),
					"error":   err,
				}).Trace("Failed to ping node for bidirectional bond")
			}
		}()
	}

	return nil
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
		h.deliverResponse(req, pong)
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
func (h *Handler) handleFindnode(fromNode *node.Node, from *net.UDPAddr, localAddr *net.UDPAddr, findnode *Findnode) error {
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
	return h.sendNeighbors(fromNode, from, localAddr, nodes)
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

	// Only accept NEIGHBORS in response to a FINDNODE we actually sent to this
	// node. Dropping unsolicited NEIGHBORS prevents a peer we never queried from
	// making us accumulate node records without bound.
	matchedReq := h.findPendingFindnode(fromNode.ID())
	if matchedReq == nil {
		return nil
	}

	// Accumulate the response, keyed by the matched request's hash so each
	// FINDNODE gets exactly one entry and a fresh request never collides with
	// a delivered one. Room is reserved before decoding, so records past the
	// cap are never persisted in the global node map, even when packets are
	// dispatched concurrently.
	key := string(matchedReq.RequestHash)

	h.pendingNeighborsMu.Lock()
	pending := h.pendingNeighbors[key]
	if pending != nil && pending.Closed {
		h.pendingNeighborsMu.Unlock()
		return nil
	}
	firstPacket := pending == nil
	if firstPacket {
		pending = &PendingNeighborsResponse{CreatedAt: time.Now()}
		h.pendingNeighbors[key] = pending
	}
	take := min(len(neighbors.Nodes), maxNeighborsPerResponse-pending.Reserved)
	pending.Reserved += take
	h.pendingNeighborsMu.Unlock()

	nodes := make([]*node.Node, 0, take)
	for _, n := range neighbors.Nodes {
		if len(nodes) >= take {
			break
		}
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
		nodes = append(nodes, h.getOrCreateNode(nodeID, pubkey, addr))
	}

	h.pendingNeighborsMu.Lock()
	if p := h.pendingNeighbors[key]; p != nil && !p.Closed {
		p.Nodes = append(p.Nodes, nodes...)
	}
	h.pendingNeighborsMu.Unlock()

	// Deliver once, after a short window that lets multi-packet responses
	// arrive. Only the first packet schedules delivery, so a flood cannot spawn
	// a goroutine per packet.
	if firstPacket {
		go func() {
			time.Sleep(neighborsCollectWindow)

			h.pendingNeighborsMu.Lock()
			finalPending := h.pendingNeighbors[key]
			var collected []*node.Node
			if finalPending != nil {
				finalPending.Closed = true
				collected = finalPending.Nodes
			}
			h.pendingNeighborsMu.Unlock()

			if finalPending != nil {
				h.deliverResponse(matchedReq, collected)
			}
		}()
	}

	return nil
}

// handleENRRequest processes an ENRREQUEST.
func (h *Handler) handleENRRequest(fromNode *node.Node, from *net.UDPAddr, localAddr *net.UDPAddr, req *ENRRequest, hash []byte) error {
	logrus.WithFields(logrus.Fields{
		"from":    from.String(),
		"node_id": fmt.Sprintf("%x", fromNode.IDBytes()[:8]),
	}).Debug("Received ENRREQUEST")

	// Check expiration
	if Expired(req.Expiration) {
		h.incrementExpiredPackets()
		return ErrExpired
	}

	// IMPORTANT: Check if node is bonded (bidirectional bond required)
	// This prevents amplification attacks and matches reth's behavior.
	// Only respond to ENRRequest if we've established a bidirectional bond:
	// - We sent them a PING
	// - They sent us a PONG
	if !fromNode.IsBonded() {
		logrus.WithFields(logrus.Fields{
			"from":    from.String(),
			"node_id": fmt.Sprintf("%x", fromNode.IDBytes()[:8]),
		}).Debug("Ignoring ENRREQUEST from unbonded node")
		return fmt.Errorf("node not bonded")
	}

	// Call callback
	if h.config.OnENRRequest != nil {
		if err := h.config.OnENRRequest(fromNode); err != nil {
			return err
		}
	}

	// Send ENRResponse
	return h.sendENRResponse(fromNode, from, localAddr, hash)
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
		h.deliverResponse(req, resp.Record)
	}

	return nil
}

// Sending Methods

// Ping sends a PING request to a node.
func (h *Handler) Ping(n *node.Node) (*Pong, error) {
	// Build PING message
	ping := &Ping{
		Version: 4,
		// A bootnode serves no RLPx, so it advertises tcp-port 0; the recipient's
		// tcp is not the sender's to set (spec: to = [ip, udp-port, 0]).
		From:       NewEndpoint(h.config.LocalAddr, 0),
		To:         NewEndpoint(n.Addr(), 0),
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

	// Register pending request; removal is deferred so every exit path clears it.
	req := h.addPendingRequest(hash, n, PingPacket)
	defer h.removePendingRequest(string(hash))

	// Send packet
	if err := h.transport.SendTo(packet, n.Addr()); err != nil {
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
		n.MarkTimeout()
		return nil, fmt.Errorf("timeout")
	case <-h.ctx.Done():
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

	// Register pending request. Removal is deferred so every exit path clears
	// it: a completed request left in the map keeps matching later NEIGHBORS
	// from that node and reopens collection windows until cleanup runs.
	req := h.addPendingRequest(hash, n, FindnodePacket)
	defer h.removePendingRequest(string(hash))

	// Send packet
	if err := h.transport.SendTo(packet, n.Addr()); err != nil {
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
		n.MarkTimeout()
		return nil, fmt.Errorf("timeout")
	case <-h.ctx.Done():
		return nil, h.ctx.Err()
	}
}

// RequestENR sends an ENRREQUEST to a node.
func (h *Handler) RequestENR(n *node.Node) (*enr.Record, error) {
	// IMPORTANT: Some clients (like reth) require bidirectional bonding before responding to ENRRequest.
	// Bidirectional bond means BOTH:
	// 1. They ping us, we pong them (allows them to query us with FINDNODE)
	// 2. We ping them, they pong us (allows us to query them with ENRREQUEST)
	//
	// Always ping before ENRRequest to ensure bidirectional bond, even if IsBonded() returns true
	// (since IsBonded() only checks if they've pinged us, not if we've pinged them).
	if _, err := h.Ping(n); err != nil {
		return nil, fmt.Errorf("failed to establish bidirectional bond: %w", err)
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

	// Register pending request; removal is deferred so every exit path clears it.
	pendingReq := h.addPendingRequest(hash, n, ENRRequestPacket)
	defer h.removePendingRequest(string(hash))

	// Send packet
	if err := h.transport.SendTo(packet, n.Addr()); err != nil {
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
		n.MarkTimeout()
		return nil, fmt.Errorf("timeout")
	case <-h.ctx.Done():
		return nil, h.ctx.Err()
	}
}

// sendPong sends a PONG response.
func (h *Handler) sendPong(to *node.Node, addr *net.UDPAddr, localAddr *net.UDPAddr, replyTok []byte) error {
	pong := &Pong{
		To:         NewEndpoint(addr, 0),
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

	if err := h.transport.Send(packet, addr, localAddr); err != nil {
		return err
	}

	h.incrementPacketsSent()
	to.IncrementPacketsSent()
	to.MarkPongSent()

	return nil
}

// sendNeighbors sends NEIGHBORS response(s).
func (h *Handler) sendNeighbors(to *node.Node, addr *net.UDPAddr, localAddr *net.UDPAddr, nodes []*node.Node) error {
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

		if err := h.transport.Send(packet, addr, localAddr); err != nil {
			return err
		}

		h.incrementPacketsSent()
		to.IncrementPacketsSent()
	}

	return nil
}

// sendENRResponse sends an ENRRESPONSE.
func (h *Handler) sendENRResponse(to *node.Node, addr *net.UDPAddr, localAddr *net.UDPAddr, replyTok []byte) error {
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

	if err := h.transport.Send(packet, addr, localAddr); err != nil {
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

	// Create new node. Stamp last-seen with the insertion time: a node learned
	// from a NEIGHBORS record has never sent us a packet, and a zero timestamp
	// would make cleanup evict it on its next run regardless of NodeTTL.
	n = node.New(pubkey, addr)
	n.UpdateLastSeen()

	// Bound the map so an unauthenticated flood of distinct node IDs (for
	// example fabricated NEIGHBORS records) cannot grow it without limit. Stale
	// unbonded entries are reclaimed by cleanup; until a slot frees up we still
	// return the node so the packet is handled, but we do not retain it.
	if len(h.nodes) >= h.config.MaxNodes {
		return n
	}

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

// findPendingFindnode returns a pending FINDNODE request awaiting a response
// from the given node, or nil if none exists.
func (h *Handler) findPendingFindnode(id node.ID) *PendingRequest {
	h.requestsMu.RLock()
	defer h.requestsMu.RUnlock()
	for _, req := range h.requests {
		if req.PacketType == FindnodePacket && req.ToNode != nil && req.ToNode.ID() == id {
			return req
		}
	}
	return nil
}

// removePendingRequest removes a pending request.
func (h *Handler) removePendingRequest(hash string) {
	h.requestsMu.Lock()
	delete(h.requests, hash)
	h.requestsMu.Unlock()
}

// deliverResponse hands a response to a waiting request without blocking.
//
// ResponseChan is buffered (size 1) and read at most once by the waiter. A
// duplicate, replayed or late response therefore finds the buffer full or the
// waiter already gone. Sending directly would park the packet-dispatch
// goroutine forever, so an unauthenticated peer could leak goroutines by
// replaying responses. The non-blocking send drops the extra response instead.
func (h *Handler) deliverResponse(req *PendingRequest, resp interface{}) {
	select {
	case req.ResponseChan <- resp:
	default:
	}
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
		if now.Sub(pending.CreatedAt) > neighborsTimeout {
			delete(h.pendingNeighbors, key)
		}
	}
	h.pendingNeighborsMu.Unlock()

	// Evict stale, unbonded nodes so the map stays bounded. Bonded nodes are
	// kept until their bond expires, after which IsBonded reports false and they
	// become eligible here.
	h.nodesMu.Lock()
	for id, n := range h.nodes {
		if !n.IsBonded() && now.Sub(n.LastSeen()) > h.config.NodeTTL {
			delete(h.nodes, id)
		}
	}
	h.nodesMu.Unlock()
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

// HandlerStats is a snapshot of the handler's counters.
type HandlerStats struct {
	PacketsReceived       uint64
	PacketsSent           uint64
	InvalidPackets        uint64
	ExpiredPackets        uint64
	UnbondedFindnode      uint64
	FindnodeRequestsRecv  uint64
	FindnodeResponsesRecv uint64
	KnownNodes            int
	PendingRequests       int
	PendingNeighbors      int
}

// GetStats returns current statistics.
func (h *Handler) GetStats() HandlerStats {
	h.nodesMu.RLock()
	knownNodes := len(h.nodes)
	h.nodesMu.RUnlock()
	h.requestsMu.RLock()
	pendingRequests := len(h.requests)
	h.requestsMu.RUnlock()
	h.pendingNeighborsMu.RLock()
	pendingNeighbors := len(h.pendingNeighbors)
	h.pendingNeighborsMu.RUnlock()

	h.statsMu.RLock()
	defer h.statsMu.RUnlock()

	return HandlerStats{
		PacketsReceived:       h.packetsReceived,
		PacketsSent:           h.packetsSent,
		InvalidPackets:        h.invalidPackets,
		ExpiredPackets:        h.expiredPackets,
		UnbondedFindnode:      h.unbondedFindnode,
		FindnodeRequestsRecv:  h.findnodeRequestsRecv,
		FindnodeResponsesRecv: h.findnodeResponsesRecv,
		KnownNodes:            knownNodes,
		PendingRequests:       pendingRequests,
		PendingNeighbors:      pendingNeighbors,
	}
}

// Stats returns current statistics as a map, for callers that render it
// generically.
func (h *Handler) Stats() map[string]interface{} {
	s := h.GetStats()
	return map[string]interface{}{
		"packets_received":        s.PacketsReceived,
		"packets_sent":            s.PacketsSent,
		"invalid_packets":         s.InvalidPackets,
		"expired_packets":         s.ExpiredPackets,
		"unbonded_findnode":       s.UnbondedFindnode,
		"findnode_requests_recv":  s.FindnodeRequestsRecv,
		"findnode_responses_recv": s.FindnodeResponsesRecv,
		"known_nodes":             s.KnownNodes,
		"pending_requests":        s.PendingRequests,
		"pending_neighbors":       s.PendingNeighbors,
	}
}
