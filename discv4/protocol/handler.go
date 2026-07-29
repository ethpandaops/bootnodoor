package protocol

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"slices"
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
//
// provenAddr is the address the answered PING was sent to. Callers must use it
// rather than from.Addr(), which any later inbound packet rewrites, including a
// spoofed one; attributing a report to that address would undo the endpoint
// proof this callback is gated on.
type OnPongReceivedCallback func(from *node.Node, provenAddr *net.UDPAddr, ip net.IP, port uint16)

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

	// Pending requests, keyed by packet hash + destination node ID: the hash
	// alone aliases across peers (deterministic signatures, 1s Expiration
	// granularity), and identical requests to one peer share a key's slice.
	requestsMu sync.RWMutex
	requests   map[string][]*PendingRequest

	// Pending multi-packet FINDNODE responses
	pendingNeighborsMu sync.RWMutex
	pendingNeighbors   map[string]*PendingNeighborsResponse

	// Local ENR, replaceable while running (fork transitions, IP discovery)
	localENRMu sync.RWMutex
	localENR   *enr.Record

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

	// LocalENR is our node's ENR record (optional). It seeds the handler's
	// record; SetLocalENR replaces it while running, so handler code must read
	// LocalRecord() rather than this field.
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

	// DestIP is the IP the request was sent to, snapshotted at send time.
	// ToNode.Addr() is unusable for verifying a response's origin because
	// lookupOrCreateNode deliberately never rewrites it, but the node object can
	// still be re-addressed by a proven promotion between send and response.
	DestIP net.IP

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
		requests:         make(map[string][]*PendingRequest),
		pendingNeighbors: make(map[string]*PendingNeighborsResponse),
		localENR:         config.LocalENR,
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

	// Look up the node without promoting this packet's source to its canonical
	// address, and without touching liveness or firing OnNodeSeen: none of that is
	// warranted before the handler has checked expiration and solicitation. Each
	// handler states its own gate and calls noteSeen/noteProven itself.
	fromNode := h.lookupOrCreateNode(fromNodeID, pubkey, from)

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

	h.noteSeen(fromNode)

	// Admission and its outbound traffic need a proven source; an already-bonded
	// peer has one. Otherwise the reciprocal PING below proves it a moment later
	// and its PONG runs noteProven then.
	if fromNode.IsBondedFrom(from) {
		h.noteProven(fromNode)
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

	// Receiving a PING grants no bond: we ponged whatever address the packet
	// claimed, which proves nothing if that source was spoofed. Bonding here
	// would let an attacker bond a victim's address and then have us reflect
	// NEIGHBORS at it. The bond is established by the reciprocal PING below,
	// when its PONG comes back from the address we sent it to.

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
		// Ping the source we just ponged, not the canonical address: a peer that
		// moved is only reachable at its new address, and its PONG from there is
		// what proves the new endpoint.
		go func() {
			if _, err := h.pingTo(fromNode, from); err != nil {
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

	h.noteSeen(fromNode)

	// Nothing below may run for a PONG we did not solicit from this address: it
	// establishes a bond, casts a vote in the external-IP election that rewrites
	// our published ENR, and can trigger outbound ENR traffic.
	req := h.consumePendingPing(pong.ReplyTok, fromNode.ID(), from)
	if req == nil {
		return nil
	}

	// Bind the bond to the address we proved, not the packet's source.
	provenAddr := &net.UDPAddr{IP: req.DestIP, Port: from.Port}
	h.promoteAddr(fromNode, provenAddr)
	h.promoteAddr(req.ToNode, provenAddr)
	fromNode.MarkPongReceived(h.config.BondExpiration, provenAddr)
	h.noteProven(fromNode)

	// The To field in PONG contains our address as seen by the remote peer.
	if h.config.OnPongReceived != nil && pong.To.IP != nil && pong.To.UDP > 0 {
		h.config.OnPongReceived(fromNode, provenAddr, pong.To.IP, pong.To.UDP)
	}

	h.deliverResponse(req, pong)

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

	h.noteSeen(fromNode)

	// Bonded at this source address specifically: a bond earned elsewhere would
	// let a spoofed source have us reflect NEIGHBORS at a third party.
	if !fromNode.IsBondedFrom(from) {
		h.incrementUnbondedFindnode()
		logrus.WithField("node_id", fmt.Sprintf("%x", fromNode.IDBytes()[:8])).
			Debug("Rejected FINDNODE from unbonded node")
		return fmt.Errorf("node not bonded")
	}

	h.noteProven(fromNode)
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

	h.noteSeen(fromNode)

	// Only accept NEIGHBORS in response to a FINDNODE we actually sent to this
	// address. Dropping unsolicited NEIGHBORS prevents a peer we never queried
	// from making us accumulate node records without bound; requiring the source
	// to be the address queried stops a peer answering from a spoofed one.
	// NEIGHBORS carries no reply token, so the match is by node ID plus endpoint.
	matchedReq := h.findPendingFindnode(fromNode.ID(), from)
	if matchedReq == nil {
		return nil
	}

	// Counted after the gate: this reports responses to our queries, so counting
	// unsolicited packets here would let any peer inflate it.
	h.noteProven(fromNode)
	h.incrementFindnodeResponsesRecv()

	// Accumulate the response, keyed by the matched request's hash so each
	// FINDNODE gets exactly one entry and a fresh request never collides with
	// a delivered one. Room is reserved before decoding, so records past the
	// cap are never persisted in the global node map, even when packets are
	// dispatched concurrently.
	key := requestKey(matchedReq.RequestHash, matchedReq.ToNode.ID())

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
		nodes = append(nodes, h.lookupOrCreateNode(nodeID, pubkey, addr))
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
	// - They sent us a PONG from this address
	if !fromNode.IsBondedFrom(from) {
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

	h.noteSeen(fromNode)

	// Only a response to an ENRREQUEST we actually sent to this address may touch
	// any state: ENRRESPONSE carries no expiration, so an unsolicited replay could
	// otherwise roll the node back to an older record. The type and destination
	// must both match, or a peer could answer with the hash of some other packet
	// we sent it and resolve the wrong waiter.
	reqs := h.pendingRequestsFrom(resp.ReplyTok, fromNode.ID(), from, ENRRequestPacket)
	if len(reqs) == 0 {
		return nil
	}

	// Bind the record to the sender's identity before installing it, so a
	// matched response cannot attach another node's ENR to this node.
	if resp.Record == nil {
		return nil
	}
	pub := resp.Record.PublicKey()
	if pub == nil || node.PubkeyToID(pub) != fromNode.ID() {
		logrus.WithFields(logrus.Fields{
			"from":    from.String(),
			"node_id": fmt.Sprintf("%x", fromNode.IDBytes()[:8]),
		}).Debug("Dropping ENRRESPONSE: record does not match sender identity")
		return nil
	}

	fromNode.UpdateENR(resp.Record)

	// After UpdateENR, so OnNodeSeen sees the record and admits the node instead of
	// requesting an ENR it already has.
	h.noteProven(fromNode)

	for _, req := range reqs {
		h.deliverResponse(req, resp.Record)
	}

	return nil
}

// Sending Methods

// Ping sends a PING request to a node at its canonical address.
func (h *Handler) Ping(n *node.Node) (*Pong, error) {
	return h.pingTo(n, n.Addr())
}

// pingTo sends a PING to an explicit destination.
//
// handlePing uses it to ping back the source it just ponged, rather than the
// node's canonical address. That is what lets a peer which moved re-prove its new
// endpoint: without it, a moved peer would be pinged only at its old address, never
// answer, and so never bond or be served again.
func (h *Handler) pingTo(n *node.Node, destAddr *net.UDPAddr) (*Pong, error) {
	// Build PING message
	ping := &Ping{
		Version: 4,
		// A bootnode serves no RLPx, so it advertises tcp-port 0; the recipient's
		// tcp is not the sender's to set (spec: to = [ip, udp-port, 0]).
		From:       NewEndpoint(h.config.LocalAddr, 0),
		To:         NewEndpoint(destAddr, 0),
		Expiration: MakeExpiration(h.config.ExpirationWindow),
	}

	// Add ENR sequence if we have an ENR
	if rec := h.LocalRecord(); rec != nil {
		ping.ENRSeq = rec.Seq()
	}

	// Encode packet
	packet, hash, err := Encode(h.config.PrivateKey, ping)
	if err != nil {
		return nil, fmt.Errorf("encode error: %w", err)
	}

	// Register pending request; removal is deferred so every exit path clears it.
	req, err := h.addPendingRequest(hash, n, PingPacket, destAddr)
	if err != nil {
		return nil, err
	}
	defer h.removePendingRequest(req)

	// Send packet
	if err := h.transport.SendTo(packet, destAddr); err != nil {
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
	destAddr := n.Addr()
	req, err := h.addPendingRequest(hash, n, FindnodePacket, destAddr)
	if err != nil {
		return nil, err
	}
	defer h.removePendingRequest(req)

	// Send packet
	if err := h.transport.SendTo(packet, destAddr); err != nil {
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
	destAddr := n.Addr()
	pendingReq, err := h.addPendingRequest(hash, n, ENRRequestPacket, destAddr)
	if err != nil {
		return nil, err
	}
	defer h.removePendingRequest(pendingReq)

	// Send packet
	if err := h.transport.SendTo(packet, destAddr); err != nil {
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
	if rec := h.LocalRecord(); rec != nil {
		pong.ENRSeq = rec.Seq()
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
	rec := h.LocalRecord()
	if rec == nil {
		return fmt.Errorf("no local ENR configured")
	}

	resp := &ENRResponse{
		ReplyTok: replyTok,
		Record:   rec,
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

// lookupOrCreateNode returns the tracked node for id, creating one at addr if the
// id is unknown.
//
// addr is used ONLY when creating: an existing node's canonical address is never
// rewritten here, because addr is either an unauthenticated packet source or an
// address a peer claimed in a NEIGHBORS record. Every sender reads that address,
// and sendNeighbors republishes it, so letting either source set it would steer
// our outbound traffic and let a peer poison what we publish about a third party.
// Only promoteAddr, on a proven endpoint, may move it.
func (h *Handler) lookupOrCreateNode(id node.ID, pubkey *ecdsa.PublicKey, addr *net.UDPAddr) *node.Node {
	h.nodesMu.RLock()
	n, exists := h.nodes[id]
	h.nodesMu.RUnlock()
	if exists {
		return n
	}

	h.nodesMu.Lock()
	defer h.nodesMu.Unlock()

	if n, exists := h.nodes[id]; exists {
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

// promoteAddr installs a proven endpoint as n's canonical address.
//
// Only handlePong may call this, and only for the address a matched PING was sent
// to — see lookupOrCreateNode for why nothing else may move it.
func (h *Handler) promoteAddr(n *node.Node, proven *net.UDPAddr) {
	if n == nil || proven == nil || proven.IP == nil {
		return
	}
	if n.Addr().String() == proven.String() {
		return
	}

	n.SetAddr(proven)

	logrus.WithFields(logrus.Fields{
		"node_id": fmt.Sprintf("%x", n.IDBytes()[:8]),
		"addr":    proven.String(),
	}).Debug("promoted proven endpoint to canonical address")
}

// noteSeen refreshes identity-scoped liveness.
//
// Safe for any non-expired packet: the signature authenticates the identity, so a
// peer can only refresh its own liveness. Withholding it until the source is
// proven would evict a peer that is actively signing packets but whose bond has
// lapsed, and it would come back with no proven addresses at all.
func (h *Handler) noteSeen(n *node.Node) {
	n.UpdateLastSeen()
	n.IncrementPacketsReceived()
}

// noteProven is noteSeen plus OnNodeSeen, which admits the node to the routing
// table and can spawn outbound PING/ENRREQUEST traffic toward it. It requires a
// proven or solicited source.
func (h *Handler) noteProven(n *node.Node) {
	h.noteSeen(n)

	if h.config.OnNodeSeen != nil {
		h.config.OnNodeSeen(n, time.Now())
	}
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

// requestKey scopes a pending request to its destination, since the packet
// hash alone aliases across peers (see the requests field).
func requestKey(hash []byte, id node.ID) string {
	return string(hash) + string(id[:])
}

// addPendingRequest registers a new pending request. A second FINDNODE to a
// peer with one already in flight is rejected: NEIGHBORS carries no reply
// token, so two in-flight FINDNODEs to one peer cannot be told apart.
// destAddr must be the address the caller sends the packet to, captured once:
// toNode.Addr() is rewritten by concurrent inbound packets, so reading it here
// can record an endpoint the request never went to.
func (h *Handler) addPendingRequest(hash []byte, toNode *node.Node, packetType byte, destAddr *net.UDPAddr) (*PendingRequest, error) {
	var destIP net.IP
	if destAddr != nil && destAddr.IP != nil {
		destIP = append(net.IP(nil), destAddr.IP...)
	}

	req := &PendingRequest{
		RequestHash:  hash,
		ToNode:       toNode,
		DestIP:       destIP,
		PacketType:   packetType,
		CreatedAt:    time.Now(),
		Timeout:      time.Now().Add(h.config.RequestTimeout),
		ResponseChan: make(chan interface{}, 1),
	}

	h.requestsMu.Lock()
	defer h.requestsMu.Unlock()

	if packetType == FindnodePacket && h.pendingFindnodeLocked(toNode.ID()) != nil {
		return nil, fmt.Errorf("findnode already in flight to %x", toNode.IDBytes()[:8])
	}

	key := requestKey(hash, toNode.ID())
	h.requests[key] = append(h.requests[key], req)

	return req, nil
}

// getPendingRequests returns the pending requests matching a reply token and
// its sender, so a response can only resolve requests sent to that peer.
func (h *Handler) getPendingRequests(replyTok []byte, id node.ID) []*PendingRequest {
	h.requestsMu.RLock()
	defer h.requestsMu.RUnlock()
	return append([]*PendingRequest(nil), h.requests[requestKey(replyTok, id)]...)
}

// pendingRequestsFrom returns the pending requests of the given type that match
// this reply token and were sent to this address.
func (h *Handler) pendingRequestsFrom(replyTok []byte, id node.ID, from *net.UDPAddr, packetType byte) []*PendingRequest {
	if from == nil || from.IP == nil {
		return nil
	}

	h.requestsMu.RLock()
	defer h.requestsMu.RUnlock()

	var out []*PendingRequest
	for _, req := range h.requests[requestKey(replyTok, id)] {
		if req.PacketType == packetType && req.DestIP != nil && req.DestIP.Equal(from.IP) {
			out = append(out, req)
		}
	}
	return out
}

// consumePendingPing removes and returns the pending PING this PONG answers, or
// nil if there is none.
//
// Three properties beyond "a token matched" are required before a PONG may
// mutate state, and all three are enforced here so no caller can forget one:
//
//   - from must be the IP the PING was sent to. The token alone proves only that
//     somebody received that PING; an attacker who receives it at their own
//     address can replay it with a victim's source and bond the victim.
//   - the request must be a PING. Peers know the hashes of packets we sent them,
//     so an ENRREQUEST or FINDNODE hash would otherwise match as a reply token.
//   - the entry is deleted here, under the same lock, so a replayed PONG finds
//     nothing and the side effects run at most once per PING.
func (h *Handler) consumePendingPing(replyTok []byte, id node.ID, from *net.UDPAddr) *PendingRequest {
	if from == nil || from.IP == nil {
		return nil
	}

	key := requestKey(replyTok, id)

	h.requestsMu.Lock()
	defer h.requestsMu.Unlock()

	reqs := h.requests[key]
	for i, req := range reqs {
		if req.PacketType != PingPacket || req.DestIP == nil || !req.DestIP.Equal(from.IP) {
			continue
		}

		reqs = slices.Delete(reqs, i, i+1)
		if len(reqs) == 0 {
			delete(h.requests, key)
		} else {
			h.requests[key] = reqs
		}
		return req
	}

	return nil
}

// findPendingFindnode returns the pending FINDNODE request awaiting a response
// from the given node, or nil if none exists.
func (h *Handler) findPendingFindnode(id node.ID, from *net.UDPAddr) *PendingRequest {
	if from == nil || from.IP == nil {
		return nil
	}

	h.requestsMu.RLock()
	defer h.requestsMu.RUnlock()

	req := h.pendingFindnodeLocked(id)
	if req == nil || req.DestIP == nil || !req.DestIP.Equal(from.IP) {
		return nil
	}
	return req
}

func (h *Handler) pendingFindnodeLocked(id node.ID) *PendingRequest {
	for _, reqs := range h.requests {
		for _, req := range reqs {
			if req.PacketType == FindnodePacket && req.ToNode != nil && req.ToNode.ID() == id {
				return req
			}
		}
	}
	return nil
}

// removePendingRequest removes one pending request, leaving other waiters on
// the same key in place so one caller's cleanup cannot orphan another's.
func (h *Handler) removePendingRequest(req *PendingRequest) {
	if req == nil || req.ToNode == nil {
		return
	}
	key := requestKey(req.RequestHash, req.ToNode.ID())

	h.requestsMu.Lock()
	defer h.requestsMu.Unlock()

	reqs := h.requests[key]
	if i := slices.Index(reqs, req); i >= 0 {
		reqs = slices.Delete(reqs, i, i+1)
	}
	if len(reqs) == 0 {
		delete(h.requests, key)
	} else {
		h.requests[key] = reqs
	}
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
	for key, reqs := range h.requests {
		kept := slices.DeleteFunc(reqs, func(req *PendingRequest) bool { return now.After(req.Timeout) })
		if len(kept) == 0 {
			delete(h.requests, key)
		} else {
			h.requests[key] = kept
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
	// become eligible here. Scanning under the read lock keeps a full-map sweep
	// from stalling every inbound packet in getOrCreateNode.
	stale := h.staleNodes(now)
	if len(stale) == 0 {
		return
	}

	h.nodesMu.Lock()
	for _, id := range stale {
		// Re-check: a node may have been seen again since the scan.
		if n, ok := h.nodes[id]; ok && !n.IsBonded() && now.Sub(n.LastSeen()) > h.config.NodeTTL {
			delete(h.nodes, id)
		}
	}
	h.nodesMu.Unlock()
}

// staleNodes returns the IDs of unbonded nodes past their TTL.
func (h *Handler) staleNodes(now time.Time) []node.ID {
	h.nodesMu.RLock()
	defer h.nodesMu.RUnlock()

	var stale []node.ID
	for id, n := range h.nodes {
		if !n.IsBonded() && now.Sub(n.LastSeen()) > h.config.NodeTTL {
			stale = append(stale, id)
		}
	}
	return stale
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
	pendingRequests := 0
	for _, reqs := range h.requests {
		pendingRequests += len(reqs)
	}
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

// LocalRecord returns the ENR the handler currently advertises.
func (h *Handler) LocalRecord() *enr.Record {
	h.localENRMu.RLock()
	defer h.localENRMu.RUnlock()
	return h.localENR
}

// SetLocalENR replaces the advertised ENR in place, so a fork transition or an
// IP-discovery update does not have to rebuild the handler and lose its bonds,
// known nodes, pending requests and stats.
func (h *Handler) SetLocalENR(record *enr.Record) {
	h.localENRMu.Lock()
	h.localENR = record
	h.localENRMu.Unlock()
}
