// Package discv4 implements the Ethereum Discovery v4 protocol.
//
// Discovery v4 is a UDP-based protocol for finding peers in the Ethereum network.
// It uses a Kademlia-style DHT for distributed node discovery with a bond mechanism
// to prevent amplification attacks.
//
// Key features:
//   - PING/PONG for liveness and endpoint verification
//   - FINDNODE/NEIGHBORS for peer discovery
//   - ENRREQUEST/ENRRESPONSE for ENR record exchange (EIP-868)
//   - Bond mechanism (PING/PONG required before FINDNODE)
//   - No encryption (packets are signed but not encrypted)
package discv4

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"sync"

	"github.com/ethpandaops/bootnodoor/discv4/node"
	"github.com/ethpandaops/bootnodoor/discv4/protocol"
	"github.com/ethpandaops/bootnodoor/enode"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/sirupsen/logrus"
)

// Transport is the interface for sending packets.
// It must have a LocalAddr() method to get the bind address.
type Transport interface {
	protocol.Transport
	LocalAddr() *net.UDPAddr
	AddHandler(handler func(data []byte, from *net.UDPAddr) bool)
}

// Service represents a discv4 service instance.
//
// The service manages:
//   - Protocol handler
//   - Node database
//   - Request routing
type Service struct {
	// Configuration
	config *Config

	// Private key
	privateKey *ecdsa.PrivateKey

	// Local ENR (optional)
	localENR *enr.Record

	// Transport layer
	transport Transport

	// Protocol handler
	handler *protocol.Handler

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Running state
	mu      sync.Mutex
	running bool
}

// New creates a new discv4 service.
//
// The transport must be created first and passed to New().
// The service will register its packet handler with the transport.
//
// Example:
//
//	transport, _ := transport.NewUDPTransport(&transport.Config{
//	    ListenAddr: "0.0.0.0:30303",
//	})
//
//	privKey, _ := crypto.GenerateKey()
//	config := DefaultConfig()
//	config.PrivateKey = privKey
//
//	service, err := New(config, transport)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer service.Stop()
func New(config *Config, transport Transport) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	config.ApplyDefaults()

	ctx, cancel := context.WithCancel(context.Background())

	// Get local address from transport for handler config
	localAddr := transport.LocalAddr()

	// Create protocol handler
	handlerConfig := protocol.HandlerConfig{
		PrivateKey:       config.PrivateKey,
		LocalENR:         config.LocalENR,
		LocalAddr:        localAddr,
		BondExpiration:   config.BondExpiration,
		RequestTimeout:   config.RequestTimeout,
		ExpirationWindow: config.ExpirationWindow,
		OnPing:           config.OnPing,
		OnFindnode:       config.OnFindnode,
		OnENRRequest:     config.OnENRRequest,
		OnNodeSeen:       config.OnNodeSeen,
	}

	handler := protocol.NewHandler(ctx, handlerConfig, transport)

	s := &Service{
		config:     config,
		privateKey: config.PrivateKey,
		localENR:   config.LocalENR,
		transport:  transport,
		handler:    handler,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Register packet handler with transport
	transport.AddHandler(s.packetHandler)

	return s, nil
}

// packetHandler is the packet handler function registered with the transport.
// It wraps the protocol handler's HandlePacket method.
func (s *Service) packetHandler(data []byte, from *net.UDPAddr) bool {
	// Try to handle as discv4 packet.
	// The handler validates the packet signature and structure.
	// Note: We don't pre-filter based on magic strings because a discv4
	// packet (which has a random hash) could theoretically start with
	// the bytes "discv5". We rely on cryptographic validation.
	s.handler.HandlePacket(data, from)

	// Note: discv4.HandlePacket doesn't currently return an error.
	// The handler internally validates and drops invalid packets.
	// For now, we assume any packet that reaches here could be discv4.
	// This means if both discv5 and discv4 reject a packet, discv4
	// will be the last one to try (and silently drop it).
	return true
}

// Start starts the discv4 service.
//
// Note: The transport is started separately and passed to New().
// This method is kept for compatibility and lifecycle management.
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service already running")
	}

	s.running = true

	logrus.Info("discv4 service started")

	return nil
}

// Stop stops the discv4 service.
//
// Note: This does NOT close the transport as it's managed externally.
// The caller is responsible for closing the transport.
func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	logrus.Info("Stopping discv4 service")

	// Cancel context
	s.cancel()

	// NOTE: Transport is NOT closed here - it's managed by the caller

	s.running = false

	logrus.Info("discv4 service stopped")

	return nil
}

// IsRunning returns whether the service is currently running.
func (s *Service) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Public API Methods

// Ping sends a PING request to a node.
//
// This establishes a bond with the node and verifies liveness.
// Returns the PONG response or an error.
func (s *Service) Ping(n *node.Node) (*protocol.Pong, error) {
	if !s.running {
		return nil, fmt.Errorf("service not running")
	}
	return s.handler.Ping(n)
}

// PingAddr sends a PING to a node identified by address.
//
// This is a convenience method that creates a temporary node from an enode URL.
func (s *Service) PingAddr(enodeURL string) (*protocol.Pong, error) {
	n, err := node.ParseEnode(enodeURL)
	if err != nil {
		return nil, fmt.Errorf("invalid enode URL: %w", err)
	}
	return s.Ping(n)
}

// Findnode sends a FINDNODE request to discover nodes near a target.
//
// The node must have an active bond (will automatically PING if needed).
// Returns a list of discovered nodes.
func (s *Service) Findnode(n *node.Node, target []byte) ([]*node.Node, error) {
	if !s.running {
		return nil, fmt.Errorf("service not running")
	}
	return s.handler.Findnode(n, target)
}

// RequestENR requests a node's ENR record.
//
// Returns the ENR record or an error.
func (s *Service) RequestENR(n *node.Node) (*enr.Record, error) {
	if !s.running {
		return nil, fmt.Errorf("service not running")
	}
	return s.handler.RequestENR(n)
}

// LookupRandom performs a random node lookup.
//
// This is useful for populating the routing table with random nodes.
func (s *Service) LookupRandom() ([]*node.Node, error) {
	// Use our own node ID as target for random lookup
	// (this will return nodes from all distance ranges)
	localID := node.PubkeyToID(&s.privateKey.PublicKey)

	allNodes := s.handler.AllNodes()
	if len(allNodes) == 0 {
		return nil, fmt.Errorf("no bootstrap nodes")
	}

	// Query a random bonded node
	for _, n := range allNodes {
		if n.IsBonded() {
			return s.handler.Findnode(n, localID[:])
		}
	}

	return nil, fmt.Errorf("no bonded nodes available")
}

// Node Management

// AddNode adds a node to the known nodes list.
//
// This is useful for adding bootstrap nodes.
func (s *Service) AddNode(n *node.Node) {
	// The handler will automatically track this node when we communicate with it
	// For now, we can just ping it to add it to the handler's node map
	go func() {
		if _, err := s.Ping(n); err != nil {
			logrus.WithError(err).WithField("node", n.String()).Debug("Failed to ping node")
		}
	}()
}

// AddBootstrapNode adds a bootstrap node from an enode URL.
func (s *Service) AddBootstrapNode(enodeURL string) error {
	n, err := node.ParseEnode(enodeURL)
	if err != nil {
		return fmt.Errorf("invalid enode URL: %w", err)
	}
	s.AddNode(n)
	return nil
}

// GetNode returns a known node by ID.
func (s *Service) GetNode(id node.ID) *node.Node {
	return s.handler.GetNode(id)
}

// AllNodes returns all known nodes.
func (s *Service) AllNodes() []*node.Node {
	return s.handler.AllNodes()
}

// BondedNodes returns all bonded nodes.
func (s *Service) BondedNodes() []*node.Node {
	all := s.handler.AllNodes()
	bonded := make([]*node.Node, 0)
	for _, n := range all {
		if n.IsBonded() {
			bonded = append(bonded, n)
		}
	}
	return bonded
}

// LocalNode Information

// LocalAddr returns the local listening address.
func (s *Service) LocalAddr() *net.UDPAddr {
	return s.transport.LocalAddr()
}


// LocalNodeID returns the local node ID.
func (s *Service) LocalNodeID() node.ID {
	return node.PubkeyToID(&s.privateKey.PublicKey)
}

// LocalENR returns the local ENR record (if configured).
func (s *Service) LocalENR() *enr.Record {
	return s.localENR
}

// SetLocalENR updates the local ENR record.
//
// This should be called when the ENR is updated (e.g., IP change).
func (s *Service) SetLocalENR(record *enr.Record) {
	s.mu.Lock()
	s.localENR = record
	if s.handler != nil && s.transport != nil {
		// Update handler config
		s.handler = protocol.NewHandler(s.ctx, protocol.HandlerConfig{
			PrivateKey:       s.privateKey,
			LocalENR:         record,
			LocalAddr:        s.transport.LocalAddr(),
			BondExpiration:   s.config.BondExpiration,
			RequestTimeout:   s.config.RequestTimeout,
			ExpirationWindow: s.config.ExpirationWindow,
			OnPing:           s.config.OnPing,
			OnFindnode:       s.config.OnFindnode,
			OnENRRequest:     s.config.OnENRRequest,
			OnNodeSeen:       s.config.OnNodeSeen,
		}, s.transport)
	}
	s.mu.Unlock()
}

// LocalEnode returns the local enode:// URL.
func (s *Service) LocalEnode() string {
	addr := s.transport.LocalAddr()
	en := &enode.Enode{
		PublicKey: &s.privateKey.PublicKey,
		IP:        addr.IP,
		UDP:       uint16(addr.Port),
		TCP:       uint16(addr.Port),
	}
	return en.String()
}

// Statistics

// Stats returns service statistics.
func (s *Service) Stats() map[string]interface{} {
	if s.handler == nil {
		return map[string]interface{}{}
	}

	stats := s.handler.Stats()

	// Note: Transport stats are not included since transport is managed externally

	return stats
}

// Utility Methods

// ParseNodeFromEnode creates a node from an enode:// URL.
func ParseNodeFromEnode(enodeURL string) (*node.Node, error) {
	return node.ParseEnode(enodeURL)
}

// ParseNodeFromENR creates a node from an ENR record.
func ParseNodeFromENR(record *enr.Record, addr *net.UDPAddr) (*node.Node, error) {
	return node.FromENR(record, addr)
}
