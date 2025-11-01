// Package discv5 implements the Ethereum Discovery v5 protocol.
//
// This is a generic discv5 implementation providing:
//   - UDP transport for network communication
//   - Session management for encrypted communication
//   - Protocol handler for message processing
//   - ENR (Ethereum Node Record) support
package discv5

import (
	"context"
	"fmt"
	"net"
	"sync"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/pk910/bootoor/discv5/protocol"
	"github.com/pk910/bootoor/discv5/session"
	"github.com/pk910/bootoor/discv5/transport"
	"github.com/sirupsen/logrus"
)

// Service is the main discv5 service.
//
// It provides a minimal, generic discv5 implementation that can be
// extended by higher-level services (e.g., beacon bootnode).
type Service struct {
	// config is the service configuration
	config *Config

	// localNode is our node information
	localNode *node.Node

	// transport is the UDP transport layer
	transport *transport.UDPTransport

	// sessions manages encrypted sessions
	sessions *session.Cache

	// handler processes protocol messages
	handler *protocol.Handler

	// Lifecycle management
	running   bool
	mu        sync.RWMutex
	ctx       context.Context
	cancelCtx context.CancelFunc
}

// New creates a new discv5 service.
//
// Example:
//
//	privKey, _ := crypto.GenerateKey()
//	config := DefaultConfig()
//	config.PrivateKey = privKey
//
//	service, err := New(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer service.Stop()
func New(cfg *Config) (*Service, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Set defaults
	if cfg.Logger == nil {
		cfg.Logger = logrus.New()
	}

	// Create local ENR
	localENR, err := createLocalENR(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create local ENR: %w", err)
	}

	// Create local node
	localNode, err := node.New(localENR)
	if err != nil {
		return nil, fmt.Errorf("failed to create local node: %w", err)
	}

	cfg.Logger.WithField("peerID", localNode.PeerID()).WithField("ip", cfg.BindIP).WithField("port", cfg.BindPort).Info("created local node")

	// Create context for graceful shutdown
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancelCtx := context.WithCancel(ctx)

	// Create session cache
	sessionCache := session.NewCache(cfg.MaxSessions, cfg.SessionLifetime, cfg.Logger)

	// Create protocol handler (transport will be set later)
	// Wire up callbacks from our config to the handler
	handlerConfig := protocol.HandlerConfig{
		LocalNode:           localNode,
		Sessions:            sessionCache,
		PrivateKey:          cfg.PrivateKey,
		OnHandshakeComplete: cfg.OnHandshakeComplete,
		OnNodeUpdate:        cfg.OnNodeUpdate,
		OnFindNode:          cfg.OnFindNode,
		OnTalkReq:           cfg.OnTalkReq,
		OnPongReceived:      cfg.OnPongReceived,
		Logger:              cfg.Logger,
	}
	protocolHandler := protocol.NewHandler(ctx, handlerConfig)

	// Create UDP transport
	listenAddr := fmt.Sprintf("%s:%d", cfg.BindIP.String(), cfg.BindPort)
	transportConfig := &transport.Config{
		ListenAddr: listenAddr,
		Handler: func(data []byte, from *net.UDPAddr) {
			protocolHandler.HandleIncomingPacket(data, from)
		},
		Logger:         cfg.Logger,
		RateLimitPerIP: 100, // 100 packets/sec per IP
	}

	udpTransport, err := transport.NewUDPTransport(transportConfig)
	if err != nil {
		cancelCtx() // Clean up context
		return nil, fmt.Errorf("failed to create UDP transport: %w", err)
	}

	// Connect transport to handler
	protocolHandler.SetTransport(udpTransport)

	s := &Service{
		config:    cfg,
		localNode: localNode,
		transport: udpTransport,
		sessions:  sessionCache,
		handler:   protocolHandler,
		ctx:       ctx,
		cancelCtx: cancelCtx,
	}

	return s, nil
}

// Start starts the discv5 service.
//
// This starts the UDP packet receiver.
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return ErrAlreadyRunning
	}

	s.running = true

	return nil
}

// Stop stops the discv5 service.
//
// This gracefully shuts down all components.
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return ErrNotRunning
	}
	s.running = false
	s.mu.Unlock()

	// Signal stop to background tasks
	s.cancelCtx()

	// Close UDP transport
	if s.transport != nil {
		if err := s.transport.Close(); err != nil {
			s.config.Logger.WithError(err).Error("failed to close UDP transport")
		}
	}

	// Close session cache
	if err := s.sessions.Close(); err != nil {
		s.config.Logger.WithError(err).Error("failed to close session cache")
	}

	return nil
}

// LocalNode returns our local node information.
func (s *Service) LocalNode() *node.Node {
	return s.localNode
}

// Handler returns the protocol handler.
//
// This allows higher-level services to access the handler for
// sending requests and managing the protocol.
func (s *Service) Handler() *protocol.Handler {
	return s.handler
}

// Sessions returns the session cache.
func (s *Service) Sessions() *session.Cache {
	return s.sessions
}

// Transport returns the UDP transport.
func (s *Service) Transport() *transport.UDPTransport {
	return s.transport
}

// Ping sends a PING request to a node and waits for a PONG response.
//
// Returns an error if the ping fails or times out.
//
// Example:
//
//	if err := service.Ping(targetNode); err != nil {
//	    log.Printf("ping failed: %v", err)
//	}
func (s *Service) Ping(n *node.Node) error {
	respChan, err := s.handler.SendPing(n)
	if err != nil {
		return fmt.Errorf("failed to send ping: %w", err)
	}

	// Wait for response with timeout
	select {
	case resp := <-respChan:
		if resp.Error != nil {
			return fmt.Errorf("ping error: %w", resp.Error)
		}
		return nil
	case <-s.ctx.Done():
		return fmt.Errorf("service stopped")
	}
}

// FindNode sends a FINDNODE request to a node and returns the discovered nodes.
//
// The distances parameter specifies which distance buckets to query (0-255).
// Use distance 0 to request the node's own ENR.
//
// Returns a slice of discovered nodes, or an error if the request fails.
//
// Example:
//
//	// Find nodes at distance 256 (all nodes)
//	nodes, err := service.FindNode(targetNode, []uint{256})
//	if err != nil {
//	    log.Printf("findnode failed: %v", err)
//	}
func (s *Service) FindNode(n *node.Node, distances []uint) ([]*node.Node, error) {
	respChan, err := s.handler.SendFindNode(n, distances)
	if err != nil {
		return nil, fmt.Errorf("failed to send findnode: %w", err)
	}

	// Collect all NODES responses (may be multiple packets)
	var allNodes []*node.Node

	// Wait for response with timeout
	select {
	case resp := <-respChan:
		if resp.Error != nil {
			return nil, fmt.Errorf("findnode error: %w", resp.Error)
		}

		// Extract nodes from NODES message
		if nodesMsg, ok := resp.Message.(*protocol.Nodes); ok {
			for _, record := range nodesMsg.Records {
				discoveredNode, err := node.New(record)
				if err != nil {
					s.config.Logger.WithError(err).Warn("failed to create node from ENR")
					continue
				}
				allNodes = append(allNodes, discoveredNode)
			}
		}

		return allNodes, nil
	case <-s.ctx.Done():
		return nil, fmt.Errorf("service stopped")
	}
}

// TalkReq sends a TALKREQ request to a node and returns the response.
//
// The protocolName parameter identifies the application protocol.
// The request parameter contains the application-specific request data.
//
// Returns the response data, or an error if the request fails.
//
// Example:
//
//	resp, err := service.TalkReq(targetNode, "my-protocol", []byte("my-request"))
//	if err != nil {
//	    log.Printf("talkreq failed: %v", err)
//	}
func (s *Service) TalkReq(n *node.Node, protocolName string, request []byte) ([]byte, error) {
	// Create TALKREQ message
	requestID, err := protocol.NewRequestID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	talkReq := &protocol.TalkReq{
		RequestID: requestID,
		Protocol:  []byte(protocolName),
		Request:   request,
	}

	// Register pending request and send
	respChan := s.handler.Requests().AddRequest(requestID, n.ID(), protocol.TalkReqMsg)

	if err := s.handler.SendMessage(talkReq, n.ID(), n.Addr(), n); err != nil {
		s.handler.Requests().CancelRequest(requestID)
		return nil, fmt.Errorf("failed to send talkreq: %w", err)
	}

	// Wait for response with timeout
	select {
	case resp := <-respChan:
		if resp.Error != nil {
			return nil, fmt.Errorf("talkreq error: %w", resp.Error)
		}

		// Extract response from TALKRESP message
		if talkResp, ok := resp.Message.(*protocol.TalkResp); ok {
			return talkResp.Response, nil
		}

		return nil, fmt.Errorf("unexpected response type")
	case <-s.ctx.Done():
		return nil, fmt.Errorf("service stopped")
	}
}

// createLocalENR creates the local node's ENR record.
func createLocalENR(cfg *Config) (*enr.Record, error) {
	// Create ENR with IP and port
	record := enr.New()

	// Set sequence number (start at 1)
	record.SetSeq(1)

	// Determine which IP to use for ENR
	enrIPv4 := cfg.ENRIP
	if enrIPv4 == nil {
		enrIPv4 = cfg.BindIP
	}

	enrIPv6 := cfg.ENRIP6

	// Determine which port to use for ENR
	enrPort := cfg.ENRPort
	if enrPort == 0 {
		enrPort = cfg.BindPort
	}

	// Add IPv4 address
	if enrIPv4 != nil && !enrIPv4.IsUnspecified() && enrIPv4.To4() != nil {
		record.Set("ip", enrIPv4.To4())
	}

	// Add IPv6 address
	if enrIPv6 != nil && !enrIPv6.IsUnspecified() && enrIPv6.To4() == nil {
		record.Set("ip6", enrIPv6)
	}

	// Add UDP port
	record.Set("udp", uint16(enrPort))

	// Add secp256k1 public key
	pubKey := cfg.PrivateKey.PublicKey
	pubKeyBytes := ethcrypto.CompressPubkey(&pubKey)
	record.Set("secp256k1", pubKeyBytes)

	// Add eth2 field if provided
	if len(cfg.ETH2Data) >= 4 {
		record.Set("eth2", cfg.ETH2Data)
		cfg.Logger.WithField("forkDigest", fmt.Sprintf("%x", cfg.ETH2Data[:4])).Info("added eth2 field to ENR")
	}

	// Sign the record with private key
	if err := record.Sign(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign ENR: %w", err)
	}

	return record, nil
}

// Common errors
var (
	ErrMissingPrivateKey = fmt.Errorf("private key is required")
	ErrInvalidPort       = fmt.Errorf("invalid port number")
	ErrAlreadyRunning    = fmt.Errorf("service is already running")
	ErrNotRunning        = fmt.Errorf("service is not running")
)
