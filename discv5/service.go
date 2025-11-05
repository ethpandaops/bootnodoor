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
	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/discv5/protocol"
	"github.com/ethpandaops/bootnodoor/discv5/session"
	"github.com/ethpandaops/bootnodoor/enr"
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
	transport protocol.Transport

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

// Transport is the interface for sending packets.
// It must have a LocalAddr() method to get the bind address.
type Transport interface {
	protocol.Transport
	LocalAddr() *net.UDPAddr
	AddHandler(handler func(data []byte, from *net.UDPAddr) bool)
}

// New creates a new discv5 service.
//
// The transport must be created first and passed to New().
// The service will register its packet handler with the transport.
//
// Example:
//
//	transport, _ := transport.NewUDPTransport(&transport.Config{
//	    ListenAddr: "0.0.0.0:9000",
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
func New(cfg *Config, transport Transport) (*Service, error) {
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

	// Get ENR port from transport if not specified
	enrPort := cfg.ENRPort
	if enrPort == 0 {
		// Get port from transport's bind address
		bindAddr := transport.LocalAddr()
		enrPort = bindAddr.Port
		cfg.Logger.WithField("port", enrPort).Debug("using transport port for ENR")
	}

	// Create local ENR (using provided ENR as baseline if available)
	localENR, err := createLocalENR(cfg, enrPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create local ENR: %w", err)
	}

	// Create local node
	localNode, err := node.New(localENR)
	if err != nil {
		return nil, fmt.Errorf("failed to create local node: %w", err)
	}

	cfg.Logger.WithFields(logrus.Fields{
		"peerID": localNode.PeerID(),
	}).Info("created local node")

	enrStr, err := localENR.EncodeBase64()
	if err == nil {
		cfg.Logger.Infof("local ENR: %s", enrStr)
	}

	// Create context for graceful shutdown
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancelCtx := context.WithCancel(ctx)

	// Create session cache
	sessionCache := session.NewCache(cfg.MaxSessions, cfg.SessionLifetime, cfg.Logger)

	// Create protocol handler (transport will be set via SetTransport)
	// Wire up callbacks from our config to the handler
	handlerConfig := protocol.HandlerConfig{
		LocalNode:           localNode,
		Sessions:            sessionCache,
		PrivateKey:          cfg.PrivateKey,
		OnHandshakeComplete: cfg.OnHandshakeComplete,
		OnNodeUpdate:        cfg.OnNodeUpdate,
		OnNodeSeen:          cfg.OnNodeSeen,
		OnFindNode:          cfg.OnFindNode,
		OnTalkReq:           cfg.OnTalkReq,
		OnPongReceived:      cfg.OnPongReceived,
		Logger:              cfg.Logger,
	}
	protocolHandler := protocol.NewHandler(ctx, handlerConfig)

	s := &Service{
		config:    cfg,
		localNode: localNode,
		transport: transport,
		sessions:  sessionCache,
		handler:   protocolHandler,
		ctx:       ctx,
		cancelCtx: cancelCtx,
	}

	// Set transport on handler
	protocolHandler.SetTransport(transport)

	// Register packet handler with transport
	transport.AddHandler(s.packetHandler)

	return s, nil
}

// packetHandler is the packet handler function registered with the transport.
// It wraps the protocol handler's HandleIncomingPacket method.
func (s *Service) packetHandler(data []byte, from *net.UDPAddr) bool {
	// Try to handle as discv5 packet.
	// The handler does full validation including checking the "discv5" magic string.
	// Note: While discv5 packets normally start with "discv5", we don't pre-filter
	// because a discv4 packet could theoretically have a random hash collision.
	// We rely on proper cryptographic validation in the handler.
	err := s.handler.HandleIncomingPacket(data, from)
	if err != nil {
		// Could not handle as discv5, let other handlers try
		s.config.Logger.WithError(err).Trace("discv5: could not handle packet")
		return false
	}

	// Successfully handled as discv5
	return true
}

// Start starts the discv5 service.
//
// Note: The transport is started separately and passed to New().
// This method is kept for compatibility and lifecycle management.
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
// Note: This does NOT close the transport as it's managed externally.
// The caller is responsible for closing the transport.
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

	// NOTE: Transport is NOT closed here - it's managed by the caller

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
	respChan := s.handler.Requests().AddRequest(requestID, n, talkReq)

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

// createLocalENR creates a local node's ENR record.
// If cfg.LocalENR is provided and nothing changed, it returns the stored ENR as-is.
// Only increments sequence number if there are actual changes.
func createLocalENR(cfg *Config, enrPort int) (*enr.Record, error) {
	// If we have a stored ENR, check if we need to update it
	if cfg.LocalENR != nil {
		needsUpdate := false

		// Check if any config overrides the stored ENR
		if cfg.ENRIP != nil {
			storedIP := cfg.LocalENR.IP()
			if storedIP == nil || !storedIP.Equal(cfg.ENRIP) {
				needsUpdate = true
				cfg.Logger.WithFields(logrus.Fields{
					"old": storedIP,
					"new": cfg.ENRIP,
				}).Debug("IPv4 changed")
			}
		}

		if cfg.ENRIP6 != nil {
			storedIP6 := cfg.LocalENR.IP6()
			if storedIP6 == nil || !storedIP6.Equal(cfg.ENRIP6) {
				needsUpdate = true
				cfg.Logger.WithFields(logrus.Fields{
					"old": storedIP6,
					"new": cfg.ENRIP6,
				}).Debug("IPv6 changed")
			}
		}

		storedPort := cfg.LocalENR.UDP()
		if storedPort != uint16(enrPort) {
			needsUpdate = true
			cfg.Logger.WithFields(logrus.Fields{
				"old": storedPort,
				"new": enrPort,
			}).Debug("port changed")
		}

		// Check if eth2 field changed
		if len(cfg.ETH2Data) >= 4 {
			var storedEth2 []byte
			cfg.LocalENR.Get("eth2", &storedEth2)
			if len(storedEth2) != len(cfg.ETH2Data) || string(storedEth2) != string(cfg.ETH2Data) {
				needsUpdate = true
				cfg.Logger.Debug("eth2 field changed")
			}
		}

		// If nothing changed, reuse stored ENR
		if !needsUpdate {
			cfg.Logger.WithField("seq", cfg.LocalENR.Seq()).Info("reusing stored ENR (no changes)")
			return cfg.LocalENR, nil
		}
	}

	// Create new ENR record (either fresh or updating stored)
	record := enr.New()

	// Set sequence number (increment from stored ENR, or start at 1)
	var baseSeq uint64 = 0
	if cfg.LocalENR != nil {
		baseSeq = cfg.LocalENR.Seq()
	}
	record.SetSeq(baseSeq + 1)

	// Determine which IP addresses to use
	var enrIPv4 net.IP
	var enrIPv6 net.IP

	// IPv4: priority is ENRIP > stored ENR
	if cfg.ENRIP != nil {
		enrIPv4 = cfg.ENRIP
	} else if cfg.LocalENR != nil && cfg.LocalENR.IP() != nil {
		enrIPv4 = cfg.LocalENR.IP()
	}

	// IPv6: priority is ENRIP6 > stored ENR
	if cfg.ENRIP6 != nil {
		enrIPv6 = cfg.ENRIP6
	} else if cfg.LocalENR != nil && cfg.LocalENR.IP6() != nil {
		enrIPv6 = cfg.LocalENR.IP6()
	}

	// Add IPv4 address
	if enrIPv4 != nil && !enrIPv4.IsUnspecified() && enrIPv4.To4() != nil {
		record.Set("ip", enrIPv4.To4())
	}

	// Add IPv6 address
	if enrIPv6 != nil && !enrIPv6.IsUnspecified() && enrIPv6.To4() == nil {
		record.Set("ip6", enrIPv6)
	}

	// Add UDP port (from parameter, which comes from config or transport)
	record.Set("udp", uint16(enrPort))

	// Add TCP port if present in stored ENR
	if cfg.LocalENR != nil && cfg.LocalENR.TCP() != 0 {
		record.Set("tcp", cfg.LocalENR.TCP())
	}

	// Add secp256k1 public key
	pubKey := cfg.PrivateKey.PublicKey
	pubKeyBytes := ethcrypto.CompressPubkey(&pubKey)
	record.Set("secp256k1", pubKeyBytes)

	// Add eth2 field if provided
	if len(cfg.ETH2Data) >= 4 {
		record.Set("eth2", cfg.ETH2Data)
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
