package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ethpandaops/bootnodoor/discv5"
	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/transport"
)

var (
	// Global flags
	jsonOutput bool
	verbose    bool
	timeout    int
	bindAddr   string
	bindPort   int
	enrIP      string

	// Root command
	rootCmd = &cobra.Command{
		Use:   "discv5test",
		Short: "Discovery v5 test utility",
		Long: `A CLI tool for testing Discovery v5 protocol operations.

This tool can ping ENRs and discover peers using the discv5 protocol.`,
	}

	// Ping command
	pingCmd = &cobra.Command{
		Use:   "ping <enr>",
		Short: "Ping an ENR",
		Long: `Send a PING message to a node and wait for PONG response.

Example:
  discv5test ping enr:-IS4...`,
		Args: cobra.ExactArgs(1),
		RunE: runPing,
	}

	// FindNode command
	findnodeCmd = &cobra.Command{
		Use:   "findnode <enr>",
		Short: "Get peers from a node",
		Long: `Send a FINDNODE request to discover peers.

The response will be organized by distance buckets. You can filter by specific distances.

Example:
  discv5test findnode enr:-IS4...
  discv5test findnode --distances 253,254,255 enr:-IS4...`,
		Args: cobra.ExactArgs(1),
		RunE: runFindNode,
	}

	// FindNode specific flags
	distancesFlag string
	repeatCount   int
)

func init() {
	// Suppress all logging by default
	logrus.SetOutput(io.Discard)
	logrus.SetLevel(logrus.PanicLevel)

	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", false, "Output in JSON format")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging output")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 5, "Request timeout in seconds")
	rootCmd.PersistentFlags().StringVar(&bindAddr, "bind-addr", "0.0.0.0", "IP address to bind listener to")
	rootCmd.PersistentFlags().IntVar(&bindPort, "bind-port", 9000, "UDP port to bind listener to")
	rootCmd.PersistentFlags().StringVar(&enrIP, "enr-ip", "", "IP address to advertise in ENR (empty = auto-detect)")

	// FindNode specific flags
	findnodeCmd.Flags().StringVarP(&distancesFlag, "distances", "d", "", "Comma-separated list of distances to query (e.g., 253,254,255). If not set, queries all distances (256)")
	findnodeCmd.Flags().IntVarP(&repeatCount, "repeat", "r", 1, "Number of times to repeat the query per distance (to get more peers)")

	// Add commands
	rootCmd.AddCommand(pingCmd)
	rootCmd.AddCommand(findnodeCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// runPing executes the ping command
func runPing(cmd *cobra.Command, args []string) error {
	enrStr := args[0]

	// Create temporary discv5 service
	service, err := createTempService()
	if err != nil {
		return fmt.Errorf("failed to create discv5 service: %w", err)
	}
	defer service.Stop()

	// Parse target ENR
	targetNode, err := parseENR(enrStr)
	if err != nil {
		return fmt.Errorf("failed to parse ENR: %w", err)
	}

	// Ping the node
	start := time.Now()
	err = service.Ping(targetNode)
	rtt := time.Since(start)

	if err != nil {
		if jsonOutput {
			result := map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			}
			printJSON(result)
		} else {
			fmt.Printf("PING failed: %v\n", err)
		}
		return err
	}

	// Success
	if jsonOutput {
		result := map[string]interface{}{
			"success": true,
			"peer_id": targetNode.PeerID(),
			"address": fmt.Sprintf("%s:%d", targetNode.IP().String(), targetNode.UDPPort()),
			"rtt_ms":  rtt.Milliseconds(),
		}
		printJSON(result)
	} else {
		fmt.Printf("PONG received from %s (%s:%d) in %dms\n",
			targetNode.PeerID(),
			targetNode.IP().String(),
			targetNode.UDPPort(),
			rtt.Milliseconds(),
		)
	}

	return nil
}

// runFindNode executes the findnode command
func runFindNode(cmd *cobra.Command, args []string) error {
	enrStr := args[0]

	// Create temporary discv5 service
	service, err := createTempService()
	if err != nil {
		return fmt.Errorf("failed to create discv5 service: %w", err)
	}
	defer service.Stop()

	// Parse target ENR
	targetNode, err := parseENR(enrStr)
	if err != nil {
		return fmt.Errorf("failed to parse ENR: %w", err)
	}

	// Parse distances
	distances, err := parseDistances(distancesFlag)
	if err != nil {
		return fmt.Errorf("failed to parse distances: %w", err)
	}

	// Validate repeat count
	if repeatCount < 1 {
		repeatCount = 1
	}

	// Track all discovered nodes by ID to deduplicate
	allNodesMap := make(map[string]*node.Node)

	// Query each distance separately (and repeat if requested)
	for _, distance := range distances {
		for i := 0; i < repeatCount; i++ {
			// Find nodes at this specific distance
			discoveredNodes, err := service.FindNode(targetNode, []uint{distance})
			if err != nil {
				// Don't fail completely, just log the error for this distance/attempt
				if !jsonOutput {
					fmt.Fprintf(os.Stderr, "FINDNODE failed for distance %d (attempt %d/%d): %v\n",
						distance, i+1, repeatCount, err)
				}
				continue
			}

			// Add discovered nodes to our map (deduplicating by ID)
			for _, n := range discoveredNodes {
				nodeID := n.ID().String()
				if _, exists := allNodesMap[nodeID]; !exists {
					allNodesMap[nodeID] = n
				}
			}
		}
	}

	// Convert map to slice
	var allNodes []*node.Node
	for _, n := range allNodesMap {
		allNodes = append(allNodes, n)
	}

	// Group nodes by distance from the queried node
	nodesByDistance := make(map[int][]*node.Node)
	for _, n := range allNodes {
		dist := node.LogDistance(targetNode.ID(), n.ID())
		nodesByDistance[dist] = append(nodesByDistance[dist], n)
	}

	// Output results
	if jsonOutput {
		outputFindNodeJSON(allNodes, nodesByDistance)
	} else {
		outputFindNodeHuman(allNodes, nodesByDistance)
	}

	return nil
}

// createTempService creates a temporary discv5 service for testing
func createTempService() (*discv5.Service, error) {
	// Generate random private key
	privKey, err := ethcrypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Parse bind address
	bindIP := net.ParseIP(bindAddr)
	if bindIP == nil {
		return nil, fmt.Errorf("invalid bind address: %s", bindAddr)
	}

	// Determine ENR IP
	var enrIPAddr net.IP
	if enrIP != "" {
		enrIPAddr = net.ParseIP(enrIP)
		if enrIPAddr == nil {
			return nil, fmt.Errorf("invalid ENR IP address: %s", enrIP)
		}
	} else {
		// Use bind address for ENR if not specified
		enrIPAddr = bindIP
		// If binding to 0.0.0.0, try to detect a local IP
		if bindIP.IsUnspecified() {
			if localIP := getLocalIP(); localIP != nil {
				enrIPAddr = localIP
			}
		}
	}

	// Create logger based on verbose flag
	logger := logrus.New()
	if verbose {
		logrus.SetOutput(os.Stderr)
		logrus.SetLevel(logrus.InfoLevel)
		logger.SetOutput(os.Stderr)
		logger.SetLevel(logrus.InfoLevel)
	} else {
		logrus.SetOutput(io.Discard)
		logrus.SetLevel(logrus.PanicLevel)
		logger.SetOutput(io.Discard)
		logger.SetLevel(logrus.PanicLevel)
	}

	// Create transport first
	listenAddr := fmt.Sprintf("%s:%d", bindIP.String(), bindPort)
	transportConfig := &transport.Config{
		ListenAddr: listenAddr,
		Logger:     logger,
	}
	udpTransport, err := transport.NewUDPTransport(transportConfig)
	if err != nil {
		return nil, err
	}

	// Create service config
	cfg := discv5.DefaultConfig()
	cfg.PrivateKey = privKey
	cfg.ENRIP = enrIPAddr
	cfg.ENRPort = 0 // Will use actual bound port from transport
	cfg.Logger = logger
	cfg.Context = context.Background()

	// Create service (pass transport)
	service, err := discv5.New(cfg, udpTransport)
	if err != nil {
		udpTransport.Close()
		return nil, err
	}

	// Start service
	if err := service.Start(); err != nil {
		service.Stop()
		udpTransport.Close()
		return nil, err
	}

	return service, nil
}

// getLocalIP attempts to detect a local non-loopback IP address
func getLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP
			}
		}
	}

	// Fallback to 127.0.0.1 if no suitable IP found
	return net.ParseIP("127.0.0.1")
}

// parseENR parses an ENR string into a Node
func parseENR(enrStr string) (*node.Node, error) {
	// Decode ENR
	record, err := enr.DecodeBase64(enrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid ENR: %w", err)
	}

	// Create node from ENR
	n, err := node.New(record)
	if err != nil {
		return nil, fmt.Errorf("failed to create node: %w", err)
	}

	return n, nil
}

// parseDistances parses a comma-separated list of distances
func parseDistances(distStr string) ([]uint, error) {
	if distStr == "" {
		// Default: query all distances (256 means all)
		return []uint{256}, nil
	}

	parts := strings.Split(distStr, ",")
	distances := make([]uint, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		var dist uint
		if _, err := fmt.Sscanf(part, "%d", &dist); err != nil {
			return nil, fmt.Errorf("invalid distance '%s': %w", part, err)
		}
		if dist > 256 {
			return nil, fmt.Errorf("distance must be 0-256, got %d", dist)
		}
		distances = append(distances, dist)
	}

	return distances, nil
}

// outputFindNodeHuman outputs findnode results in human-readable format
func outputFindNodeHuman(nodes []*node.Node, nodesByDistance map[int][]*node.Node) {
	fmt.Printf("Found %d nodes:\n\n", len(nodes))

	// Get sorted distance keys
	var distances []int
	for dist := range nodesByDistance {
		distances = append(distances, dist)
	}

	// Simple sort
	for i := 0; i < len(distances); i++ {
		for j := i + 1; j < len(distances); j++ {
			if distances[i] > distances[j] {
				distances[i], distances[j] = distances[j], distances[i]
			}
		}
	}

	// Print by distance
	for _, dist := range distances {
		nodes := nodesByDistance[dist]
		fmt.Printf("Distance %d (%d nodes):\n", dist, len(nodes))

		for _, n := range nodes {
			// Format: PeerID | IP:Port | Fork Info
			peerID := n.PeerID()
			addr := fmt.Sprintf("%s:%d", n.IP().String(), n.UDPPort())

			// Get fork info
			forkInfo := getForkInfo(n)

			fmt.Printf("  %s | %s | %s\n", peerID, addr, forkInfo)
		}
		fmt.Println()
	}
}

// outputFindNodeJSON outputs findnode results in JSON format
func outputFindNodeJSON(nodes []*node.Node, nodesByDistance map[int][]*node.Node) {
	type NodeInfo struct {
		PeerID      string `json:"peer_id"`
		IP          string `json:"ip"`
		Port        uint16 `json:"port"`
		ForkDigest  string `json:"fork_digest,omitempty"`
		ForkVersion string `json:"fork_version,omitempty"`
		Distance    int    `json:"distance"`
	}

	nodeInfos := make([]NodeInfo, 0, len(nodes))

	for dist, distNodes := range nodesByDistance {
		for _, n := range distNodes {
			info := NodeInfo{
				PeerID:   n.PeerID(),
				IP:       n.IP().String(),
				Port:     n.UDPPort(),
				Distance: dist,
			}

			// Add eth2 fork digest if available
			if eth2Data, ok := n.Record().Eth2(); ok {
				info.ForkDigest = hex.EncodeToString(eth2Data.ForkDigest[:])
			}

			// Add eth fork version if available (eth field)
			var ethField []byte
			if err := n.Record().Get("eth", &ethField); err == nil && len(ethField) >= 4 {
				info.ForkVersion = hex.EncodeToString(ethField[:4])
			}

			nodeInfos = append(nodeInfos, info)
		}
	}

	result := map[string]interface{}{
		"success":    true,
		"node_count": len(nodes),
		"nodes":      nodeInfos,
	}

	printJSON(result)
}

// getForkInfo returns a human-readable fork info string
func getForkInfo(n *node.Node) string {
	// Check for eth2 field (fork digest)
	if eth2Data, ok := n.Record().Eth2(); ok {
		return fmt.Sprintf("fork_digest=%s", hex.EncodeToString(eth2Data.ForkDigest[:]))
	}

	// Check for eth field (fork version)
	var ethField []byte
	if err := n.Record().Get("eth", &ethField); err == nil && len(ethField) >= 4 {
		return fmt.Sprintf("fork_version=%s", hex.EncodeToString(ethField[:4]))
	}

	return "no_fork_info"
}

// printJSON prints data in JSON format
func printJSON(data interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(data)
}
