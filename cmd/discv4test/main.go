package main

import (
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

	"github.com/ethpandaops/bootnodoor/discv4"
	"github.com/ethpandaops/bootnodoor/discv4/node"
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

	// Root command
	rootCmd = &cobra.Command{
		Use:   "discv4test",
		Short: "Discovery v4 test utility",
		Long: `A CLI tool for testing Discovery v4 protocol operations.

This tool can ping nodes and discover peers using the discv4 protocol.
Nodes can be specified as enode:// URLs or ENR records.`,
	}

	// Ping command
	pingCmd = &cobra.Command{
		Use:   "ping <enode-or-enr>",
		Short: "Ping a node",
		Long: `Send a PING message to a node and wait for PONG response.

The node can be specified as either an enode:// URL or an ENR record.
A successful PING/PONG exchange establishes a bond with the node.

Examples:
  discv4test ping enode://abc123...@1.2.3.4:30303
  discv4test ping enr:-IS4...`,
		Args: cobra.ExactArgs(1),
		RunE: runPing,
	}

	// FindNode command
	findnodeCmd = &cobra.Command{
		Use:   "findnode <enode-or-enr>",
		Short: "Get peers from a node",
		Long: `Send a FINDNODE request to discover peers near a target.

The node will be automatically bonded via PING/PONG before sending FINDNODE.
By default, queries for nodes near the target node itself. You can specify
a custom target node ID in hex format.

Examples:
  discv4test findnode enode://abc123...@1.2.3.4:30303
  discv4test findnode --target abc123... enr:-IS4...`,
		Args: cobra.ExactArgs(1),
		RunE: runFindNode,
	}

	// FindNode specific flags
	targetFlag string

	// GetENR command
	getenrCmd = &cobra.Command{
		Use:   "getenr <enode-or-enr>",
		Short: "Request ENR from a node",
		Long: `Send an ENRREQUEST to a node and retrieve its ENR record.

This uses the EIP-868 ENRREQUEST/ENRRESPONSE messages to request
the node's current ENR record, which may contain additional metadata
like fork version, client info, etc.

The node will be automatically bonded via PING/PONG before sending ENRREQUEST.

Examples:
  discv4test getenr enode://abc123...@1.2.3.4:30303
  discv4test getenr enr:-IS4...`,
		Args: cobra.ExactArgs(1),
		RunE: runGetENR,
	}

	// Convert command
	convertCmd = &cobra.Command{
		Use:   "convert",
		Short: "Convert between ENR and enode formats",
		Long: `Convert between ENR records and enode:// URLs.

Note: Converting enode to ENR is not possible without a private key,
as ENR records require cryptographic signatures.`,
	}

	// ENR to enode subcommand
	enrToEnodeCmd = &cobra.Command{
		Use:   "enr-to-enode <enr>",
		Short: "Convert ENR to enode URL",
		Long: `Convert an ENR record to an enode:// URL.

The ENR must contain ip, udp, tcp, and secp256k1 public key fields.

Example:
  discv4test convert enr-to-enode enr:-IS4...`,
		Args: cobra.ExactArgs(1),
		RunE: runEnrToEnode,
	}

	// Enode to ENR subcommand
	enodeToEnrCmd = &cobra.Command{
		Use:   "enode-to-enr <enode> --private-key <hex>",
		Short: "Convert enode URL to ENR (requires private key)",
		Long: `Convert an enode:// URL to an ENR record.

This requires the node's private key to sign the ENR record.
Without the private key, this conversion is not possible as ENR
records must be cryptographically signed.

Example:
  discv4test convert enode-to-enr enode://abc...@1.2.3.4:30303 --private-key 0x123...`,
		Args: cobra.ExactArgs(1),
		RunE: runEnodeToEnr,
	}

	// Enode to ENR flags
	enodePrivateKeyFlag string
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
	rootCmd.PersistentFlags().IntVar(&bindPort, "bind-port", 30303, "UDP port to bind listener to")

	// FindNode specific flags
	findnodeCmd.Flags().StringVar(&targetFlag, "target", "", "Target node ID in hex (default: query for nodes near the target node)")

	// Enode to ENR flags
	enodeToEnrCmd.Flags().StringVar(&enodePrivateKeyFlag, "private-key", "", "Private key in hex format (required)")
	enodeToEnrCmd.MarkFlagRequired("private-key")

	// Add convert subcommands
	convertCmd.AddCommand(enrToEnodeCmd)
	convertCmd.AddCommand(enodeToEnrCmd)

	// Add commands
	rootCmd.AddCommand(pingCmd)
	rootCmd.AddCommand(findnodeCmd)
	rootCmd.AddCommand(getenrCmd)
	rootCmd.AddCommand(convertCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// runPing executes the ping command
func runPing(cmd *cobra.Command, args []string) error {
	nodeStr := args[0]

	// Create temporary discv4 service
	service, err := createTempService()
	if err != nil {
		return fmt.Errorf("failed to create discv4 service: %w", err)
	}
	defer service.Stop()

	// Parse target node
	targetNode, err := parseNode(nodeStr)
	if err != nil {
		return fmt.Errorf("failed to parse node: %w", err)
	}

	// Ping the node
	start := time.Now()
	pong, err := service.Ping(targetNode)
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
	remoteEndpoint := fmt.Sprintf("%s:%d", pong.To.IP.String(), pong.To.UDP)

	if jsonOutput {
		result := map[string]interface{}{
			"success":     true,
			"node_id":     hex.EncodeToString(targetNode.IDBytes()),
			"address":     targetNode.Addr().String(),
			"rtt_ms":      rtt.Milliseconds(),
			"remote_addr": remoteEndpoint,
		}
		printJSON(result)
	} else {
		fmt.Printf("PONG received from %s (%s) in %dms\n",
			hex.EncodeToString(targetNode.IDBytes()[:8]),
			targetNode.Addr().String(),
			rtt.Milliseconds(),
		)
		fmt.Printf("Remote endpoint: %s\n", remoteEndpoint)
	}

	return nil
}

// runFindNode executes the findnode command
func runFindNode(cmd *cobra.Command, args []string) error {
	nodeStr := args[0]

	// Create temporary discv4 service
	service, err := createTempService()
	if err != nil {
		return fmt.Errorf("failed to create discv4 service: %w", err)
	}
	defer service.Stop()

	// Parse target node
	targetNode, err := parseNode(nodeStr)
	if err != nil {
		return fmt.Errorf("failed to parse node: %w", err)
	}

	// Parse target for findnode query
	var target []byte
	if targetFlag != "" {
		// Use custom target
		target, err = hex.DecodeString(strings.TrimPrefix(targetFlag, "0x"))
		if err != nil {
			return fmt.Errorf("invalid target hex: %w", err)
		}
		if len(target) != 32 && len(target) != 64 {
			return fmt.Errorf("target must be 32 or 64 bytes, got %d", len(target))
		}
	} else {
		// Default: query for nodes near the target node itself
		target = targetNode.IDBytes()
	}

	// Find nodes
	start := time.Now()
	discoveredNodes, err := service.Findnode(targetNode, target)
	duration := time.Since(start)

	if err != nil {
		if jsonOutput {
			result := map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			}
			printJSON(result)
		} else {
			fmt.Printf("FINDNODE failed: %v\n", err)
		}
		return err
	}

	// Calculate distances from target
	var targetID node.ID
	copy(targetID[:], target[:32])

	nodesByDistance := make(map[int][]*node.Node)
	for _, n := range discoveredNodes {
		dist := logDistance(targetID, n.ID())
		nodesByDistance[dist] = append(nodesByDistance[dist], n)
	}

	// Output results
	if jsonOutput {
		outputFindNodeJSON(discoveredNodes, nodesByDistance, duration)
	} else {
		outputFindNodeHuman(discoveredNodes, nodesByDistance, duration)
	}

	return nil
}

// runGetENR executes the getenr command
func runGetENR(cmd *cobra.Command, args []string) error {
	nodeStr := args[0]

	// Create temporary discv4 service
	service, err := createTempService()
	if err != nil {
		return fmt.Errorf("failed to create discv4 service: %w", err)
	}
	defer service.Stop()

	// Parse target node
	targetNode, err := parseNode(nodeStr)
	if err != nil {
		return fmt.Errorf("failed to parse node: %w", err)
	}

	// Request ENR from the node
	start := time.Now()
	record, err := service.RequestENR(targetNode)
	rtt := time.Since(start)

	if err != nil {
		if jsonOutput {
			result := map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			}
			printJSON(result)
		} else {
			fmt.Printf("ENRREQUEST failed: %v\n", err)
		}
		return err
	}

	// Encode ENR for display
	enrStr, err := record.EncodeBase64()
	if err != nil {
		return fmt.Errorf("failed to encode ENR: %w", err)
	}

	// Extract information from ENR
	nodeID := node.PubkeyToID(record.PublicKey())

	// Output result
	if jsonOutput {
		result := map[string]interface{}{
			"success": true,
			"node_id": hex.EncodeToString(nodeID[:]),
			"enr":     enrStr,
			"seq":     record.Seq(),
			"rtt_ms":  rtt.Milliseconds(),
			"address": targetNode.Addr().String(),
		}

		// Add IP if present
		var ip net.IP
		if err := record.Get("ip", &ip); err == nil {
			result["ip"] = ip.String()
		}

		// Add UDP port if present
		var udpPort uint16
		if err := record.Get("udp", &udpPort); err == nil {
			result["udp"] = udpPort
		}

		// Add TCP port if present
		var tcpPort uint16
		if err := record.Get("tcp", &tcpPort); err == nil {
			result["tcp"] = tcpPort
		}

		// Add eth2 fork digest if present
		if eth2Data, ok := record.Eth2(); ok {
			result["fork_digest"] = hex.EncodeToString(eth2Data.ForkDigest[:])
		}

		// Add eth fork version if present
		if ethField, ok := record.Eth(); ok {
			result["fork_version"] = hex.EncodeToString(ethField[0].ForkID[:])
		}

		printJSON(result)
	} else {
		fmt.Printf("ENR received from %s in %dms:\n\n",
			hex.EncodeToString(targetNode.IDBytes()[:8]),
			rtt.Milliseconds(),
		)
		fmt.Printf("ENR:     %s\n", enrStr)
		fmt.Printf("Node ID: %s\n", hex.EncodeToString(nodeID[:]))
		fmt.Printf("Seq:     %d\n", record.Seq())

		// Show IP if present
		var ip net.IP
		if err := record.Get("ip", &ip); err == nil {
			fmt.Printf("IP:      %s\n", ip.String())
		}

		// Show UDP port if present
		var udpPort uint16
		if err := record.Get("udp", &udpPort); err == nil {
			fmt.Printf("UDP:     %d\n", udpPort)
		}

		// Show TCP port if present
		var tcpPort uint16
		if err := record.Get("tcp", &tcpPort); err == nil {
			fmt.Printf("TCP:     %d\n", tcpPort)
		}

		// Show eth2 fork digest if present
		if eth2Data, ok := record.Eth2(); ok {
			fmt.Printf("Fork:    %s\n", hex.EncodeToString(eth2Data.ForkDigest[:]))
		}

		// Show eth fork version if present
		if ethField, ok := record.Eth(); ok {
			fmt.Printf("Eth:     %s\n", hex.EncodeToString(ethField[0].ForkID[:]))
		}
	}

	return nil
}

// createTempService creates a temporary discv4 service for testing
func createTempService() (*discv4.Service, error) {
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

	// Create logger based on verbose flag
	if verbose {
		logrus.SetOutput(os.Stderr)
		logrus.SetLevel(logrus.InfoLevel)
	}

	// Create transport first
	listenAddr := fmt.Sprintf("%s:%d", bindIP.String(), bindPort)
	transportConfig := &transport.Config{
		ListenAddr: listenAddr,
		Logger:     logrus.StandardLogger(),
	}
	udpTransport, err := transport.NewUDPTransport(transportConfig)
	if err != nil {
		return nil, err
	}

	// Create service config
	cfg := discv4.DefaultConfig()
	cfg.PrivateKey = privKey

	// Create service (pass transport)
	service, err := discv4.New(cfg, udpTransport)
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

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	return service, nil
}

// parseNode parses a node from an enode:// URL or ENR record
func parseNode(nodeStr string) (*node.Node, error) {
	// Try as enode first
	if strings.HasPrefix(nodeStr, "enode://") {
		return node.ParseEnode(nodeStr)
	}

	// Try as ENR
	if strings.HasPrefix(nodeStr, "enr:") {
		record, err := enr.DecodeBase64(nodeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid ENR: %w", err)
		}

		// Extract address from ENR
		var ip net.IP
		var udpPort uint16

		if err := record.Get("ip", &ip); err != nil {
			return nil, fmt.Errorf("ENR missing IP field")
		}
		if err := record.Get("udp", &udpPort); err != nil {
			return nil, fmt.Errorf("ENR missing UDP field")
		}

		addr := &net.UDPAddr{
			IP:   ip,
			Port: int(udpPort),
		}

		return node.FromENR(record, addr)
	}

	return nil, fmt.Errorf("node must be an enode:// URL or ENR record (starting with 'enr:')")
}

// outputFindNodeHuman outputs findnode results in human-readable format
func outputFindNodeHuman(nodes []*node.Node, nodesByDistance map[int][]*node.Node, duration time.Duration) {
	fmt.Printf("Found %d nodes in %dms:\n\n", len(nodes), duration.Milliseconds())

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
			// Format: NodeID | IP:Port | ENR Info
			nodeID := hex.EncodeToString(n.IDBytes()[:8])
			addr := n.Addr().String()

			// Get ENR info if available
			enrInfo := getENRInfo(n)

			fmt.Printf("  %s... | %s | %s\n", nodeID, addr, enrInfo)
		}
		fmt.Println()
	}
}

// outputFindNodeJSON outputs findnode results in JSON format
func outputFindNodeJSON(nodes []*node.Node, nodesByDistance map[int][]*node.Node, duration time.Duration) {
	type NodeInfo struct {
		NodeID      string `json:"node_id"`
		IP          string `json:"ip"`
		Port        int    `json:"port"`
		Enode       string `json:"enode"`
		Distance    int    `json:"distance"`
		ForkDigest  string `json:"fork_digest,omitempty"`
		ForkVersion string `json:"fork_version,omitempty"`
	}

	nodeInfos := make([]NodeInfo, 0, len(nodes))

	for dist, distNodes := range nodesByDistance {
		for _, n := range distNodes {
			info := NodeInfo{
				NodeID:   hex.EncodeToString(n.IDBytes()),
				IP:       n.Addr().IP.String(),
				Port:     n.Addr().Port,
				Enode:    n.Enode().String(),
				Distance: dist,
			}

			// Add eth2 fork digest if available
			if n.ENR() != nil {
				if eth2Data, ok := n.ENR().Eth2(); ok {
					info.ForkDigest = hex.EncodeToString(eth2Data.ForkDigest[:])
				}

				// Add eth fork version if available
				var ethField []byte
				if err := n.ENR().Get("eth", &ethField); err == nil && len(ethField) >= 4 {
					info.ForkVersion = hex.EncodeToString(ethField[:4])
				}
			}

			nodeInfos = append(nodeInfos, info)
		}
	}

	result := map[string]interface{}{
		"success":     true,
		"node_count":  len(nodes),
		"duration_ms": duration.Milliseconds(),
		"nodes":       nodeInfos,
	}

	printJSON(result)
}

// getENRInfo returns a human-readable ENR info string
func getENRInfo(n *node.Node) string {
	if n.ENR() == nil {
		return "no_enr"
	}

	// Check for eth2 field (fork digest)
	if eth2Data, ok := n.ENR().Eth2(); ok {
		return fmt.Sprintf("fork_digest=%s", hex.EncodeToString(eth2Data.ForkDigest[:]))
	}

	// Check for eth field (fork version)
	var ethField []byte
	if err := n.ENR().Get("eth", &ethField); err == nil && len(ethField) >= 4 {
		return fmt.Sprintf("fork_version=%s", hex.EncodeToString(ethField[:4]))
	}

	return "enr_available"
}

// logDistance calculates the log2 distance between two node IDs
func logDistance(a, b node.ID) int {
	dist := node.Distance(a, b)

	// Find the first non-zero byte
	for i := 0; i < len(dist); i++ {
		if dist[i] != 0 {
			// Count leading zeros in this byte and calculate distance
			lz := 0
			for bit := 7; bit >= 0; bit-- {
				if (dist[i] & (1 << uint(bit))) != 0 {
					return i*8 + (7 - bit)
				}
				lz++
			}
		}
	}

	// All bits are zero (same node ID)
	return 0
}

// runEnrToEnode executes the enr-to-enode conversion
func runEnrToEnode(cmd *cobra.Command, args []string) error {
	enrStr := args[0]

	// Parse ENR
	record, err := enr.DecodeBase64(enrStr)
	if err != nil {
		return fmt.Errorf("invalid ENR: %w", err)
	}

	// Extract public key
	pubKey := record.PublicKey()
	if pubKey == nil {
		return fmt.Errorf("ENR missing public key")
	}

	// Extract IP
	var ip net.IP
	if err := record.Get("ip", &ip); err != nil {
		return fmt.Errorf("ENR missing 'ip' field: %w", err)
	}

	// Extract UDP port
	var udpPort uint16
	if err := record.Get("udp", &udpPort); err != nil {
		return fmt.Errorf("ENR missing 'udp' field: %w", err)
	}

	// Extract TCP port (default to UDP if not present)
	var tcpPort uint16
	if err := record.Get("tcp", &tcpPort); err != nil {
		tcpPort = udpPort // Default to UDP port
	}

	// Build enode URL
	pubKeyHex := hex.EncodeToString(ethcrypto.FromECDSAPub(pubKey)[1:]) // Remove 0x04 prefix
	enodeURL := fmt.Sprintf("enode://%s@%s:%d", pubKeyHex, ip.String(), udpPort)

	// Get node ID
	nodeID := node.PubkeyToID(pubKey)

	// Output result
	if jsonOutput {
		result := map[string]interface{}{
			"success": true,
			"enr":     enrStr,
			"enode":   enodeURL,
			"node_id": hex.EncodeToString(nodeID[:]),
			"ip":      ip.String(),
			"udp":     udpPort,
			"tcp":     tcpPort,
		}

		// Add additional ENR fields if present
		var eth2Field []byte
		if err := record.Get("eth2", &eth2Field); err == nil {
			result["eth2"] = hex.EncodeToString(eth2Field)
		}

		var ethField []byte
		if err := record.Get("eth", &ethField); err == nil {
			result["eth"] = hex.EncodeToString(ethField)
		}

		printJSON(result)
	} else {
		fmt.Printf("ENR to enode conversion:\n\n")
		fmt.Printf("ENR:     %s\n", enrStr)
		fmt.Printf("Enode:   %s\n", enodeURL)
		fmt.Printf("Node ID: %s\n", hex.EncodeToString(nodeID[:]))
		fmt.Printf("IP:      %s\n", ip.String())
		fmt.Printf("UDP:     %d\n", udpPort)
		fmt.Printf("TCP:     %d\n", tcpPort)

		// Show additional fields
		if eth2Data, ok := record.Eth2(); ok {
			fmt.Printf("Fork:    %s\n", hex.EncodeToString(eth2Data.ForkDigest[:]))
		}
	}

	return nil
}

// runEnodeToEnr executes the enode-to-enr conversion
func runEnodeToEnr(cmd *cobra.Command, args []string) error {
	enodeStr := args[0]

	// Parse private key
	privateKeyHex := strings.TrimPrefix(enodePrivateKeyFlag, "0x")
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key hex: %w", err)
	}

	privateKey, err := ethcrypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Parse enode
	en, err := node.ParseEnode(enodeStr)
	if err != nil {
		return fmt.Errorf("invalid enode: %w", err)
	}

	// Verify the private key matches the enode's public key
	derivedPubKey := &privateKey.PublicKey
	derivedNodeID := node.PubkeyToID(derivedPubKey)
	enodeNodeID := en.ID()

	if derivedNodeID != enodeNodeID {
		return fmt.Errorf("private key does not match enode public key\nDerived ID: %s\nEnode ID:   %s",
			hex.EncodeToString(derivedNodeID[:8]),
			hex.EncodeToString(enodeNodeID[:8]))
	}

	// Create ENR record
	record := enr.New()

	// Set fields from enode
	record.Set("id", []byte("v4"))
	record.Set("secp256k1", ethcrypto.CompressPubkey(derivedPubKey))
	record.Set("ip", en.Addr().IP)
	record.Set("udp", uint16(en.Addr().Port))
	record.Set("tcp", uint16(en.Addr().Port)) // Assume same port

	// Sign the record
	if err := record.Sign(privateKey); err != nil {
		return fmt.Errorf("failed to sign ENR: %w", err)
	}

	// Encode ENR
	enrStr, err := record.EncodeBase64()
	if err != nil {
		return fmt.Errorf("failed to encode ENR: %w", err)
	}

	// Output result
	if jsonOutput {
		result := map[string]interface{}{
			"success": true,
			"enode":   enodeStr,
			"enr":     enrStr,
			"node_id": hex.EncodeToString(derivedNodeID[:]),
			"ip":      en.Addr().IP.String(),
			"udp":     en.Addr().Port,
			"tcp":     en.Addr().Port,
			"seq":     record.Seq(),
		}
		printJSON(result)
	} else {
		fmt.Printf("Enode to ENR conversion:\n\n")
		fmt.Printf("Enode:   %s\n", enodeStr)
		fmt.Printf("ENR:     %s\n", enrStr)
		fmt.Printf("Node ID: %s\n", hex.EncodeToString(derivedNodeID[:]))
		fmt.Printf("IP:      %s\n", en.Addr().IP.String())
		fmt.Printf("Port:    %d\n", en.Addr().Port)
		fmt.Printf("Seq:     %d\n", record.Seq())
	}

	return nil
}

// printJSON prints data in JSON format
func printJSON(data interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(data)
}
