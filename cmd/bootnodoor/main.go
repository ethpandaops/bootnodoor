package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ethpandaops/bootnodoor/bootnode"
	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
	"github.com/ethpandaops/bootnodoor/db"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/webui"
	"github.com/ethpandaops/bootnodoor/webui/types"
)

var (
	// Flags
	privateKeyHex string
	nodeDBPath    string

	// EL configuration
	elConfigPath    string
	elGenesisHash   string
	elBootnodesFlag string

	// CL configuration
	clConfigPath          string
	genesisValidatorsRoot string
	clGenesisTime         uint64
	gracePeriod           time.Duration
	clBootnodesFlag       string

	// Network binding
	bindAddr string
	bindPort int

	// ENR configuration
	enrIP   string
	enrIP6  string
	enrPort int

	// Logging
	logLevel string

	// Routing table
	maxActiveNodes int
	maxNodesPerIP  int

	// Layer selection
	enableEL bool
	enableCL bool

	// WebUI flags
	enableWebUI bool
	webUIHost   string
	webUIPort   int
	webUISite   string
	webUIPprof  bool
	webUIDebug  bool

	// Devnet shim mode
	devnetShim string

	// Root command
	rootCmd = &cobra.Command{
		Use:   "bootnodoor",
		Short: "Universal Ethereum Bootnode (EL + CL)",
		Long: `Bootnodoor is a universal Ethereum bootnode implementation.

It provides peer discovery services for both Execution Layer (EL) and
Consensus Layer (CL) clients, with support for:
  - Dual protocol support (discv4 + discv5)
  - Dual layer support (EL + CL)
  - Fork-aware filtering (EIP-2124 fork IDs + fork digests)
  - Separate routing tables for each layer`,
		RunE: runBootnode,
	}
)

func init() {
	// Private key
	rootCmd.Flags().StringVar(&privateKeyHex, "private-key", "", "Private key in hex format (required)")
	rootCmd.MarkFlagRequired("private-key")

	// Node database
	rootCmd.Flags().StringVar(&nodeDBPath, "nodedb", "", "Path to node database directory (empty = in-memory)")

	// EL configuration
	rootCmd.Flags().StringVar(&elConfigPath, "el-config", "", "Path to EL genesis file (JSON, optional)")
	rootCmd.Flags().StringVar(&elGenesisHash, "el-genesis-hash", "", "EL genesis block hash (hex, required if el-config provided)")
	rootCmd.Flags().StringVar(&elBootnodesFlag, "el-bootnodes", "", "Comma-separated list of EL bootnode ENRs or enode URLs")

	// CL configuration
	rootCmd.Flags().StringVar(&clConfigPath, "cl-config", "", "Path to CL config file (optional)")
	rootCmd.Flags().StringVar(&genesisValidatorsRoot, "genesis-validators-root", "", "Genesis validators root (hex, required if cl-config provided)")
	rootCmd.Flags().Uint64Var(&clGenesisTime, "cl-genesis-time", 0, "CL genesis time (Unix timestamp, 0 = calculate from config)")
	rootCmd.Flags().DurationVar(&gracePeriod, "grace-period", 60*time.Minute, "Grace period for old fork digests")
	rootCmd.Flags().StringVar(&clBootnodesFlag, "cl-bootnodes", "", "Comma-separated list of CL bootnode ENRs")

	// Network binding
	rootCmd.Flags().StringVar(&bindAddr, "bind-addr", "0.0.0.0", "IP address to bind to")
	rootCmd.Flags().IntVar(&bindPort, "bind-port", 9000, "UDP port to bind to")

	// ENR configuration
	rootCmd.Flags().StringVar(&enrIP, "enr-ip", "", "IPv4 address to advertise in ENR (auto-detected if not specified)")
	rootCmd.Flags().StringVar(&enrIP6, "enr-ip6", "", "IPv6 address to advertise in ENR (optional)")
	rootCmd.Flags().IntVar(&enrPort, "enr-port", 0, "UDP port to advertise in ENR (0 = use bind-port)")

	// Logging
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	// Routing table
	rootCmd.Flags().IntVar(&maxActiveNodes, "max-active-nodes", 500, "Maximum number of active nodes per table")
	rootCmd.Flags().IntVar(&maxNodesPerIP, "max-nodes-per-ip", 10, "Maximum number of nodes per IP address")

	// Layer selection
	rootCmd.Flags().BoolVar(&enableEL, "enable-el", true, "Enable Execution Layer support (discv4 + discv5)")
	rootCmd.Flags().BoolVar(&enableCL, "enable-cl", true, "Enable Consensus Layer support (discv5)")

	// WebUI
	rootCmd.Flags().BoolVar(&enableWebUI, "web-ui", false, "Enable web UI")
	rootCmd.Flags().StringVar(&webUIHost, "web-host", "0.0.0.0", "Web UI host")
	rootCmd.Flags().IntVar(&webUIPort, "web-port", 8080, "Web UI port")
	rootCmd.Flags().StringVar(&webUISite, "web-sitename", "bootnodoor", "Web UI site name")
	rootCmd.Flags().BoolVar(&webUIPprof, "pprof", false, "Enable pprof endpoints")

	// Devnet shim mode
	rootCmd.Flags().StringVar(&devnetShim, "devnet-shim", "", "Run in devnet shim mode, only serve ENR/enode with given IP:port (e.g., 172.17.0.1:9000)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runBootnode(cmd *cobra.Command, args []string) error {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	logger.SetLevel(level)

	// Create context for graceful shutdown
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse private key (supports file paths)
	privKey, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Parse EL config if provided (needed for both shim and normal mode)
	var elConfig *elconfig.ChainConfig
	var elGenesisHashBytes [32]byte
	var elGenesisTime uint64
	if elConfigPath != "" {
		if elGenesisHash == "" {
			return fmt.Errorf("--el-genesis-hash is required when --el-config is provided")
		}

		logger.WithField("genesis", elConfigPath).Info("loading EL genesis")
		genesis, err := elconfig.LoadGenesis(elConfigPath)
		if err != nil {
			return fmt.Errorf("failed to load EL genesis: %w", err)
		}

		// Get chain config
		elConfig = genesis.GetChainConfig()

		// Extract genesis time from genesis file
		elGenesisTime = genesis.GetTimestamp()
		logger.WithField("timestamp", elGenesisTime).Debug("extracted genesis time from genesis file")

		// Parse genesis hash (supports file paths)
		genesisHashValue, err := parseValueOrFile(elGenesisHash)
		if err != nil {
			return fmt.Errorf("failed to parse genesis hash: %w", err)
		}
		genesisHashHex := strings.TrimPrefix(genesisHashValue, "0x")
		genesisHashBytes, err := hex.DecodeString(genesisHashHex)
		if err != nil {
			return fmt.Errorf("invalid genesis hash: %w", err)
		}
		if len(genesisHashBytes) != 32 {
			return fmt.Errorf("genesis hash must be 32 bytes, got %d", len(genesisHashBytes))
		}
		copy(elGenesisHashBytes[:], genesisHashBytes)

		logger.WithFields(logrus.Fields{
			"chainID":     elConfig.ChainID,
			"genesisHash": elGenesisHash,
			"genesisTime": elGenesisTime,
		}).Info("loaded EL config")

		// Print EL forks for debugging
		forks := elConfig.GetAllForks()

		// Gather fork data for computing fork IDs
		forksByBlock, forksByTime := elconfig.GatherForks(elConfig, elGenesisTime)

		// Compute all fork IDs
		allForkIDs := elconfig.ComputeAllForkIDs(elGenesisHashBytes, forksByBlock, forksByTime)

		// Build a map to associate each fork with its fork ID
		// Note: allForkIDs[0] is genesis, allForkIDs[i+1] is the fork ID AFTER fork i is applied
		forkIDMap := make(map[uint64]elconfig.ForkID)
		forkIndex := 0
		for _, forkBlock := range forksByBlock {
			// Fork ID is at index forkIndex+1 (after the fork is applied)
			if forkIndex+1 < len(allForkIDs) {
				forkIDMap[forkBlock] = allForkIDs[forkIndex+1]
				forkIndex++
			}
		}
		for _, forkTime := range forksByTime {
			// Fork ID is at index forkIndex+1 (after the fork is applied)
			if forkIndex+1 < len(allForkIDs) {
				forkIDMap[forkTime] = allForkIDs[forkIndex+1]
				forkIndex++
			}
		}

		if len(forks) > 0 {
			logger.Info("EL forks:")
			for _, fork := range forks {
				if fork.Block != nil {
					// Skip genesis forks (block 0)
					if *fork.Block == 0 {
						continue
					}

					forkID := forkIDMap[*fork.Block]
					logger.WithFields(logrus.Fields{
						"fork":   fork.Name,
						"block":  *fork.Block,
						"forkID": fmt.Sprintf("0x%x", forkID.Hash),
					}).Info("  - block fork")
				} else if fork.Timestamp != nil {
					// Skip genesis forks (time 0 or genesis time)
					if *fork.Timestamp == 0 || *fork.Timestamp == elGenesisTime {
						continue
					}

					forkID := forkIDMap[*fork.Timestamp]
					logger.WithFields(logrus.Fields{
						"fork":   fork.Name,
						"time":   *fork.Timestamp,
						"forkID": fmt.Sprintf("0x%x", forkID.Hash),
					}).Info("  - time fork")
				}
			}
		}
	}

	// Parse CL config if provided
	var clConfig *clconfig.Config
	if clConfigPath != "" {
		if genesisValidatorsRoot == "" {
			return fmt.Errorf("--genesis-validators-root is required when --cl-config is provided")
		}

		logger.WithField("config", clConfigPath).Info("loading CL config")
		clConfig, err = clconfig.LoadConfig(clConfigPath)
		if err != nil {
			return fmt.Errorf("failed to load CL config: %w", err)
		}

		// Parse and set genesis validators root (supports file paths)
		genesisValidatorsRootValue, err := parseValueOrFile(genesisValidatorsRoot)
		if err != nil {
			return fmt.Errorf("failed to parse genesis validators root: %w", err)
		}
		if err := clConfig.SetGenesisValidatorsRoot(genesisValidatorsRootValue); err != nil {
			return fmt.Errorf("failed to set genesis validators root: %w", err)
		}

		// Calculate or use provided genesis time
		if clGenesisTime == 0 {
			clGenesisTime = clConfig.GetGenesisTime()
			if clGenesisTime == 0 {
				return fmt.Errorf("CL genesis time not configured and not provided")
			}
			logger.WithField("genesisTime", clGenesisTime).Info("calculated CL genesis time from config")
		} else {
			logger.WithField("genesisTime", clGenesisTime).Info("using provided CL genesis time")
		}

		logger.WithFields(logrus.Fields{
			"configName":            clConfig.ConfigName,
			"genesisValidatorsRoot": genesisValidatorsRoot,
			"genesisTime":           clGenesisTime,
		}).Info("loaded CL config")

		// Print CL forks with fork digests
		forkDigestInfos := clConfig.GetAllForkDigestInfos()
		if len(forkDigestInfos) > 0 {
			logger.Info("CL forks:")
			for _, info := range forkDigestInfos {
				logger.WithFields(logrus.Fields{
					"fork":       info.Name,
					"version":    fmt.Sprintf("0x%x", info.ForkVersion),
					"epoch":      info.Epoch,
					"forkDigest": info.Digest.String(),
				}).Info("  - fork")
			}
		}
	}

	// Check if running in devnet shim mode (after parsing configs)
	if devnetShim != "" {
		return runDevnetShim(logger, privKey, devnetShim, elConfig, elGenesisHashBytes, elGenesisTime, clConfig, clGenesisTime, gracePeriod)
	}

	// Validate: at least one layer must be configured (only for normal mode)
	if elConfigPath == "" && clConfigPath == "" {
		return fmt.Errorf("at least one of --el-config or --cl-config must be provided")
	}

	// Create SQLite database
	dbPath := nodeDBPath
	if dbPath == "" {
		dbPath = ":memory:"
		logger.Info("using in-memory SQLite database")
	} else {
		logger.WithField("path", dbPath).Info("using persistent SQLite database")
	}

	sqliteDB := db.NewDatabase(&db.SqliteDatabaseConfig{
		File:         dbPath,
		MaxOpenConns: 50,
		MaxIdleConns: 10,
	}, logger)

	if err := sqliteDB.Init(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer sqliteDB.Close()

	// Apply database schema migrations
	if err := sqliteDB.ApplyEmbeddedDbSchema(-2); err != nil {
		return fmt.Errorf("failed to apply database schema: %w", err)
	}

	// Parse bind address
	bindIP := net.ParseIP(bindAddr)
	if bindIP == nil {
		return fmt.Errorf("invalid bind address: %s", bindAddr)
	}

	// Parse ENR IP addresses
	var enrIPv4 net.IP
	var enrIPv6 net.IP

	if enrIP != "" {
		enrIPv4 = net.ParseIP(enrIP)
		if enrIPv4 == nil {
			return fmt.Errorf("invalid ENR IP address: %s", enrIP)
		}
		if enrIPv4.To4() == nil {
			return fmt.Errorf("--enr-ip must be an IPv4 address, got: %s", enrIP)
		}
		logger.WithField("ip", enrIPv4.String()).Info("using provided ENR IP address")
	} else {
		// Use local IP as fallback
		enrIPv4 = getLocalIP()
		logger.WithField("ip", enrIPv4.String()).Info("using local IP for ENR address")
	}

	if enrIP6 != "" {
		enrIPv6 = net.ParseIP(enrIP6)
		if enrIPv6 == nil {
			return fmt.Errorf("invalid ENR IPv6 address: %s", enrIP6)
		}
		if enrIPv6.To4() != nil {
			return fmt.Errorf("--enr-ip6 must be an IPv6 address, got: %s", enrIP6)
		}
	}

	// Use ENR port or default to bind port
	enrUDPPort := uint16(enrPort)
	if enrUDPPort == 0 {
		enrUDPPort = uint16(bindPort)
	}

	// Parse EL bootnodes
	var elBootnodes []string
	if elBootnodesFlag != "" {
		elBootnodes = strings.Split(elBootnodesFlag, ",")
		for i, bn := range elBootnodes {
			elBootnodes[i] = strings.TrimSpace(bn)
		}
		logger.WithField("count", len(elBootnodes)).Info("loaded EL bootnodes")
	}

	// Parse CL bootnodes
	var clBootnodes []string
	if clBootnodesFlag != "" {
		clBootnodes = strings.Split(clBootnodesFlag, ",")
		for i, bn := range clBootnodes {
			clBootnodes[i] = strings.TrimSpace(bn)
		}
		logger.WithField("count", len(clBootnodes)).Info("loaded CL bootnodes")
	}

	// Determine which discovery protocols to enable based on layer selection
	// EL (Execution Layer) needs both discv4 and discv5
	// CL (Consensus Layer) only needs discv5
	enableDiscv4 := enableEL
	enableDiscv5 := enableEL || enableCL

	// Create bootnode service config
	config := bootnode.DefaultConfig()
	config.PrivateKey = privKey
	config.Database = sqliteDB
	config.BindIP = bindIP
	config.BindPort = uint16(bindPort)
	config.ENRIP = enrIPv4
	config.ENRIP6 = enrIPv6
	config.ENRPort = enrUDPPort
	config.EnableDiscv4 = enableDiscv4
	config.EnableDiscv5 = enableDiscv5
	config.MaxActiveNodes = maxActiveNodes
	config.MaxNodesPerIP = maxNodesPerIP
	config.Logger = logger

	// Set EL config if provided
	if enableEL && elConfig != nil {
		config.ELConfig = elConfig
		config.ELGenesisHash = elGenesisHashBytes
		config.ELGenesisTime = elGenesisTime
		config.ELBootnodes = elBootnodes
	}

	// Set CL config if provided
	if enableCL && clConfig != nil {
		config.CLConfig = clConfig
		config.CLBootnodes = clBootnodes
	}

	// Create bootnode service
	service, err := bootnode.New(config)
	if err != nil {
		return fmt.Errorf("failed to create bootnode service: %w", err)
	}

	// Print node information
	localNode := service.LocalNode()
	logger.WithFields(logrus.Fields{
		"nodeID":      localNode.ID().String()[:16] + "...",
		"bindAddress": fmt.Sprintf("%s:%d", bindAddr, bindPort),
		"enrAddress":  fmt.Sprintf("%s:%d", enrIPv4.String(), enrUDPPort),
	}).Info("bootnode information")

	// Print ENR
	enrStr, err := localNode.Record().EncodeBase64()
	if err == nil {
		logger.WithField("enr", enrStr).Info("local ENR")
	}

	// Start bootnode service
	if err := service.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	// Start Web UI if enabled
	if enableWebUI {
		startWebUI(service)
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	logger.Info("shutting down")

	// Cancel context to signal shutdown to all components
	cancel()

	// Stop service
	if err := service.Stop(); err != nil {
		logger.WithError(err).Error("error stopping service")
	}

	logger.Info("bootnode stopped")

	return nil
}

// startWebUI starts the web UI server.
func startWebUI(service *bootnode.Service) {
	logger := logrus.WithField("module", "webui")

	logger.WithField("host", webUIHost).WithField("port", webUIPort).Info("starting web ui")

	config := &types.FrontendConfig{
		Host:     webUIHost,
		Port:     webUIPort,
		SiteName: webUISite,
		Debug:    webUIDebug,
		Pprof:    webUIPprof,
		Minify:   true,
	}

	webui.StartHttpServer(config, logger, service)
}

// getLocalIP attempts to detect a local non-loopback IP address.
func getLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return net.ParseIP("0.0.0.0")
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP
			}
		}
	}

	// Fallback to 0.0.0.0
	return net.ParseIP("0.0.0.0")
}

// parsePrivateKey parses a hex-encoded private key.
func runDevnetShim(
	logger *logrus.Logger,
	privKey *ecdsa.PrivateKey,
	shimEndpoint string,
	elConfig *elconfig.ChainConfig,
	elGenesisHash [32]byte,
	elGenesisTime uint64,
	clConfig *clconfig.Config,
	clGenesisTime uint64,
	gracePeriod time.Duration,
) error {
	// Parse the endpoint
	parts := strings.Split(shimEndpoint, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid devnet-shim format, expected IP:port, got: %s", shimEndpoint)
	}

	shimIP := parts[0]
	shimPort := parts[1]

	// Get public key and node ID
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	nodeID := ethcrypto.PubkeyToAddress(*pubKey)

	// Generate enode URL (for EL)
	enode := fmt.Sprintf("enode://%x@%s:%s", ethcrypto.FromECDSAPub(pubKey)[1:], shimIP, shimPort)

	// Generate ENR using the exact same logic as buildENR in bootnode/localnode.go
	record := enr.New()

	// Set identity scheme (v4) and public key
	record.Set(enr.WithIdentityScheme("v4"))
	record.Set(enr.WithPublicKey(pubKey))

	// Set IP address
	if ipAddr := net.ParseIP(shimIP); ipAddr != nil {
		if ipv4 := ipAddr.To4(); ipv4 != nil {
			record.Set("ip", ipv4)
		}
	}

	// Set UDP and TCP ports
	portNum := 0
	fmt.Sscanf(shimPort, "%d", &portNum)
	if portNum > 0 {
		record.Set("udp", uint16(portNum))
		record.Set("tcp", uint16(portNum)) // TCP same as UDP
	}

	// Add EL 'eth' field if config provided
	if elConfig != nil {
		// Gather fork data for computing fork IDs
		forksByBlock, forksByTime := elconfig.GatherForks(elConfig, elGenesisTime)
		// Compute all fork IDs
		allForkIDs := elconfig.ComputeAllForkIDs(elGenesisHash, forksByBlock, forksByTime)
		// Use current fork ID (last one in the list)
		currentForkID := allForkIDs[len(allForkIDs)-1]

		ethField := []struct {
			Hash []byte
			Next uint64
		}{
			{
				Hash: currentForkID.Hash[:],
				Next: currentForkID.Next,
			},
		}
		record.Set("eth", ethField)
		logger.WithField("forkID", currentForkID.String()).Debug("added eth field to shim ENR")
	}

	// Add CL 'eth2' field if config provided
	if clConfig != nil {
		// Create fork digest filter to compute eth2 field
		clFilter := clconfig.NewForkDigestFilter(clConfig, gracePeriod)
		eth2Field := clFilter.ComputeEth2Field()
		record.Set("eth2", eth2Field)

		// Extract fork digest for logging
		var forkDigest [4]byte
		if len(eth2Field) >= 4 {
			copy(forkDigest[:], eth2Field[0:4])
		}
		logger.WithField("forkDigest", fmt.Sprintf("%#x", forkDigest)).Debug("added eth2 field to shim ENR")
	}

	// Set sequence number to 1
	record.SetSeq(1)

	// Sign the record
	if err := record.Sign(privKey); err != nil {
		return fmt.Errorf("failed to sign ENR: %w", err)
	}

	// Get the ENR string using proper base64 encoding
	enrString, err := record.EncodeBase64()
	if err != nil {
		return fmt.Errorf("failed to encode ENR: %w", err)
	}

	logger.Info("Running in devnet shim mode")
	logger.Infof("Private key: %s...%s", privateKeyHex[:10], privateKeyHex[len(privateKeyHex)-6:])
	logger.Infof("Node ID: %s", nodeID.Hex())
	logger.Infof("Enode: %s", enode)
	logger.Infof("ENR: %s", enrString)
	logger.Infof("Shim endpoint: %s", shimEndpoint)

	// Output to stdout for easy capture
	fmt.Println("=== BOOTNODE INFO ===")
	fmt.Printf("ENODE=%s\n", enode)
	fmt.Printf("ENR=%s\n", enrString)
	fmt.Printf("NODE_ID=%s\n", nodeID.Hex())
	fmt.Printf("PRIVKEY=%s\n", privateKeyHex)
	fmt.Println("=== END ===")

	// Start a simple HTTP server to serve the bootnode info
	http.HandleFunc("/privkey", func(w http.ResponseWriter, r *http.Request) {
		logger.Infof("Serving private key to %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s", privateKeyHex)
	})

	http.HandleFunc("/enode", func(w http.ResponseWriter, r *http.Request) {
		logger.Infof("Serving enode to %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s", enode)
	})

	http.HandleFunc("/enr", func(w http.ResponseWriter, r *http.Request) {
		logger.Infof("Serving ENR to %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s", enrString)
	})

	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"enode":"%s","enr":"%s","node_id":"%s","privkey":"%s"}`, enode, enrString, nodeID.Hex(), privateKeyHex)
	})

	// Start HTTP server in background
	go func() {
		logger.Infof("Starting HTTP server on :8080 for shim mode endpoints")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			logger.Errorf("HTTP server error: %v", err)
		}
	}()

	// Keep the container running
	logger.Info("Devnet shim mode active. Container will stay running...")
	logger.Info("Private key available at http://localhost:8080/privkey")
	logger.Info("Full info available at http://localhost:8080/info")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down devnet shim")
	return nil
}

// parseValueOrFile reads a value directly or from a file if it's a file path
func parseValueOrFile(value string) (string, error) {
	// Check if it's a file path
	if _, err := os.Stat(value); err == nil {
		// It's a file, read it
		data, err := os.ReadFile(value)
		if err != nil {
			return "", fmt.Errorf("failed to read file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	// It's a direct value
	return value, nil
}

func parsePrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	// Parse value or file
	hexKey, err := parseValueOrFile(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Remove 0x prefix if present
	if len(hexKey) >= 2 && hexKey[0:2] == "0x" {
		hexKey = hexKey[2:]
	}

	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}

	privKey, err := ethcrypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	return privKey, nil
}
