package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	bootnode "github.com/pk910/bootoor/beacon-bootnode"
	"github.com/pk910/bootoor/beacon-bootnode/config"
	"github.com/pk910/bootoor/beacon-bootnode/db"
	"github.com/pk910/bootoor/beacon-bootnode/nodedb"
	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/pk910/bootoor/webui"
	"github.com/pk910/bootoor/webui/types"
)

var (
	// Flags
	privateKeyHex         string
	nodeDBPath            string
	clConfigPath          string
	bindAddr              string
	bindPort              int
	enrIP                 string
	enrIP6                string
	enrPort               int
	enableIPDiscovery     bool
	genesisValidatorsRoot string
	genesisTime           uint64
	gracePeriod           time.Duration
	logLevel              string
	maxNodesPerIP         int

	// WebUI flags
	enableWebUI bool
	webUIHost   string
	webUIPort   int
	webUISite   string
	webUIPprof  bool
	webUIDebug  bool

	// Bootnode flags
	bootnodesFlag string

	// Root command
	rootCmd = &cobra.Command{
		Use:   "bootnode",
		Short: "Ethereum Discovery v5 Bootnode",
		Long: `Bootnode is an Ethereum Discovery v5 bootnode implementation.

It provides peer discovery services for Ethereum consensus layer clients,
with support for dynamic fork digest filtering and ENR-based discovery.`,
		RunE: runBootnode,
	}
)

func init() {
	// Private key
	rootCmd.Flags().StringVar(&privateKeyHex, "private-key", "", "Private key in hex format (required)")
	rootCmd.MarkFlagRequired("private-key")

	// Node database
	rootCmd.Flags().StringVar(&nodeDBPath, "nodedb", "", "Path to node database directory (empty = in-memory)")

	// CL config
	rootCmd.Flags().StringVar(&clConfigPath, "cl-config", "", "Path to consensus layer config file (required for fork filtering)")
	rootCmd.MarkFlagRequired("cl-config")

	// Network binding
	rootCmd.Flags().StringVar(&bindAddr, "bind-addr", "0.0.0.0", "IP address to bind to")
	rootCmd.Flags().IntVar(&bindPort, "bind-port", 9000, "UDP port to bind to")

	// ENR configuration (advertised address)
	rootCmd.Flags().StringVar(&enrIP, "enr-ip", "", "IPv4 address to advertise in ENR (auto-detected if not specified)")
	rootCmd.Flags().StringVar(&enrIP6, "enr-ip6", "", "IPv6 address to advertise in ENR (optional)")
	rootCmd.Flags().IntVar(&enrPort, "enr-port", 0, "UDP port to advertise in ENR (0 = use bind-port)")
	rootCmd.Flags().BoolVar(&enableIPDiscovery, "enable-ip-discovery", false, "Enable automatic IP discovery from PONG responses (default: enabled when --enr-ip not specified, disabled when specified)")

	// Genesis configuration
	rootCmd.Flags().StringVar(&genesisValidatorsRoot, "genesis-validators-root", "", "Genesis validators root (hex, required)")
	rootCmd.MarkFlagRequired("genesis-validators-root")
	rootCmd.Flags().Uint64Var(&genesisTime, "genesis-time", 0, "Genesis time (Unix timestamp, 0 = calculate from config)")

	// Fork digest filtering
	rootCmd.Flags().DurationVar(&gracePeriod, "grace-period", 60*time.Minute, "Grace period for old fork digests")

	// Logging
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	// Routing table
	rootCmd.Flags().IntVar(&maxNodesPerIP, "max-nodes-per-ip", 100, "Maximum number of nodes to track per IP address")

	// WebUI
	rootCmd.Flags().BoolVar(&enableWebUI, "web-ui", false, "Enable web UI")
	rootCmd.Flags().StringVar(&webUIHost, "web-host", "0.0.0.0", "Web UI host")
	rootCmd.Flags().IntVar(&webUIPort, "web-port", 8080, "Web UI port")
	rootCmd.Flags().StringVar(&webUISite, "web-sitename", "Bootoor", "Web UI site name")
	rootCmd.Flags().BoolVar(&webUIPprof, "pprof", false, "Enable pprof endpoints")

	// Bootnodes
	rootCmd.Flags().StringVar(&bootnodesFlag, "bootnodes", "", "Comma-separated list of bootnode ENRs (e.g., enr:-IS4...,enr:-IS4...)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// getLocalIP attempts to detect a local non-loopback IP address.
// This is used as a fallback when --enr-ip is not specified.
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

	// Fallback to 0.0.0.0 if no suitable IP found
	// This will be replaced by IP discovery
	return net.ParseIP("0.0.0.0")
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse private key
	privKey, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Load CL config
	clCfg, err := config.LoadConfig(clConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load CL config: %w", err)
	}

	logger.WithField("config", clCfg.ConfigName).Info("Loaded CL config")

	// Set genesis validators root
	if err := clCfg.SetGenesisValidatorsRoot(genesisValidatorsRoot); err != nil {
		return fmt.Errorf("failed to set genesis validators root: %w", err)
	}

	// Calculate or use provided genesis time
	if genesisTime == 0 {
		genesisTime = clCfg.GetGenesisTime()
		if genesisTime == 0 {
			return fmt.Errorf("genesis time not configured and not provided")
		}
		logger.WithField("genesisTime", genesisTime).Info("Calculated genesis time from config")
	} else {
		logger.WithField("genesisTime", genesisTime).Info("Using provided genesis time")
	}

	// Create fork digest filter
	forkFilter := config.NewForkDigestFilter(clCfg, gracePeriod)
	forkFilter.SetLogger(logger)
	currentDigest := forkFilter.GetCurrentForkDigest()

	logger.WithField("currentDigest", currentDigest.String()).Info("current fork digest")
	logger.WithField("gracePeriod", gracePeriod).Info("grace period for old forks")

	// Print all accepted fork digests
	logger.Info("accepted fork digests:")
	forkInfos := clCfg.GetAllForkDigestInfos()
	for _, info := range forkInfos {
		bpoInfo := ""
		if info.BlobParams != nil {
			bpoInfo = fmt.Sprintf(" [BPO: epoch=%d, max_blobs=%d]", info.BlobParams.Epoch, info.BlobParams.MaxBlobsPerBlock)
		}
		logger.WithFields(logrus.Fields{
			"digest":      info.Digest.String(),
			"fork":        info.Name,
			"epoch":       info.Epoch,
			"forkVersion": hex.EncodeToString(info.ForkVersion[:]),
		}).Infof("  %s: %s (epoch %d)%s", info.Digest.String(), info.Name, info.Epoch, bpoInfo)
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

	// Create node database wrapper
	ndb := nodedb.NewNodeDB(ctx, sqliteDB, logger)
	defer ndb.Close()

	// Parse bind address
	bindIP := net.ParseIP(bindAddr)
	if bindIP == nil {
		return fmt.Errorf("invalid bind address: %s", bindAddr)
	}

	// Determine if we should enable IP discovery
	// Default behavior:
	// - If --enr-ip is not specified: enable IP discovery (can be overridden with --enable-ip-discovery=false)
	// - If --enr-ip is specified: disable IP discovery (can be overridden with --enable-ip-discovery=true)
	var shouldEnableIPDiscovery bool
	if cmd.Flags().Changed("enable-ip-discovery") {
		// Flag was explicitly set, use that value
		shouldEnableIPDiscovery = enableIPDiscovery
	} else {
		// Use default based on whether --enr-ip is specified
		shouldEnableIPDiscovery = enrIP == ""
	}

	// Validate configuration
	if enrIP == "" && !shouldEnableIPDiscovery {
		return fmt.Errorf("--enr-ip is required when IP discovery is disabled (--enable-ip-discovery=false)")
	}

	// Parse ENR IP addresses
	var enrIPv4 net.IP
	var enrIPv6 net.IP

	if enrIP != "" {
		// User provided explicit IP
		enrIPv4 = net.ParseIP(enrIP)
		if enrIPv4 == nil {
			return fmt.Errorf("invalid ENR IP address: %s", enrIP)
		}
		// Ensure it's IPv4
		if enrIPv4.To4() == nil {
			return fmt.Errorf("--enr-ip must be an IPv4 address, got: %s", enrIP)
		}
		logger.WithField("ip", enrIPv4.String()).Info("using provided ENR IP address")
	} else if shouldEnableIPDiscovery {
		// Use local IP as fallback when IP discovery is enabled
		enrIPv4 = getLocalIP()
		logger.WithField("ip", enrIPv4.String()).Info("using local IP as temporary ENR address (will be updated via IP discovery)")
	}

	if enrIP6 != "" {
		enrIPv6 = net.ParseIP(enrIP6)
		if enrIPv6 == nil {
			return fmt.Errorf("invalid ENR IPv6 address: %s", enrIP6)
		}
		// Ensure it's IPv6
		if enrIPv6.To4() != nil {
			return fmt.Errorf("--enr-ip6 must be an IPv6 address, got: %s", enrIP6)
		}
	}

	// Use ENR port or default to bind port
	enrUDPPort := enrPort
	if enrUDPPort == 0 {
		enrUDPPort = bindPort
	}

	// Parse bootnodes from flag
	var bootNodes []*node.Node
	if bootnodesFlag != "" {
		enrStrings := strings.Split(bootnodesFlag, ",")
		for _, enrStr := range enrStrings {
			enrStr = strings.TrimSpace(enrStr)
			if enrStr == "" {
				continue
			}

			// Decode ENR
			record, err := enr.DecodeBase64(enrStr)
			if err != nil {
				logger.WithField("enr", enrStr).WithError(err).Warn("failed to decode bootnode ENR")
				continue
			}

			// Create node from ENR
			bootNode, err := node.New(record)
			if err != nil {
				logger.WithField("enr", enrStr).WithError(err).Warn("failed to create bootnode from ENR")
				continue
			}

			bootNodes = append(bootNodes, bootNode)
		}

		if len(bootNodes) > 0 {
			logger.WithField("count", len(bootNodes)).Info("loaded bootnodes")
		} else if bootnodesFlag != "" {
			logger.Warn("no valid bootnodes loaded")
		}
	}

	// Create bootnode service
	config := bootnode.DefaultConfig()
	config.PrivateKey = privKey
	config.BindIP = bindIP
	config.BindPort = bindPort
	config.ENRIP = enrIPv4
	config.ENRIP6 = enrIPv6
	config.ENRPort = enrUDPPort
	config.CLConfig = clCfg
	config.GracePeriod = gracePeriod
	config.NodeDB = ndb
	config.MaxNodesPerIP = maxNodesPerIP
	config.BootNodes = bootNodes
	config.EnableIPDiscovery = shouldEnableIPDiscovery
	config.Logger = logger

	service, err := bootnode.New(config)
	if err != nil {
		return fmt.Errorf("failed to create bootnode service: %w", err)
	}

	// Print node information
	localNode := service.LocalNode()
	enrIPStr := "not set"
	if enrIPv4 != nil {
		enrIPStr = enrIPv4.String()
	}
	logger.WithFields(logrus.Fields{
		"peerID":      localNode.PeerID(),
		"bindAddress": fmt.Sprintf("%s:%d", bindAddr, bindPort),
		"enrAddress":  fmt.Sprintf("%s:%d", enrIPStr, enrUDPPort),
	}).Info("bootnode information")

	// Start bootnode service (handles fork digest updates internally)
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
	logger.Info("Shutting down")

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

// parsePrivateKey parses a hex-encoded private key.
func parsePrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
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
