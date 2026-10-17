package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ethpandaops/bootnodoor/bootnode/clconfig"
	"github.com/ethpandaops/bootnodoor/bootnode/elconfig"
)

var networkConfigBaseURL = "https://raw.githubusercontent.com/eth-clients"

type namedNetwork struct {
	chainID               uint64
	elGenesisHash         string
	genesisValidatorsRoot string
	// clGenesisTime is required: mainnet's MIN_GENESIS_TIME + GENESIS_DELAY
	// is 7 days later than its actual genesis.
	clGenesisTime uint64
}

var knownNetworks = map[string]namedNetwork{
	"mainnet": {
		chainID:               1,
		elGenesisHash:         "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
		genesisValidatorsRoot: "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
		clGenesisTime:         1606824023,
	},
	"sepolia": {
		chainID:               11155111,
		elGenesisHash:         "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9",
		genesisValidatorsRoot: "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
		clGenesisTime:         1655733600,
	},
	"hoodi": {
		chainID:               560048,
		elGenesisHash:         "0xbbe312868b376a3001692a646dd2d7d1e4406380dfd86b98aa8a34d1557c971b",
		genesisValidatorsRoot: "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
		clGenesisTime:         1742213400,
	},
}

// A set --el-config or --cl-config leaves that whole layer to the user, so a
// custom genesis never picks up a named network's genesis values.
func resolveNetwork(cmd *cobra.Command, logger logrus.FieldLogger) error {
	nw, ok := knownNetworks[network]
	if !ok {
		names := make([]string, 0, len(knownNetworks))
		for name := range knownNetworks {
			names = append(names, name)
		}
		slices.Sort(names)
		return fmt.Errorf("unknown network %q (known: %s)", network, strings.Join(names, ", "))
	}
	if !enableEL && !enableCL {
		return fmt.Errorf("--network requires --enable-el or --enable-cl")
	}

	flags := cmd.Flags()
	fetchEL := enableEL && !flags.Changed("el-config")
	fetchCL := enableCL && !flags.Changed("cl-config")
	if !fetchEL && !fetchCL {
		return nil
	}

	dir, err := networkCacheDir()
	if err != nil {
		return fmt.Errorf("failed to create network config cache: %w", err)
	}

	if fetchEL {
		path := filepath.Join(dir, "genesis.json")
		if err := fetchNetworkFile(logger, networkFileURL("genesis.json"), path, func(p string) error {
			return validateNetworkGenesis(p, nw.chainID)
		}); err != nil {
			return err
		}
		elConfigPath = path
		if !flags.Changed("el-genesis-hash") {
			elGenesisHash = nw.elGenesisHash
		}
	}
	if fetchCL {
		path := filepath.Join(dir, "config.yaml")
		if err := fetchNetworkFile(logger, networkFileURL("config.yaml"), path, func(p string) error {
			return validateNetworkCLConfig(p, network)
		}); err != nil {
			return err
		}
		clConfigPath = path
		if !flags.Changed("genesis-validators-root") {
			genesisValidatorsRoot = nw.genesisValidatorsRoot
		}
		if !flags.Changed("cl-genesis-time") {
			clGenesisTime = nw.clGenesisTime
		}
	}
	return nil
}

// A shared path such as /tmp/bootnodoor would let another local user plant a
// symlink and redirect the cache rename, so only private locations are used.
func networkCacheDir() (string, error) {
	if nodeDBPath != "" {
		return makeCacheDir(filepath.Join(filepath.Dir(nodeDBPath), "network-"+network))
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no user cache directory (%w); set --nodedb", err)
	}
	return makeCacheDir(filepath.Join(cache, "bootnodoor", "network-"+network))
}

// --nodedb may sit in a world-writable directory, where another user could
// pre-create the cache directory as a symlink to redirect the writes.
func makeCacheDir(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory (symlinks are refused)", dir)
	}
	return dir, nil
}

func networkFileURL(file string) string {
	return fmt.Sprintf("%s/%s/main/metadata/%s", networkConfigBaseURL, network, file)
}

func fetchNetworkFile(logger logrus.FieldLogger, url, path string, validate func(string) error) error {
	err := downloadNetworkFile(url, path, validate)
	if err == nil {
		logger.WithField("url", url).Info("fetched network config")
		return nil
	}

	info, statErr := os.Stat(path)
	if statErr != nil {
		return fmt.Errorf("failed to fetch %s and no cached copy at %s: %w", url, path, err)
	}
	if cacheErr := validate(path); cacheErr != nil {
		return fmt.Errorf("failed to fetch %s (%w) and cached copy at %s is invalid: %v", url, err, path, cacheErr)
	}
	logger.WithError(err).WithFields(logrus.Fields{
		"url":      url,
		"cache":    path,
		"cachedAt": info.ModTime().UTC().Format(time.RFC3339),
	}).Warn("failed to fetch network config, using cached copy")
	return nil
}

func downloadNetworkFile(url, path string, validate func(string) error) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}

	// A unique temp file per fetch keeps instances that share the cache
	// directory from writing over each other before the atomic rename.
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := validate(tmp.Name()); err != nil {
		return fmt.Errorf("invalid %s: %w", filepath.Base(path), err)
	}
	return os.Rename(tmp.Name(), path)
}

func validateNetworkGenesis(path string, chainID uint64) error {
	genesis, err := elconfig.LoadGenesis(path)
	if err != nil {
		return err
	}
	if id := genesis.GetChainID(); id == nil || !id.IsUint64() || id.Uint64() != chainID {
		return fmt.Errorf("chain ID %v, want %d", id, chainID)
	}
	if _, byTime := elconfig.GatherForks(genesis.GetChainConfig(), genesis.GetTimestamp()); len(byTime) == 0 {
		return fmt.Errorf("no time-based forks")
	}
	return nil
}

func validateNetworkCLConfig(path, name string) error {
	cfg, err := clconfig.LoadConfig(path)
	if err != nil {
		return err
	}
	if cfg.ConfigName != name {
		return fmt.Errorf("CONFIG_NAME %q, want %q", cfg.ConfigName, name)
	}
	epochs := cfg.ForkEpochs()
	if len(epochs) == 0 || epochs[len(epochs)-1] == 0 {
		return fmt.Errorf("no forks after genesis")
	}
	return nil
}
