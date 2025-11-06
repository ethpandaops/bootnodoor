// Package clconfig provides Ethereum Consensus Layer configuration parsing.
//
// This package handles:
//   - Parsing CL config files (YAML format)
//   - Computing fork digests for different network forks
//   - Tracking fork schedules and activation epochs
package clconfig

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	dynssz "github.com/pk910/dynamic-ssz"
	"gopkg.in/yaml.v3"
)

// BlobScheduleEntry represents a blob parameter change at a specific epoch.
type BlobScheduleEntry struct {
	Epoch            uint64 `yaml:"EPOCH"`
	MaxBlobsPerBlock uint64 `yaml:"MAX_BLOBS_PER_BLOCK"`
}

// Config represents an Ethereum consensus layer configuration.
type Config struct {
	// ConfigName is the network name (e.g., "mainnet", "prater")
	ConfigName string `yaml:"CONFIG_NAME"`

	// PresetBase is the preset base (e.g., "mainnet", "minimal")
	PresetBase string `yaml:"PRESET_BASE"`

	// Genesis configuration
	MinGenesisTime     uint64 `yaml:"MIN_GENESIS_TIME"`
	GenesisDelay       uint64 `yaml:"GENESIS_DELAY"`
	GenesisForkVersion string `yaml:"GENESIS_FORK_VERSION"`

	// Blob parameters
	MaxBlobsPerBlockElectra uint64              `yaml:"MAX_BLOBS_PER_BLOCK_ELECTRA"`
	BlobSchedule            []BlobScheduleEntry `yaml:"BLOB_SCHEDULE"`

	// Time parameters
	SecondsPerSlot uint64 `yaml:"SECONDS_PER_SLOT"`

	// Parsed values (not in YAML)
	customGenesisTime     uint64
	genesisValidatorsRoot [32]byte
	genesisForkVersion    [4]byte

	// Fork data - dynamically parsed from YAML, stored in chronological order
	forks []forkDefinition

	// Original YAML data for fields not explicitly handled
	rawConfig map[string]interface{}
}

// forkDefinition represents a fork with its configuration.
type forkDefinition struct {
	name          string
	epoch         uint64
	versionStr    string
	parsedVersion [4]byte
}

// getForks returns all forks in chronological order.
// Forks are sorted by epoch (ascending), then alphabetically by name for equal epochs.
// EIP-prefixed forks come after named forks within the same epoch.
// This is the single source of truth for fork ordering in the codebase.
func (c *Config) getForks() []forkDefinition {
	return c.forks
}

// GetForkEpoch returns the epoch for a given fork name.
// Returns nil if the fork is not defined.
func (c *Config) GetForkEpoch(forkName string) *uint64 {
	for i := range c.forks {
		if c.forks[i].name == forkName {
			return &c.forks[i].epoch
		}
	}
	return nil
}

// GetForkVersion returns the fork version bytes for a given fork name.
// Returns zero bytes if the fork is not defined.
func (c *Config) GetForkVersion(forkName string) [4]byte {
	for i := range c.forks {
		if c.forks[i].name == forkName {
			return c.forks[i].parsedVersion
		}
	}
	return [4]byte{}
}

// ForkDigest represents a 4-byte fork digest.
type ForkDigest [4]byte

// String returns hex representation of fork digest.
func (fd ForkDigest) String() string {
	return hex.EncodeToString(fd[:])
}

// LoadConfig loads a CL config from a YAML file.
//
// Example:
//
//	config, err := LoadConfig("config.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// First parse as map to extract fork data dynamically
	var rawConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &rawConfig); err != nil {
		return nil, fmt.Errorf("failed to parse config as map: %w", err)
	}

	// Then parse into struct for known fields
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	cfg.rawConfig = rawConfig

	// Extract fork data dynamically from the map
	if err := cfg.extractForkData(rawConfig); err != nil {
		return nil, fmt.Errorf("failed to extract fork data: %w", err)
	}

	// Parse hex values (GenesisValidatorsRoot is optional, set via SetGenesisValidatorsRoot)
	if err := cfg.parseHexValues(); err != nil {
		return nil, fmt.Errorf("failed to parse hex values: %w", err)
	}

	return &cfg, nil
}

// SetGenesisValidatorsRoot sets the genesis validators root from a hex string.
func (c *Config) SetGenesisValidatorsRoot(hexRoot string) error {
	root, err := hexToBytes32(hexRoot)
	if err != nil {
		return fmt.Errorf("invalid genesis validators root: %w", err)
	}
	c.genesisValidatorsRoot = root
	return nil
}

// SetGenesisTime sets the genesis time from a Unix timestamp.
func (c *Config) SetGenesisTime(unixTime uint64) error {
	c.customGenesisTime = unixTime
	return nil
}

// GetGenesisTime calculates the genesis time from MinGenesisTime and GenesisDelay.
// Returns 0 if not configured.
func (c *Config) GetGenesisTime() uint64 {
	if c.customGenesisTime != 0 {
		return c.customGenesisTime
	}
	if c.MinGenesisTime == 0 {
		return 0
	}
	return c.MinGenesisTime + c.GenesisDelay
}

// extractForkData dynamically extracts fork information from the raw YAML map.
// It looks for keys matching the pattern *_FORK_EPOCH and *_FORK_VERSION.
func (c *Config) extractForkData(rawConfig map[string]interface{}) error {
	// Temporary maps to collect fork data
	forkEpochs := make(map[string]uint64)
	forkVersions := make(map[string]string)

	// Extract fork data from YAML
	for key, value := range rawConfig {
		if strings.HasSuffix(key, "_FORK_EPOCH") {
			// Extract fork name (e.g., "ALTAIR_FORK_EPOCH" -> "Altair")
			forkNameUpper := strings.TrimSuffix(key, "_FORK_EPOCH")
			forkName := toTitleCase(forkNameUpper)

			// Convert to uint64
			var epoch uint64
			switch v := value.(type) {
			case int:
				epoch = uint64(v)
			case int64:
				epoch = uint64(v)
			case uint64:
				epoch = v
			case float64:
				epoch = uint64(v)
			default:
				continue // Skip if not a number
			}

			forkEpochs[forkName] = epoch
		} else if strings.HasSuffix(key, "_FORK_VERSION") && key != "GENESIS_FORK_VERSION" {
			// Extract fork name (e.g., "ALTAIR_FORK_VERSION" -> "Altair")
			forkNameUpper := strings.TrimSuffix(key, "_FORK_VERSION")
			forkName := toTitleCase(forkNameUpper)

			// Convert to string (handle both string and numeric hex values)
			var versionStr string
			switch v := value.(type) {
			case string:
				versionStr = v
			case int:
				versionStr = fmt.Sprintf("0x%08x", v)
			case int64:
				versionStr = fmt.Sprintf("0x%08x", v)
			case uint64:
				versionStr = fmt.Sprintf("0x%08x", v)
			default:
				continue // Skip if not a recognized type
			}

			forkVersions[forkName] = versionStr
		}
	}

	// Ensure we have both epoch and version for each fork
	for forkName := range forkEpochs {
		if _, ok := forkVersions[forkName]; !ok {
			return fmt.Errorf("fork %s has epoch but no version", forkName)
		}
	}
	for forkName := range forkVersions {
		if _, ok := forkEpochs[forkName]; !ok {
			return fmt.Errorf("fork %s has version but no epoch", forkName)
		}
	}

	// Build forks list sorted by epoch (ascending), then by name
	c.forks = []forkDefinition{}

	// Collect all fork definitions
	for forkName := range forkEpochs {
		c.forks = append(c.forks, forkDefinition{
			name:       forkName,
			epoch:      forkEpochs[forkName],
			versionStr: forkVersions[forkName],
		})
	}

	// Sort the forks
	c.sortForks()

	// Add BPO entries to the fork list
	// BPOs are blob parameter override entries that act like mini-forks
	if err := c.addBPOForks(); err != nil {
		return err
	}

	// Sort the forks again
	c.sortForks()

	return nil
}

// addBPOForks adds BPO (Blob Parameter Override) entries to the fork list.
// Each BPO entry is treated as a fork variant with modified blob parameters.
func (c *Config) addBPOForks() error {
	// Check if we have Fulu fork (BPOs only apply from Fulu onwards)
	var fuluEpoch *uint64
	for i := range c.forks {
		if c.forks[i].name == "Fulu" {
			fuluEpoch = &c.forks[i].epoch
			break
		}
	}

	if fuluEpoch == nil || *fuluEpoch == math.MaxUint64 {
		return nil // No Fulu fork, no BPOs to add
	}

	// Add each BPO entry as a fork
	for i, blobEntry := range c.BlobSchedule {
		if blobEntry.Epoch >= *fuluEpoch {
			// Find which fork is active at this BPO's epoch
			// IMPORTANT: Skip other BPOs, only consider real forks (named/EIP forks)
			var bpoForkVersion [4]byte
			var bpoVersionStr string

			// Search backwards through forks to find the active one
			for j := len(c.forks) - 1; j >= 0; j-- {
				// Skip BPO entries - we only want real fork versions
				if strings.HasPrefix(c.forks[j].name, "BPO-") {
					continue
				}

				if c.forks[j].epoch <= blobEntry.Epoch {
					bpoForkVersion = c.forks[j].parsedVersion
					bpoVersionStr = c.forks[j].versionStr
					break
				}
			}

			// Add BPO as a fork entry
			c.forks = append(c.forks, forkDefinition{
				name:          fmt.Sprintf("BPO-%d", i+1),
				epoch:         blobEntry.Epoch,
				versionStr:    bpoVersionStr,
				parsedVersion: bpoForkVersion,
			})
		}
	}

	return nil
}

func (c *Config) sortForks() {
	// Sort: by epoch (ascending), then by name for equal epochs
	// EIP* and BPO* forks go to the end within the same epoch
	sort.Slice(c.forks, func(i, j int) bool {
		// First sort by epoch
		if c.forks[i].epoch != c.forks[j].epoch {
			return c.forks[i].epoch < c.forks[j].epoch
		}

		// For equal epochs, determine order by type:
		// 1. Named forks (not starting with "EIP" or "BPO")
		// 2. EIP forks (starting with "EIP")
		// 3. BPO entries (starting with "BPO")

		isBPO_i := strings.HasPrefix(c.forks[i].name, "BPO-")
		isBPO_j := strings.HasPrefix(c.forks[j].name, "BPO-")
		isEIP_i := strings.HasPrefix(c.forks[i].name, "EIP")
		isEIP_j := strings.HasPrefix(c.forks[j].name, "EIP")

		// If one is BPO and other is not, BPO comes last
		if isBPO_i != isBPO_j {
			return !isBPO_i
		}

		// If one is EIP and other is not (and neither is BPO), EIP comes after named fork
		if !isBPO_i && !isBPO_j && isEIP_i != isEIP_j {
			return !isEIP_i
		}

		// Otherwise, sort alphabetically
		return c.forks[i].name < c.forks[j].name
	})
}

// toTitleCase converts "ALTAIR" to "Altair", "EIP1234" to "EIP1234"
func toTitleCase(s string) string {
	if s == "" {
		return s
	}

	// Special case: if it starts with EIP, keep it all uppercase for the prefix
	if strings.HasPrefix(s, "EIP") {
		return s
	}

	// Otherwise: first letter uppercase, rest lowercase
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// parseHexValues parses hex string values into byte arrays.
func (c *Config) parseHexValues() error {
	var err error

	// Parse genesis fork version (required)
	c.genesisForkVersion, err = hexToBytes4(c.GenesisForkVersion)
	if err != nil {
		return fmt.Errorf("invalid genesis fork version: %w", err)
	}

	// Parse all fork versions dynamically
	for i := range c.forks {
		if c.forks[i].versionStr != "" {
			c.forks[i].parsedVersion, err = hexToBytes4(c.forks[i].versionStr)
			if err != nil {
				return fmt.Errorf("invalid %s fork version: %w", c.forks[i].name, err)
			}
		}
	}

	return nil
}

// GetForkVersionAtEpoch returns the fork version for a given epoch.
func (c *Config) GetForkVersionAtEpoch(epoch uint64) [4]byte {
	// Iterate through forks in reverse order (latest to earliest)
	forks := c.getForks()
	for i := len(forks) - 1; i >= 0; i-- {
		fork := forks[i]
		if epoch >= fork.epoch {
			return fork.parsedVersion
		}
	}
	// Default to genesis fork
	return c.genesisForkVersion
}

// GetForkNameAtEpoch returns the fork name for a given epoch.
func (c *Config) GetForkNameAtEpoch(epoch uint64) string {
	// Iterate through forks in reverse order (latest to earliest)
	forks := c.getForks()
	for i := len(forks) - 1; i >= 0; i-- {
		fork := forks[i]
		if epoch >= fork.epoch {
			return fork.name
		}
	}
	// Default to genesis fork
	return "Phase0"
}

// GetBlobParamsForEpoch returns the blob parameters for a given epoch (Fulu+).
// Returns nil if not in Fulu fork or no blob schedule applies.
func (c *Config) GetBlobParamsForEpoch(epoch uint64) *BlobScheduleEntry {
	fuluEpoch := c.GetForkEpoch("Fulu")
	if fuluEpoch == nil || epoch < *fuluEpoch {
		return nil
	}

	// Start with Electra's max blobs
	var currentBlobParams *BlobScheduleEntry
	electraEpoch := c.GetForkEpoch("Electra")
	if electraEpoch != nil {
		currentBlobParams = &BlobScheduleEntry{
			Epoch:            *electraEpoch,
			MaxBlobsPerBlock: c.MaxBlobsPerBlockElectra,
		}
	}

	// Find the latest applicable blob schedule entry
	for i := range c.BlobSchedule {
		if c.BlobSchedule[i].Epoch <= epoch {
			currentBlobParams = &c.BlobSchedule[i]
		} else {
			break
		}
	}

	return currentBlobParams
}

// ForkData provides data about a fork.
type ForkData struct {
	// Current version is the current fork version.
	CurrentVersion [4]byte `ssz-size:"4"`
	// GenesisValidatorsRoot is the hash tree root of the validators at genesis.
	GenesisValidatorsRoot [32]byte `ssz-size:"32"`
}

// GetForkDigest computes a fork digest with optional blob parameters.
//
// For Fulu fork and later, the digest is modified with blob parameters:
//   - Compute base digest: sha256(fork_version || genesis_validators_root)[:4]
//   - If blobParams provided: digest XOR sha256(epoch || max_blobs_per_block)[:4]
func (c *Config) GetForkDigest(forkVersion [4]byte, blobParams *BlobScheduleEntry) ForkDigest {

	// Compute base fork data
	forkData := &ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: c.genesisValidatorsRoot,
	}
	ds := dynssz.NewDynSsz(nil)
	forkDataRoot, err := ds.HashTreeRoot(forkData)
	if err != nil {
		return ForkDigest{}
	}

	// For Fulu fork and later, modify with blob parameters
	if blobParams != nil {
		// Serialize epoch and max_blobs_per_block as uint64 little-endian
		epochBytes := make([]byte, 8)
		maxBlobsBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(epochBytes, blobParams.Epoch)
		binary.LittleEndian.PutUint64(maxBlobsBytes, blobParams.MaxBlobsPerBlock)
		blobParamBytes := append(epochBytes, maxBlobsBytes...)

		blobParamHash := sha256.Sum256(blobParamBytes)

		// XOR baseDigest with first 4 bytes of blobParamHash
		var forkDigest ForkDigest
		for i := 0; i < 4; i++ {
			forkDigest[i] = forkDataRoot[i] ^ blobParamHash[i]
		}
		return forkDigest
	}

	// Return standard digest (first 4 bytes of hash)
	var digest ForkDigest
	copy(digest[:], forkDataRoot[:4])
	return digest
}

// GetForkDigestForEpoch computes the fork digest for a given epoch with BPO support.
func (c *Config) GetForkDigestForEpoch(epoch uint64) ForkDigest {
	forkVersion := c.GetForkVersionAtEpoch(epoch)
	blobParams := c.GetBlobParamsForEpoch(epoch)
	return c.GetForkDigest(forkVersion, blobParams)
}

// GetCurrentForkDigest returns the fork digest for the current epoch.
//
// Calculates the current epoch based on genesis time and returns the appropriate fork digest.
func (c *Config) GetCurrentForkDigest() ForkDigest {
	// Get genesis time
	genesisTime := c.GetGenesisTime()
	if genesisTime == 0 {
		// No genesis time, fall back to latest fork with realistic epoch
		return c.getFallbackForkDigest()
	}

	// Calculate current epoch
	currentTime := uint64(time.Now().Unix())

	// Determine SLOTS_PER_EPOCH based on preset
	// Minimal preset: 8 slots per epoch (for testing)
	// Mainnet preset: 32 slots per epoch (default)
	slotsPerEpoch := uint64(32)
	if c.PresetBase == "minimal" {
		slotsPerEpoch = 8
	}

	secondsPerSlot := c.SecondsPerSlot
	if secondsPerSlot == 0 {
		secondsPerSlot = 12 // Default
	}

	currentEpoch := uint64(GetCurrentEpoch(genesisTime, currentTime, secondsPerSlot, slotsPerEpoch))

	// Return fork digest for current epoch
	return c.GetForkDigestForEpoch(currentEpoch)
}

// GetGenesisForkDigest returns the fork digest for the genesis fork (Phase 0).
func (c *Config) GetGenesisForkDigest() ForkDigest {
	return c.GetForkDigest(c.genesisForkVersion, nil)
}

// GetPreviousForkDigest returns the fork digest for the previous fork before the current one.
// Returns the genesis fork digest if there is no previous fork.
func (c *Config) GetPreviousForkDigest() ForkDigest {
	// Get genesis time
	genesisTime := c.GetGenesisTime()
	if genesisTime == 0 {
		// No genesis time, return genesis fork digest
		return c.GetGenesisForkDigest()
	}

	// Calculate current epoch
	currentTime := uint64(time.Now().Unix())
	slotsPerEpoch := uint64(32)
	if c.PresetBase == "minimal" {
		slotsPerEpoch = 8
	}
	secondsPerSlot := c.SecondsPerSlot
	if secondsPerSlot == 0 {
		secondsPerSlot = 12
	}
	currentEpoch := uint64(GetCurrentEpoch(genesisTime, currentTime, secondsPerSlot, slotsPerEpoch))

	// Find the fork before the current one by iterating through forks in forward order
	forks := c.getForks()
	var currentFork *forkDefinition
	var previousFork *forkDefinition

	for i := 0; i < len(forks); i++ {
		fork := forks[i]
		if currentEpoch >= fork.epoch {
			// This fork is active, remember it as current
			previousFork = currentFork // The last current becomes previous
			currentFork = &forks[i]    // This is now current
		}
	}

	// Return the previous fork if it exists
	if previousFork != nil {
		return c.GetForkDigest(previousFork.parsedVersion, nil)
	}

	// No previous fork, return genesis
	return c.GetGenesisForkDigest()
}

// GetPreviousForkName returns the name of the previous fork before the current one.
func (c *Config) GetPreviousForkName() string {
	// Get genesis time
	genesisTime := c.GetGenesisTime()
	if genesisTime == 0 {
		return "Phase0"
	}

	// Calculate current epoch
	currentTime := uint64(time.Now().Unix())
	slotsPerEpoch := uint64(32)
	if c.PresetBase == "minimal" {
		slotsPerEpoch = 8
	}
	secondsPerSlot := c.SecondsPerSlot
	if secondsPerSlot == 0 {
		secondsPerSlot = 12
	}
	currentEpoch := uint64(GetCurrentEpoch(genesisTime, currentTime, secondsPerSlot, slotsPerEpoch))

	// Find the fork before the current one by iterating through forks in forward order
	forks := c.getForks()
	var currentFork *forkDefinition
	var previousFork *forkDefinition

	for i := 0; i < len(forks); i++ {
		fork := forks[i]
		if currentEpoch >= fork.epoch {
			// This fork is active, remember it as current
			previousFork = currentFork // The last current becomes previous
			currentFork = &forks[i]    // This is now current
		}
	}

	// Return the previous fork name if it exists
	if previousFork != nil {
		return previousFork.name
	}

	// No previous fork, return Phase0
	return "Phase0"
}

// getFallbackForkDigest returns the latest fork with a realistic epoch.
// Used as fallback when genesis time is not available.
func (c *Config) getFallbackForkDigest() ForkDigest {
	// FAR_FUTURE_EPOCH is the standard Ethereum spec constant for unscheduled forks
	const farFutureEpoch = math.MaxUint64

	// Check forks in reverse order (newest to oldest)
	// Skip forks with epoch == FAR_FUTURE_EPOCH (placeholder for unscheduled forks)
	forks := c.getForks()
	for i := len(forks) - 1; i >= 0; i-- {
		fork := forks[i]
		if fork.epoch != farFutureEpoch {
			return c.GetForkDigest(fork.parsedVersion, nil)
		}
	}

	// Fall back to genesis
	return c.GetForkDigest(c.genesisForkVersion, nil)
}

// ForkDigestInfo contains information about a fork digest.
type ForkDigestInfo struct {
	Digest      ForkDigest
	Name        string
	Epoch       uint64
	BlobParams  *BlobScheduleEntry
	ForkVersion [4]byte
}

// GetAllForkDigests returns all possible fork digests for this config.
//
// This is useful for creating filters that accept nodes from multiple forks.
// Note: For Fulu+ forks with blob schedules, this returns multiple digests per fork.
func (c *Config) GetAllForkDigests() []ForkDigest {
	var digests []ForkDigest

	// Genesis (epoch 0) - use genesis fork version
	digests = append(digests, c.GetForkDigest(c.genesisForkVersion, nil))

	// All forks (including BPOs) - use their specific fork versions
	for _, fork := range c.getForks() {
		if fork.epoch != math.MaxUint64 {
			// Get blob parameters active at this fork's epoch (if any)
			blobParams := c.GetBlobParamsForEpoch(fork.epoch)
			digests = append(digests, c.GetForkDigest(fork.parsedVersion, blobParams))
		}
	}

	return digests
}

// GetAllForkDigestInfos returns all fork digests with their metadata.
func (c *Config) GetAllForkDigestInfos() []ForkDigestInfo {
	var infos []ForkDigestInfo

	// Add Genesis (epoch 0)
	infos = append(infos, ForkDigestInfo{
		Digest:      c.GetForkDigest(c.genesisForkVersion, nil),
		Name:        "Phase0/Genesis",
		Epoch:       0,
		BlobParams:  nil,
		ForkVersion: c.genesisForkVersion,
	})

	// Add all forks (including BPOs) - they're already in the correct order
	for _, fork := range c.getForks() {
		if fork.epoch != math.MaxUint64 {
			// Get blob parameters active at this fork's epoch (if any)
			blobParams := c.GetBlobParamsForEpoch(fork.epoch)

			infos = append(infos, ForkDigestInfo{
				Digest:      c.GetForkDigest(fork.parsedVersion, blobParams),
				Name:        fork.name,
				Epoch:       fork.epoch,
				BlobParams:  blobParams,
				ForkVersion: fork.parsedVersion,
			})
		}
	}

	return infos
}

// hexToBytes32 converts a hex string to a 32-byte array.
func hexToBytes32(s string) ([32]byte, error) {
	var result [32]byte

	// Remove 0x prefix if present
	if len(s) >= 2 && s[0:2] == "0x" {
		s = s[2:]
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return result, err
	}

	if len(bytes) != 32 {
		return result, fmt.Errorf("expected 32 bytes, got %d", len(bytes))
	}

	copy(result[:], bytes)
	return result, nil
}

// hexToBytes4 converts a hex string to a 4-byte array.
func hexToBytes4(s string) ([4]byte, error) {
	var result [4]byte

	// Remove 0x prefix if present
	if len(s) >= 2 && s[0:2] == "0x" {
		s = s[2:]
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return result, err
	}

	if len(bytes) != 4 {
		return result, fmt.Errorf("expected 4 bytes, got %d", len(bytes))
	}

	copy(result[:], bytes)
	return result, nil
}

// Epoch represents a beacon chain epoch.
type Epoch uint64

// GetCurrentEpoch computes the current epoch from a Unix timestamp.
//
// Parameters:
//   - genesisTime: Unix timestamp of genesis
//   - currentTime: Current Unix timestamp
//   - secondsPerSlot: Seconds per slot (default 12)
//   - slotsPerEpoch: Slots per epoch (default 32)
func GetCurrentEpoch(genesisTime, currentTime uint64, secondsPerSlot, slotsPerEpoch uint64) Epoch {
	if currentTime < genesisTime {
		return 0
	}

	if secondsPerSlot == 0 {
		secondsPerSlot = 12
	}
	if slotsPerEpoch == 0 {
		slotsPerEpoch = 32
	}

	elapsedTime := currentTime - genesisTime
	currentSlot := elapsedTime / secondsPerSlot
	currentEpoch := currentSlot / slotsPerEpoch

	return Epoch(currentEpoch)
}

// ParseETH2Field extracts the fork digest from an eth2 ENR field.
//
// The eth2 field format is:
//   - Bytes 0-3: Fork digest (this is what we check)
//   - Bytes 4+: Next fork version and epoch (we ignore these)
//
// Returns the 4-byte fork digest.
func ParseETH2Field(eth2Data []byte) (ForkDigest, error) {
	if len(eth2Data) < 4 {
		return ForkDigest{}, fmt.Errorf("eth2 field too short: %d bytes", len(eth2Data))
	}

	var digest ForkDigest
	copy(digest[:], eth2Data[0:4])

	return digest, nil
}

// EncodeETH2Field encodes fork information into an eth2 ENR field.
//
// Format:
//   - Bytes 0-3: Current fork digest
//   - Bytes 4-7: Next fork version
//   - Bytes 8-15: Next fork epoch (big endian)
func EncodeETH2Field(currentDigest ForkDigest, nextForkVersion [4]byte, nextForkEpoch uint64) []byte {
	field := make([]byte, 16)

	// Current fork digest (bytes 0-3)
	copy(field[0:4], currentDigest[:])

	// Next fork version (bytes 4-7)
	copy(field[4:8], nextForkVersion[:])

	// Next fork epoch (bytes 8-15, big endian)
	binary.BigEndian.PutUint64(field[8:16], nextForkEpoch)

	return field
}
