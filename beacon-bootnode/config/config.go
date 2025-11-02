// Package clconfig provides Ethereum Consensus Layer configuration parsing.
//
// This package handles:
//   - Parsing CL config files (YAML format)
//   - Computing fork digests for different network forks
//   - Tracking fork schedules and activation epochs
package config

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
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

	// Fork versions
	AltairForkVersion    string `yaml:"ALTAIR_FORK_VERSION"`
	BellatrixForkVersion string `yaml:"BELLATRIX_FORK_VERSION"`
	CapellaForkVersion   string `yaml:"CAPELLA_FORK_VERSION"`
	DenebForkVersion     string `yaml:"DENEB_FORK_VERSION"`
	ElectraForkVersion   string `yaml:"ELECTRA_FORK_VERSION"`
	FuluForkVersion      string `yaml:"FULU_FORK_VERSION"`
	GloasForkVersion     string `yaml:"GLOAS_FORK_VERSION"`

	// Fork epochs
	AltairForkEpoch    *uint64 `yaml:"ALTAIR_FORK_EPOCH"`
	BellatrixForkEpoch *uint64 `yaml:"BELLATRIX_FORK_EPOCH"`
	CapellaForkEpoch   *uint64 `yaml:"CAPELLA_FORK_EPOCH"`
	DenebForkEpoch     *uint64 `yaml:"DENEB_FORK_EPOCH"`
	ElectraForkEpoch   *uint64 `yaml:"ELECTRA_FORK_EPOCH"`
	FuluForkEpoch      *uint64 `yaml:"FULU_FORK_EPOCH"`
	GloasForkEpoch     *uint64 `yaml:"GLOAS_FORK_EPOCH"`

	// Blob parameters
	MaxBlobsPerBlockElectra uint64              `yaml:"MAX_BLOBS_PER_BLOCK_ELECTRA"`
	BlobSchedule            []BlobScheduleEntry `yaml:"BLOB_SCHEDULE"`

	// Time parameters
	SecondsPerSlot uint64 `yaml:"SECONDS_PER_SLOT"`

	// Parsed values (not in YAML)
	customGenesisTime     uint64
	genesisValidatorsRoot [32]byte
	genesisForkVersion    [4]byte
	altairForkVersion     [4]byte
	bellatrixForkVersion  [4]byte
	capellaForkVersion    [4]byte
	denebForkVersion      [4]byte
	electraForkVersion    [4]byte
	fuluForkVersion       [4]byte
	gloasForkVersion      [4]byte
}

// forkDefinition represents a fork with its configuration.
type forkDefinition struct {
	name          string
	versionStr    *string  // Pointer to the Config's version string field
	epoch         *uint64  // Pointer to the Config's epoch field
	parsedVersion *[4]byte // Pointer to the Config's parsed version field
}

// getForks returns all forks in chronological order (genesis first, latest last).
// This is the single source of truth for fork ordering in the codebase.
func (c *Config) getForks() []forkDefinition {
	return []forkDefinition{
		{name: "Altair", versionStr: &c.AltairForkVersion, epoch: c.AltairForkEpoch, parsedVersion: &c.altairForkVersion},
		{name: "Bellatrix", versionStr: &c.BellatrixForkVersion, epoch: c.BellatrixForkEpoch, parsedVersion: &c.bellatrixForkVersion},
		{name: "Capella", versionStr: &c.CapellaForkVersion, epoch: c.CapellaForkEpoch, parsedVersion: &c.capellaForkVersion},
		{name: "Deneb", versionStr: &c.DenebForkVersion, epoch: c.DenebForkEpoch, parsedVersion: &c.denebForkVersion},
		{name: "Electra", versionStr: &c.ElectraForkVersion, epoch: c.ElectraForkEpoch, parsedVersion: &c.electraForkVersion},
		{name: "Fulu", versionStr: &c.FuluForkVersion, epoch: c.FuluForkEpoch, parsedVersion: &c.fuluForkVersion},
		{name: "Gloas", versionStr: &c.GloasForkVersion, epoch: c.GloasForkEpoch, parsedVersion: &c.gloasForkVersion},
	}
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

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
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

// parseHexValues parses hex string values into byte arrays.
func (c *Config) parseHexValues() error {
	var err error

	// Parse genesis fork version (required)
	c.genesisForkVersion, err = hexToBytes4(c.GenesisForkVersion)
	if err != nil {
		return fmt.Errorf("invalid genesis fork version: %w", err)
	}

	// Parse all other fork versions dynamically
	for _, fork := range c.getForks() {
		if *fork.versionStr != "" {
			*fork.parsedVersion, err = hexToBytes4(*fork.versionStr)
			if err != nil {
				return fmt.Errorf("invalid %s fork version: %w", fork.name, err)
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
		if fork.epoch != nil && epoch >= *fork.epoch {
			return *fork.parsedVersion
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
		if fork.epoch != nil && epoch >= *fork.epoch {
			return fork.name
		}
	}
	// Default to genesis fork
	return "Phase0"
}

// GetBlobParamsForEpoch returns the blob parameters for a given epoch (Fulu+).
// Returns nil if not in Fulu fork or no blob schedule applies.
func (c *Config) GetBlobParamsForEpoch(epoch uint64) *BlobScheduleEntry {
	if c.FuluForkEpoch == nil || epoch < *c.FuluForkEpoch {
		return nil
	}

	// Start with Electra's max blobs
	var currentBlobParams *BlobScheduleEntry
	if c.ElectraForkEpoch != nil {
		currentBlobParams = &BlobScheduleEntry{
			Epoch:            *c.ElectraForkEpoch,
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

	// Find the fork before the current one by iterating through forks in reverse order
	forks := c.getForks()
	var previousFork *forkDefinition

	for i := len(forks) - 1; i >= 0; i-- {
		fork := forks[i]
		if fork.epoch != nil && currentEpoch >= *fork.epoch {
			// Found the current fork, return the previous one
			if previousFork != nil && previousFork.epoch != nil {
				return c.GetForkDigest(*previousFork.parsedVersion, nil)
			}
			// No previous fork, return genesis
			return c.GetGenesisForkDigest()
		}
		// Only remember forks that are scheduled
		if fork.epoch != nil {
			previousFork = &fork
		}
	}

	// We're in Phase0, no previous fork
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

	// Find the fork before the current one by iterating through forks in reverse order
	forks := c.getForks()
	var previousFork *forkDefinition

	for i := len(forks) - 1; i >= 0; i-- {
		fork := forks[i]
		if fork.epoch != nil && currentEpoch >= *fork.epoch {
			// Found the current fork, return the previous one
			if previousFork != nil {
				return previousFork.name
			}
			// No previous fork, return Phase0
			return "Phase0"
		}
		// Only remember forks that are scheduled
		if fork.epoch != nil {
			previousFork = &fork
		}
	}

	// We're in Phase0, no previous fork
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
		if fork.epoch != nil && *fork.epoch != farFutureEpoch {
			return c.GetForkDigest(*fork.parsedVersion, nil)
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

	// All forks - use their specific fork versions
	for _, fork := range c.getForks() {
		if fork.epoch != nil {
			digests = append(digests, c.GetForkDigest(*fork.parsedVersion, nil))

			// Special handling for Fulu fork with blob schedules (BPO)
			if fork.name == "Fulu" {
				for _, blobEntry := range c.BlobSchedule {
					if blobEntry.Epoch >= *fork.epoch {
						digests = append(digests, c.GetForkDigest(*fork.parsedVersion, &blobEntry))
					}
				}
			}
		}
	}

	return digests
}

// GetAllForkDigestInfos returns all fork digests with their metadata.
func (c *Config) GetAllForkDigestInfos() []ForkDigestInfo {
	var infos []ForkDigestInfo

	// Helper to add digest info for a specific fork version
	addDigestInfo := func(name string, forkVersion [4]byte, epoch uint64, blobParams *BlobScheduleEntry) {
		digest := c.GetForkDigest(forkVersion, blobParams)

		infos = append(infos, ForkDigestInfo{
			Digest:      digest,
			Name:        name,
			Epoch:       epoch,
			BlobParams:  blobParams,
			ForkVersion: forkVersion,
		})
	}

	// Genesis (epoch 0) - use genesis fork version
	addDigestInfo("Phase0/Genesis", c.genesisForkVersion, 0, nil)

	// All forks - use their specific fork versions
	for _, fork := range c.getForks() {
		if fork.epoch != nil {
			addDigestInfo(fork.name, *fork.parsedVersion, *fork.epoch, nil)

			// Special handling for Fulu fork with blob schedules (BPO)
			if fork.name == "Fulu" {
				for i, blobEntry := range c.BlobSchedule {
					if blobEntry.Epoch >= *fork.epoch {
						addDigestInfo(fmt.Sprintf("BPO-%d", i+1), *fork.parsedVersion, blobEntry.Epoch, &blobEntry)
					}
				}
			}
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
