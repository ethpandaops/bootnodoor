package config

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/pk910/bootoor/discv5/enr"
)

// DefaultGracePeriod is the default time to keep nodes with old fork digests.
const DefaultGracePeriod = 60 * time.Minute

// ForkDigestFilter creates an ENR filter that checks fork digests dynamically.
//
// Features:
//   - Accepts nodes with ANY historically valid fork digest from the network
//   - Tracks current fork digest for prioritization
//   - Tracks old fork digests with grace period for response filtering
//   - Only checks the first 4 bytes of the eth2 field (fork digest)
//   - Ignores remainder bytes (future fork information)
type ForkDigestFilter struct {
	// config is the CL configuration
	config *Config

	// gracePeriod is how long to accept old fork digests in FINDNODE responses
	gracePeriod time.Duration

	// currentForkDigest is the current expected fork digest
	currentForkDigest ForkDigest

	// oldForkDigests tracks fork digests from previous forks with their activation times
	// These are used for response filtering (within grace period)
	oldForkDigests map[ForkDigest]time.Time

	// historicalDigests contains ALL valid fork digests from network history
	// These are accepted in admission filter but may be excluded from responses
	historicalDigests map[ForkDigest]bool

	// logger for debug messages (optional)
	logger Logger

	// mu protects concurrent access
	mu sync.RWMutex

	// lastUpdate is when we last updated the fork digest
	lastUpdate time.Time

	// Stats
	totalChecks        int
	acceptedCurrent    int
	acceptedOld        int
	acceptedHistorical int
	rejectedInvalid    int
	rejectedExpired    int
}

// Logger interface for debug messages
type Logger interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
}

// NewForkDigestFilter creates a new dynamic fork digest filter.
//
// Parameters:
//   - config: CL configuration for computing fork digests
//   - gracePeriod: How long to accept old fork digests (0 = default 60 minutes)
//
// Example:
//
//	config, _ := LoadConfig("config.yaml")
//	filter := NewForkDigestFilter(config, 60*time.Minute)
//
//	// Use as admission filter
//	service, _ := discv5.New(&discv5.Config{
//	    AdmissionFilter: filter.Filter(),
//	})
func NewForkDigestFilter(config *Config, gracePeriod time.Duration) *ForkDigestFilter {
	if gracePeriod <= 0 {
		gracePeriod = DefaultGracePeriod
	}

	// Get all historical fork digests from the config
	allDigests := config.GetAllForkDigests()
	historicalDigests := make(map[ForkDigest]bool)
	for _, digest := range allDigests {
		historicalDigests[digest] = true
	}

	f := &ForkDigestFilter{
		config:            config,
		gracePeriod:       gracePeriod,
		currentForkDigest: config.GetCurrentForkDigest(),
		oldForkDigests:    make(map[ForkDigest]time.Time),
		historicalDigests: historicalDigests,
		lastUpdate:        time.Now(),
	}

	return f
}

// SetLogger sets a logger for debug output.
func (f *ForkDigestFilter) SetLogger(logger Logger) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logger = logger
}

// Filter returns an ENR admission filter function.
//
// This filter accepts ALL historically valid fork digests:
//   - Current fork digest
//   - Old fork digests (within grace period)
//   - Any historically valid fork digest from the network
//
// Nodes with old digests are accepted into the routing table and will be
// pinged, which triggers ENR updates. Use ResponseFilter() to exclude them
// from FINDNODE responses.
//
// Example:
//
//	filter := NewForkDigestFilter(config, 60*time.Minute)
//	service, _ := discv5.New(&discv5.Config{
//	    AdmissionFilter: filter.Filter(),
//	    ResponseFilter: filter.ResponseFilter(),
//	})
func (f *ForkDigestFilter) Filter(record *enr.Record) bool {
	f.mu.Lock()
	f.totalChecks++
	f.mu.Unlock()

	// Get eth2 field from ENR
	var eth2Data []byte
	if err := record.Get("eth2", &eth2Data); err != nil {
		// No eth2 field, reject
		f.mu.Lock()
		f.rejectedInvalid++
		if f.logger != nil {
			f.logger.Debugf("Rejected node: no eth2 field in ENR")
		}
		f.mu.Unlock()
		return false
	}

	// Parse fork digest (first 4 bytes only)
	forkDigest, err := ParseETH2Field(eth2Data)
	if err != nil {
		// Invalid eth2 field, reject
		f.mu.Lock()
		f.rejectedInvalid++
		if f.logger != nil {
			f.logger.Debugf("Rejected node: invalid eth2 field - %v", err)
		}
		f.mu.Unlock()
		return false
	}

	f.mu.RLock()
	currentDigest := f.currentForkDigest
	oldDigests := f.oldForkDigests
	gracePeriod := f.gracePeriod
	historicalDigests := f.historicalDigests
	f.mu.RUnlock()

	// Check if matches current fork digest
	if forkDigest == currentDigest {
		f.mu.Lock()
		f.acceptedCurrent++
		f.mu.Unlock()
		return true
	}

	// Check if matches old fork digest within grace period
	if activationTime, exists := oldDigests[forkDigest]; exists {
		age := time.Since(activationTime)
		if age <= gracePeriod {
			f.mu.Lock()
			f.acceptedOld++
			f.mu.Unlock()
			return true
		}
		// Grace period expired but still historically valid - fall through
	}

	// Check if it's any historically valid fork digest
	// These nodes will be added to the table and pinged (triggering ENR updates)
	// but may be excluded from FINDNODE responses via ResponseFilter
	if historicalDigests[forkDigest] {
		f.mu.Lock()
		f.acceptedHistorical++
		if f.logger != nil {
			f.logger.Debugf("Accepted node with historical fork digest: %s (current: %s)", forkDigest.String(), currentDigest.String())
		}
		f.mu.Unlock()
		return true
	}

	// Unknown fork digest, reject
	f.mu.Lock()
	f.rejectedInvalid++
	if f.logger != nil {
		f.logger.Debugf("Rejected node: unknown fork digest %s (current: %s, %d historical digests known)",
			forkDigest.String(), currentDigest.String(), len(historicalDigests))
	}
	f.mu.Unlock()
	return false
}

// Update updates the fork digest based on the current epoch.
//
// This should be called periodically (e.g., every 5 minutes) to detect fork activations.
//
// When a fork activates:
//   - The old fork digest is moved to oldForkDigests with current timestamp
//   - The new fork digest becomes the current digest
//   - Nodes with the old digest are accepted for the grace period
func (f *ForkDigestFilter) Update() {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Compute fork digest for current epoch
	newDigest := f.config.GetCurrentForkDigest()

	// Check if fork digest changed
	if newDigest != f.currentForkDigest {
		// Fork activation detected!
		oldDigest := f.currentForkDigest

		// Move old digest to grace period tracking
		f.oldForkDigests[oldDigest] = time.Now()

		// Update current digest
		f.currentForkDigest = newDigest
		f.lastUpdate = time.Now()

		// Log would go here
		// logger.Info("Fork activated", "old", oldDigest, "new", newDigest)
	}

	// Clean up expired old digests
	now := time.Now()
	for digest, activationTime := range f.oldForkDigests {
		if now.Sub(activationTime) > f.gracePeriod {
			delete(f.oldForkDigests, digest)
		}
	}
}

// StartPeriodicUpdate starts a background goroutine that periodically updates the fork digest.
//
// Parameters:
//   - interval: How often to check for fork activations (e.g., 5 minutes)
//   - stopCh: Channel to signal shutdown
//
// Example:
//
//	stopCh := make(chan struct{})
//	filter.StartPeriodicUpdate(5*time.Minute, genesisTime, stopCh)
//
//	// Later, to stop:
//	close(stopCh)
func (f *ForkDigestFilter) StartPeriodicUpdate(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Update fork digest
			f.Update()

		case <-stopCh:
			return
		}
	}
}

// GetCurrentForkDigest returns the current fork digest being checked.
func (f *ForkDigestFilter) GetCurrentForkDigest() ForkDigest {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.currentForkDigest
}

// GetOldForkDigests returns the old fork digests still in grace period.
func (f *ForkDigestFilter) GetOldForkDigests() map[ForkDigest]time.Duration {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make(map[ForkDigest]time.Duration)
	now := time.Now()

	for digest, activationTime := range f.oldForkDigests {
		remaining := f.gracePeriod - now.Sub(activationTime)
		if remaining > 0 {
			result[digest] = remaining
		}
	}

	return result
}

// GetStats returns statistics about the filter.
type FilterStats struct {
	TotalChecks        int
	AcceptedCurrent    int
	AcceptedOld        int
	AcceptedHistorical int
	RejectedInvalid    int
	RejectedExpired    int
	CurrentDigest      ForkDigest
	OldDigests         int
	LastUpdate         time.Time
}

// GetStats returns filter statistics.
func (f *ForkDigestFilter) GetStats() FilterStats {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return FilterStats{
		TotalChecks:        f.totalChecks,
		AcceptedCurrent:    f.acceptedCurrent,
		AcceptedOld:        f.acceptedOld,
		AcceptedHistorical: f.acceptedHistorical,
		RejectedInvalid:    f.rejectedInvalid,
		RejectedExpired:    f.rejectedExpired,
		CurrentDigest:      f.currentForkDigest,
		OldDigests:         len(f.oldForkDigests),
		LastUpdate:         f.lastUpdate,
	}
}

// SetGracePeriod updates the grace period for old fork digests.
func (f *ForkDigestFilter) SetGracePeriod(period time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.gracePeriod = period
}

// ComputeEth2Field computes the eth2 ENR field for the current config.
//
// This is useful when creating your own ENR.
func (f *ForkDigestFilter) ComputeEth2Field() []byte {
	f.mu.RLock()
	currentDigest := f.currentForkDigest
	f.mu.RUnlock()

	// For simplicity, use placeholder for next fork
	// In production, this should track upcoming forks
	nextForkVersion := [4]byte{0xff, 0xff, 0xff, 0xff}
	nextForkEpoch := ^uint64(0) // Far future

	return EncodeETH2Field(currentDigest, nextForkVersion, nextForkEpoch)
}

// ForkFilterStatsProvider interface methods for webui integration

// GetCurrentFork returns the name of the current fork.
func (f *ForkDigestFilter) GetCurrentFork() string {
	// Get genesis time
	genesisTime := f.config.GetGenesisTime()
	if genesisTime == 0 {
		// No genesis time, fallback to "Unknown"
		return "Unknown"
	}

	// Calculate current epoch
	currentTime := uint64(time.Now().Unix())
	slotsPerEpoch := uint64(32)
	if f.config.PresetBase == "minimal" {
		slotsPerEpoch = 8
	}
	secondsPerSlot := f.config.SecondsPerSlot
	if secondsPerSlot == 0 {
		secondsPerSlot = 12
	}
	currentEpoch := uint64(GetCurrentEpoch(genesisTime, currentTime, secondsPerSlot, slotsPerEpoch))

	// Get fork name for current epoch
	return f.config.GetForkNameForEpoch(currentEpoch)
}

// GetCurrentDigest returns the current fork digest as a hex string.
func (f *ForkDigestFilter) GetCurrentDigest() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.currentForkDigest.String()
}

// GetGracePeriod returns the grace period as a string.
func (f *ForkDigestFilter) GetGracePeriod() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.gracePeriod.String()
}

// GetNetworkName returns the network name (e.g., "mainnet", "testnet").
func (f *ForkDigestFilter) GetNetworkName() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.config.ConfigName
}

// GetForkScoringInfo returns fork digest information for node scoring.
// This includes current, previous, and genesis fork digests with grace period info.
func (f *ForkDigestFilter) GetForkScoringInfo() *ForkScoringInfo {
	f.mu.RLock()
	defer f.mu.RUnlock()

	info := &ForkScoringInfo{
		CurrentForkDigest: f.currentForkDigest,
		GenesisForkDigest: f.config.GetGenesisForkDigest(),
	}

	// Find the most recent previous fork digest (if any)
	var mostRecentTime time.Time
	for digest, activationTime := range f.oldForkDigests {
		if activationTime.After(mostRecentTime) {
			info.PreviousForkDigest = digest
			mostRecentTime = activationTime
			info.GracePeriodEnd = activationTime.Add(f.gracePeriod)
		}
	}

	return info
}

// ForkScoringInfo contains fork digest information for node scoring.
type ForkScoringInfo struct {
	CurrentForkDigest  ForkDigest
	PreviousForkDigest ForkDigest
	GenesisForkDigest  ForkDigest
	GracePeriodEnd     time.Time
}

// GetOldDigests returns old fork digests with remaining grace time.
func (f *ForkDigestFilter) GetOldDigests() map[string]time.Duration {
	result := make(map[string]time.Duration)

	oldDigests := f.GetOldForkDigests()
	for digest, remaining := range oldDigests {
		result[digest.String()] = remaining
	}

	return result
}

// GetAcceptedCurrent returns the count of nodes accepted with current fork digest.
func (f *ForkDigestFilter) GetAcceptedCurrent() int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.acceptedCurrent
}

// GetAcceptedOld returns the count of nodes accepted with old fork digests.
func (f *ForkDigestFilter) GetAcceptedOld() int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.acceptedOld
}

// GetRejectedInvalid returns the count of nodes rejected due to invalid fork digest.
func (f *ForkDigestFilter) GetRejectedInvalid() int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.rejectedInvalid
}

// GetRejectedExpired returns the count of nodes rejected due to expired grace period.
func (f *ForkDigestFilter) GetRejectedExpired() int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.rejectedExpired
}

// GetTotalChecks returns the total number of filter checks performed.
func (f *ForkDigestFilter) GetTotalChecks() int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.totalChecks
}

// GetPreviousForkDigest returns the previous fork digest as a hex string.
func (f *ForkDigestFilter) GetPreviousForkDigest() string {
	return f.config.GetPreviousForkDigest().String()
}

// GetPreviousForkName returns the name of the previous fork.
func (f *ForkDigestFilter) GetPreviousForkName() string {
	return f.config.GetPreviousForkName()
}

// GetGenesisForkDigest returns the genesis fork digest as a hex string.
func (f *ForkDigestFilter) GetGenesisForkDigest() string {
	return f.config.GetGenesisForkDigest().String()
}

// CompatibilityMode creates a filter that accepts multiple fork digests.
//
// This is useful for networks during fork transitions where you want to
// be more lenient with peer acceptance.
//
// Example:
//
//	// Accept both Capella and Deneb
//	filter := CompatibilityMode([]ForkDigest{capellaDigest, denebDigest})
func CompatibilityMode(acceptedDigests []ForkDigest) enr.ENRFilter {
	digestMap := make(map[ForkDigest]bool)
	for _, d := range acceptedDigests {
		digestMap[d] = true
	}

	return func(record *enr.Record) bool {
		// Get eth2 field
		var eth2Data []byte
		if err := record.Get("eth2", &eth2Data); err != nil {
			return false
		}

		// Parse fork digest
		forkDigest, err := ParseETH2Field(eth2Data)
		if err != nil {
			return false
		}

		// Check if accepted
		return digestMap[forkDigest]
	}
}

// Helper to convert uint64 to bytes (big endian)
func uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// ForkFilterStats contains statistics about fork digest filtering.
type ForkFilterStats struct {
	NetworkName         string
	CurrentFork         string
	CurrentDigest       string
	PreviousFork        string
	PreviousDigest      string
	GenesisDigest       string
	GracePeriod         string
	OldDigests          map[string]time.Duration
	AcceptedCurrent     int
	AcceptedOld         int
	RejectedInvalid     int
	RejectedExpired     int
	TotalChecks         int
}
