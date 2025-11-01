package discv5

import (
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// DefaultMinReports is the minimum number of PONG responses needed before considering IP valid
const DefaultMinReports = 5

// DefaultMajorityThreshold is the percentage threshold for IP consensus (0.0-1.0)
const DefaultMajorityThreshold = 0.75

// DefaultReportExpiry is how long to keep IP reports before expiring them
const DefaultReportExpiry = 30 * time.Minute

// DefaultRecentWindow is the time window to consider reports "recent" for IP change detection
const DefaultRecentWindow = 5 * time.Minute

// IPDiscovery tracks external IP addresses reported by peers via PONG messages.
//
// It implements a consensus mechanism to detect the node's public IP address:
//   - Collects IPs from PONG responses (IP field shows our address as seen by remote peer)
//   - Requires minimum number of reports before considering an IP valid
//   - Requires majority threshold (e.g., 75%) for consensus
//   - Expires old reports to handle IP changes
type IPDiscovery struct {
	// mu protects the internal state
	mu sync.RWMutex

	// reports maps IP address to report info
	reports map[string]*ipReport

	// currentConsensusIP is the IP that reached consensus
	currentConsensusIP net.IP

	// config
	minReports         int           // Minimum reports needed
	majorityThreshold  float64       // Threshold for majority (0.0-1.0)
	reportExpiry       time.Duration // How long to keep reports
	recentWindow       time.Duration // Time window for recent reports
	onConsensusReached func(net.IP)  // Callback when consensus is reached
	logger             logrus.FieldLogger

	// stats
	totalReports     int
	uniqueIPs        int
	consensusReached bool
}

// ipReport tracks reports for a specific IP
type ipReport struct {
	ip          net.IP
	count       int
	firstSeen   time.Time
	lastSeen    time.Time
	reporterIDs []string // Track which peers reported this (for debugging)
}

// IPDiscoveryConfig contains configuration for IP discovery
type IPDiscoveryConfig struct {
	// MinReports is the minimum number of PONG responses needed (default: 3)
	MinReports int

	// MajorityThreshold is the percentage needed for consensus (default: 0.75)
	MajorityThreshold float64

	// ReportExpiry is how long to keep reports (default: 30 minutes)
	ReportExpiry time.Duration

	// RecentWindow is the time window to consider reports "recent" (default: 5 minutes)
	// Used for detecting IP changes - recent reports get priority
	RecentWindow time.Duration

	// OnConsensusReached is called when IP consensus is reached or changes
	OnConsensusReached func(net.IP)

	// Logger for debug messages
	Logger logrus.FieldLogger
}

// NewIPDiscovery creates a new IP discovery service.
func NewIPDiscovery(cfg IPDiscoveryConfig) *IPDiscovery {
	if cfg.MinReports <= 0 {
		cfg.MinReports = DefaultMinReports
	}
	if cfg.MajorityThreshold <= 0 || cfg.MajorityThreshold > 1.0 {
		cfg.MajorityThreshold = DefaultMajorityThreshold
	}
	if cfg.ReportExpiry <= 0 {
		cfg.ReportExpiry = DefaultReportExpiry
	}
	if cfg.RecentWindow <= 0 {
		cfg.RecentWindow = DefaultRecentWindow
	}
	if cfg.Logger == nil {
		cfg.Logger = logrus.New()
	}

	return &IPDiscovery{
		reports:            make(map[string]*ipReport),
		minReports:         cfg.MinReports,
		majorityThreshold:  cfg.MajorityThreshold,
		reportExpiry:       cfg.ReportExpiry,
		recentWindow:       cfg.RecentWindow,
		onConsensusReached: cfg.OnConsensusReached,
		logger:             cfg.Logger,
	}
}

// ReportIP records an IP address from a PONG response.
//
// Parameters:
//   - ip: The IP address as reported by the remote peer
//   - reporterID: The node ID of the peer that sent the PONG (for tracking)
func (ipd *IPDiscovery) ReportIP(ip net.IP, reporterID string) {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		// Ignore invalid IPs
		return
	}

	ipd.mu.Lock()
	defer ipd.mu.Unlock()

	// Clean up expired reports first
	ipd.cleanupExpiredLocked()

	ipStr := ip.String()
	now := time.Now()

	// Get or create report for this IP
	report, exists := ipd.reports[ipStr]
	if !exists {
		report = &ipReport{
			ip:          ip,
			firstSeen:   now,
			reporterIDs: make([]string, 0),
		}
		ipd.reports[ipStr] = report
		ipd.uniqueIPs++
	}

	// Update report
	report.count++
	report.lastSeen = now
	report.reporterIDs = append(report.reporterIDs, reporterID)
	ipd.totalReports++

	ipd.logger.WithFields(logrus.Fields{
		"ip":           ipStr,
		"count":        report.count,
		"reporter":     reporterID[:16],
		"totalReports": ipd.totalReports,
	}).Debug("IP discovery: received IP report")

	// Check for consensus
	ipd.checkConsensusLocked()
}

// checkConsensusLocked checks if an IP has reached consensus.
// Must be called with lock held.
//
// This function handles both initial consensus and IP changes:
// - For initial consensus: requires minimum reports and majority threshold
// - For IP changes: prioritizes recent reports to detect when IP has changed
func (ipd *IPDiscovery) checkConsensusLocked() {
	now := time.Now()

	// Separate recent reports from all reports
	recentReports := make(map[string]int)
	allReports := make(map[string]int)

	for ipStr, report := range ipd.reports {
		allReports[ipStr] = report.count

		// Count reports within the recent window
		if now.Sub(report.lastSeen) <= ipd.recentWindow {
			recentReports[ipStr] = report.count
		}
	}

	// Calculate totals
	totalReports := 0
	for _, count := range allReports {
		totalReports += count
	}

	totalRecentReports := 0
	for _, count := range recentReports {
		totalRecentReports += count
	}

	// Need minimum reports before considering consensus
	if totalReports < ipd.minReports {
		ipd.logger.WithFields(logrus.Fields{
			"totalReports": totalReports,
			"minReports":   ipd.minReports,
		}).Debug("IP discovery: not enough reports for consensus")
		return
	}

	// If we already have consensus, check recent reports for IP changes
	if ipd.consensusReached && totalRecentReports >= ipd.minReports {
		// Find IP with most recent reports
		var maxRecentIP string
		maxRecentCount := 0
		for ipStr, count := range recentReports {
			if count > maxRecentCount {
				maxRecentCount = count
				maxRecentIP = ipStr
			}
		}

		// Check if recent reports show consensus on a DIFFERENT IP
		if maxRecentIP != "" && maxRecentIP != ipd.currentConsensusIP.String() {
			recentMajority := float64(maxRecentCount) / float64(totalRecentReports)

			if recentMajority >= ipd.majorityThreshold {
				// IP change detected!
				newIP := net.ParseIP(maxRecentIP)

				ipd.logger.WithFields(logrus.Fields{
					"oldIP":          ipd.currentConsensusIP.String(),
					"newIP":          newIP.String(),
					"recentCount":    maxRecentCount,
					"recentTotal":    totalRecentReports,
					"recentMajority": recentMajority,
				}).Warn("IP discovery: IP change detected")

				// Save the new IP report before clearing
				var newIPReport *ipReport
				if report, exists := ipd.reports[maxRecentIP]; exists {
					newIPReport = report
				}

				// Clear old reports to prevent flip-flopping
				ipd.reports = make(map[string]*ipReport)

				// Re-add only the report for the new IP
				if newIPReport != nil {
					ipd.reports[maxRecentIP] = newIPReport
				}

				ipd.currentConsensusIP = newIP
				ipd.totalReports = maxRecentCount
				ipd.uniqueIPs = 1

				// Call callback for IP change
				if ipd.onConsensusReached != nil {
					ip := newIP
					go ipd.onConsensusReached(ip)
				}
				return
			}
		}
	}

	// Check for initial consensus or stable consensus on all reports
	var maxReport *ipReport
	maxCount := 0
	for _, report := range ipd.reports {
		if report.count > maxCount {
			maxCount = report.count
			maxReport = report
		}
	}

	if maxReport == nil {
		return
	}

	// Check if it meets majority threshold
	majority := float64(maxReport.count) / float64(totalReports)
	if majority >= ipd.majorityThreshold {
		// Consensus reached!
		if !ipd.consensusReached || !maxReport.ip.Equal(ipd.currentConsensusIP) {
			ipd.logger.WithFields(logrus.Fields{
				"ip":        maxReport.ip.String(),
				"count":     maxReport.count,
				"total":     totalReports,
				"majority":  majority,
				"threshold": ipd.majorityThreshold,
			}).Info("IP discovery: consensus reached")

			ipd.currentConsensusIP = maxReport.ip
			ipd.consensusReached = true

			// Call callback if provided
			if ipd.onConsensusReached != nil {
				// Call in goroutine to avoid blocking
				ip := maxReport.ip
				go ipd.onConsensusReached(ip)
			}
		}
	} else {
		ipd.logger.WithFields(logrus.Fields{
			"topIP":     maxReport.ip.String(),
			"count":     maxReport.count,
			"total":     totalReports,
			"majority":  majority,
			"threshold": ipd.majorityThreshold,
		}).Debug("IP discovery: no consensus yet")
	}
}

// cleanupExpiredLocked removes reports older than reportExpiry.
// Must be called with lock held.
func (ipd *IPDiscovery) cleanupExpiredLocked() {
	now := time.Now()
	for ipStr, report := range ipd.reports {
		if now.Sub(report.lastSeen) > ipd.reportExpiry {
			delete(ipd.reports, ipStr)
			ipd.logger.WithField("ip", ipStr).Debug("IP discovery: expired old report")
		}
	}
}

// GetConsensusIP returns the current consensus IP, or nil if no consensus.
func (ipd *IPDiscovery) GetConsensusIP() net.IP {
	ipd.mu.RLock()
	defer ipd.mu.RUnlock()
	return ipd.currentConsensusIP
}

// GetStats returns statistics about IP discovery.
type IPDiscoveryStats struct {
	TotalReports     int
	UniqueIPs        int
	ConsensusReached bool
	ConsensusIP      string
	Reports          map[string]int // IP -> count
}

// GetStats returns current statistics.
func (ipd *IPDiscovery) GetStats() IPDiscoveryStats {
	ipd.mu.RLock()
	defer ipd.mu.RUnlock()

	stats := IPDiscoveryStats{
		TotalReports:     ipd.totalReports,
		UniqueIPs:        len(ipd.reports),
		ConsensusReached: ipd.consensusReached,
		Reports:          make(map[string]int),
	}

	if ipd.currentConsensusIP != nil {
		stats.ConsensusIP = ipd.currentConsensusIP.String()
	}

	for ipStr, report := range ipd.reports {
		stats.Reports[ipStr] = report.count
	}

	return stats
}

// Reset clears all reports and resets consensus state.
// This can be used when the node's network changes.
func (ipd *IPDiscovery) Reset() {
	ipd.mu.Lock()
	defer ipd.mu.Unlock()

	ipd.reports = make(map[string]*ipReport)
	ipd.currentConsensusIP = nil
	ipd.consensusReached = false
	ipd.totalReports = 0
	ipd.uniqueIPs = 0

	ipd.logger.Info("IP discovery: reset all reports")
}
