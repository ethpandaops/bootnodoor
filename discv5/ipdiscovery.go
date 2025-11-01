package discv5

import (
	"fmt"
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

// IPDiscovery tracks external IP addresses and ports reported by peers via PONG messages.
//
// It implements a consensus mechanism to detect the node's public IP address and port:
//   - Collects IP:Port from PONG responses (shows our address as seen by remote peer)
//   - Tracks IPv4 and IPv6 independently (separate consensus for each)
//   - Requires minimum number of reports before considering an address valid
//   - Requires majority threshold (e.g., 75%) for consensus
//   - Expires old reports to handle IP/port changes
type IPDiscovery struct {
	// mu protects the internal state
	mu sync.RWMutex

	// ipv4Reports maps "IP:Port" string to report info for IPv4
	ipv4Reports map[string]*ipReport

	// ipv6Reports maps "IP:Port" string to report info for IPv6
	ipv6Reports map[string]*ipReport

	// currentConsensusIPv4 is the IPv4 address that reached consensus
	currentConsensusIPv4 net.IP

	// currentConsensusIPv4Port is the IPv4 port that reached consensus
	currentConsensusIPv4Port uint16

	// currentConsensusIPv6 is the IPv6 address that reached consensus
	currentConsensusIPv6 net.IP

	// currentConsensusIPv6Port is the IPv6 port that reached consensus
	currentConsensusIPv6Port uint16

	// config
	minReports         int                             // Minimum reports needed
	majorityThreshold  float64                         // Threshold for majority (0.0-1.0)
	reportExpiry       time.Duration                   // How long to keep reports
	recentWindow       time.Duration                   // Time window for recent reports
	onConsensusReached func(ip net.IP, port uint16, isIPv6 bool) // Callback when consensus is reached
	logger             logrus.FieldLogger

	// stats
	totalReportsIPv4     int
	totalReportsIPv6     int
	consensusReachedIPv4 bool
	consensusReachedIPv6 bool
}

// ipReport tracks reports for a specific IP:Port combination
type ipReport struct {
	ip          net.IP
	port        uint16
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

	// OnConsensusReached is called when IP:Port consensus is reached or changes
	// isIPv6 indicates whether this is an IPv6 address (true) or IPv4 (false)
	OnConsensusReached func(ip net.IP, port uint16, isIPv6 bool)

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
		ipv4Reports:        make(map[string]*ipReport),
		ipv6Reports:        make(map[string]*ipReport),
		minReports:         cfg.MinReports,
		majorityThreshold:  cfg.MajorityThreshold,
		reportExpiry:       cfg.ReportExpiry,
		recentWindow:       cfg.RecentWindow,
		onConsensusReached: cfg.OnConsensusReached,
		logger:             cfg.Logger,
	}
}

// ReportIP records an IP address and port from a PONG response.
//
// Parameters:
//   - ip: The IP address as reported by the remote peer
//   - port: The port as reported by the remote peer
//   - reporterID: The node ID of the peer that sent the PONG (for tracking)
func (ipd *IPDiscovery) ReportIP(ip net.IP, port uint16, reporterID string) {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		// Ignore invalid IPs
		return
	}

	if port == 0 {
		// Ignore invalid ports
		return
	}

	// Determine if IPv4 or IPv6
	isIPv6 := ip.To4() == nil

	ipd.mu.Lock()
	defer ipd.mu.Unlock()

	// Clean up expired reports first
	ipd.cleanupExpiredLocked()

	// Use "IP:Port" as the key
	addrKey := fmt.Sprintf("%s:%d", ip.String(), port)
	now := time.Now()

	// Select appropriate reports map
	var reports map[string]*ipReport
	var totalReports *int
	if isIPv6 {
		reports = ipd.ipv6Reports
		totalReports = &ipd.totalReportsIPv6
	} else {
		reports = ipd.ipv4Reports
		totalReports = &ipd.totalReportsIPv4
	}

	// Get or create report for this IP:Port
	report, exists := reports[addrKey]
	if !exists {
		report = &ipReport{
			ip:          ip,
			port:        port,
			firstSeen:   now,
			reporterIDs: make([]string, 0),
		}
		reports[addrKey] = report
	}

	// Update report
	report.count++
	report.lastSeen = now
	report.reporterIDs = append(report.reporterIDs, reporterID)
	*totalReports++

	ipd.logger.WithFields(logrus.Fields{
		"addr":         addrKey,
		"ipv6":         isIPv6,
		"count":        report.count,
		"reporter":     reporterID[:16],
		"totalReports": *totalReports,
	}).Debug("IP discovery: received address report")

	// Check for consensus (check both IPv4 and IPv6)
	ipd.checkConsensusLocked()
}

// checkConsensusLocked checks if an IP:Port has reached consensus for both IPv4 and IPv6.
// Must be called with lock held.
//
// This function handles both initial consensus and address changes:
// - For initial consensus: requires minimum reports and majority threshold
// - For address changes: prioritizes recent reports to detect when IP or port has changed
func (ipd *IPDiscovery) checkConsensusLocked() {
	// Check IPv4 consensus
	ipd.checkConsensusForFamilyLocked(false)

	// Check IPv6 consensus
	ipd.checkConsensusForFamilyLocked(true)
}

// checkConsensusForFamilyLocked checks consensus for a specific address family (IPv4 or IPv6).
// Must be called with lock held.
func (ipd *IPDiscovery) checkConsensusForFamilyLocked(isIPv6 bool) {
	now := time.Now()

	// Select appropriate maps and state
	var reports map[string]*ipReport
	var currentConsensusIP *net.IP
	var currentConsensusPort *uint16
	var consensusReached *bool
	var totalReports *int
	familyName := "IPv4"

	if isIPv6 {
		reports = ipd.ipv6Reports
		currentConsensusIP = &ipd.currentConsensusIPv6
		currentConsensusPort = &ipd.currentConsensusIPv6Port
		consensusReached = &ipd.consensusReachedIPv6
		totalReports = &ipd.totalReportsIPv6
		familyName = "IPv6"
	} else {
		reports = ipd.ipv4Reports
		currentConsensusIP = &ipd.currentConsensusIPv4
		currentConsensusPort = &ipd.currentConsensusIPv4Port
		consensusReached = &ipd.consensusReachedIPv4
		totalReports = &ipd.totalReportsIPv4
	}

	// Separate recent reports from all reports
	recentReports := make(map[string]int)
	allReports := make(map[string]int)

	for addrKey, report := range reports {
		allReports[addrKey] = report.count

		// Count reports within the recent window
		if now.Sub(report.lastSeen) <= ipd.recentWindow {
			recentReports[addrKey] = report.count
		}
	}

	// Calculate totals
	totalCount := 0
	for _, count := range allReports {
		totalCount += count
	}

	totalRecentCount := 0
	for _, count := range recentReports {
		totalRecentCount += count
	}

	// Need minimum reports before considering consensus
	if totalCount < ipd.minReports {
		return
	}

	// Current consensus address key
	currentAddrKey := ""
	if *currentConsensusIP != nil && *currentConsensusPort != 0 {
		currentAddrKey = fmt.Sprintf("%s:%d", (*currentConsensusIP).String(), *currentConsensusPort)
	}

	// If we already have consensus, check recent reports for address changes
	if *consensusReached && totalRecentCount >= ipd.minReports {
		// Find address with most recent reports
		var maxRecentAddr string
		maxRecentCount := 0
		for addrKey, count := range recentReports {
			if count > maxRecentCount {
				maxRecentCount = count
				maxRecentAddr = addrKey
			}
		}

		// Check if recent reports show consensus on a DIFFERENT address
		if maxRecentAddr != "" && maxRecentAddr != currentAddrKey {
			recentMajority := float64(maxRecentCount) / float64(totalRecentCount)

			if recentMajority >= ipd.majorityThreshold {
				// Address change detected!
				newReport := reports[maxRecentAddr]

				ipd.logger.WithFields(logrus.Fields{
					"family":         familyName,
					"oldAddr":        currentAddrKey,
					"newAddr":        maxRecentAddr,
					"recentCount":    maxRecentCount,
					"recentTotal":    totalRecentCount,
					"recentMajority": recentMajority,
				}).Warn("IP discovery: address change detected")

				// Clear old reports to prevent flip-flopping
				for k := range reports {
					delete(reports, k)
				}

				// Re-add only the report for the new address
				if newReport != nil {
					reports[maxRecentAddr] = newReport
				}

				*currentConsensusIP = newReport.ip
				*currentConsensusPort = newReport.port
				*totalReports = maxRecentCount

				// Call callback for address change
				if ipd.onConsensusReached != nil {
					ip := newReport.ip
					port := newReport.port
					go ipd.onConsensusReached(ip, port, isIPv6)
				}
				return
			}
		}
	}

	// Check for initial consensus or stable consensus on all reports
	var maxReport *ipReport
	maxCount := 0
	for _, report := range reports {
		if report.count > maxCount {
			maxCount = report.count
			maxReport = report
		}
	}

	if maxReport == nil {
		return
	}

	// Check if it meets majority threshold
	majority := float64(maxReport.count) / float64(totalCount)
	if majority >= ipd.majorityThreshold {
		// Consensus reached!
		addrChanged := !*consensusReached ||
			*currentConsensusIP == nil ||
			!maxReport.ip.Equal(*currentConsensusIP) ||
			maxReport.port != *currentConsensusPort

		if addrChanged {
			ipd.logger.WithFields(logrus.Fields{
				"family":    familyName,
				"addr":      fmt.Sprintf("%s:%d", maxReport.ip.String(), maxReport.port),
				"count":     maxReport.count,
				"total":     totalCount,
				"majority":  majority,
				"threshold": ipd.majorityThreshold,
			}).Info("IP discovery: consensus reached")

			*currentConsensusIP = maxReport.ip
			*currentConsensusPort = maxReport.port
			*consensusReached = true

			// Call callback if provided
			if ipd.onConsensusReached != nil {
				// Call in goroutine to avoid blocking
				ip := maxReport.ip
				port := maxReport.port
				go ipd.onConsensusReached(ip, port, isIPv6)
			}
		}
	}
}

// cleanupExpiredLocked removes reports older than reportExpiry.
// Must be called with lock held.
func (ipd *IPDiscovery) cleanupExpiredLocked() {
	now := time.Now()

	// Clean up IPv4 reports
	for addrKey, report := range ipd.ipv4Reports {
		if now.Sub(report.lastSeen) > ipd.reportExpiry {
			delete(ipd.ipv4Reports, addrKey)
			ipd.logger.WithField("addr", addrKey).Debug("IP discovery: expired old IPv4 report")
		}
	}

	// Clean up IPv6 reports
	for addrKey, report := range ipd.ipv6Reports {
		if now.Sub(report.lastSeen) > ipd.reportExpiry {
			delete(ipd.ipv6Reports, addrKey)
			ipd.logger.WithField("addr", addrKey).Debug("IP discovery: expired old IPv6 report")
		}
	}
}

// GetConsensusIP returns the current consensus IPv4 address, or nil if no consensus.
// For IPv6, this returns nil. Use GetStats() for complete information.
func (ipd *IPDiscovery) GetConsensusIP() net.IP {
	ipd.mu.RLock()
	defer ipd.mu.RUnlock()
	return ipd.currentConsensusIPv4
}

// GetStats returns statistics about IP discovery.
type IPDiscoveryStats struct {
	TotalReportsIPv4     int
	TotalReportsIPv6     int
	UniqueIPv4Addrs      int
	UniqueIPv6Addrs      int
	ConsensusReachedIPv4 bool
	ConsensusReachedIPv6 bool
	ConsensusIPv4Addr    string            // "IP:Port" format
	ConsensusIPv6Addr    string            // "IP:Port" format
	IPv4Reports          map[string]int    // "IP:Port" -> count
	IPv6Reports          map[string]int    // "IP:Port" -> count
}

// GetStats returns current statistics.
func (ipd *IPDiscovery) GetStats() IPDiscoveryStats {
	ipd.mu.RLock()
	defer ipd.mu.RUnlock()

	stats := IPDiscoveryStats{
		TotalReportsIPv4:     ipd.totalReportsIPv4,
		TotalReportsIPv6:     ipd.totalReportsIPv6,
		UniqueIPv4Addrs:      len(ipd.ipv4Reports),
		UniqueIPv6Addrs:      len(ipd.ipv6Reports),
		ConsensusReachedIPv4: ipd.consensusReachedIPv4,
		ConsensusReachedIPv6: ipd.consensusReachedIPv6,
		IPv4Reports:          make(map[string]int),
		IPv6Reports:          make(map[string]int),
	}

	if ipd.currentConsensusIPv4 != nil && ipd.currentConsensusIPv4Port > 0 {
		stats.ConsensusIPv4Addr = fmt.Sprintf("%s:%d", ipd.currentConsensusIPv4.String(), ipd.currentConsensusIPv4Port)
	}

	if ipd.currentConsensusIPv6 != nil && ipd.currentConsensusIPv6Port > 0 {
		stats.ConsensusIPv6Addr = fmt.Sprintf("%s:%d", ipd.currentConsensusIPv6.String(), ipd.currentConsensusIPv6Port)
	}

	for addrKey, report := range ipd.ipv4Reports {
		stats.IPv4Reports[addrKey] = report.count
	}

	for addrKey, report := range ipd.ipv6Reports {
		stats.IPv6Reports[addrKey] = report.count
	}

	return stats
}

// Reset clears all reports and resets consensus state.
// This can be used when the node's network changes.
func (ipd *IPDiscovery) Reset() {
	ipd.mu.Lock()
	defer ipd.mu.Unlock()

	ipd.ipv4Reports = make(map[string]*ipReport)
	ipd.ipv6Reports = make(map[string]*ipReport)
	ipd.currentConsensusIPv4 = nil
	ipd.currentConsensusIPv4Port = 0
	ipd.currentConsensusIPv6 = nil
	ipd.currentConsensusIPv6Port = 0
	ipd.consensusReachedIPv4 = false
	ipd.consensusReachedIPv6 = false
	ipd.totalReportsIPv4 = 0
	ipd.totalReportsIPv6 = 0

	ipd.logger.Info("IP discovery: reset all reports")
}
