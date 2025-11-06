// Package stats provides shared statistics tracking for nodes.
package stats

import (
	"sync"
	"time"
)

// DirtyFlags represents which stats fields were updated.
type DirtyFlags uint8

const (
	DirtyLastSeen DirtyFlags = 0x01 // last_seen updated
	DirtyStats    DirtyFlags = 0x02 // success/failure/rtt updated
)

// SharedStats holds node statistics that can be shared between protocol-specific
// nodes (v4/v5) and the generic node wrapper.
// It includes its own mutex for thread-safe access.
type SharedStats struct {
	mu           sync.RWMutex
	firstSeen    time.Time
	lastSeen     time.Time
	lastPing     time.Time
	failureCount int
	successCount int
	avgRTT       time.Duration

	// updateCallback is called when stats are updated with dirty flags
	// This is used to trigger database writes
	updateCallback func(DirtyFlags)
}

// NewSharedStats creates a new SharedStats with the given first seen time.
func NewSharedStats(firstSeen time.Time) *SharedStats {
	return &SharedStats{
		firstSeen:      firstSeen,
		lastSeen:       time.Time{},
		lastPing:       time.Time{},
		failureCount:   0,
		successCount:   0,
		avgRTT:         0,
		updateCallback: nil,
	}
}

// SetCallback sets the callback function that is triggered when stats are updated.
// The callback receives dirty flags indicating which fields were changed.
// This is typically used to notify the database to persist changes.
func (s *SharedStats) SetCallback(callback func(DirtyFlags)) {
	s.mu.Lock()
	s.updateCallback = callback
	s.mu.Unlock()
}

// triggerCallback calls the update callback if it's set.
// This should be called after the lock is released to avoid deadlocks.
func (s *SharedStats) triggerCallback(flags DirtyFlags) {
	s.mu.RLock()
	callback := s.updateCallback
	s.mu.RUnlock()

	if callback != nil {
		callback(flags)
	}
}

// FirstSeen returns the first time the node was discovered.
func (s *SharedStats) FirstSeen() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.firstSeen
}

// SetFirstSeen updates the first seen time.
func (s *SharedStats) SetFirstSeen(t time.Time) {
	s.mu.Lock()
	s.firstSeen = t
	s.mu.Unlock()
}

// LastSeen returns the last time the node was seen.
func (s *SharedStats) LastSeen() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSeen
}

// SetLastSeen updates the last seen time.
func (s *SharedStats) SetLastSeen(t time.Time) {
	s.mu.Lock()
	s.lastSeen = t
	s.mu.Unlock()
	s.triggerCallback(DirtyLastSeen)
}

// LastPing returns the last time a ping was sent to the node.
func (s *SharedStats) LastPing() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastPing
}

// SetLastPing updates the last ping time.
func (s *SharedStats) SetLastPing(t time.Time) {
	s.mu.Lock()
	s.lastPing = t
	s.mu.Unlock()
}

// FailureCount returns the consecutive failure count.
func (s *SharedStats) FailureCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.failureCount
}

// SetFailureCount sets the failure count.
func (s *SharedStats) SetFailureCount(count int) {
	s.mu.Lock()
	s.failureCount = count
	s.mu.Unlock()
	s.triggerCallback(DirtyStats)
}

// IncrementFailureCount increases the failure count by 1.
func (s *SharedStats) IncrementFailureCount() {
	s.mu.Lock()
	s.failureCount++
	s.mu.Unlock()
	s.triggerCallback(DirtyStats)
}

// SuccessCount returns the total success count.
func (s *SharedStats) SuccessCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.successCount
}

// SetSuccessCount sets the success count.
func (s *SharedStats) SetSuccessCount(count int) {
	s.mu.Lock()
	s.successCount = count
	s.mu.Unlock()
	s.triggerCallback(DirtyStats)
}

// IncrementSuccessCount increases the success count by 1.
func (s *SharedStats) IncrementSuccessCount() {
	s.mu.Lock()
	s.successCount++
	s.mu.Unlock()
	s.triggerCallback(DirtyStats)
}

// ResetFailureCount resets the failure count to 0 and increments success count.
func (s *SharedStats) ResetFailureCount() {
	s.mu.Lock()
	s.failureCount = 0
	s.successCount++
	s.mu.Unlock()
	s.triggerCallback(DirtyStats)
}

// AvgRTT returns the average round-trip time.
func (s *SharedStats) AvgRTT() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.avgRTT
}

// UpdateRTT updates the average RTT using exponential moving average.
// The new average is: avgRTT = (0.875 * avgRTT) + (0.125 * newRTT)
func (s *SharedStats) UpdateRTT(rtt time.Duration) {
	s.mu.Lock()
	if s.avgRTT == 0 {
		s.avgRTT = rtt
	} else {
		// Exponential moving average (7/8 old + 1/8 new)
		s.avgRTT = (s.avgRTT * 7 / 8) + (rtt / 8)
	}
	s.mu.Unlock()
	s.triggerCallback(DirtyStats)
}

// IsAlive checks if the node is considered alive.
// A node is alive if it was seen recently and has few failures.
func (s *SharedStats) IsAlive(maxAge time.Duration, maxFailures int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.lastSeen.IsZero() {
		return false // Never seen
	}

	age := time.Since(s.lastSeen)
	return age < maxAge && s.failureCount < maxFailures
}

// NeedsPing checks if the node needs a liveness check.
// Returns true if never pinged or it's been longer than pingInterval.
func (s *SharedStats) NeedsPing(pingInterval time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.lastPing.IsZero() {
		return true // Never pinged
	}

	return time.Since(s.lastPing) > pingInterval
}

// Snapshot returns a snapshot of all stats (for GetStats methods).
type Snapshot struct {
	FirstSeen    time.Time
	LastSeen     time.Time
	LastPing     time.Time
	FailureCount int
	SuccessCount int
	AvgRTT       time.Duration
}

// GetSnapshot returns a snapshot of the current statistics.
func (s *SharedStats) GetSnapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Snapshot{
		FirstSeen:    s.firstSeen,
		LastSeen:     s.lastSeen,
		LastPing:     s.lastPing,
		FailureCount: s.failureCount,
		SuccessCount: s.successCount,
		AvgRTT:       s.avgRTT,
	}
}
