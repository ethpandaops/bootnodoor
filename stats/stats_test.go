package stats

import (
	"testing"
	"time"
)

func TestIsAliveFallsBackToFirstSeen(t *testing.T) {
	const (
		maxAge      = 24 * time.Hour
		maxFailures = 3
	)
	now := time.Now()

	tests := []struct {
		name         string
		firstSeen    time.Time
		lastSeen     time.Time
		failureCount int
		want         bool
	}{
		{"fresh never contacted", now, time.Time{}, 0, true},
		{"stale never contacted", now.Add(-25 * time.Hour), time.Time{}, 0, false},
		{"no timestamps at all", time.Time{}, time.Time{}, 0, false},
		{"recently seen old node", now.Add(-48 * time.Hour), now.Add(-time.Hour), 0, true},
		{"stale last seen", now.Add(-48 * time.Hour), now.Add(-25 * time.Hour), 0, false},
		{"fresh but too many failures", now, time.Time{}, maxFailures, false},
		{"seen but too many failures", now, now, maxFailures, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSharedStats(tt.firstSeen)
			s.SetLastSeen(tt.lastSeen)
			s.SetFailureCount(tt.failureCount)

			if got := s.IsAlive(maxAge, maxFailures); got != tt.want {
				t.Errorf("IsAlive() = %v, want %v", got, tt.want)
			}
		})
	}
}
