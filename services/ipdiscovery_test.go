package services

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func quietIPDiscovery(t *testing.T) (*IPDiscovery, <-chan string) {
	t.Helper()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	reached := make(chan string, 4)
	ipd := NewIPDiscovery(IPDiscoveryConfig{
		MinReports:     5,
		MinDistinctIPs: 3,
		Logger:         logger,
		OnConsensusReached: func(ip net.IP, port uint16, isIPv6 bool) {
			reached <- fmt.Sprintf("%s:%d", ip.String(), port)
		},
	})
	return ipd, reached
}

// A single peer must not reach consensus on its own, however many source
// addresses it appears to report from: UDP source IPs are spoofable, so
// distinct-IP alone is not a measure of independent opinions.
func TestConsensusRequiresDistinctReporters(t *testing.T) {
	ipd, reached := quietIPDiscovery(t)

	external := net.ParseIP("203.0.113.7")
	for i := 0; i < 8; i++ {
		reporterIP := net.IPv4(198, 51, 100, byte(1+i%4))
		ipd.ReportIP(external, 30303, "same-reporter-node-id-0000000000", reporterIP)
	}

	// The callback is dispatched with `go`, so a non-blocking receive here would
	// pass even when consensus fired.
	select {
	case addr := <-reached:
		t.Fatalf("one reporter reached consensus on %s across spoofed source IPs", addr)
	case <-time.After(500 * time.Millisecond):
	}
}

// The same report volume from genuinely distinct peers must still reach
// consensus, so the new gate does not simply disable IP discovery.
func TestConsensusReachedWithDistinctReporters(t *testing.T) {
	ipd, reached := quietIPDiscovery(t)

	external := net.ParseIP("203.0.113.7")
	for i := 0; i < 6; i++ {
		reporterIP := net.IPv4(198, 51, 100, byte(1+i))
		ipd.ReportIP(external, 30303, fmt.Sprintf("reporter-node-id-%026d", i), reporterIP)
	}

	select {
	case addr := <-reached:
		if addr != "203.0.113.7:30303" {
			t.Fatalf("consensus on %s, want 203.0.113.7:30303", addr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("distinct reporters did not reach consensus")
	}
}

// Every PONG refreshes the report for our own address, so it never expires.
// Its reporter sets must not grow with each node ID that ever answers.
func TestReporterSetsStayBounded(t *testing.T) {
	ipd, reached := quietIPDiscovery(t)

	external := net.ParseIP("203.0.113.7")
	for i := 0; i < 10000; i++ {
		reporterIP := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		ipd.ReportIP(external, 30303, fmt.Sprintf("reporter-node-id-%026d", i), reporterIP)
	}

	report := ipd.ipv4Reports["203.0.113.7:30303"]
	if report == nil {
		t.Fatal("no report for 203.0.113.7:30303")
	}
	if n := len(report.reporterIDs); n > ipd.minDistinctIPs {
		t.Fatalf("reporterIDs holds %d entries, want at most %d", n, ipd.minDistinctIPs)
	}
	if n := len(report.reporterIPs); n > ipd.minDistinctIPs {
		t.Fatalf("reporterIPs holds %d entries, want at most %d", n, ipd.minDistinctIPs)
	}

	select {
	case addr := <-reached:
		if addr != "203.0.113.7:30303" {
			t.Fatalf("consensus on %s, want 203.0.113.7:30303", addr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bounded reporter sets prevented consensus")
	}
}
