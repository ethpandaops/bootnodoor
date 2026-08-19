package ipnames

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func writeMapping(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip-names.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLookup(t *testing.T) {
	path := writeMapping(t, `
"170.64.167.121": do-syd-bootnode-1
"10.0.0.0/16": lab-wide
"10.0.1.0/24": lab-subnet
"10.0.1.5": lab-host
"2001:db8::/32": v6-range
`)
	r, err := NewResolver(path, logrus.New())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ip   string
		want string
	}{
		{"170.64.167.121", "do-syd-bootnode-1"}, // exact match
		{"10.0.2.7", "lab-wide"},                // CIDR match
		{"10.0.1.9", "lab-subnet"},              // longest prefix wins over /16
		{"10.0.1.5", "lab-host"},                // exact wins over both CIDRs
		{"2001:db8::1", "v6-range"},             // IPv6 CIDR
		{"8.8.8.8", ""},                         // unmapped
		{"not-an-ip", ""},                       // garbage input
	}
	for _, tt := range tests {
		if got := r.Lookup(tt.ip); got != tt.want {
			t.Errorf("Lookup(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestInvalidEntry(t *testing.T) {
	path := writeMapping(t, `"not-an-ip": some-name`)
	if _, err := NewResolver(path, logrus.New()); err == nil {
		t.Fatal("expected error for invalid IP entry")
	}
}

func TestMissingFile(t *testing.T) {
	if _, err := NewResolver(filepath.Join(t.TempDir(), "nope.yaml"), logrus.New()); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReload(t *testing.T) {
	path := writeMapping(t, `"1.2.3.4": old-name`)
	r, err := NewResolver(path, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Lookup("1.2.3.4"); got != "old-name" {
		t.Fatalf("Lookup = %q, want old-name", got)
	}

	if err := os.WriteFile(path, []byte(`"1.2.3.4": new-name`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Force the throttle window to be considered expired.
	r.mu.Lock()
	r.lastCheck = r.lastCheck.Add(-2 * reloadCheckInterval)
	r.modTime = r.modTime.Add(-time.Hour)
	r.mu.Unlock()

	if got := r.Lookup("1.2.3.4"); got != "new-name" {
		t.Fatalf("Lookup after reload = %q, want new-name", got)
	}
}
