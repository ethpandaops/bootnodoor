// Package ipnames maps peer IP addresses to human-readable names for the
// web UI, based on a YAML file provided by the operator.
//
// The file is a flat map of IP addresses or CIDR ranges to names:
//
//	"170.64.167.121": do-syd-bootnode-1
//	"10.0.0.0/24": internal-lab
//
// Exact IP entries win over CIDR ranges; among matching CIDR ranges the
// longest prefix wins. The file is re-read when its modification time
// changes, so edits apply without restarting the bootnode.
package ipnames

import (
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// reloadCheckInterval limits how often Lookup stats the mapping file.
const reloadCheckInterval = 30 * time.Second

type cidrName struct {
	net  *net.IPNet
	ones int
	name string
}

// Resolver resolves IP addresses to configured display names.
// The zero value is not usable; create one with NewResolver.
type Resolver struct {
	path   string
	logger logrus.FieldLogger

	mu        sync.RWMutex
	exact     map[string]string
	cidrs     []cidrName
	modTime   time.Time
	lastCheck time.Time
}

// NewResolver loads the mapping file at path. It returns an error if the
// file cannot be read or parsed, so a misconfigured flag fails at startup
// instead of silently showing no names.
func NewResolver(path string, logger logrus.FieldLogger) (*Resolver, error) {
	r := &Resolver{
		path:   path,
		logger: logger,
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat IP names file: %w", err)
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	r.modTime = info.ModTime()
	r.lastCheck = time.Now()
	return r, nil
}

// load parses the file and swaps in the new mapping.
func (r *Resolver) load() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return fmt.Errorf("failed to read IP names file: %w", err)
	}

	var raw map[string]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to parse IP names file: %w", err)
	}

	exact := make(map[string]string, len(raw))
	cidrs := make([]cidrName, 0)
	for key, name := range raw {
		if _, ipNet, err := net.ParseCIDR(key); err == nil {
			ones, _ := ipNet.Mask.Size()
			cidrs = append(cidrs, cidrName{net: ipNet, ones: ones, name: name})
			continue
		}
		ip := net.ParseIP(key)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR in IP names file: %q", key)
		}
		// Normalize so lookups by net.IP.String() always hit.
		exact[ip.String()] = name
	}
	// Longest prefix first, so the first CIDR match is the most specific one.
	sort.Slice(cidrs, func(i, j int) bool { return cidrs[i].ones > cidrs[j].ones })

	r.mu.Lock()
	r.exact = exact
	r.cidrs = cidrs
	r.mu.Unlock()
	return nil
}

// maybeReload re-reads the file if its modification time changed. Checks
// are throttled to once per reloadCheckInterval. A file that turns invalid
// after startup keeps the last good mapping and logs the error.
func (r *Resolver) maybeReload() {
	r.mu.RLock()
	due := time.Since(r.lastCheck) >= reloadCheckInterval
	r.mu.RUnlock()
	if !due {
		return
	}

	r.mu.Lock()
	if time.Since(r.lastCheck) < reloadCheckInterval {
		r.mu.Unlock()
		return
	}
	r.lastCheck = time.Now()
	prevMod := r.modTime
	r.mu.Unlock()

	info, err := os.Stat(r.path)
	if err != nil {
		r.logger.WithError(err).Warn("failed to stat IP names file, keeping current mapping")
		return
	}
	if info.ModTime().Equal(prevMod) {
		return
	}

	if err := r.load(); err != nil {
		r.logger.WithError(err).Warn("failed to reload IP names file, keeping current mapping")
		return
	}
	r.mu.Lock()
	r.modTime = info.ModTime()
	r.mu.Unlock()
	r.logger.WithField("file", r.path).Info("reloaded IP names file")
}

// Lookup returns the configured name for ip, or "" if there is none.
func (r *Resolver) Lookup(ipStr string) string {
	r.maybeReload()

	r.mu.RLock()
	defer r.mu.RUnlock()

	if name, ok := r.exact[ipStr]; ok {
		return name
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	for _, c := range r.cidrs {
		if c.net.Contains(ip) {
			return c.name
		}
	}
	return ""
}
