// Package ipnames maps peer IP addresses to human-readable names for the
// web UI, based on a mapping file provided by the operator.
//
// Two file formats are supported, auto-detected:
//
// A flat YAML map of IP addresses or CIDR ranges to names:
//
//	"170.64.167.121": do-syd-bootnode-1
//	"10.0.0.0/24": internal-lab
//
// Or an Ansible INI inventory, where the inventory hostname becomes the
// display name for its ansible_host IP:
//
//	[bootnodes]
//	do-syd-bootnode-1 ansible_host=170.64.167.121
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
	"strings"
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

// load parses the file (YAML map or Ansible INI inventory, auto-detected)
// and swaps in the new mapping.
func (r *Resolver) load() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return fmt.Errorf("failed to read IP names file: %w", err)
	}

	exact, cidrs, yamlErr := parseYAMLMapping(data)
	if yamlErr != nil {
		var iniErr error
		exact, iniErr = parseIniInventory(data)
		if iniErr != nil {
			return fmt.Errorf("IP names file is neither a YAML IP->name map (%v) nor an Ansible INI inventory (%v)", yamlErr, iniErr)
		}
		cidrs = nil
	}

	r.mu.Lock()
	r.exact = exact
	r.cidrs = cidrs
	r.mu.Unlock()
	return nil
}

// parseYAMLMapping parses the native format: a flat YAML map of IP or CIDR
// to display name.
func parseYAMLMapping(data []byte) (map[string]string, []cidrName, error) {
	var raw map[string]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("failed to parse as YAML map: %w", err)
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
			return nil, nil, fmt.Errorf("invalid IP or CIDR: %q", key)
		}
		// Normalize so lookups by net.IP.String() always hit.
		exact[ip.String()] = name
	}
	// Longest prefix first, so the first CIDR match is the most specific one.
	sort.Slice(cidrs, func(i, j int) bool { return cidrs[i].ones > cidrs[j].ones })
	return exact, cidrs, nil
}

// parseIniInventory extracts hostname -> ansible_host pairs from an Ansible
// INI inventory and returns them inverted (IP -> hostname). Hosts without an
// ansible_host that parses as an IP are skipped (e.g. DNS names, which the
// bootnode cannot match against the addresses it sees). [group:vars] and
// [group:children] sections are ignored. At least one usable entry is
// required, so an arbitrary text file is rejected instead of silently
// producing an empty mapping.
func parseIniInventory(data []byte) (map[string]string, error) {
	exact := make(map[string]string)
	inHostSection := true // hosts may appear before any [section]

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := line[1 : len(line)-1]
			// Only plain group sections list hosts.
			inHostSection = !strings.Contains(section, ":")
			continue
		}
		if !inHostSection {
			continue
		}

		fields := strings.Fields(line)
		name := fields[0]
		for _, kv := range fields[1:] {
			val, ok := strings.CutPrefix(kv, "ansible_host=")
			if !ok {
				continue
			}
			val = strings.Trim(val, `"'`)
			if ip := net.ParseIP(val); ip != nil {
				exact[ip.String()] = name
			}
			break
		}
	}

	if len(exact) == 0 {
		return nil, fmt.Errorf("no hosts with an ansible_host=<ip> entry found")
	}
	return exact, nil
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
