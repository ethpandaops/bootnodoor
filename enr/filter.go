package enr

import (
	"bytes"
	"net"
)

// ENRFilter is a function that filters ENR records based on arbitrary criteria.
//
// Filters return true if the record should be accepted, false if it should be rejected.
// They are used in two stages of the discovery process:
//
//  1. Admission filtering: Before adding nodes to the local routing table
//  2. Response filtering: When serving FINDNODE responses to remote peers
//
// Example filters:
//   - Check for specific protocol support (e.g., eth2 fork digest)
//   - Verify IP address ranges
//   - Check client versions or capabilities
//   - Validate custom application-specific fields
//
// Example:
//
//	// Filter for nodes with a specific eth2 fork digest
//	filter := func(r *Record) bool {
//	    var eth2Data Eth2ENRData
//	    if err := r.Get("eth2", &eth2Data); err != nil {
//	        return false // No eth2 field
//	    }
//	    return bytes.Equal(eth2Data.ForkDigest[:], expectedDigest[:])
//	}
type ENRFilter func(*Record) bool

// ResponseFilter is a context-aware filter for serving FINDNODE responses.
//
// Unlike ENRFilter which operates only on the record, ResponseFilter also
// receives information about the requester (their network address).
//
// This enables filtering based on the relationship between requester and node:
//   - Don't serve LAN IPs to WAN requesters
//   - Apply geographic filtering
//   - Implement custom privacy policies
//
// Example:
//
//	// Don't serve LAN nodes to WAN requesters
//	filter := func(requester *net.UDPAddr, r *Record) bool {
//	    if IsWANAddress(requester.IP) && IsLANAddress(r.IP()) {
//	        return false
//	    }
//	    return true
//	}
type ResponseFilter func(requester *net.UDPAddr, record *Record) bool

// ChainFilters combines multiple filters with AND logic.
//
// The combined filter returns true only if all filters return true.
// If any filter returns false, the combined filter returns false.
//
// Short-circuit evaluation: Filters are evaluated in order and evaluation
// stops at the first filter that returns false.
//
// Example:
//
//	// Combine eth2 fork check and IP range check
//	filter := ChainFilters(
//	    Eth2ForkFilter(expectedForkDigest),
//	    IPRangeFilter(allowedRanges),
//	)
func ChainFilters(filters ...ENRFilter) ENRFilter {
	return func(r *Record) bool {
		for _, filter := range filters {
			if !filter(r) {
				return false
			}
		}
		return true
	}
}

// ChainResponseFilters combines multiple response filters with AND logic.
//
// Similar to ChainFilters but for ResponseFilter types.
func ChainResponseFilters(filters ...ResponseFilter) ResponseFilter {
	return func(requester *net.UDPAddr, r *Record) bool {
		for _, filter := range filters {
			if !filter(requester, r) {
				return false
			}
		}
		return true
	}
}

// ByKey creates a filter that checks if a key exists in the record.
//
// This is useful for filtering nodes that support specific features or protocols.
//
// Example:
//
//	// Filter for nodes that have UDP port set
//	filter := ByKey("udp")
func ByKey(key string) ENRFilter {
	return func(r *Record) bool {
		return r.Has(key)
	}
}

// ByIP creates a filter that checks if the node's IP address is in the given range.
//
// The range is specified as a CIDR notation string (e.g., "192.168.0.0/16").
//
// Example:
//
//	// Filter for nodes in private network
//	filter := ByIP("192.168.0.0/16")
func ByIP(cidr string) ENRFilter {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Invalid CIDR, return filter that rejects all
		return func(r *Record) bool {
			return false
		}
	}

	return func(r *Record) bool {
		ip := r.IP()
		if ip == nil {
			// Also check IPv6
			ip = r.IP6()
		}
		if ip == nil {
			return false
		}
		return ipNet.Contains(ip)
	}
}

// ByUDPPort creates a filter that checks if the UDP port matches.
//
// Example:
//
//	// Filter for nodes on port 9000
//	filter := ByUDPPort(9000)
func ByUDPPort(port uint16) ENRFilter {
	return func(r *Record) bool {
		return r.UDP() == port
	}
}

// ByIdentityScheme creates a filter that checks the identity scheme.
//
// Common schemes:
//   - "v4": secp256k1-based identity (most common)
//
// Example:
//
//	// Filter for v4 identity scheme
//	filter := ByIdentityScheme("v4")
func ByIdentityScheme(scheme string) ENRFilter {
	return func(r *Record) bool {
		return r.IdentityScheme() == scheme
	}
}

// Eth2ENRData represents the eth2 field in an ENR record.
//
// This field contains Ethereum 2.0 specific metadata including:
//   - ForkDigest: 4-byte identifier for the current fork
//   - NextForkVersion: Version of the next planned fork
//   - NextForkEpoch: Epoch when the next fork activates
type Eth2ENRData struct {
	ForkDigest      [4]byte
	NextForkVersion [4]byte
	NextForkEpoch   uint64
}

// EthENRData represents the eth field in an ENR record.
//
// This field contains Ethereum specific metadata including:
//   - ForkID: 4-byte identifier for the current fork
//   - NextForkEpoch: Epoch when the next fork activates
type EthENRData []struct {
	ForkID        [4]byte
	NextForkEpoch uint64
}

// Eth2ForkFilter creates a filter that checks for a specific eth2 fork digest.
//
// The fork digest identifies which Ethereum 2.0 network and fork the node
// is operating on (mainnet, testnet, etc.).
//
// This is commonly used as an admission filter to ensure discovered nodes
// are on the same network.
//
// Example:
//
//	// Filter for mainnet nodes (example fork digest)
//	mainnetForkDigest := [4]byte{0x01, 0x02, 0x03, 0x04}
//	filter := Eth2ForkFilter(mainnetForkDigest)
func Eth2ForkFilter(expectedForkDigest [4]byte) ENRFilter {
	return func(r *Record) bool {
		var eth2Data Eth2ENRData
		if err := r.Get("eth2", &eth2Data); err != nil {
			return false // No eth2 field
		}
		return bytes.Equal(eth2Data.ForkDigest[:], expectedForkDigest[:])
	}
}

// LANAwareResponseFilter creates a response filter that prevents serving
// LAN (private network) IPs to WAN (public internet) requesters.
//
// This is a security and efficiency measure:
//   - WAN peers can't connect to LAN addresses
//   - Prevents leaking internal network topology
//
// LAN addresses include:
//   - 10.0.0.0/8 (RFC1918)
//   - 172.16.0.0/12 (RFC1918)
//   - 192.168.0.0/16 (RFC1918)
//   - fc00::/7 (IPv6 ULA)
//   - fe80::/10 (IPv6 link-local)
//   - 127.0.0.0/8 (loopback)
//   - ::1 (IPv6 loopback)
//
// Example:
//
//	config := &Config{
//	    ResponseFilter: LANAwareResponseFilter(),
//	}
func LANAwareResponseFilter() ResponseFilter {
	return func(requester *net.UDPAddr, r *Record) bool {
		requesterIsLAN := IsLANAddress(requester.IP)

		recordIP := r.IP()
		if recordIP == nil {
			recordIP = r.IP6()
		}
		if recordIP == nil {
			return false // No IP in record
		}

		recordIsLAN := IsLANAddress(recordIP)

		// Don't serve LAN nodes to WAN requesters
		if !requesterIsLAN && recordIsLAN {
			return false
		}

		return true
	}
}

// IsLANAddress checks if an IP address is a private/local address.
//
// Returns true for:
//   - 10.0.0.0/8 (RFC1918)
//   - 172.16.0.0/12 (RFC1918)
//   - 192.168.0.0/16 (RFC1918)
//   - fc00::/7 (IPv6 ULA)
//   - fe80::/10 (IPv6 link-local)
//   - 127.0.0.0/8 (loopback)
//   - ::1 (IPv6 loopback)
func IsLANAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check for loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() {
		return true
	}

	// IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		return false
	}

	// IPv6 private ranges
	if ip6 := ip.To16(); ip6 != nil {
		// fc00::/7 (ULA)
		if ip6[0]&0xfe == 0xfc {
			return true
		}
		// fe80::/10 (link-local) - already checked above
	}

	return false
}

// IsWANAddress checks if an IP address is a publicly routable address.
//
// This is the inverse of IsLANAddress - returns true for public internet IPs.
func IsWANAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return !IsLANAddress(ip)
}
