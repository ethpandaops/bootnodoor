package node

import (
	"math/bits"
)

// Distance calculates the XOR distance between two node IDs.
//
// In Kademlia, distance is defined as the XOR of two node IDs.
// This creates a metric space where:
//   - d(x, x) = 0 (distance to self is zero)
//   - d(x, y) = d(y, x) (symmetric)
//   - d(x, z) <= d(x, y) + d(y, z) (triangle inequality)
//
// The distance is returned as the ID itself (32 bytes).
//
// Example:
//
//	id1 := PubkeyToID(pubKey1)
//	id2 := PubkeyToID(pubKey2)
//	dist := Distance(id1, id2)
func Distance(a, b ID) ID {
	var result ID
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// LogDistance calculates the logarithmic distance (bucket index) between two node IDs.
//
// Returns the position of the most significant bit in the XOR distance,
// which determines the Kademlia bucket (0-255).
//
// A distance of 0 means the nodes are identical (returns -1).
// A distance with MSB at position N means the nodes differ starting at bit N.
//
// Example:
//
//	logDist := LogDistance(id1, id2)
//	// logDist is the bucket index (0-255) for the routing table
func LogDistance(a, b ID) int {
	dist := Distance(a, b)

	// Count leading zeros across all bytes
	// This follows the Geth/Ethereum implementation
	lz := 0
	for i := 0; i < len(dist); i++ {
		if dist[i] == 0 {
			lz += 8
		} else {
			lz += bits.LeadingZeros8(dist[i])
			break
		}
	}

	// Return 255 - leadingZeros (position of MSB)
	// If all bits are zero (identical nodes), lz = 256, return -1
	if lz == 256 {
		return -1
	}

	// Bucket index is the position of the MSB (0-255)
	return 255 - lz
}

// Compare compares the distance from target to a vs target to b.
//
// Returns:
//   - -1 if a is closer to target than b
//   - 0 if a and b are equidistant from target
//   - 1 if b is closer to target than a
//
// This is used for sorting nodes by distance in discovery operations.
//
// Example:
//
//	// Sort nodes by distance to target
//	sort.Slice(nodes, func(i, j int) bool {
//	    return Compare(target, nodes[i].ID(), nodes[j].ID()) < 0
//	})
func Compare(target, a, b ID) int {
	distA := Distance(target, a)
	distB := Distance(target, b)

	for i := 0; i < len(distA); i++ {
		if distA[i] < distB[i] {
			return -1
		}
		if distA[i] > distB[i] {
			return 1
		}
	}

	return 0
}

// CloserTo checks if node a is closer to target than node b.
//
// Equivalent to Compare(target, a, b) < 0, but more readable.
//
// Example:
//
//	if CloserTo(target, node1.ID(), node2.ID()) {
//	    // node1 is closer to target
//	}
func CloserTo(target, a, b ID) bool {
	return Compare(target, a, b) < 0
}

// FindClosest finds the k closest node IDs to the target from a list.
//
// The result is sorted by distance (closest first).
// If the list contains fewer than k nodes, all nodes are returned.
//
// Example:
//
//	target := localNode.ID()
//	nodeIDs := []ID{id1, id2, id3, id4, id5}
//	closest := FindClosest(target, nodeIDs, 3) // Get 3 closest
func FindClosest(target ID, nodes []ID, k int) []ID {
	if len(nodes) == 0 {
		return nil
	}

	if len(nodes) <= k {
		// All nodes fit, just sort them
		result := make([]ID, len(nodes))
		copy(result, nodes)
		sortByDistance(target, result)
		return result
	}

	// Use partial sort to find k closest
	result := make([]ID, len(nodes))
	copy(result, nodes)
	sortByDistance(target, result)

	return result[:k]
}

// sortByDistance sorts node IDs by distance to target (closest first).
func sortByDistance(target ID, nodes []ID) {
	// Simple insertion sort (efficient for small lists)
	for i := 1; i < len(nodes); i++ {
		key := nodes[i]
		j := i - 1

		for j >= 0 && Compare(target, key, nodes[j]) < 0 {
			nodes[j+1] = nodes[j]
			j--
		}
		nodes[j+1] = key
	}
}

// BucketIndex returns the bucket index for a given distance.
//
// This is the same as LogDistance but named more clearly for routing table use.
func BucketIndex(local, remote ID) int {
	return LogDistance(local, remote)
}
