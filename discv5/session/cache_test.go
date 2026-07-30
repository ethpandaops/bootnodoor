package session

import (
	"net"
	"testing"
	"time"

	"github.com/ethpandaops/bootnodoor/discv5/node"
	"github.com/sirupsen/logrus"
)

func quietCache(t *testing.T, maxSessions int) *Cache {
	t.Helper()
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	return NewCache(maxSessions, time.Hour, logger)
}

func testSession(id byte, addr *net.UDPAddr) *Session {
	var nodeID node.ID
	nodeID[0] = id
	keys := &SessionKeys{
		InitiatorKey: []byte("0123456789abcdef"),
		RecipientKey: []byte("fedcba9876543210"),
	}
	return NewSession(nodeID, addr, keys, false, time.Hour)
}

// Replacing an existing session frees no slot, so it must not evict anyone.
// Handshake recovery replaces a retained session by node ID; evicting on that
// path would drop an unrelated live peer and leave the cache below capacity.
func TestPutReplacingDoesNotEvict(t *testing.T) {
	cache := quietCache(t, 2)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 30303}

	first := testSession(1, addr)
	second := testSession(2, addr)
	cache.Put(first)
	cache.Put(second)

	if cache.Count() != 2 {
		t.Fatalf("Count = %d after filling, want 2", cache.Count())
	}

	// Recovery touches the stale entry, then replaces it with fresh keys.
	cache.Get(first.RemoteID)
	cache.Put(testSession(1, addr))

	if cache.Count() != 2 {
		t.Errorf("Count = %d after replacing an existing session, want 2", cache.Count())
	}
	if cache.Get(second.RemoteID) == nil {
		t.Error("replacing one session evicted an unrelated peer")
	}
}

// Adding a genuinely new session at capacity must still evict, or the cache
// would grow without bound.
func TestPutNewAtCapacityEvicts(t *testing.T) {
	cache := quietCache(t, 2)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 30303}

	cache.Put(testSession(1, addr))
	cache.Put(testSession(2, addr))
	cache.Put(testSession(3, addr))

	if cache.Count() > 2 {
		t.Fatalf("Count = %d, want the cache bounded at 2", cache.Count())
	}
}
