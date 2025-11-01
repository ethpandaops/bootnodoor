package session

import (
	"net"
	"sync"
	"time"

	"github.com/pk910/bootoor/discv5/node"
	"github.com/sirupsen/logrus"
)

// DefaultSessionLifetime is the default lifetime for sessions (12 hours).
const DefaultSessionLifetime = 12 * time.Hour

// DefaultMaxSessions is the default maximum number of cached sessions.
const DefaultMaxSessions = 1000

// Cache manages active sessions with peers.
//
// The cache provides:
//   - Fast session lookup by node ID and address
//   - Automatic session expiration and cleanup
//   - LRU eviction when the cache is full
//   - Thread-safe concurrent access
type Cache struct {
	// sessions maps node ID to session
	sessions map[node.ID]*Session

	// sessionLifetime is how long sessions remain valid
	sessionLifetime time.Duration

	// maxSessions is the maximum number of sessions to cache
	maxSessions int

	// mu protects the sessions map
	mu sync.RWMutex

	// logger for debug messages
	logger logrus.FieldLogger
}

// NewCache creates a new session cache.
//
// Parameters:
//   - maxSessions: Maximum number of sessions to cache (0 = unlimited)
//   - sessionLifetime: How long sessions remain valid (0 = default 12h)
//   - logger: Optional logger for debug messages
//
// Example:
//
//	cache := NewCache(1000, 12*time.Hour, logger)
//	defer cache.Close()
func NewCache(maxSessions int, sessionLifetime time.Duration, logger logrus.FieldLogger) *Cache {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}

	if sessionLifetime <= 0 {
		sessionLifetime = DefaultSessionLifetime
	}

	return &Cache{
		sessions:        make(map[node.ID]*Session),
		sessionLifetime: sessionLifetime,
		maxSessions:     maxSessions,
		logger:          logger,
	}
}

// Get retrieves a session by node ID.
//
// Returns nil if no session exists or if the session has expired.
//
// Example:
//
//	session := cache.Get(remoteNodeID)
//	if session != nil {
//	    // Use session for encryption
//	}
func (c *Cache) Get(nodeID node.ID) *Session {
	c.mu.RLock()
	defer c.mu.RUnlock()

	session, exists := c.sessions[nodeID]
	if !exists {
		return nil
	}

	// Check if expired
	if session.IsExpired() {
		return nil
	}

	// Update last used time
	session.Touch()

	return session
}

// Put stores a session in the cache.
//
// If the cache is full, the least recently used session is evicted.
// If a session already exists for this node ID, it is replaced.
//
// Example:
//
//	cache.Put(session)
func (c *Cache) Put(session *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict
	if len(c.sessions) >= c.maxSessions {
		// Find and remove the least recently used session
		c.evictLRU()
	}

	// Store the session
	c.sessions[session.RemoteID] = session

	c.logger.WithField("nodeID", session.RemoteID).WithField("addr", session.RemoteAddr).WithField("lifetime", c.sessionLifetime).Trace("cached new session")
}

// Delete removes a session from the cache.
//
// Example:
//
//	cache.Delete(remoteNodeID)
func (c *Cache) Delete(nodeID node.ID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.sessions, nodeID)

	c.logger.WithField("nodeID", nodeID).Trace("deleted session")
}

// Count returns the number of cached sessions.
func (c *Cache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.sessions)
}

// CleanupExpired removes all expired sessions from the cache.
//
// This should be called periodically by a background goroutine.
//
// Returns the number of sessions removed.
//
// Example:
//
//	count := cache.CleanupExpired()
//	log.Printf("Removed %d expired sessions", count)
func (c *Cache) CleanupExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	var toDelete []node.ID

	for id, session := range c.sessions {
		if session.IsExpired() {
			toDelete = append(toDelete, id)
		}
	}

	for _, id := range toDelete {
		delete(c.sessions, id)
	}

	if len(toDelete) > 0 {
		c.logger.WithField("count", len(toDelete)).Info("cleaned up expired sessions")
	}

	return len(toDelete)
}

// evictLRU removes the least recently used session.
//
// Must be called with c.mu locked.
func (c *Cache) evictLRU() {
	if len(c.sessions) == 0 {
		return
	}

	// Find the session with the oldest LastUsed time
	var oldestID node.ID
	var oldestTime time.Time

	first := true
	for id, session := range c.sessions {
		session.mu.RLock()
		lastUsed := session.LastUsed
		session.mu.RUnlock()

		if first || lastUsed.Before(oldestTime) {
			oldestID = id
			oldestTime = lastUsed
			first = false
		}
	}

	// Delete the oldest session
	delete(c.sessions, oldestID)

	c.logger.WithField("nodeID", oldestID).WithField("lastUsed", time.Since(oldestTime)).Debug("evicted LRU session")
}

// GetByAddr retrieves a session by network address.
//
// This is slower than GetByID since it requires scanning all sessions.
// Use GetByID when possible.
func (c *Cache) GetByAddr(addr *net.UDPAddr) *Session {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, session := range c.sessions {
		if session.RemoteAddr.String() == addr.String() {
			if !session.IsExpired() {
				session.Touch()
				return session
			}
		}
	}

	return nil
}

// Stats returns statistics about the cache.
type Stats struct {
	Total   int
	Expired int
	Active  int
}

// GetStats returns statistics about cached sessions.
func (c *Cache) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := Stats{
		Total: len(c.sessions),
	}

	for _, session := range c.sessions {
		if session.IsExpired() {
			stats.Expired++
		} else {
			stats.Active++
		}
	}

	return stats
}

// GetNodeByID retrieves a node by ID from the session cache.
//
// Returns nil if no session exists or if the session has no node reference.
//
// This allows the session cache to act as a local node lookup table.
func (c *Cache) GetNodeByID(nodeID node.ID) *node.Node {
	session := c.Get(nodeID)
	if session == nil {
		return nil
	}

	return session.GetNode()
}

// Close cleans up the cache and releases resources.
func (c *Cache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sessions = nil

	return nil
}
