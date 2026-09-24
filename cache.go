package ipgeolocation

import (
	"sync"
	"time"
)

// cacheEntry is one memoized lookup.
type cacheEntry struct {
	fields  map[string]string
	found   bool
	expires time.Time
}

// resultCache is a bounded, time-limited cache. It keeps two generations of
// entries: writes go to the current generation, reads fall back to the
// previous one. When the current generation fills up it becomes the previous
// generation and a fresh map takes its place, which bounds memory at roughly
// twice maxEntries without the bookkeeping of a linked list.
type resultCache struct {
	mu         sync.RWMutex
	current    map[string]cacheEntry
	previous   map[string]cacheEntry
	maxEntries int
	ttl        time.Duration
}

func newResultCache(maxEntries int, ttl time.Duration) *resultCache {
	if maxEntries <= 0 || ttl <= 0 {
		return nil
	}
	return &resultCache{
		current:    make(map[string]cacheEntry, 64),
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

func (c *resultCache) get(key string) (cacheEntry, bool) {
	if c == nil {
		return cacheEntry{}, false
	}
	c.mu.RLock()
	entry, ok := c.current[key]
	if !ok && c.previous != nil {
		entry, ok = c.previous[key]
	}
	c.mu.RUnlock()

	if !ok || time.Now().After(entry.expires) {
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *resultCache) put(key string, fields map[string]string, found bool) {
	if c == nil {
		return
	}
	entry := cacheEntry{fields: fields, found: found, expires: time.Now().Add(c.ttl)}

	c.mu.Lock()
	if len(c.current) >= c.maxEntries {
		c.previous = c.current
		c.current = make(map[string]cacheEntry, c.maxEntries/4+1)
	}
	c.current[key] = entry
	c.mu.Unlock()
}

// reset empties the cache. It is called after a database refresh so that
// stale answers cannot outlive the data they came from.
func (c *resultCache) reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.current = make(map[string]cacheEntry, 64)
	c.previous = nil
	c.mu.Unlock()
}

// len reports the number of live entries, used by the tests.
func (c *resultCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.current) + len(c.previous)
}
