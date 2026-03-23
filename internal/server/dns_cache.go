package server

import (
	"sync"
	"time"
)

// DNSCacheEntry represents a cached DNS resolution
type DNSCacheEntry struct {
	Hostname  string
	ExpiresAt time.Time
}

// DNSCache maintains IP to hostname mappings with TTL
type DNSCache struct {
	cache map[string]*DNSCacheEntry
	mu    sync.RWMutex
	ttl   time.Duration
}

// NewDNSCache creates a new DNS cache with the specified TTL
func NewDNSCache(ttl time.Duration) *DNSCache {
	dc := &DNSCache{
		cache: make(map[string]*DNSCacheEntry),
		ttl:   ttl,
	}

	// Start cleanup goroutine
	go dc.cleanupExpired()

	return dc
}

// Set adds or updates an IP to hostname mapping
func (dc *DNSCache) Set(ip, hostname string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	dc.cache[ip] = &DNSCacheEntry{
		Hostname:  hostname,
		ExpiresAt: time.Now().Add(dc.ttl),
	}
}

// Get retrieves a hostname for an IP if it exists and hasn't expired
func (dc *DNSCache) Get(ip string) (string, bool) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	entry, exists := dc.cache[ip]
	if !exists {
		return "", false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return "", false
	}

	return entry.Hostname, true
}

// cleanupExpired periodically removes expired entries
func (dc *DNSCache) cleanupExpired() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		dc.mu.Lock()
		now := time.Now()
		for ip, entry := range dc.cache {
			if now.After(entry.ExpiresAt) {
				delete(dc.cache, ip)
			}
		}
		dc.mu.Unlock()
	}
}

// Size returns the number of entries in the cache
func (dc *DNSCache) Size() int {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	return len(dc.cache)
}
