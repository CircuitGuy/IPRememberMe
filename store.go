package main

import (
	"sync"
	"time"
)

// entry represents a trusted IP record along with bookkeeping timestamps.
type entry struct {
	User      string    `json:"user"`
	ExpiresAt time.Time `json:"expiresAt"`
	LastSeen  time.Time `json:"lastSeen"`
}

// store owns the in-memory allowlist. It is intentionally simple: no persistence and guarded by a mutex.
type store struct {
	mu         sync.Mutex
	entries    map[string]entry
	duration   time.Duration
	maxPerUser int
}

func newStore(duration time.Duration, maxPerUser int) *store {
	return &store{
		entries:    make(map[string]entry),
		duration:   duration,
		maxPerUser: maxPerUser,
	}
}

// allowed returns the entry for an IP if it exists (expired entries are automatically pruned).
func (s *store) allowed(ip string, now time.Time) (entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	e, ok := s.entries[ip]
	return e, ok
}

// upsert registers or refreshes an IP. When a user exceeds their IP cap the oldest IP is evicted.
func (s *store) upsert(ip, user string, now time.Time) (entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)

	if existing, exists := s.entries[ip]; exists {
		existing.ExpiresAt = now.Add(s.duration)
		existing.LastSeen = now
		existing.User = user
		s.entries[ip] = existing
		return existing, nil
	}

	userIPs := make([]string, 0)
	for addr, e := range s.entries {
		if e.User == user {
			userIPs = append(userIPs, addr)
		}
	}
	if s.maxPerUser > 0 && len(userIPs) >= s.maxPerUser {
		oldestIP := userIPs[0]
		oldest := s.entries[oldestIP]
		for _, addr := range userIPs[1:] {
			e := s.entries[addr]
			if e.LastSeen.Before(oldest.LastSeen) {
				oldestIP = addr
				oldest = e
			}
		}
		delete(s.entries, oldestIP)
	}
	e := entry{
		User:      user,
		ExpiresAt: now.Add(s.duration),
		LastSeen:  now,
	}
	s.entries[ip] = e
	return e, nil
}

// refresh bumps TTL/LastSeen for existing entries only; cookies cannot recreate cleared IPs.
func (s *store) refresh(ip, user string, now time.Time) (entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	e, ok := s.entries[ip]
	if !ok {
		return entry{}, false
	}
	e.User = user
	e.LastSeen = now
	e.ExpiresAt = now.Add(s.duration)
	s.entries[ip] = e
	return e, true
}

// clear removes either a specific IP or the full allowlist. Returns number of entries removed.
func (s *store) clear(ip string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ip == "" {
		count := len(s.entries)
		s.entries = make(map[string]entry)
		return count
	}
	if _, ok := s.entries[ip]; ok {
		delete(s.entries, ip)
		return 1
	}
	return 0
}

// list returns a snapshot copy of all active entries.
func (s *store) list(now time.Time) map[string]entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	out := make(map[string]entry, len(s.entries))
	for k, v := range s.entries {
		out[k] = v
	}
	return out
}

// listByUser filters entries to a single user (used for the /user page).
func (s *store) listByUser(now time.Time, user string) map[string]entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	out := make(map[string]entry)
	for ip, e := range s.entries {
		if e.User == user {
			out[ip] = e
		}
	}
	return out
}

func (s *store) pruneLocked(now time.Time) {
	for ip, e := range s.entries {
		if now.After(e.ExpiresAt) {
			delete(s.entries, ip)
		}
	}
}
