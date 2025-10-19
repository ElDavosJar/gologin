package gologin

import (
	"fmt"
	"sync"
	"time"
)

// RateLimiter provides protection against brute force attacks
// by limiting the number of attempts from a specific identifier (IP, username, etc.)
type RateLimiter interface {
	// Allow checks if an action is allowed for the given identifier
	// Returns true if allowed, false if rate limit exceeded
	Allow(identifier string) bool
	
	// Reset clears the attempt count for an identifier
	Reset(identifier string)
}

// InMemoryRateLimiter is a simple in-memory implementation of RateLimiter
// For production use, consider a distributed solution (Redis, etc.)
type InMemoryRateLimiter struct {
	attempts     map[string]*attemptTracker
	maxAttempts  int
	windowPeriod time.Duration
	mu           sync.RWMutex
}

type attemptTracker struct {
	count      int
	windowStart time.Time
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter
// maxAttempts: maximum number of attempts allowed within the window period
// windowPeriod: time window for counting attempts (e.g., 15 minutes)
func NewInMemoryRateLimiter(maxAttempts int, windowPeriod time.Duration) *InMemoryRateLimiter {
	limiter := &InMemoryRateLimiter{
		attempts:     make(map[string]*attemptTracker),
		maxAttempts:  maxAttempts,
		windowPeriod: windowPeriod,
	}
	
	// Start background cleanup goroutine
	go limiter.cleanup()
	
	return limiter
}

// Allow checks if an attempt is allowed for the given identifier
func (rl *InMemoryRateLimiter) Allow(identifier string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	tracker, exists := rl.attempts[identifier]
	
	if !exists {
		// First attempt
		rl.attempts[identifier] = &attemptTracker{
			count:      1,
			windowStart: now,
		}
		return true
	}
	
	// Check if window has expired
	if now.Sub(tracker.windowStart) > rl.windowPeriod {
		// Reset the window
		tracker.count = 1
		tracker.windowStart = now
		return true
	}
	
	// Increment attempt count
	tracker.count++
	
	// Check if limit exceeded
	return tracker.count <= rl.maxAttempts
}

// Reset clears the attempt count for an identifier
func (rl *InMemoryRateLimiter) Reset(identifier string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, identifier)
}

// cleanup removes expired entries periodically to prevent memory leaks
func (rl *InMemoryRateLimiter) cleanup() {
	ticker := time.NewTicker(rl.windowPeriod)
	defer ticker.Stop()
	
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for identifier, tracker := range rl.attempts {
			if now.Sub(tracker.windowStart) > rl.windowPeriod {
				delete(rl.attempts, identifier)
			}
		}
		rl.mu.Unlock()
	}
}

// GetRemainingAttempts returns how many attempts are left for an identifier
func (rl *InMemoryRateLimiter) GetRemainingAttempts(identifier string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	
	tracker, exists := rl.attempts[identifier]
	if !exists {
		return rl.maxAttempts
	}
	
	// Check if window expired
	if time.Since(tracker.windowStart) > rl.windowPeriod {
		return rl.maxAttempts
	}
	
	remaining := rl.maxAttempts - tracker.count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ErrRateLimitExceeded is returned when rate limit is exceeded
var ErrRateLimitExceeded = fmt.Errorf("rate limit exceeded: too many attempts, please try again later")
