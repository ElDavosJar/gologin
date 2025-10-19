package gologin

import (
	"fmt"
	"sync"
	"time"
)

// TokenBlacklist provides a mechanism to revoke tokens before they expire
// This is essential for logout functionality and security incidents
type TokenBlacklist interface {
	// Add adds a token to the blacklist until its expiration time
	Add(tokenID string, expiresAt time.Time) error
	
	// IsBlacklisted checks if a token is blacklisted
	IsBlacklisted(tokenID string) bool
	
	// Remove removes a token from the blacklist (cleanup after expiration)
	Remove(tokenID string) error
}

// InMemoryTokenBlacklist is a simple in-memory implementation
// For production, use Redis or a database with TTL support
type InMemoryTokenBlacklist struct {
	tokens map[string]time.Time
	mu     sync.RWMutex
}

// NewInMemoryTokenBlacklist creates a new in-memory token blacklist
func NewInMemoryTokenBlacklist() *InMemoryTokenBlacklist {
	bl := &InMemoryTokenBlacklist{
		tokens: make(map[string]time.Time),
	}
	
	// Start cleanup goroutine
	go bl.cleanup()
	
	return bl
}

// Add adds a token to the blacklist
func (bl *InMemoryTokenBlacklist) Add(tokenID string, expiresAt time.Time) error {
	if tokenID == "" {
		return fmt.Errorf("tokenID cannot be empty")
	}
	
	bl.mu.Lock()
	defer bl.mu.Unlock()
	
	bl.tokens[tokenID] = expiresAt
	return nil
}

// IsBlacklisted checks if a token is blacklisted
func (bl *InMemoryTokenBlacklist) IsBlacklisted(tokenID string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	
	expiresAt, exists := bl.tokens[tokenID]
	if !exists {
		return false
	}
	
	// If token has expired, remove it and return false
	if time.Now().After(expiresAt) {
		bl.mu.RUnlock()
		bl.mu.Lock()
		delete(bl.tokens, tokenID)
		bl.mu.Unlock()
		bl.mu.RLock()
		return false
	}
	
	return true
}

// Remove removes a token from the blacklist
func (bl *InMemoryTokenBlacklist) Remove(tokenID string) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	
	delete(bl.tokens, tokenID)
	return nil
}

// cleanup removes expired tokens periodically
func (bl *InMemoryTokenBlacklist) cleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		bl.mu.Lock()
		now := time.Now()
		for tokenID, expiresAt := range bl.tokens {
			if now.After(expiresAt) {
				delete(bl.tokens, tokenID)
			}
		}
		bl.mu.Unlock()
	}
}

// Count returns the number of blacklisted tokens
func (bl *InMemoryTokenBlacklist) Count() int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return len(bl.tokens)
}
