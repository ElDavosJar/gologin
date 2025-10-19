// Package gologin_test provides integration tests for the gologin package
// Run these tests with: go test -v ./examples/integration_test.go
package gologin_test

import (
	"testing"
	"time"

	"gologin"
)

// InMemoryUserRepository for testing
type testUserRepository struct {
	users       map[string]*gologin.User
	activeTokens map[string][]string // userID -> []tokenIDs
}

func newTestUserRepository() *testUserRepository {
	return &testUserRepository{
		users:        make(map[string]*gologin.User),
		activeTokens: make(map[string][]string),
	}
}

func (r *testUserRepository) Save(user *gologin.User) error {
	if user.ID == nil {
		id := "test-user-" + user.Username
		user.ID = &id
	}
	r.users[*user.ID] = user
	return nil
}

func (r *testUserRepository) FindByUsername(username string) (*gologin.User, error) {
	for _, user := range r.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, nil
}

func (r *testUserRepository) FindByID(id string) (*gologin.User, error) {
	user, exists := r.users[id]
	if !exists {
		return nil, nil
	}
	return user, nil
}

func (r *testUserRepository) IsUsernameTaken(username string) (bool, error) {
	for _, user := range r.users {
		if user.Username == username {
			return true, nil
		}
	}
	return false, nil
}

func (r *testUserRepository) GetActiveTokenIDs(userID string) ([]string, error) {
	return r.activeTokens[userID], nil
}

func (r *testUserRepository) AddActiveToken(userID, tokenID string) {
	r.activeTokens[userID] = append(r.activeTokens[userID], tokenID)
}

// Integration test: Complete user lifecycle
func TestCompleteUserLifecycle(t *testing.T) {
	repo := newTestUserRepository()
	jwtSecret := "test-jwt-secret-at-least-32-characters-long-for-testing"
	authService := gologin.NewAuthService(repo, jwtSecret)

	// 1. Register a new user
	user, err := authService.RegisterUser("business", "biz-123", "testuser", "Password123")
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user.Username)
	}
	if user.OwnerID != "biz-123" {
		t.Errorf("Expected ownerID 'biz-123', got '%s'", user.OwnerID)
	}

	// 2. Try to login with wrong password
	_, err = authService.Login(gologin.LoginRequest{
		Username: "testuser",
		Password: "WrongPassword",
	})
	if err == nil {
		t.Error("Expected login to fail with wrong password")
	}

	// 3. Login with correct password
	resp, err := authService.Login(gologin.LoginRequest{
		Username: "testuser",
		Password: "Password123",
	})
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("Expected access token to be present")
	}
	if resp.RefreshToken == "" {
		t.Error("Expected refresh token to be present")
	}

	// 4. Validate access token
	claims, err := authService.ValidateToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("Failed to validate access token: %v", err)
	}
	if claims.Username != "testuser" {
		t.Errorf("Expected username 'testuser' in claims, got '%s'", claims.Username)
	}
	if claims.OwnerID != "biz-123" {
		t.Errorf("Expected ownerID 'biz-123' in claims, got '%s'", claims.OwnerID)
	}

	// 5. Refresh access token
	newResp, err := authService.RefreshAccessToken(resp.RefreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}
	if newResp.AccessToken == resp.AccessToken {
		t.Error("Expected new access token after refresh")
	}

	// 6. Old access token should still be valid (until expiry)
	_, err = authService.ValidateToken(resp.AccessToken)
	if err != nil {
		t.Logf("Old access token expired (expected): %v", err)
	}

	// 7. Logout with new access token
	err = authService.Logout(newResp.AccessToken)
	if err != nil {
		t.Fatalf("Failed to logout: %v", err)
	}

	// 8. Validate that token is now blacklisted
	_, err = authService.ValidateToken(newResp.AccessToken)
	if err == nil {
		t.Error("Expected token to be blacklisted after logout")
	}
}

// Integration test: Rate limiting
func TestRateLimitingIntegration(t *testing.T) {
	repo := newTestUserRepository()

	// Create auth service with rate limiting
	blacklist := gologin.NewInMemoryBlacklist()
	loginLimiter := gologin.NewInMemoryRateLimiter(2, time.Minute) // 2 attempts per minute
	authService := gologin.NewAuthServiceWithOptions(repo, "test-secret-32-chars-minimum-length", blacklist, loginLimiter, nil)

	// Register a user
	_, err := authService.RegisterUser("business", "biz-123", "ratetest", "Password123")
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	// First login attempt (should succeed)
	_, err = authService.Login(gologin.LoginRequest{
		Username: "ratetest",
		Password: "Password123",
	})
	if err != nil {
		t.Fatalf("First login should succeed: %v", err)
	}

	// Second login attempt (should succeed)
	_, err = authService.Login(gologin.LoginRequest{
		Username: "ratetest",
		Password: "Password123",
	})
	if err != nil {
		t.Fatalf("Second login should succeed: %v", err)
	}

	// Third login attempt (should be rate limited)
	_, err = authService.Login(gologin.LoginRequest{
		Username: "ratetest",
		Password: "Password123",
	})
	if err == nil {
		t.Error("Third login should be rate limited")
	}
	if err.Error() != "rate limit exceeded" {
		t.Errorf("Expected 'rate limit exceeded' error, got: %v", err)
	}
}

// Integration test: Token rotation security
func TestTokenRotationSecurity(t *testing.T) {
	repo := newTestUserRepository()
	blacklist := gologin.NewInMemoryBlacklist()
	authService := gologin.NewAuthServiceWithOptions(repo, "test-secret-32-chars-minimum-length", blacklist, nil, nil)

	// Register and login
	_, err := authService.RegisterUser("business", "biz-123", "rotationtest", "Password123")
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	resp, err := authService.Login(gologin.LoginRequest{
		Username: "rotationtest",
		Password: "Password123",
	})
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	// Refresh token once
	resp2, err := authService.RefreshAccessToken(resp.RefreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh: %v", err)
	}

	// Try to use the old refresh token again (should fail due to rotation)
	_, err = authService.RefreshAccessToken(resp.RefreshToken)
	if err == nil {
		t.Error("Expected old refresh token to be invalidated after rotation")
	}

	// New refresh token should work
	resp3, err := authService.RefreshAccessToken(resp2.RefreshToken)
	if err != nil {
		t.Fatalf("New refresh token should work: %v", err)
	}

	// Verify tokens are different
	if resp.AccessToken == resp2.AccessToken {
		t.Error("Access tokens should be different after refresh")
	}
	if resp2.AccessToken == resp3.AccessToken {
		t.Error("Access tokens should be different after second refresh")
	}
	if resp.RefreshToken == resp2.RefreshToken {
		t.Error("Refresh tokens should be different after rotation")
	}
}

// Integration test: Multiple users with same owner
func TestMultipleUsersSameOwner(t *testing.T) {
	repo := newTestUserRepository()
	authService := gologin.NewAuthService(repo, "test-secret-32-chars-minimum-length")

	ownerID := "company-abc"

	// Register multiple users for same owner
	user1, err := authService.RegisterUser("business", ownerID, "admin", "Password123")
	if err != nil {
		t.Fatalf("Failed to register admin: %v", err)
	}

	user2, err := authService.RegisterUser("business", ownerID, "manager", "Password123")
	if err != nil {
		t.Fatalf("Failed to register manager: %v", err)
	}

	user3, err := authService.RegisterUser("business", ownerID, "employee", "Password123")
	if err != nil {
		t.Fatalf("Failed to register employee: %v", err)
	}

	// Verify all users have same owner
	if user1.OwnerID != ownerID || user2.OwnerID != ownerID || user3.OwnerID != ownerID {
		t.Error("All users should have same owner ID")
	}

	// Verify different usernames work
	if user1.Username == user2.Username || user2.Username == user3.Username {
		t.Error("Users should have different usernames")
	}

	// All should be able to login
	resp1, err := authService.Login(gologin.LoginRequest{Username: "admin", Password: "Password123"})
	if err != nil {
		t.Fatalf("Admin login failed: %v", err)
	}

	resp2, err := authService.Login(gologin.LoginRequest{Username: "manager", Password: "Password123"})
	if err != nil {
		t.Fatalf("Manager login failed: %v", err)
	}

	resp3, err := authService.Login(gologin.LoginRequest{Username: "employee", Password: "Password123"})
	if err != nil {
		t.Fatalf("Employee login failed: %v", err)
	}

	// Verify claims have correct owner info
	claims1, _ := authService.ValidateToken(resp1.AccessToken)
	claims2, _ := authService.ValidateToken(resp2.AccessToken)
	claims3, _ := authService.ValidateToken(resp3.AccessToken)

	if claims1.OwnerID != ownerID || claims2.OwnerID != ownerID || claims3.OwnerID != ownerID {
		t.Error("All tokens should have same owner ID in claims")
	}
}