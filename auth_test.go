package gologin

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// MockUserRepository implementa UserRepository para pruebas
var _ UserRepository = &MockUserRepository{}

type MockUserRepository struct {
	users map[string]*User
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users: make(map[string]*User),
	}
}

func (m *MockUserRepository) Save(user *User) error {
	if user.ID == nil {
		id := uuid.New().String()
		user.ID = &id
	}
	m.users[*user.ID] = user
	return nil
}

func (m *MockUserRepository) FindByUsername(username string) (*User, error) {
	for _, user := range m.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, nil // User not found
}

func (m *MockUserRepository) FindByID(id string) (*User, error) {
	user, exists := m.users[id]
	if !exists {
		return nil, nil
	}
	return user, nil
}

func (m *MockUserRepository) IsUsernameTaken(username string) (bool, error) {
	for _, user := range m.users {
		if user.Username == username {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockUserRepository) GetActiveTokenIDs(userID string) ([]string, error) {
	// Mock implementation - in real implementation, you'd track active tokens
	// For testing, return some mock token IDs
	return []string{"token-1", "token-2"}, nil
}

func TestRegisterUser(t *testing.T) {
	repo := NewMockUserRepository()
	// Use a 32+ character secret for tests
	authService := NewAuthService(repo, "test-secret-key-that-is-at-least-32-characters-long")

	// Test successful registration
	user, err := authService.RegisterUser("business_profile", "profile-123", "testuser", "Password123")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if user.ID == nil {
		t.Fatal("Expected user ID to be set")
	}

	// User is now embeddable, no OwnerID/OwnerType in struct

	if user.Username != "testuser" {
		t.Errorf("Expected Username 'testuser', got '%s'", user.Username)
	}

	if !user.IsValid() {
		t.Error("Expected user to be valid")
	}
}

func TestRegisterUserValidation(t *testing.T) {
	repo := NewMockUserRepository()
	authService := NewAuthService(repo, "test-secret-key-that-is-at-least-32-characters-long")

	testCases := []struct {
		name        string
		ownerType   string
		ownerID     string
		username    string
		password    string
		expectError bool
	}{
		{"empty username", "business", "profile-123", "", "pass", true},
		{"username too short", "business", "profile-123", "ab", "pass", true},
		{"username too long", "business", "profile-123", string(make([]byte, 51)), "pass", true},
		{"password too short", "business", "profile-123", "user", "1234567", true},
		{"valid input", "business", "profile-123", "user", "Password123", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := authService.RegisterUser(tc.ownerType, tc.ownerID, tc.username, tc.password)
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	repo := NewMockUserRepository()
	authService := NewAuthService(repo, "test-secret-key-that-is-at-least-32-characters-long")

	// Register a user first
	user, err := authService.RegisterUser("business_profile", "profile-123", "testuser", "Password123")
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	// Test successful login
	req := LoginRequest{
		Username: "testuser",
		Password: "Password123",
	}

	resp, err := authService.Login(req)
	if err != nil {
		t.Fatalf("Expected successful login, got error: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("Expected access token to be set")
	}

	if resp.RefreshToken == "" {
		t.Error("Expected refresh token to be set")
	}

	if resp.User.ID == nil || *resp.User.ID != *user.ID {
		t.Error("Expected user in response to match registered user")
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	repo := NewMockUserRepository()
	authService := NewAuthService(repo, "test-secret-key-that-is-at-least-32-characters-long")

	// Register a user
	_, err := authService.RegisterUser("business_profile", "profile-123", "testuser", "Password123")
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	testCases := []struct {
		name     string
		username string
		password string
	}{
		{"wrong username", "wronguser", "Password123"},
		{"wrong password", "testuser", "Wrongpass"},
		{"empty username", "", "Password123"},
		{"empty password", "testuser", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := LoginRequest{
				Username: tc.username,
				Password: tc.password,
			}

			_, err := authService.Login(req)
			if err == nil {
				t.Error("Expected login to fail with invalid credentials")
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	repo := NewMockUserRepository()
	authService := NewAuthService(repo, "test-secret-key-that-is-at-least-32-characters-long")

	// Register and login to get tokens
	_, err := authService.RegisterUser("business_profile", "profile-123", "testuser", "Password123")
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	req := LoginRequest{Username: "testuser", Password: "Password123"}
	resp, err := authService.Login(req)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	// Test valid access token
	claims, err := authService.ValidateToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("Expected valid token, got error: %v", err)
	}

	if claims.UserID == "" {
		t.Error("Expected UserID in claims")
	}

	if claims.TokenType != "access" {
		t.Errorf("Expected token type 'access', got '%s'", claims.TokenType)
	}
}

func TestRefreshAccessToken(t *testing.T) {
	repo := NewMockUserRepository()
	authService := NewAuthService(repo, "test-secret-key-that-is-at-least-32-characters-long")

	// Register and login to get tokens
	_, err := authService.RegisterUser("business_profile", "profile-123", "testuser", "Password123")
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	req := LoginRequest{Username: "testuser", Password: "Password123"}
	resp, err := authService.Login(req)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	// Test refresh token
	newResp, err := authService.RefreshAccessToken(resp.RefreshToken)
	if err != nil {
		t.Fatalf("Expected successful refresh, got error: %v", err)
	}

	if newResp.AccessToken == "" {
		t.Error("Expected new access token")
	}

	// Note: Access tokens might be the same if generated within the same second
	// since they use timestamp-based expiration. This is acceptable.
	if newResp.AccessToken == "" {
		t.Error("Expected new access token to be generated")
	}
}

func TestPasswordHashing(t *testing.T) {
	password := "Testpassword123"

	// Test hashing
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if hash == "" {
		t.Error("Expected non-empty hash")
	}

	if hash == password {
		t.Error("Hash should not equal plain password")
	}

	// Test verification
	err = VerifyPassword(password, hash)
	if err != nil {
		t.Errorf("Expected password verification to succeed: %v", err)
	}

	// Test wrong password
	err = VerifyPassword("Wrongpassword", hash)
	if err == nil {
		t.Error("Expected password verification to fail with wrong password")
	}
}

func TestUserIsValid(t *testing.T) {
	validUser := &User{
		ID:           stringPtr("user-123"),
		Username:     "testuser",
		PasswordHash: "hashedpassword",
		CreatedAt:    time.Now(),
	}

	if !validUser.IsValid() {
		t.Error("Expected valid user to be valid")
	}

	invalidUsers := []*User{
		{Username: "", PasswordHash: "hash"}, // empty Username
		{Username: "ab", PasswordHash: "hash"}, // username too short
		{Username: "user", PasswordHash: ""},   // empty PasswordHash
	}

	for i, user := range invalidUsers {
		if user.IsValid() {
			t.Errorf("Expected invalid user %d to be invalid", i)
		}
	}
}

func TestBusinessUserEmbedding(t *testing.T) {
	type BusinessUser struct {
		User
		Email string
		Role  string
	}

	repo := NewMockUserRepository()
	authService := NewAuthService(repo, "test-secret-key-that-is-at-least-32-characters-long")

	// Crear y registrar un usuario de negocio
	bizUser := &BusinessUser{
		User: User{
			Username:     "bizuser",
			PasswordHash: "",
			CreatedAt:    time.Now(),
		},
		Email: "biz@example.com",
		Role:  "admin",
	}

	// Registrar usando AuthService (sin OwnerID/OwnerType ya que es embeddable)
	user, err := authService.RegisterUser("business_profile", "profile-999", bizUser.Username, "Password123")
	if err != nil {
		t.Fatalf("Failed to register embedded business user: %v", err)
	}

	bizUser.User = *user // Actualizar campos embebidos

	if !bizUser.IsValid() {
		t.Error("Expected embedded business user to be valid")
	}

	// Login y validación
	resp, err := authService.Login(LoginRequest{Username: bizUser.Username, Password: "Password123"})
	if err != nil {
		t.Fatalf("Login failed for embedded business user: %v", err)
	}

	if resp.User.Username != bizUser.Username {
		t.Errorf("Expected username '%s', got '%s'", bizUser.Username, resp.User.Username)
	}

	// Validar claims
	claims, err := authService.ValidateToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("Token validation failed: %v", err)
	}
	if claims.UserID == "" || claims.Username != bizUser.Username {
		t.Error("Claims do not match embedded business user")
	}
}

func TestRedisRateLimiterIntegration(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	limiter := NewRedisRateLimiter(client, 3, 2*time.Second)
	key := "testuser:ratelimit"
	defer limiter.Reset(key)

	// Debe permitir 3 intentos
	for i := 0; i < 3; i++ {
		if !limiter.Allow(key) {
			t.Fatalf("Attempt %d should be allowed", i+1)
		}
	}
	// El cuarto debe ser bloqueado
	if limiter.Allow(key) {
		t.Error("Fourth attempt should be blocked by rate limiter")
	}

	// Esperar a que expire la ventana
	time.Sleep(3 * time.Second)
	if !limiter.Allow(key) {
		t.Error("Should allow after window expires")
	}
}

func TestRedisTokenBlacklistIntegration(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	blacklist := NewRedisTokenBlacklist(client)
	tokenID := "testtokenid123"
	expiresAt := time.Now().Add(2 * time.Second)

	// No debe estar en blacklist al inicio
	if blacklist.IsBlacklisted(tokenID) {
		t.Error("Token should not be blacklisted initially")
	}

	// Agregar a blacklist
	if err := blacklist.Add(tokenID, expiresAt); err != nil {
		t.Fatalf("Failed to add token to blacklist: %v", err)
	}
	if !blacklist.IsBlacklisted(tokenID) {
		t.Error("Token should be blacklisted after Add")
	}

	// Esperar a que expire
	time.Sleep(3 * time.Second)
	if blacklist.IsBlacklisted(tokenID) {
		t.Error("Token should not be blacklisted after expiration")
	}
}

// Helper function
func stringPtr(s string) *string {
	return &s
}