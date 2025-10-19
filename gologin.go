// Package gologin provides a flexible authentication system for Go applications.
// It allows creating user credentials that belong to any domain entity (business profiles,
// customers, admins, etc.) without assuming specific domain models.
//
// The package assumes standard database field names (id, username, password_hash, created_at)
// but allows customization for legacy systems.
//
// The package is designed to be cohesive and idiomatic Go, with structs that have
// methods and interfaces for dependency injection.
package gologin

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Standard field names assumed by the library
const (
	DefaultIDField           = "id"
	DefaultUsernameField     = "username"
	DefaultPasswordHashField = "password_hash"
	DefaultCreatedAtField    = "created_at"
)

// FieldMapping allows customization of database field names for legacy systems
type FieldMapping struct {
	ID           string
	Username     string
	PasswordHash string
	CreatedAt    string
}

// DefaultFieldMapping returns the standard field mapping
func DefaultFieldMapping() *FieldMapping {
	return &FieldMapping{
		ID:           DefaultIDField,
		Username:     DefaultUsernameField,
		PasswordHash: DefaultPasswordHashField,
		CreatedAt:    DefaultCreatedAtField,
	}
}

// User represents authentication credentials that belong to a domain entity.
// The OwnerID and OwnerType fields allow the credentials to be associated with
// any entity in your application domain.
type User struct {
	ID           *string    // nil until saved to storage
	OwnerID      string     // ID of the entity that owns these credentials
	OwnerType    string     // Type of owner ("business_profile", "customer", etc.)
	Username     string     // Unique username for login
	PasswordHash string     // bcrypt hash of the password
	CreatedAt    time.Time  // When the user was created
}

// IsValid checks if the user has valid data according to business rules
func (u *User) IsValid() bool {
	return u.OwnerID != "" && u.OwnerType != "" &&
		   u.Username != "" && u.PasswordHash != "" &&
		   len(u.Username) >= 3 && len(u.Username) <= 50
}

// LoginRequest contains the credentials for authentication
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthResponse contains the tokens returned after successful authentication
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	User         *User  `json:"user"`
}

// Claims represents the JWT payload
type Claims struct {
	UserID    string `json:"user_id"`
	OwnerID   string `json:"owner_id"`
	OwnerType string `json:"owner_type"`
	Username  string `json:"username"`
	TokenType string `json:"token_type"` // "access" or "refresh"
	TokenID   string `json:"jti"`        // JWT ID for blacklisting
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
}

// GetExpirationTime implements jwt.Claims interface
func (c *Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt implements jwt.Claims interface
func (c *Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetNotBefore implements jwt.Claims interface
func (c *Claims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetIssuer implements jwt.Claims interface
func (c *Claims) GetIssuer() (string, error) {
	return "", nil
}

// GetSubject implements jwt.Claims interface
func (c *Claims) GetSubject() (string, error) {
	return "", nil
}

// GetAudience implements jwt.Claims interface
func (c *Claims) GetAudience() (jwt.ClaimStrings, error) {
	return nil, nil
}

// UserRepository defines the interface for user persistence.
// Implement this interface to integrate with your storage system.
type UserRepository interface {
	Save(user *User) error
	FindByUsername(username string) (*User, error)
	FindByID(id string) (*User, error)
	IsUsernameTaken(username string) (bool, error)
	// GetActiveTokenIDs returns all active token IDs for a user (for LogoutAll)
	GetActiveTokenIDs(userID string) ([]string, error)
}

// AuthService provides authentication operations.
// It depends on a UserRepository for persistence.
type AuthService interface {
	RegisterUser(ownerType, ownerID, username, password string) (*User, error)
	Login(req LoginRequest) (*AuthResponse, error)
	ValidateToken(tokenString string) (*Claims, error)
	RefreshAccessToken(refreshToken string) (*AuthResponse, error)
	Logout(tokenString string) error // Revoke token
	LogoutAll(userID string) error   // Revoke all tokens for a user
}