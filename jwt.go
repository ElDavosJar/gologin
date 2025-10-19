package gologin

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTService handles JWT token operations
type JWTService struct {
	secretKey     []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

// NewJWTService creates a new JWT service with the given secret key
// SECURITY: secretKey MUST be at least 32 bytes for production use
func NewJWTService(secretKey string, accessExpiry, refreshExpiry time.Duration) *JWTService {
	if secretKey == "" {
		panic("JWT secret key cannot be empty - this is a critical security requirement")
	}

	// Validate minimum key length (256 bits = 32 bytes)
	if len(secretKey) < 32 {
		panic("JWT secret key must be at least 32 characters for security")
	}

	return &JWTService{
		secretKey:     []byte(secretKey),
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
	}
}

// GenerateTokenPair creates both access and refresh tokens for a user
func (j *JWTService) GenerateTokenPair(user *User) (*AuthResponse, error) {
	if user.ID == nil {
		return nil, fmt.Errorf("user must have an ID to generate tokens")
	}

	accessToken, err := j.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := j.generateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

// generateAccessToken creates a short-lived access token
func (j *JWTService) generateAccessToken(user *User) (string, error) {
	now := time.Now()
	
	// Generate unique token ID for blacklisting support
	tokenID := generateTokenID()
	
	claims := &Claims{
		UserID:    *user.ID,
		OwnerID:   user.OwnerID,
		OwnerType: user.OwnerType,
		Username:  user.Username,
		TokenType: "access",
		TokenID:   tokenID,
		ExpiresAt: now.Add(j.accessExpiry).Unix(),
		IssuedAt:  now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// generateRefreshToken creates a long-lived refresh token
func (j *JWTService) generateRefreshToken(user *User) (string, error) {
	now := time.Now()
	
	// Generate unique token ID for blacklisting support
	tokenID := generateTokenID()
	
	claims := &Claims{
		UserID:    *user.ID,
		OwnerID:   user.OwnerID,
		OwnerType: user.OwnerType,
		Username:  user.Username,
		TokenType: "refresh",
		TokenID:   tokenID,
		ExpiresAt: now.Add(j.refreshExpiry).Unix(),
		IssuedAt:  now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// generateTokenID creates a unique identifier for tokens
func generateTokenID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ValidateToken parses and validates a JWT token
func (j *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Check if token is expired
		if claims.ExpiresAt < time.Now().Unix() {
			return nil, fmt.Errorf("token has expired")
		}
		
		// Validate required claims
		if claims.UserID == "" || claims.OwnerID == "" || claims.OwnerType == "" || claims.Username == "" {
			return nil, fmt.Errorf("invalid token: missing required claims")
		}
		
		if claims.TokenType != "access" && claims.TokenType != "refresh" {
			return nil, fmt.Errorf("invalid token: unknown token type")
		}
		
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// RefreshAccessToken generates a new access token using a valid refresh token
func (j *JWTService) RefreshAccessToken(refreshToken string) (*AuthResponse, error) {
	claims, err := j.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.TokenType != "refresh" {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	// Create a dummy user object for token generation
	user := &User{
		ID:        &claims.UserID,
		OwnerID:   claims.OwnerID,
		OwnerType: claims.OwnerType,
		Username:  claims.Username,
	}

	return j.GenerateTokenPair(user)
}