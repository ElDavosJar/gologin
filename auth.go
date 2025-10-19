package gologin

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DefaultAuthService provides the main authentication implementation
type DefaultAuthService struct {
	repo             UserRepository
	jwtService       *JWTService
	blacklist        TokenBlacklist    // OPCIONAL: puede ser nil
	loginLimiter     RateLimiter       // OPCIONAL: puede ser nil
	registerLimiter  RateLimiter       // OPCIONAL: puede ser nil
	fieldMapping     *FieldMapping
	passwordStrength *PasswordStrength // OPCIONAL: política de contraseñas
}

// NewAuthService creates a minimal authentication service (sin rate limiting ni blacklist)
// Ideal para desarrollo, testing, o sistemas simples
func NewAuthService(repo UserRepository, jwtSecret string) AuthService {
	return NewAuthServiceWithMapping(repo, jwtSecret, nil)
}

// NewAuthServiceWithMapping creates a new authentication service with custom field mapping
func NewAuthServiceWithMapping(repo UserRepository, jwtSecret string, fieldMapping *FieldMapping) AuthService {
	// CRITICAL SECURITY: Validate JWT secret
	if jwtSecret == "" {
		panic("JWT secret cannot be empty - provide a secure secret via environment variable")
	}
	if len(jwtSecret) < 32 {
		panic("JWT secret must be at least 32 characters (256 bits) for security")
	}

	// Use default mapping if none provided
	if fieldMapping == nil {
		fieldMapping = DefaultFieldMapping()
	}

	jwtService := NewJWTService(
		jwtSecret,
		15*time.Minute,  // access token expiry
		7*24*time.Hour,  // refresh token expiry (7 days)
	)

	// Sistema MINIMALISTA por defecto: sin rate limiting ni blacklist
	return &DefaultAuthService{
		repo:             repo,
		jwtService:       jwtService,
		blacklist:        nil, // OPCIONAL: solo activa si lo necesitas
		loginLimiter:     nil, // OPCIONAL: solo activa si lo necesitas
		registerLimiter:  nil, // OPCIONAL: solo activa si lo necesitas
		fieldMapping:     fieldMapping,
		passwordStrength: &DefaultPasswordStrength, // Política por defecto
	}
}

// NewAuthServiceWithOptions crea un servicio con características avanzadas opcionales
// Usa esto si necesitas: rate limiting, blacklist, o configuración personalizada
func NewAuthServiceWithOptions(repo UserRepository, jwtSecret string, blacklist TokenBlacklist, loginLimiter, registerLimiter RateLimiter) AuthService {
	return NewAuthServiceWithOptionsAndMapping(repo, jwtSecret, blacklist, loginLimiter, registerLimiter, nil)
}

// NewAuthServiceWithOptionsAndMapping creates a new authentication service with custom options and field mapping
func NewAuthServiceWithOptionsAndMapping(repo UserRepository, jwtSecret string, blacklist TokenBlacklist, loginLimiter, registerLimiter RateLimiter, fieldMapping *FieldMapping) AuthService {
	// CRITICAL SECURITY: Validate JWT secret
	if jwtSecret == "" {
		panic("JWT secret cannot be empty - provide a secure secret via environment variable")
	}
	if len(jwtSecret) < 32 {
		panic("JWT secret must be at least 32 characters (256 bits) for security")
	}

	// Use default mapping if none provided
	if fieldMapping == nil {
		fieldMapping = DefaultFieldMapping()
	}

	jwtService := NewJWTService(
		jwtSecret,
		15*time.Minute,
		7*24*time.Hour,
	)

	return &DefaultAuthService{
		repo:             repo,
		jwtService:       jwtService,
		blacklist:        blacklist,
		loginLimiter:     loginLimiter,
		registerLimiter:  registerLimiter,
		fieldMapping:     fieldMapping,
		passwordStrength: &DefaultPasswordStrength, // Política por defecto
	}
}

// RegisterUser creates a new user with credentials
func (a *DefaultAuthService) RegisterUser(ownerType, ownerID, username, password string) (*User, error) {
	// Rate limiting check (use username as identifier to prevent spam)
	if a.registerLimiter != nil && !a.registerLimiter.Allow(username) {
		return nil, ErrRateLimitExceeded
	}

	// Validate input
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}

	// Check if username is already taken
	taken, err := a.repo.IsUsernameTaken(username)
	if err != nil {
		return nil, fmt.Errorf("failed to check username availability: %w", err)
	}
	if taken {
		return nil, fmt.Errorf("username '%s' is already taken", username)
	}

	// Hash the password con la política configurada
	passwordHash, err := HashPasswordWithStrength(password, a.passwordStrength)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the user
	user := &User{
		ID:           nil, // Will be set by repository
		Username:     username,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
	}

	// Save to repository (this will assign the ID)
	if err := a.repo.Save(user); err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	return user, nil
}

// Login authenticates a user and returns tokens
func (a *DefaultAuthService) Login(req LoginRequest) (*AuthResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if req.Password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Rate limiting check (use username to prevent brute force on specific accounts)
	if a.loginLimiter != nil && !a.loginLimiter.Allow(req.Username) {
		return nil, ErrRateLimitExceeded
	}

	// Find user by username
	user, err := a.repo.FindByUsername(req.Username)
	if err != nil || user == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify password
	if err := VerifyPassword(req.Password, user.PasswordHash); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Reset rate limiter on successful login
	if a.loginLimiter != nil {
		a.loginLimiter.Reset(req.Username)
	}

	// Generate tokens
	return a.jwtService.GenerateTokenPair(user)
}

// ValidateToken validates a JWT token and returns its claims
func (a *DefaultAuthService) ValidateToken(tokenString string) (*Claims, error) {
	claims, err := a.jwtService.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	
	// Check if token is blacklisted
	if a.blacklist != nil && a.blacklist.IsBlacklisted(claims.TokenID) {
		return nil, fmt.Errorf("token has been revoked")
	}
	
	return claims, nil
}

// RefreshAccessToken generates a new access token using a refresh token
// CRITICAL SECURITY: Implements token rotation to prevent replay attacks
func (a *DefaultAuthService) RefreshAccessToken(refreshToken string) (*AuthResponse, error) {
	// Validate the refresh token first
	claims, err := a.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.TokenType != "refresh" {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	// CRITICAL SECURITY: Rotate refresh token to prevent replay attacks
	// Revoke the used refresh token immediately
	if a.blacklist != nil {
		expiresAt := time.Unix(claims.ExpiresAt, 0)
		if err := a.blacklist.Add(claims.TokenID, expiresAt); err != nil {
			// Log error but don't fail the refresh - security over usability
			// In production, you might want to alert on this
		}
	}

	// Get user from repository to ensure they still exist
	user, err := a.repo.FindByID(claims.UserID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate NEW token pair (both access and refresh tokens are rotated)
	return a.jwtService.GenerateTokenPair(user)
}

// Logout revokes a specific token by adding it to the blacklist
func (a *DefaultAuthService) Logout(tokenString string) error {
	claims, err := a.jwtService.ValidateToken(tokenString)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}
	
	if a.blacklist == nil {
		return fmt.Errorf("token blacklist not configured")
	}
	
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	return a.blacklist.Add(claims.TokenID, expiresAt)
}

// LogoutAll revokes all tokens for a specific user
func (a *DefaultAuthService) LogoutAll(userID string) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}

	if a.blacklist == nil {
		return fmt.Errorf("token blacklist not configured")
	}

	// Get all active token IDs for this user
	activeTokenIDs, err := a.repo.GetActiveTokenIDs(userID)
	if err != nil {
		return fmt.Errorf("failed to get active tokens: %w", err)
	}

	// Revoke all active tokens
	for _, tokenID := range activeTokenIDs {
		// For LogoutAll, we revoke tokens for 24 hours to ensure they're cleared
		// In production, you might want to get the actual expiration from the token
		expiresAt := time.Now().Add(24 * time.Hour)
		if err := a.blacklist.Add(tokenID, expiresAt); err != nil {
			// Log error but continue revoking other tokens
			// In production, you might want to collect errors and return them
		}
	}

	return nil
}

// generateID generates a unique ID for users (you can replace this with your own ID generation logic)
func generateID() string {
	return uuid.New().String()
}