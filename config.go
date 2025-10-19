package gologin

import "time"

// AuthConfig contiene toda la configuración del sistema de autenticación
// Todos los campos son opcionales y tienen valores por defecto seguros
type AuthConfig struct {
	// JWT Configuration
	JWTSecret         string        // OBLIGATORIO: Secreto para firmar tokens (mínimo 32 caracteres)
	AccessTokenExpiry time.Duration // Por defecto: 15 minutos
	RefreshTokenExpiry time.Duration // Por defecto: 7 días
	
	// Optional Features
	Blacklist       TokenBlacklist // OPCIONAL: Para revocar tokens (nil = desactivado)
	LoginLimiter    RateLimiter    // OPCIONAL: Para proteger login (nil = desactivado)
	RegisterLimiter RateLimiter    // OPCIONAL: Para proteger registro (nil = desactivado)
	
	// Field Mapping (para sistemas legacy)
	FieldMapping *FieldMapping // OPCIONAL: Por defecto usa campos estándar
	
	// Password Policy
	PasswordStrength *PasswordStrength // OPCIONAL: Por defecto usa DefaultPasswordStrength
}

// DefaultAuthConfig retorna una configuración por defecto segura
func DefaultAuthConfig(jwtSecret string) *AuthConfig {
	return &AuthConfig{
		JWTSecret:          jwtSecret,
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
		Blacklist:          nil, // Desactivado por defecto
		LoginLimiter:       nil, // Desactivado por defecto
		RegisterLimiter:    nil, // Desactivado por defecto
		FieldMapping:       DefaultFieldMapping(),
		PasswordStrength:   &DefaultPasswordStrength,
	}
}

// Validate verifica que la configuración sea válida
func (c *AuthConfig) Validate() error {
	if c.JWTSecret == "" {
		panic("JWT secret cannot be empty - provide a secure secret via environment variable")
	}
	if len(c.JWTSecret) < 32 {
		panic("JWT secret must be at least 32 characters (256 bits) for security")
	}
	if c.AccessTokenExpiry <= 0 {
		c.AccessTokenExpiry = 15 * time.Minute
	}
	if c.RefreshTokenExpiry <= 0 {
		c.RefreshTokenExpiry = 7 * 24 * time.Hour
	}
	if c.FieldMapping == nil {
		c.FieldMapping = DefaultFieldMapping()
	}
	if c.PasswordStrength == nil {
		c.PasswordStrength = &DefaultPasswordStrength
	}
	return nil
}

// NewAuthServiceWithConfig crea un servicio con configuración completa
func NewAuthServiceWithConfig(repo UserRepository, config *AuthConfig) AuthService {
	config.Validate()
	
	jwtService := NewJWTService(
		config.JWTSecret,
		config.AccessTokenExpiry,
		config.RefreshTokenExpiry,
	)
	
	return &DefaultAuthService{
		repo:            repo,
		jwtService:      jwtService,
		blacklist:       config.Blacklist,
		loginLimiter:    config.LoginLimiter,
		registerLimiter: config.RegisterLimiter,
		fieldMapping:    config.FieldMapping,
		passwordStrength: config.PasswordStrength,
	}
}
