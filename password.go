package gologin

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordStrength represents the strength requirements for passwords
type PasswordStrength struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

// DefaultPasswordStrength provides secure default password requirements
var DefaultPasswordStrength = PasswordStrength{
	MinLength:      8,
	RequireUpper:   true,
	RequireLower:   true,
	RequireNumber:  true,
	RequireSpecial: false, // Can be enabled for higher security
}

// ValidatePasswordStrength checks if a password meets strength requirements
func ValidatePasswordStrength(password string, strength PasswordStrength) error {
	if len(password) < strength.MinLength {
		return fmt.Errorf("password must be at least %d characters long", strength.MinLength)
	}

	if strength.RequireUpper {
		hasUpper := false
		for _, char := range password {
			if char >= 'A' && char <= 'Z' {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			return fmt.Errorf("password must contain at least one uppercase letter")
		}
	}

	if strength.RequireLower {
		hasLower := false
		for _, char := range password {
			if char >= 'a' && char <= 'z' {
				hasLower = true
				break
			}
		}
		if !hasLower {
			return fmt.Errorf("password must contain at least one lowercase letter")
		}
	}

	if strength.RequireNumber {
		hasNumber := false
		for _, char := range password {
			if char >= '0' && char <= '9' {
				hasNumber = true
				break
			}
		}
		if !hasNumber {
			return fmt.Errorf("password must contain at least one number")
		}
	}

	if strength.RequireSpecial {
		specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
		hasSpecial := false
		for _, char := range password {
			for _, special := range specialChars {
				if char == special {
					hasSpecial = true
					break
				}
			}
			if hasSpecial {
				break
			}
		}
		if !hasSpecial {
			return fmt.Errorf("password must contain at least one special character")
		}
	}

	return nil
}

// HashPassword creates a bcrypt hash of the given password.
// It uses the default cost for bcrypt which provides good security.
func HashPassword(password string) (string, error) {
	return HashPasswordWithStrength(password, &DefaultPasswordStrength)
}

// HashPasswordWithStrength creates a bcrypt hash with custom password policy
func HashPasswordWithStrength(password string, strength *PasswordStrength) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	// Validar fuerza de contraseña si está configurada
	if strength != nil {
		if err := ValidatePasswordStrength(password, *strength); err != nil {
			return "", err
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hash), nil
}

// VerifyPassword compares a password with its hash.
// Returns nil if the password matches, error otherwise.
func VerifyPassword(password, hash string) error {
	if password == "" || hash == "" {
		return fmt.Errorf("password and hash cannot be empty")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password")
	}

	return nil
}