package gologin

import (
	"fmt"
	"regexp"
	"unicode"
)

// ValidateUsername checks if a username meets security and format requirements
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	
	// Check length
	if len(username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}
	if len(username) > 50 {
		return fmt.Errorf("username must not exceed 50 characters")
	}
	
	// Check for valid characters (alphanumeric, underscore, hyphen, dot)
	// Must start with a letter or number
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	if !validUsername.MatchString(username) {
		return fmt.Errorf("username must start with a letter or number and contain only letters, numbers, dots, hyphens, or underscores")
	}
	
	// Prevent usernames that are only dots, hyphens, or underscores
	hasAlphaNumeric := false
	for _, char := range username {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			hasAlphaNumeric = true
			break
		}
	}
	if !hasAlphaNumeric {
		return fmt.Errorf("username must contain at least one letter or number")
	}
	
	// Prevent consecutive special characters
	if regexp.MustCompile(`[._-]{2,}`).MatchString(username) {
		return fmt.Errorf("username cannot contain consecutive special characters")
	}
	
	// Prevent ending with special characters
	if regexp.MustCompile(`[._-]$`).MatchString(username) {
		return fmt.Errorf("username cannot end with a special character")
	}
	
	return nil
}

// SanitizeUsername removes or replaces invalid characters from a username
// This can be used to suggest valid usernames to users
func SanitizeUsername(username string) string {
	// Remove all invalid characters
	reg := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	sanitized := reg.ReplaceAllString(username, "")
	
	// Remove consecutive special characters
	sanitized = regexp.MustCompile(`[._-]{2,}`).ReplaceAllString(sanitized, "_")
	
	// Ensure it starts with alphanumeric
	if len(sanitized) > 0 && !unicode.IsLetter(rune(sanitized[0])) && !unicode.IsDigit(rune(sanitized[0])) {
		sanitized = "user_" + sanitized
	}
	
	// Trim to max length
	if len(sanitized) > 50 {
		sanitized = sanitized[:50]
	}
	
	// Remove trailing special characters
	sanitized = regexp.MustCompile(`[._-]+$`).ReplaceAllString(sanitized, "")
	
	return sanitized
}
