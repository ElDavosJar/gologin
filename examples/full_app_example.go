// Package main demonstrates a complete application using gologin
// This example shows how to integrate gologin into a real web application
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"gologin"
)

// InMemoryUserRepository implements UserRepository for demo purposes
type InMemoryUserRepository struct {
	users map[string]*gologin.User
}

func NewInMemoryUserRepository() *InMemoryUserRepository {
	return &InMemoryUserRepository{
		users: make(map[string]*gologin.User),
	}
}

func (r *InMemoryUserRepository) Save(user *gologin.User) error {
	if user.ID == nil {
		id := fmt.Sprintf("user_%d", time.Now().UnixNano())
		user.ID = &id
	}
	r.users[*user.ID] = user
	return nil
}

func (r *InMemoryUserRepository) FindByUsername(username string) (*gologin.User, error) {
	for _, user := range r.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (r *InMemoryUserRepository) FindByID(id string) (*gologin.User, error) {
	user, exists := r.users[id]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

func (r *InMemoryUserRepository) IsUsernameTaken(username string) (bool, error) {
	for _, user := range r.users {
		if user.Username == username {
			return true, nil
		}
	}
	return false, nil
}

func (r *InMemoryUserRepository) GetActiveTokenIDs(userID string) ([]string, error) {
	// For demo purposes, return empty slice (no active tokens tracked)
	return []string{}, nil
}

// HTTP handlers
type AuthHandler struct {
	authService gologin.AuthService
}

func NewAuthHandler(authService gologin.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OwnerType string `json:"owner_type"`
		OwnerID   string `json:"owner_id"`
		Username  string `json:"username"`
		Password  string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	user, err := h.authService.RegisterUser(req.OwnerType, req.OwnerID, req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User registered successfully",
		"user":    user,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req gologin.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	resp, err := h.authService.Login(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	resp, err := h.authService.RefreshAccessToken(req.RefreshToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	token := authHeader[7:]
	if err := h.authService.Logout(token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// Middleware for protected routes
func (h *AuthHandler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		token := authHeader[7:]
		claims, err := h.authService.ValidateToken(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to request context for use in handlers
		// In a real app, you'd use context.WithValue
		r.Header.Set("X-User-ID", claims.UserID)
		r.Header.Set("X-Owner-ID", claims.OwnerID)
		r.Header.Set("X-Owner-Type", claims.OwnerType)

		next(w, r)
	}
}

func (h *AuthHandler) ProtectedProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	ownerID := r.Header.Get("X-Owner-ID")
	ownerType := r.Header.Get("X-Owner-Type")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Welcome to your profile!",
		"user_id":   userID,
		"owner_id":  ownerID,
		"owner_type": ownerType,
	})
}

func main() {
	// Initialize repository and auth service
	repo := NewInMemoryUserRepository()

	// Use a secure JWT secret (in production, use environment variable)
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "your-super-secure-jwt-secret-key-at-least-32-characters-long"
	}

	authService := gologin.NewAuthService(repo, jwtSecret)
	authHandler := NewAuthHandler(authService)

	// Routes
	http.HandleFunc("/auth/register", authHandler.Register)
	http.HandleFunc("/auth/login", authHandler.Login)
	http.HandleFunc("/auth/refresh", authHandler.Refresh)
	http.HandleFunc("/auth/logout", authHandler.Logout)
	http.HandleFunc("/profile", authHandler.AuthMiddleware(authHandler.ProtectedProfile))

	fmt.Println("🚀 Server starting on http://localhost:8080")
	fmt.Println("📖 API Endpoints:")
	fmt.Println("  POST /auth/register - Register new user")
	fmt.Println("  POST /auth/login - Login user")
	fmt.Println("  POST /auth/refresh - Refresh access token")
	fmt.Println("  POST /auth/logout - Logout user")
	fmt.Println("  GET /profile - Protected profile endpoint")

	log.Fatal(http.ListenAndServe(":8080", nil))
}