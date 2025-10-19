package main

import (
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"gologin"
)

// Ejemplo de repositorio de usuarios (in-memory para demo)
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
	return nil, nil
}

func (r *InMemoryUserRepository) FindByID(id string) (*gologin.User, error) {
	user, exists := r.users[id]
	if !exists {
		return nil, nil
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
	return []string{}, nil
}

var repo gologin.UserRepository = NewInMemoryUserRepository()

func main() {
	// ==================================================
	// EJEMPLO 1: Configuración MÍNIMA (desarrollo/testing)
	// ==================================================
	jwtSecret1 := "my-super-secret-jwt-key-with-32-chars-minimum"
	authService1 := gologin.NewAuthService(repo, jwtSecret1)
	// ✅ Sin rate limiting, sin blacklist, política de contraseña por defecto

	// ==================================================
	// EJEMPLO 2: Configuración PERSONALIZADA
	// ==================================================
	jwtSecret2 := os.Getenv("JWT_SECRET")
	if jwtSecret2 == "" {
		jwtSecret2 = "another-32-char-secret-key-for-custom-config"
	}

	// Configuración personalizada con in-memory components
	authService2 := gologin.NewAuthServiceWithOptions(
		repo,
		jwtSecret2,
		gologin.NewInMemoryTokenBlacklist(), // Blacklist activada
		gologin.NewInMemoryRateLimiter(5, 15*time.Minute), // Rate limiting activado
		gologin.NewInMemoryRateLimiter(3, 1*time.Hour),
	)

	// ==================================================
	// EJEMPLO 3: Configuración COMPLETA (producción)
	// ==================================================
	redisClient := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_ADDR"),
	})

	authService3 := gologin.NewAuthServiceWithOptions(
		repo,
		os.Getenv("JWT_SECRET"),
		gologin.NewRedisTokenBlacklist(redisClient),
		gologin.NewRedisRateLimiter(redisClient, 5, 15*time.Minute),
		gologin.NewRedisRateLimiter(redisClient, 3, 1*time.Hour),
	)

	// ==================================================
	// EJEMPLO 4: Configuración CONDICIONAL
	// ==================================================
	var authService4 gologin.AuthService

	if os.Getenv("ENV") == "production" {
		// Producción: Todo activado con Redis
		authService4 = gologin.NewAuthServiceWithOptions(
			repo,
			os.Getenv("JWT_SECRET"),
			gologin.NewRedisTokenBlacklist(redisClient),
			gologin.NewRedisRateLimiter(redisClient, 5, 15*time.Minute),
			gologin.NewRedisRateLimiter(redisClient, 3, 1*time.Hour),
		)
	} else {
		// Desarrollo: Simple y rápido
		authService4 = gologin.NewAuthService(repo, "dev-secret-key-with-32-characters-min")
	}

	fmt.Println("AuthService configurado correctamente")
	fmt.Printf("Servicio 1 (mínimo): %+v\n", authService1)
	fmt.Printf("Servicio 2 (personalizado): %+v\n", authService2)
	fmt.Printf("Servicio 3 (completo): %+v\n", authService3)
	fmt.Printf("Servicio 4 (condicional): %+v\n", authService4)
}
