# gologin 🔐

Sistema de autenticación seguro, flexible y **agnóstico de infraestructura** para Go. Reutilizable en cualquier proyecto sin modificaciones.

## ✨ Características

### 🏗️ Arquitectura
- **🔌 100% Agnóstico de Infraestructura**: Usa tu base de datos favorita (PostgreSQL, MongoDB, DynamoDB, etc.)
- **🎯 Agnóstico al Dominio**: Funciona con cualquier entidad (users, customers, admins, tenants, etc.)
- **📦 Basado en Interfaces**: Inyección de dependencias pura, fácil de testear y extender
- **🧪 Test-Friendly**: Mocks incluidos y alta cobertura de tests

### 🔒 Seguridad Production-Ready
- **✅ JWT Tokens**: Access (15min) + Refresh (7 días) con revocación
- **✅ Bcrypt Hashing**: Validación robusta de passwords (longitud, mayúsculas, números)
- **✅ Rate Limiting**: Protección contra brute force (configurable)
- **✅ Token Blacklist**: Logout funcional, revocación de sesiones
- **✅ Username Validation**: Prevención de caracteres peligrosos
- **✅ Claims Validation**: Verificación completa de JWT

### 📚 Documentación Completa
- `SECURITY.md` - Análisis de vulnerabilidades y correcciones
- `INFRASTRUCTURE.md` - Ejemplos para PostgreSQL, MongoDB, Redis, DynamoDB, etc.
- Tests exhaustivos con ejemplos de uso

## Instalación

```bash
go get github.com/davos/gologin
```

## Inicio Rápido

### Para Bases de Datos Estándar (90% de casos)

Si tu base de datos usa nombres de campos estándar (`id`, `username`, `password_hash`, `created_at`), funciona out-of-the-box:

```go
// 1. Implementa UserRepository con campos estándar
repo := &MyUserRepository{db: db}

// 2. Crea servicio de auth (sin configuración adicional)
authService := gologin.NewAuthService(repo, "tu-secreto-jwt-de-32-chars")

// 3. ¡Listo! Registra y autentica usuarios
user, _ := authService.RegisterUser("business", "profile-123", "admin", "SecurePass123")
```

### Para Bases de Datos Legacy (10% de casos)

Si tu BD tiene nombres de campos diferentes, especifica el mapeo:

```go
// Define mapeo de campos para tu schema legacy
customMapping := &gologin.FieldMapping{
    ID:           "user_id",
    Username:     "user_name",
    PasswordHash: "pwd_hash",
    CreatedAt:    "create_date",
}

// Crea servicio con mapeo custom
authService := gologin.NewAuthServiceWithMapping(repo, jwtSecret, customMapping)
```

## Uso Básico

### 1. Implementa la interfaz UserRepository

```go
type MyUserRepository struct {
    db *sql.DB
}

func (r *MyUserRepository) Save(user *gologin.User) error {
    // Asigna ID y guarda en DB
    user.ID = &generatedID
    return r.db.Save(user)
}

func (r *MyUserRepository) FindByUsername(username string) (*gologin.User, error) {
    // Busca en DB
}

func (r *MyUserRepository) FindByID(id string) (*gologin.User, error) {
    // Busca por ID
}

func (r *MyUserRepository) IsUsernameTaken(username string) (bool, error) {
    // Verifica unicidad
}
```

### 2. Crea el servicio de autenticación

```go
// Desarrollo (in-memory)
repo := &MyUserRepository{db: myDB}
authService := gologin.NewAuthService(repo, "your-32-char-jwt-secret-key-here")

// Producción (con infraestructura real)
authService := gologin.NewAuthServiceWithOptions(
    postgresRepo,           // Tu implementación de UserRepository
    os.Getenv("JWT_SECRET"), // Secreto desde env (mínimo 32 chars)
    redisBlacklist,         // Tu implementación de TokenBlacklist
    redisLoginLimiter,      // Tu implementación de RateLimiter
    redisRegisterLimiter,   // Tu implementación de RateLimiter
)
```

**Ver `INFRASTRUCTURE.md`** para ejemplos completos de PostgreSQL, MongoDB, Redis, etc.

### 3. Registra usuarios

```go
// Registra credenciales para un perfil de negocio
user, err := authService.RegisterUser(
    "business_profile",  // tipo de entidad
    "profile-123",       // ID del perfil
    "johndoe",           // username único
    "securepassword123", // password
)
```

### 4. Login

```go
req := gologin.LoginRequest{
    Username: "johndoe",
    Password: "securepassword123",
}

resp, err := authService.Login(req)
if err != nil {
    // Error de autenticación
}

// Usa los tokens
accessToken := resp.AccessToken
refreshToken := resp.RefreshToken
```

### 5. Valida tokens en tus endpoints

```go
claims, err := authService.ValidateToken(accessTokenFromHeader)
if err != nil {
    // Token inválido
}

// Accede a la información del usuario
userID := claims.UserID
ownerID := claims.OwnerID  // ID del perfil de negocio
ownerType := claims.OwnerType  // "business_profile"
```

### 6. Renueva access tokens

```go
newResp, err := authService.RefreshAccessToken(refreshToken)
if err != nil {
    // Refresh token inválido
}

newAccessToken := newResp.AccessToken
```

### 7. Logout (revocación de tokens)

```go
// Revocar un token específico
err := authService.Logout(accessToken)

// Revocar todas las sesiones de un usuario
err := authService.LogoutAll(userID)
```

---

## 🔌 Configuración flexible: Redis o memoria

Puedes elegir la infraestructura para rate limiting y blacklist:

```go
import (
    "github.com/redis/go-redis/v9"
    "github.com/davos/gologin"
)

// Configuración con Redis
redisClient := redis.NewClient(&redis.Options{
    Addr: "localhost:6379",
})
loginLimiter := gologin.NewRedisRateLimiter(redisClient, 5, 15*time.Minute)
registerLimiter := gologin.NewRedisRateLimiter(redisClient, 3, 1*time.Hour)
blacklist := gologin.NewRedisTokenBlacklist(redisClient)

authService := gologin.NewAuthServiceWithOptions(
    repo, jwtSecret, blacklist, loginLimiter, registerLimiter,
)

// O bien, para desarrollo/local:
loginLimiter := gologin.NewInMemoryRateLimiter(5, 15*time.Minute)
registerLimiter := gologin.NewInMemoryRateLimiter(3, 1*time.Hour)
blacklist := gologin.NewInMemoryTokenBlacklist()

authService := gologin.NewAuthServiceWithOptions(
    repo, jwtSecret, blacklist, loginLimiter, registerLimiter,
)
```

---

## 🏗️ Agnosticismo de Infraestructura

**gologin es 100% agnóstico** - tú decides tu stack tecnológico:

| Componente | Interfaz | Ejemplos de Implementación |
|-----------|----------|---------------------------|
| 💾 **Base de Datos** | `UserRepository` | PostgreSQL, MySQL, MongoDB, DynamoDB, Firestore, In-Memory |
| 🚦 **Rate Limiting** | `RateLimiter` | Redis, Memcached, DynamoDB, In-Memory |
| 🚫 **Token Blacklist** | `TokenBlacklist` | Redis, PostgreSQL, Memcached, DynamoDB, In-Memory |

### Cambiar de infraestructura es trivial:

```go
// Desarrollo local (in-memory)
authService := gologin.NewAuthService(mockRepo, secret)

// Producción (PostgreSQL + Redis)
authService := gologin.NewAuthServiceWithOptions(
    postgresRepo,      // Cambias esto
    secret,
    redisBlacklist,    // Cambias esto
    redisLoginLimiter, // Cambias esto
    redisRegisterLimiter, // Cambias esto
)

// La API del servicio NO CAMBIA ✅
// Tu lógica de negocio permanece intacta
```

**📖 Ver `INFRASTRUCTURE.md`** para ejemplos completos:
- PostgreSQL + Redis
- MongoDB + Memcached
- AWS (DynamoDB + ElastiCache)
- GCP (Cloud SQL + Memorystore)

---

## Ejemplo Completo de Integración

```go
package main

import (
    "database/sql"
    "log"

    "github.com/davos/gologin"
    _ "github.com/lib/pq"
)

type BusinessProfile struct {
    ID          string
    CompanyName string
    Email       string
    TaxID       string
}

type MyRepository struct {
    db *sql.DB
}

func (r *MyRepository) Save(user *gologin.User) error {
    // Asigna ID único
    id := generateUUID()
    user.ID = &id

    // Guarda en DB
    _, err := r.db.Exec(`
        INSERT INTO users (id, owner_id, owner_type, username, password_hash, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)`,
        user.ID, user.OwnerID, user.OwnerType, user.Username, user.PasswordHash, user.CreatedAt)
    return err
}

// ... implementa los otros métodos

func main() {
    db, _ := sql.Open("postgres", "connstring")

    repo := &MyRepository{db: db}
    authService := gologin.NewAuthService(repo, "my-secret-key")

    // En tu aplicación:
    // 1. Crea el perfil de negocio
    profile := createBusinessProfile("My Company", "company@email.com")

    // 2. Registra credenciales para ese perfil
    user, err := authService.RegisterUser("business_profile", profile.ID, "admin", "password123")
    if err != nil {
        log.Fatal(err)
    }

    // 3. El usuario puede hacer login
    resp, err := authService.Login(gologin.LoginRequest{
        Username: "admin",
        Password: "password123",
    })

    fmt.Printf("Login exitoso! Access token: %s\n", resp.AccessToken)
}
```

## Arquitectura

### Componentes Principales

- **`User`**: Struct con credenciales (username, password hash, owner info)
- **`AuthService`**: Interfaz para operaciones de autenticación
- **`UserRepository`**: Interfaz para persistencia (implementa tú)
- **`JWTService`**: Manejo interno de tokens JWT

### Diseño Agnóstico

La librería no asume nada sobre tu dominio. El `User` pertenece a cualquier entidad vía `OwnerID` y `OwnerType`:

- `OwnerType`: "business_profile", "customer", "admin", etc.
- `OwnerID`: ID de la entidad que "tiene" estas credenciales

Esto permite flexibilidad total en tu aplicación.

## Seguridad

- **Passwords**: bcrypt con cost default (seguro)
- **JWT**: HS256 con secreto configurable
- **Tokens**: Access (15 min), Refresh (7 días)
- **Validación**: Unicidad de username, reglas de password

## Tests

```bash
go test -v
```

La librería incluye tests completos con mocks para todas las funcionalidades.

## Licencia

MIT License