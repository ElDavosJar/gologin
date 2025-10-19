# gologin - Sistema de Autenticación Seguro 🔐

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-hardened-green.svg)](SECURITY.md)

Sistema de autenticación flexible y seguro para aplicaciones Go. Diseñado para ser reutilizable en cualquier proyecto sin asumir modelos de dominio específicos.

## ✨ Características

- 🔒 **Seguridad robusta**: Bcrypt, JWT con HMAC-SHA256, validación estricta
- 🚦 **Rate limiting**: Protección contra ataques de fuerza bruta
- 🔄 **Revocación de tokens**: Sistema de blacklist para logout
- ✅ **Validación completa**: Contraseñas, usernames, JWT claims
- 🎯 **Dominio-agnóstico**: Asocia credenciales a cualquier entidad de negocio
- 🧪 **Bien testeado**: Cobertura completa de casos de uso
- 🔧 **Extensible**: Interfaces para personalización (rate limiters, blacklists, storage)

## 📋 Requisitos de Seguridad

- **Go 1.21+**
- **JWT Secret**: Mínimo 32 caracteres (256 bits)
- **HTTPS en producción**: Obligatorio para proteger tokens
- **Redis/Memcached**: Recomendado para rate limiting distribuido

## 🚀 Instalación Rápida

```bash
go get github.com/yourusername/gologin
```

## 📖 Uso Básico

### 1. Configurar el servicio de autenticación

```go
package main

import (
    "github.com/yourusername/gologin"
    "os"
)

func main() {
    // Repositorio de usuarios (implementa la interfaz UserRepository)
    repo := NewMyUserRepository()
    
    // Secreto JWT desde variable de entorno (OBLIGATORIO)
    jwtSecret := os.Getenv("JWT_SECRET")
    if len(jwtSecret) < 32 {
        panic("JWT_SECRET debe tener al menos 32 caracteres")
    }
    
    // Crear servicio de autenticación
    authService := gologin.NewAuthService(repo, jwtSecret)
}
```

### 2. Registrar usuarios

```go
user, err := authService.RegisterUser(
    "business_profile",  // Tipo de entidad dueña
    "profile-uuid-123",  // ID de la entidad
    "johndoe",          // Username
    "MyP@ssw0rd123",    // Password (cumple requisitos de seguridad)
)

if err != nil {
    // Manejar errores:
    // - "username already taken"
    // - "password must contain uppercase/lowercase/number"
    // - "rate limit exceeded"
    log.Fatal(err)
}
```

### 3. Login

```go
loginReq := gologin.LoginRequest{
    Username: "johndoe",
    Password: "MyP@ssw0rd123",
}

resp, err := authService.Login(loginReq)
if err != nil {
    // Error: "invalid credentials" o "rate limit exceeded"
    http.Error(w, "Login failed", http.StatusUnauthorized)
    return
}

// resp.AccessToken - Token de corta duración (15 min)
// resp.RefreshToken - Token de larga duración (7 días)
// resp.User - Datos del usuario
```

### 4. Validar tokens

```go
claims, err := authService.ValidateToken(accessToken)
if err != nil {
    // Token inválido, expirado o revocado
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
    return
}

// Usar claims para autorización
userID := claims.UserID
ownerID := claims.OwnerID
ownerType := claims.OwnerType
```

### 5. Refresh tokens

```go
newTokens, err := authService.RefreshAccessToken(refreshToken)
if err != nil {
    // Refresh token inválido o expirado
    http.Error(w, "Token refresh failed", http.StatusUnauthorized)
    return
}

// Enviar nuevos tokens al cliente
```

### 6. Logout (revocar tokens)

```go
// Logout simple - revoca un token específico
err := authService.Logout(accessToken)
if err != nil {
    log.Printf("Logout error: %v", err)
}

// El token queda en blacklist hasta su expiración natural
```

## 🛡️ Seguridad Avanzada

### Configuración Personalizada

```go
// Rate limiters personalizados
loginLimiter := gologin.NewInMemoryRateLimiter(3, 10*time.Minute)
registerLimiter := gologin.NewInMemoryRateLimiter(5, 1*time.Hour)

// Blacklist de tokens
blacklist := gologin.NewInMemoryTokenBlacklist()

// Servicio con configuración personalizada
authService := gologin.NewAuthServiceWithOptions(
    repo,
    jwtSecret,
    blacklist,
    loginLimiter,
    registerLimiter,
)
```

### Validación de Contraseñas Personalizada

```go
// Política más estricta
strictPassword := gologin.PasswordStrength{
    MinLength:      12,
    RequireUpper:   true,
    RequireLower:   true,
    RequireNumber:  true,
    RequireSpecial: true,
}

err := gologin.ValidatePasswordStrength(password, strictPassword)
```

### Rate Limiting con Redis (Producción)

```go
type RedisRateLimiter struct {
    client *redis.Client
    maxAttempts int
    window time.Duration
}

func (r *RedisRateLimiter) Allow(identifier string) bool {
    key := fmt.Sprintf("ratelimit:%s", identifier)
    count, _ := r.client.Incr(ctx, key).Result()
    
    if count == 1 {
        r.client.Expire(ctx, key, r.window)
    }
    
    return count <= int64(r.maxAttempts)
}

func (r *RedisRateLimiter) Reset(identifier string) {
    r.client.Del(ctx, fmt.Sprintf("ratelimit:%s", identifier))
}

// Usar en NewAuthServiceWithOptions
```

## 🔌 Implementar UserRepository

```go
type UserRepository interface {
    Save(user *User) error
    FindByUsername(username string) (*User, error)
    FindByID(id string) (*User, error)
    IsUsernameTaken(username string) (bool, error)
}

// Ejemplo con base de datos
type PostgresUserRepository struct {
    db *sql.DB
}

func (r *PostgresUserRepository) Save(user *gologin.User) error {
    if user.ID == nil {
        // INSERT
        id := uuid.New().String()
        _, err := r.db.Exec(
            "INSERT INTO auth_users (id, owner_id, owner_type, username, password_hash, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
            id, user.OwnerID, user.OwnerType, user.Username, user.PasswordHash, user.CreatedAt,
        )
        user.ID = &id
        return err
    }
    
    // UPDATE
    _, err := r.db.Exec(
        "UPDATE auth_users SET username=$1, password_hash=$2 WHERE id=$3",
        user.Username, user.PasswordHash, *user.ID,
    )
    return err
}

func (r *PostgresUserRepository) FindByUsername(username string) (*gologin.User, error) {
    user := &gologin.User{}
    err := r.db.QueryRow(
        "SELECT id, owner_id, owner_type, username, password_hash, created_at FROM auth_users WHERE username=$1",
        username,
    ).Scan(&user.ID, &user.OwnerID, &user.OwnerType, &user.Username, &user.PasswordHash, &user.CreatedAt)
    
    if err == sql.ErrNoRows {
        return nil, nil
    }
    return user, err
}
```

## 📊 Schema de Base de Datos Recomendado

```sql
CREATE TABLE auth_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id VARCHAR(255) NOT NULL,
    owner_type VARCHAR(100) NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP,
    
    -- Índices para performance
    INDEX idx_username (username),
    INDEX idx_owner (owner_type, owner_id)
);

-- Opcional: Tabla para tracking de sesiones
CREATE TABLE auth_sessions (
    token_id VARCHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth_users(id),
    token_type VARCHAR(20) NOT NULL, -- 'access' o 'refresh'
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    INDEX idx_user_sessions (user_id, expires_at)
);
```

## 🧪 Testing

```bash
go test ./... -v -cover
```

## 📋 Requisitos de Contraseña por Defecto

- ✅ Mínimo 8 caracteres
- ✅ Al menos una mayúscula (A-Z)
- ✅ Al menos una minúscula (a-z)
- ✅ Al menos un número (0-9)
- 🔧 Opcional: Caracteres especiales (!@#$%^&*)

## 📋 Requisitos de Username

- ✅ 3-50 caracteres
- ✅ Debe empezar con letra o número
- ✅ Solo permite: letras, números, `.`, `_`, `-`
- ✅ No permite caracteres especiales consecutivos
- ✅ No puede terminar en carácter especial

## 🎯 Arquitectura Recomendada

### Cliente (Frontend)
```javascript
// Access token en memoria (se pierde al recargar - más seguro)
let accessToken = null;

async function login(username, password) {
    const response = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include', // Envía cookies
        body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    accessToken = data.access_token; // En memoria
    // refresh_token viene en HttpOnly cookie automáticamente
}

// Interceptor para renovar token
axios.interceptors.response.use(
    response => response,
    async error => {
        if (error.response.status === 401) {
            // Renovar con refresh token (cookie)
            const response = await fetch('/api/auth/refresh', {
                method: 'POST',
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                accessToken = data.access_token;
                // Reintentar request original
                error.config.headers.Authorization = `Bearer ${accessToken}`;
                return axios.request(error.config);
            }
        }
        return Promise.reject(error);
    }
);
```

### Servidor (Backend)
```go
// Handler de login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    var req gologin.LoginRequest
    json.NewDecoder(r.Body).Decode(&req)
    
    resp, err := authService.Login(req)
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }
    
    // Refresh token en HttpOnly cookie (no accesible desde JS)
    http.SetCookie(w, &http.Cookie{
        Name:     "refresh_token",
        Value:    resp.RefreshToken,
        HttpOnly: true,
        Secure:   true, // Solo HTTPS
        SameSite: http.SameSiteStrictMode,
        MaxAge:   7 * 24 * 3600, // 7 días
        Path:     "/api/auth",
    })
    
    // Access token en respuesta JSON
    json.NewEncoder(w).Encode(map[string]interface{}{
        "access_token": resp.AccessToken,
        "user": resp.User,
    })
}

// Middleware de autenticación
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        
        token := strings.TrimPrefix(authHeader, "Bearer ")
        claims, err := authService.ValidateToken(token)
        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
        
        // Agregar claims al contexto
        ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
        ctx = context.WithValue(ctx, "owner_id", claims.OwnerID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

## 🔍 Troubleshooting

### Error: "JWT secret key cannot be empty"
**Solución:** Configura la variable de entorno `JWT_SECRET` con al menos 32 caracteres.

```bash
# Generar secreto seguro
openssl rand -hex 32
```

### Error: "rate limit exceeded"
**Causa:** Demasiados intentos de login/registro desde la misma IP o username.
**Solución:** Espera el tiempo del window period o implementa CAPTCHA.

### Error: "token has been revoked"
**Causa:** El token fue revocado mediante `Logout()`.
**Solución:** El usuario debe hacer login nuevamente.

## 📚 Documentación Completa

- [Guía de Seguridad](SECURITY.md) - Mejores prácticas y configuración segura
- [API Reference](docs/API.md) - Documentación completa de la API
- [Examples](examples/) - Ejemplos de integración

## 🤝 Contribuir

Las contribuciones son bienvenidas. Para cambios importantes:

1. Abre un issue para discutir el cambio
2. Fork el proyecto
3. Crea una rama feature (`git checkout -b feature/AmazingFeature`)
4. Commit tus cambios (`git commit -m 'Add AmazingFeature'`)
5. Push a la rama (`git push origin feature/AmazingFeature`)
6. Abre un Pull Request

## 🔒 Reportar Vulnerabilidades

Si encuentras vulnerabilidades de seguridad, por favor **NO** abras un issue público.
Contáctanos de forma privada en: [tu-email-de-seguridad]

## 📄 Licencia

MIT License - Ver [LICENSE](LICENSE) para más detalles.

## ⭐ Casos de Uso

Este sistema es ideal para:

- ✅ **SaaS multi-tenant**: Asocia usuarios a organizaciones/empresas
- ✅ **Marketplaces**: Diferentes tipos de usuarios (vendedores, compradores, admins)
- ✅ **APIs REST**: Autenticación JWT estándar
- ✅ **Microservicios**: Servicio de autenticación independiente
- ✅ **Aplicaciones móviles**: Refresh tokens para sesiones largas

---

Desarrollado con ❤️ para la comunidad Go
