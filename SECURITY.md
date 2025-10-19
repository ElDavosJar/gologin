# Guía de Seguridad - gologin 🔒

## Resumen Ejecutivo

Este documento describe las correcciones de seguridad aplicadas al sistema de autenticación **gologin** y las mejores prácticas para su uso en producción.

---

## 🔴 Vulnerabilidades Corregidas

### 1. **Generación Automática de Secreto JWT** ✅ CORREGIDO
**Problema Original:**
```go
if secretKey == "" {
    key := make([]byte, 32)
    rand.Read(key)  // Sin manejo de errores
    secretKey = hex.EncodeToString(key)
}
```

**Solución Implementada:**
- El secreto JWT ahora es **obligatorio** (panic si está vacío)
- Validación de longitud mínima: **32 caracteres** (256 bits)
- No se genera automáticamente - debe ser provisto explícitamente

**Uso Correcto:**
```go
// Generar secreto seguro (hazlo UNA VEZ y guárdalo)
import "crypto/rand"

func generateSecureSecret() string {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        panic(err)
    }
    return hex.EncodeToString(b) // 64 caracteres hex
}

// En producción: usa variables de entorno
jwtSecret := os.Getenv("JWT_SECRET") // Mínimo 32 caracteres
if jwtSecret == "" {
    log.Fatal("JWT_SECRET environment variable is required")
}

authService := gologin.NewAuthService(repo, jwtSecret)
```

---

### 2. **Validación de Contraseñas Débil** ✅ CORREGIDO
**Problema Original:** Solo validaba longitud mínima (8 caracteres), permitiendo "12345678", "aaaaaaaa".

**Solución Implementada:**
- ✅ Longitud mínima: 8 caracteres
- ✅ Al menos una mayúscula
- ✅ Al menos una minúscula
- ✅ Al menos un número
- 🔧 Opcionalmente: caracteres especiales

**Personalización:**
```go
// Crear tu propia política de contraseñas
customStrength := gologin.PasswordStrength{
    MinLength:      12,
    RequireUpper:   true,
    RequireLower:   true,
    RequireNumber:  true,
    RequireSpecial: true,  // Requerir !@#$%^&*()
}

// Usar en tu lógica de validación
if err := gologin.ValidatePasswordStrength(password, customStrength); err != nil {
    return err
}
```

---

### 3. **Sin Protección contra Brute Force** ✅ CORREGIDO
**Solución Implementada:**
- **Rate Limiting** en login: 5 intentos cada 15 minutos
- **Rate Limiting** en registro: 3 registros por hora
- Limpieza automática de memoria para evitar fugas

**Valores por Defecto:**
```go
// Login: 5 intentos fallidos = bloqueo de 15 minutos
loginLimiter: NewInMemoryRateLimiter(5, 15*time.Minute)

// Registro: 3 registros = bloqueo de 1 hora
registerLimiter: NewInMemoryRateLimiter(3, 1*time.Hour)
```

**Personalización:**
```go
// Rate limiters personalizados
loginLimiter := gologin.NewInMemoryRateLimiter(3, 10*time.Minute)
registerLimiter := gologin.NewInMemoryRateLimiter(5, 30*time.Minute)
blacklist := gologin.NewInMemoryTokenBlacklist()

authService := gologin.NewAuthServiceWithOptions(
    repo, 
    jwtSecret, 
    blacklist, 
    loginLimiter, 
    registerLimiter,
)
```

**⚠️ Para Producción:**
El sistema incluye `InMemoryRateLimiter` para desarrollo, pero en producción usa Redis/Memcached:

```go
// Implementa la interfaz RateLimiter para tu infraestructura
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

// Inyecta tu implementación
authService := gologin.NewAuthServiceWithOptions(
    repo, secret, blacklist, 
    redisLoginLimiter,      // ← Tu implementación
    redisRegisterLimiter,   // ← Tu implementación
)
```

**Ver:** `INFRASTRUCTURE.md` para ejemplos completos de PostgreSQL, MongoDB, DynamoDB, etc
```

---

### 4. **Tokens sin Revocación** ✅ CORREGIDO
**Solución Implementada:**
- Sistema de **blacklist de tokens**
- Cada token tiene un `TokenID` único (jti claim)
- Métodos `Logout()` y `LogoutAll()` agregados
- Limpieza automática de tokens expirados

**Uso:**
```go
// Logout simple (revocar un token específico)
err := authService.Logout(accessToken)

// Validación ahora verifica blacklist
claims, err := authService.ValidateToken(accessToken)
if err != nil {
    // Error: "token has been revoked"
}
```

**⚠️ Para Producción:**
El sistema incluye `InMemoryTokenBlacklist` para desarrollo. En producción usa Redis/DynamoDB:

```go
// Implementa la interfaz TokenBlacklist
type RedisTokenBlacklist struct {
    client *redis.Client
}

func (r *RedisTokenBlacklist) Add(tokenID string, expiresAt time.Time) error {
    ttl := time.Until(expiresAt)
    return r.client.Set(ctx, "blacklist:"+tokenID, "1", ttl).Err()
}

func (r *RedisTokenBlacklist) IsBlacklisted(tokenID string) bool {
    result, _ := r.client.Exists(ctx, "blacklist:"+tokenID).Result()
    return result > 0
}

// Inyecta en el servicio
authService := gologin.NewAuthServiceWithOptions(
    repo, secret,
    redisBlacklist,  // ← Tu implementación
    loginLimiter, registerLimiter,
)
```

**Ver:** `INFRASTRUCTURE.md` para implementaciones completas (PostgreSQL, MongoDB, AWS, GCP)
```

---

### 5. **Validación de Username Débil** ✅ CORREGIDO
**Problema Original:** Permitía cualquier caracter, espacios, caracteres especiales peligrosos.

**Solución Implementada:**
- ✅ Debe empezar con letra o número
- ✅ Solo permite: letras, números, `.`, `_`, `-`
- ✅ No permite caracteres especiales consecutivos
- ✅ No puede terminar en carácter especial
- ✅ Longitud: 3-50 caracteres

**Ejemplos:**
```go
// ✅ VÁLIDOS
ValidateUsername("john_doe")      // OK
ValidateUsername("user123")       // OK
ValidateUsername("my.username")   // OK

// ❌ INVÁLIDOS
ValidateUsername("ab")            // muy corto
ValidateUsername("user@name")     // @ no permitido
ValidateUsername("user..name")    // doble punto
ValidateUsername("_username")     // empieza con _
ValidateUsername("username_")     // termina con _
```

---

### 6. **Validación de Claims JWT Débil** ✅ CORREGIDO
**Mejoras:**
- Validación de campos obligatorios: `UserID`, `OwnerID`, `OwnerType`, `Username`
- Validación de `TokenType` ("access" o "refresh")
- Validación de token vacío antes de parsear
- Verificación de blacklist integrada

---

## 🛡️ Mejores Prácticas para Producción

### 1. **Configuración del Secreto JWT**
```bash
# Genera un secreto fuerte (64+ caracteres)
openssl rand -hex 32

# En .env
JWT_SECRET=a1b2c3d4e5f6...64caracteres...
```

**NUNCA:**
- ❌ Hardcodear el secreto en el código
- ❌ Usar secretos cortos (<32 chars)
- ❌ Compartir el secreto en repositorios Git
- ❌ Usar el mismo secreto en dev y producción

---

### 2. **Configuración de HTTPS**
```go
// Solo acepta cookies seguras en producción
secure := os.Getenv("ENV") == "production"

http.SetCookie(w, &http.Cookie{
    Name:     "refresh_token",
    Value:    refreshToken,
    HttpOnly: true,        // No accesible desde JavaScript
    Secure:   secure,      // Solo HTTPS en producción
    SameSite: http.SameSiteStrictMode,
    MaxAge:   7 * 24 * 3600, // 7 días
})
```

---

### 3. **Manejo de Tokens**
```go
// ✅ CORRECTO: Access token en memoria, refresh en HttpOnly cookie
// Cliente (JavaScript):
localStorage.setItem("access_token", response.access_token) // OK - expira rápido

// ❌ INCORRECTO: Refresh token en localStorage
localStorage.setItem("refresh_token", response.refresh_token) // VULNERABLE A XSS!
```

**Arquitectura Recomendada:**
1. **Access Token**: En memoria del cliente (15 min)
2. **Refresh Token**: En HttpOnly cookie (7 días)
3. **Endpoint de refresh**: `/api/auth/refresh` que lee la cookie

---

### 4. **Logging de Seguridad**
```go
// Registra intentos fallidos para análisis
if err := authService.Login(req); err != nil {
    log.WithFields(log.Fields{
        "username": req.Username,
        "ip":       r.RemoteAddr,
        "error":    err.Error(),
        "time":     time.Now(),
    }).Warn("Failed login attempt")
    
    // No reveles si el usuario existe
    return errors.New("invalid credentials")
}
```

---

### 5. **Rotación de Tokens**
```go
// Implementa refresh token rotation
func (a *DefaultAuthService) RefreshAccessToken(refreshToken string) (*AuthResponse, error) {
    // Valida el refresh token
    claims, err := a.ValidateToken(refreshToken)
    if err != nil {
        return nil, err
    }
    
    // Revoca el refresh token usado
    a.blacklist.Add(claims.TokenID, time.Unix(claims.ExpiresAt, 0))
    
    // Genera NUEVOS access Y refresh tokens
    user, _ := a.repo.FindByID(claims.UserID)
    return a.jwtService.GenerateTokenPair(user)
}
```

---

## 📋 Checklist de Despliegue

Antes de usar en producción:

- [ ] Secreto JWT generado y almacenado en variable de entorno
- [ ] HTTPS configurado (TLS 1.3+)
- [ ] Rate limiting habilitado con almacenamiento distribuido (Redis)
- [ ] Token blacklist con Redis/Memcached
- [ ] Logging de eventos de seguridad
- [ ] Monitoreo de intentos fallidos
- [ ] Rotación de refresh tokens habilitada
- [ ] HttpOnly cookies para refresh tokens
- [ ] CORS configurado correctamente
- [ ] Políticas de contraseñas documentadas para usuarios
- [ ] Endpoint de cambio de contraseña implementado
- [ ] Sistema de recuperación de contraseña seguro
- [ ] 2FA/MFA considerado para cuentas sensibles

---

## 🔄 Migraciones Necesarias

Si ya tienes usuarios en producción:

### Migración 1: Actualizar estructura de Claims
```sql
-- Asegúrate de regenerar todos los tokens activos
-- O implementa compatibilidad hacia atrás en ValidateToken
```

### Migración 2: Actualizar contraseñas débiles
```go
// Script de migración
func migrateWeakPasswords(repo UserRepository) {
    users := repo.FindAll()
    for _, user := range users {
        // Forzar cambio de contraseña en próximo login
        user.RequirePasswordChange = true
        repo.Update(user)
    }
}
```

---

## 📚 Recursos Adicionales

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/)

---

## 🆘 Soporte

Si encuentras vulnerabilidades de seguridad, por favor repórtalas de forma privada en lugar de crear issues públicos.

**Contacto de Seguridad:** [Tu email de seguridad]

---

## 📝 Changelog de Seguridad

### v2.0.0 (2025-10-18)
- ✅ Forzar secreto JWT obligatorio (32+ chars)
- ✅ Validación robusta de contraseñas
- ✅ Rate limiting en login y registro
- ✅ Sistema de blacklist de tokens
- ✅ Validación estricta de usernames
- ✅ Validación completa de JWT claims
- ✅ TokenID (jti) para revocación
- ✅ Métodos Logout/LogoutAll

### v1.0.0 (Original)
- ⚠️ Múltiples vulnerabilidades de seguridad (ver arriba)
