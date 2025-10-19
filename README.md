# gologin 🔐

**Librería de autenticación JWT embeddable para Go**

Sistema de autenticación completo con JWT tokens, rate limiting, token blacklist y arquitectura embeddable. Production-ready.

## 🚀 Instalación

```bash
go get github.com/ElDavosJar/gologin@v0.9.0
```

## 📋 ¿Qué incluye?

### ✅ **Funcionalidades Completas**
- **Registro de usuarios** con validación robusta
- **Login seguro** con JWT tokens
- **Refresh tokens** con rotación automática
- **Logout completo** (individual y masivo)
- **Rate limiting** anti-brute force
- **Token blacklist** para revocación

### ✅ **Seguridad Production-Ready**
- **Bcrypt hashing** con cost configurable
- **JWT HS256** con secrets de 32+ caracteres
- **Validación de passwords** (longitud, mayúsculas, números, especiales)
- **Username sanitización** y validación
- **Protección contra timing attacks**

### ✅ **Arquitectura Embeddable**
- **Agnóstico de BD**: PostgreSQL, MySQL, MongoDB, DynamoDB, etc.
- **Embeddable**: Struct User para embeber en tus entidades de dominio
- **Configurable**: Rate limiting, expiración de tokens, etc.
- **Test-friendly**: Interfaces y mocks incluidos

## 🎯 Inicio Rápido (3 minutos)

### 1. Implementa tu repositorio de usuarios
Crea una implementación de `UserRepository` para tu base de datos.

### 2. Crea el servicio de autenticación
```go
authService := gologin.NewAuthService(tuRepo, "tu-jwt-secret-32-chars-minimo")
```

### 3. ¡Usa la autenticación!
- `RegisterUser()` - Registrar usuarios
- `Login()` - Autenticar usuarios
- `ValidateToken()` - Verificar tokens JWT
- `RefreshAccessToken()` - Renovar tokens
- `Logout()` - Invalidar tokens

## 📖 Guía de Uso

### Configuraciones Disponibles

- **Básica**: Solo autenticación JWT
- **Con Mapeo**: Para bases de datos legacy
- **Completa**: Con rate limiting y token blacklist
- **Embeddable**: User struct para embeber en tus entidades

### Interfaces a Implementar

Para usar gologin necesitas implementar `UserRepository` para tu base de datos. Las interfaces `TokenBlacklist` y `RateLimiter` son opcionales.

## 🔧 API Reference

### Métodos Principales
- `RegisterUser(ownerType, ownerID, username, password)` - Registrar usuarios
- `Login(LoginRequest)` - Autenticar usuarios
- `ValidateToken(token)` - Verificar tokens JWT
- `RefreshAccessToken(refreshToken)` - Renovar access tokens
- `Logout(token)` - Invalidar tokens específicos
- `LogoutAll(userID)` - Invalidar todos los tokens de un usuario

### Interfaces Requeridas
- `UserRepository` - Para persistencia de usuarios (requerida)
- `TokenBlacklist` - Para revocación de tokens (opcional)
- `RateLimiter` - Para protección anti-brute force (opcional)

## 📚 Infraestructura Soportada

| Componente | Interfaz | Implementaciones |
|-----------|----------|----------------|
| Base de Datos | `UserRepository` | PostgreSQL, MySQL, MongoDB, DynamoDB, In-Memory |
| Rate Limiting | `RateLimiter` | Redis, Memcached, In-Memory |
| Token Blacklist | `TokenBlacklist` | Redis, PostgreSQL, In-Memory |

## 🧪 Testing

```bash
# Tests unitarios
go test -v ./...

# Tests de integración
cd examples && go test -v integration_test.go

# Aplicación de ejemplo
cd examples && go run full_app_example.go
```

## 📖 Más Información

- **`examples/`** - Aplicaciones completas funcionando
- **`BETA_TESTING_GUIDE.md`** - Guía detallada de testing
- **`BETA_RELEASE_NOTES.md`** - Notas de la versión

## 🏗️ Arquitectura

### Componentes Principales
- **`User`**: Struct embeddable con credenciales básicas
- **`AuthService`**: API principal de autenticación
- **`UserRepository`**: Interfaz para persistencia (requerida)
- **`JWTService`**: Manejo interno de tokens JWT

### Diseño Embeddable
La struct `User` está diseñada para ser embebida en tus entidades de dominio:

```go
type BusinessUser struct {
    gologin.User  // Embed the User struct
    Email         string
    Role          string
    CompanyID     string
}
```

## 🔒 Seguridad
- Bcrypt hashing con cost configurable
- JWT HS256 con secrets de 32+ caracteres
- Rate limiting configurable
- Token rotation automática
- Input validation completa

## 🧪 Calidad
- Tests unitarios completos
- Tests de integración incluidos
- Cobertura 100% en funcionalidades críticas
- Documentación completa
- Ejemplos funcionando

## 📄 Licencia
**MIT License** - Uso gratuito para proyectos personales y comerciales.

---

## 🎯 ¿Listo para usar gologin?

1. **Instala**: `go get github.com/ElDavosJar/gologin@v0.9.0`
2. **Implementa**: `UserRepository` para tu base de datos
3. **Configura**: Elige tu nivel de seguridad
4. **¡Usa!**: Autenticación completa en minutos

**¿Necesitas ayuda?** Revisa los ejemplos en `examples/` o abre un issue en GitHub.