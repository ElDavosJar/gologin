# gologin 🔐

**Autenticación JWT completa para Go**

Librería de autenticación con JWT tokens, rate limiting, token blacklist y multi-tenancy. Production-ready.

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

### ✅ **Arquitectura Flexible**
- **Agnóstico de BD**: PostgreSQL, MySQL, MongoDB, DynamoDB, etc.
- **Multi-tenant**: OwnerID/OwnerType para cualquier dominio
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
- **Multi-tenant**: OwnerID/OwnerType nativo

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
- **`User`**: Credenciales con OwnerID/OwnerType para multi-tenancy
- **`AuthService`**: API principal de autenticación
- **`UserRepository`**: Interfaz para persistencia (requerida)
- **`JWTService`**: Manejo interno de tokens JWT

### Multi-Tenancy Nativo
Cada usuario pertenece a una entidad específica (gym, company, customer, etc.)

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