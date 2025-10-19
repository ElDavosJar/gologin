# 🧪 Guía de Testing Beta - gologin v0.9.0-beta


## 📋 Lista de Verificación de Testing

### ✅ Tests Obligatorios (Haz todos estos)

- [ ] **Test Básico**: Registrar usuario, hacer login, validar token
- [ ] **Test de Seguridad**: Intentar login con credenciales incorrectas
- [ ] **Test de Refresh**: Generar nuevos tokens usando refresh token
- [ ] **Test de Logout**: Invalidar tokens específicos
- [ ] **Test de Rate Limiting**: Verificar protección contra brute force

### ✅ Tests Recomendados (Haz al menos 3)

- [ ] **Test Multi-usuario**: Múltiples usuarios para el mismo owner
- [ ] **Test de Expiración**: Verificar que tokens expiran correctamente
- [ ] **Test de Validación**: Probar límites de username/password
- [ ] **Test de Concurrencia**: Múltiples logins simultáneos

### ✅ Tests Avanzados (Opcional)

- [ ] **Test con Base de Datos**: Integrar con PostgreSQL/MySQL
- [ ] **Test con Redis**: Rate limiting y blacklist distribuidos
- [ ] **Test de Rendimiento**: Cargar con muchos usuarios/tokens
- [ ] **Test de Seguridad Avanzado**: Análisis de vulnerabilidades

### ✅ Tests de Seguridad (Importante)

- [ ] **Intentar romper la seguridad**: Probar inyecciones, tokens manipulados, etc.

## 🚀 Inicio Rápido (5 minutos)

### 1. Instalar y Ejecutar Tests Unitarios

```bash
cd gologin
go test -v ./...
```

**Resultado esperado**: Todos los tests pasan ✅

### 2. Ejecutar Tests de Integración

```bash
cd gologin/examples
go test -v -run "TestCompleteUserLifecycle|TestRateLimitingIntegration|TestTokenRotationSecurity|TestMultipleUsersSameOwner"
```

**Resultado esperado**: Todos los tests de integración pasan ✅

### 3. Probar la Aplicación de Ejemplo

```bash
cd gologin/examples
go run full_app_example.go
```

La aplicación se ejecutará en `http://localhost:8080`

## 🧪 Escenarios de Testing Detallados

### Escenario 1: Flujo Básico de Autenticación

```bash
# Terminal 1: Ejecutar el servidor
cd gologin/examples && go run full_app_example.go

# Terminal 2: Registrar usuario
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "owner_type": "business",
    "owner_id": "my-company-123",
    "username": "admin",
    "password": "SecurePass123"
  }'

# Terminal 2: Hacer login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePass123"
  }'
```

**Validar**:
- ✅ Respuesta contiene `access_token` y `refresh_token`
- ✅ Usuario registrado correctamente
- ✅ Login exitoso

### Escenario 2: Acceso a Endpoint Protegido

```bash
# Usar el access_token del login anterior
curl -X GET http://localhost:8080/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

**Validar**:
- ✅ Acceso permitido con token válido
- ✅ Respuesta contiene información del usuario

### Escenario 3: Refresh Token

```bash
# Usar el refresh_token del login
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN_HERE"
  }'
```

**Validar**:
- ✅ Nuevos tokens generados
- ✅ Token anterior aún válido (hasta expirar)

### Escenario 4: Logout

```bash
# Logout con access token
curl -X POST http://localhost:8080/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

**Validar**:
- ✅ Token invalidado (próximo acceso debería fallar)

### Escenario 5: Rate Limiting

```bash
# Intentar login múltiples veces con contraseña incorrecta
for i in {1..5}; do
  curl -X POST http://localhost:8080/auth/login \
    -H "Content-Type: application/json" \
    -d '{
      "username": "admin",
      "password": "WrongPassword"
    }'
done
```

**Validar**:
- ✅ Después de 2-3 intentos, recibir "rate limit exceeded"

## 🔍 Validación de Seguridad

### Test de Fuerza de Contraseña

```bash
# Probar contraseñas débiles
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "owner_type": "business",
    "owner_id": "test",
    "username": "weak",
    "password": "123"
  }'
```

**Validar**: ❌ Debe rechazar contraseñas débiles

### Test de Username Inválido

```bash
# Probar usernames con caracteres especiales inválidos
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "owner_type": "business",
    "owner_id": "test",
    "username": "user@domain.com",
    "password": "SecurePass123"
  }'
```

**Validar**: ❌ Debe rechazar usernames inválidos

## 🐛 Reporte de Bugs

Si encuentras algún problema, por favor incluye:

1. **Descripción del bug**
2. **Pasos para reproducir**
3. **Resultado esperado vs real**
4. **Entorno**: Go version, OS, etc.
5. **Logs relevantes**

## 📊 Métricas de Éxito

Tu beta test es exitoso si:

- ✅ **100%** de tests unitarios pasan
- ✅ **100%** de tests de integración pasan
- ✅ Todos los endpoints de la API funcionan
- ✅ Rate limiting protege contra brute force
- ✅ Tokens se refrescan correctamente
- ✅ Logout invalida tokens apropiadamente

## 🎉 Próximos Pasos

Después de completar los tests:

1. **Feedback**: Comparte tus resultados y sugerencias
2. **Integración**: Integra gologin en tu aplicación real
3. **Producción**: Una vez que liberes v1.0.0, estarás listo para producción

## 📞 Soporte

Para preguntas sobre testing o integración:
- Revisa la documentación en `README.md`
- Ejecuta `go doc` para ver documentación del código
- Revisa los ejemplos en `gologin/examples/`
- Los tests unitarios pasan correctamente ✅
- Los tests de integración están disponibles en `gologin/examples/integration_test.go`

---

**¡Gracias por probar gologin!** Tu feedback es crucial para hacer esta librería mejor. 🚀