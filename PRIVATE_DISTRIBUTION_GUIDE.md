# 🔒 Guía de Distribución Privada - gologin

## 🎯 Repositorio Privado/Protegido

Esta guía explica cómo configurar gologin en un repositorio **privado** para distribución controlada a clientes específicos.

## 📋 Opciones de Repositorios Privados

### Opción 1: GitHub Private Repository (Recomendado)
- ✅ Fácil de configurar
- ✅ Control total de acceso
- ✅ Integración con GitHub Actions
- ✅ Issues y documentación incluida

### Opción 2: GitLab Self-Hosted
- ✅ Control total de infraestructura
- ✅ CI/CD integrado
- ✅ Registry privado para Go modules

### Opción 3: Bitbucket Private
- ✅ Similar a GitHub
- ✅ Bueno para equipos Atlassian

## 🚀 Configuración de Repositorio Privado en GitHub

### Paso 1: Crear Repositorio Privado
```bash
# Crear repo privado en GitHub
# Nombre: gologin-private
# Visibilidad: Private
# URL: https://github.com/davos/gologin-private
```

### Paso 2: Subir el Código
```bash
cd gologin
git init
git add .
git commit -m "Initial private release: gologin v1.0.0-private"

# Configurar remote privado
git remote add origin https://github.com/davos/gologin-private.git
git push -u origin main
```

### Paso 3: Configurar Módulo Go Privado
```go
// go.mod - Cambiar a ruta privada
module github.com/davos/gologin-private

go 1.21
```

### Paso 4: Actualizar Todos los Imports
```bash
# En todos los archivos .go
sed -i 's|github.com/davos/gologin|github.com/davos/gologin-private|g' *.go examples/*.go
```

## 🔑 Configuración de Acceso para Clientes

### Método 1: Invitar como Collaborators
1. Ir a Settings → Collaborators
2. Invitar usuarios específicos con acceso "Read" o "Write"
3. Clientes pueden clonar y usar directamente

### Método 2: Personal Access Tokens (Recomendado)
1. Cliente genera Personal Access Token en GitHub
2. Tú configuras el token en tu CI/CD
3. Cliente puede instalar vía Go modules

### Método 3: Deploy Keys (Para CI/CD)
1. Generar SSH key pair
2. Agregar public key como Deploy Key
3. Usar private key en CI/CD pipelines

## 📦 Instalación para Clientes

### Configuración Inicial
```bash
# Configurar Git para repositorios privados
git config --global url."https://YOUR_USERNAME@github.com".insteadOf "https://github.com"

# O usar token
git config --global url."https://oauth2:YOUR_TOKEN@github.com".insteadOf "https://github.com"
```

### Instalación del Módulo
```bash
# Con token de acceso personal
export GOPRIVATE=github.com/davos/gologin-private
go env -w GOPRIVATE=github.com/davos/gologin-private

# Instalar
go get github.com/davos/gologin-private@v1.0.0
```

### Uso en Código
```go
import "github.com/davos/gologin-private"

// Usar normalmente
authService := gologin.NewAuthService(repo, "secret")
```

## 🔐 Seguridad y Control de Acceso

### Niveles de Acceso
- **Owner**: Control total
- **Maintainers**: Push, releases, settings
- **Contributors**: Push limitado
- **Readers**: Solo lectura (para clientes)

### Auditoría de Acceso
- ✅ GitHub logs all access
- ✅ Ver commits y cambios
- ✅ Control de quién instala

### Protección de Branches
```yaml
# .github/workflows/protect-main.yml
name: Protect Main Branch
on:
  push:
    branches: [main]
jobs:
  protect:
    runs-on: ubuntu-latest
    steps:
      - name: Require PR reviews
        run: echo "Main branch protected"
```

## 📋 Proceso de Distribución a Clientes

### Paso 1: Validar Cliente
- ✅ Verificar legitimidad
- ✅ Firmar NDA si necesario
- ✅ Definir términos de uso

### Paso 2: Configurar Acceso
- ✅ Invitar como collaborator
- ✅ Proporcionar instrucciones de instalación
- ✅ Configurar soporte técnico

### Paso 3: Proporcionar Documentación
- ✅ README.md actualizado
- ✅ Guía de integración
- ✅ Ejemplos de uso
- ✅ Información de soporte

### Paso 4: Soporte y Actualizaciones
- ✅ Canal de comunicación establecido
- ✅ Proceso de reportar bugs
- ✅ Política de actualizaciones

## 🏷️ Versionado Privado

### Estrategia de Versiones
```
v1.0.0-private        # Versión base privada
v1.0.1-private        # Bug fixes
v1.1.0-private        # Nuevas features
v1.1.0-private-gym    # Versión custom para gimnasios
```

### Releases en GitHub
- Crear releases marcados como "Pre-release"
- Notas detalladas de cambios
- Assets adicionales si es necesario

## 💰 Modelo de Negocio

### Opciones de Distribución
1. **Licencia por Proyecto**: $X por implementación
2. **Licencia por Cliente**: $Y por cliente/mes
3. **Licencia Lifetime**: $Z por cliente (pago único)
4. **SaaS**: Hospedado por ti, cliente paga suscripción

### Control de Uso
- ✅ GitHub insights para ver uso
- ✅ Logs de instalación
- ✅ Métricas de adopción

## 📞 Soporte y Mantenimiento

### Canales de Soporte
- **Issues en GitHub**: Para bugs técnicos
- **Email/WhatsApp**: Para soporte personalizado
- **Videollamadas**: Para integración compleja

### SLA Recomendado
- **Bugs críticos**: 24 horas
- **Features requests**: 1 semana
- **Actualizaciones de seguridad**: Inmediatas

## 🔄 Actualizaciones y Mantenimiento

### Proceso de Updates
1. Cliente reporta issue/requiere feature
2. Tú desarrollas y pruebas
3. Crear nueva release
4. Cliente actualiza: `go get -u github.com/davos/gologin-private`

### Backward Compatibility
- ✅ Mantener API compatible
- ✅ Deprecar gradualmente
- ✅ Comunicar cambios grandes

## 📊 Métricas y Monitoreo

### Métricas a Trackear
- Número de clientes activos
- Frecuencia de actualizaciones
- Bugs reportados vs resueltos
- Tiempo de respuesta a soporte

### Herramientas
- **GitHub Insights**: Uso del repo
- **Google Analytics**: Para sitio web si tienes
- **CRM simple**: Para trackear clientes

---

## 🎯 Checklist de Distribución Privada

### Configuración Inicial
- [ ] Repositorio privado creado
- [ ] Código subido
- [ ] Módulo Go configurado
- [ ] Imports actualizados

### Gestión de Clientes
- [ ] Proceso de onboarding definido
- [ ] Niveles de acceso configurados
- [ ] Instrucciones de instalación listas
- [ ] Canal de soporte establecido

### Operaciones
- [ ] Proceso de releases definido
- [ ] Política de actualizaciones clara
- [ ] SLA de soporte establecido
- [ ] Métricas de seguimiento configuradas

**¡Tu librería está lista para distribución privada y controlada!** 🔒