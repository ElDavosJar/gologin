#!/bin/bash

# Script de configuración para gologin
# Este script prepara el repositorio para desarrollo y testing

set -e

echo "🚀 Configurando gologin..."

# Verificar que estamos en el directorio correcto
if [ ! -f "go.mod" ]; then
    echo "❌ Error: Ejecutar desde el directorio raíz de gologin"
    exit 1
fi

# Instalar dependencias
echo "📦 Instalando dependencias..."
go mod tidy
go mod download

# Verificar que las dependencias se instalaron correctamente
echo "✅ Verificando dependencias..."
go build ./...

# Ejecutar tests
echo "🧪 Ejecutando tests..."
go test -v ./...

# Crear directorio de ejemplos si no existe
if [ ! -d "examples" ]; then
    mkdir examples
    echo "📁 Directorio examples creado"
fi

echo "🎉 ¡Configuración completa!"
echo ""
echo "📚 Comandos disponibles:"
echo "  go test -v          # Ejecutar tests"
echo "  go run examples/full_app_example.go  # Ejecutar demo"
echo "  go doc              # Ver documentación"
echo ""
echo "📖 Ver README.md para más información"