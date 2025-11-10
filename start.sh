#!/bin/bash

# Script di avvio per il server IP Lookup

echo "🚀 Avvio IP Lookup Server..."
echo ""

# Verifica che Go sia installato
if ! command -v go &> /dev/null; then
    echo "❌ Errore: Go non è installato"
    echo "Installa Go da: https://golang.org/dl/"
    exit 1
fi

# Mostra la versione di Go
echo "✅ Go version: $(go version)"
echo ""

# Verifica le dipendenze
echo "📦 Verifica dipendenze..."
go mod tidy
echo ""

# Verifica le variabili d'ambiente e il file .env
echo "🔑 Verifica API Keys:"
if [ -f ".env" ]; then
    echo "   ✅ File .env trovato (verrà caricato automaticamente)"
else
    echo "   ℹ️  File .env non trovato (opzionale)"
fi

# Controlla se le variabili sono già impostate nel sistema
if [ -z "$VT_API_KEY" ]; then
    echo "   ⚠️  VT_API_KEY non impostata (opzionale)"
else
    echo "   ✅ VT_API_KEY impostata nel sistema"
fi

if [ -z "$ABUSE_API_KEY" ]; then
    echo "   ⚠️  ABUSE_API_KEY non impostata (opzionale)"
else
    echo "   ✅ ABUSE_API_KEY impostata nel sistema"
fi
echo ""

# Verifica che le directory esistano
if [ ! -d "templates" ]; then
    echo "❌ Errore: directory 'templates' non trovata"
    exit 1
fi

if [ ! -d "static" ]; then
    echo "❌ Errore: directory 'static' non trovata"
    exit 1
fi

echo "✅ Directory verificate"
echo ""

# Determina la porta
PORT=${PORT:-8080}
echo "🌐 Avvio server sulla porta $PORT"
echo "📱 Apri http://localhost:$PORT nel browser"
echo ""
echo "Premi Ctrl+C per fermare il server"
echo ""

# Avvia il server
go run main.go

