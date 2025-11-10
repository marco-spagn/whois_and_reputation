#!/bin/bash
# Build script per il progetto IP Lookup

echo "Building IP Lookup server..."
go build -o server main.go

if [ $? -eq 0 ]; then
    echo "Build completato con successo!"
    echo "Esegui ./server per avviare il server"
else
    echo "Errore durante il build"
    exit 1
fi

