# 🧪 Guida per Test Locale

## Passaggi Rapidi

### 1. Verifica che Go sia installato

```bash
go version
```

Dovresti vedere almeno Go 1.21 o superiore.

### 2. Installa le dipendenze

```bash
go mod tidy
```

### 3. (Opzionale) Configura le API Keys

Le chiavi API sono **opzionali**. Il servizio funzionerà comunque, ma senza dati di reputazione:

```bash
# Terminale 1 - Esporta le variabili d'ambiente
export VT_API_KEY="your_virustotal_api_key"
export ABUSE_API_KEY="your_abuseipdb_api_key"
```

**Nota**: Se non hai le chiavi API, salta questo step. Il servizio mostrerà comunque:
- Informazioni IP (ISP, ASN, Country, City, ecc.)
- Messaggio che le API keys non sono configurate per VirusTotal/AbuseIPDB

### 4. Avvia il server

```bash
go run main.go
```

Dovresti vedere:
```
Server avviato sulla porta 8080
Apri http://localhost:8080 nel browser
```

### 5. Testa nel browser

Apri il browser e vai su: **http://localhost:8080**

Prova con questi IP di esempio:
- `8.8.8.8` (Google DNS)
- `1.1.1.1` (Cloudflare DNS)
- `208.67.222.222` (OpenDNS)

### 6. Testa l'API direttamente

In un altro terminale, puoi testare l'endpoint API:

```bash
# Test con curl
curl "http://localhost:8080/lookup?ip=8.8.8.8"

# Oppure con IP diverso
curl "http://localhost:8080/lookup?ip=1.1.1.1"
```

### 7. Verifica la risposta JSON

Dovresti ricevere una risposta JSON come questa:

```json
{
  "ip": "8.8.8.8",
  "isp": "Google LLC",
  "usage_type": "Hosting",
  "asn": "AS15169",
  "domain_name": "dns.google",
  "country": "United States",
  "country_code": "US",
  "city": "Mountain View",
  "region": "California",
  "virustotal": {
    "malicious": 0,
    "total": 92,
    "status": "ok"
  },
  "abuseipdb": {
    "abuse_confidence": 0,
    "status": "ok"
  }
}
```

## 🐛 Risoluzione Problemi

### Errore: "cannot find package"
```bash
go mod tidy
go mod download
```

### Errore: "port already in use"
Cambia la porta:
```bash
PORT=3000 go run main.go
```

### Errore: "template: no such file"
Assicurati di essere nella directory del progetto:
```bash
pwd
# Dovrebbe mostrare: .../whois_reputation
```

### Le API keys non funzionano
- Verifica che le chiavi siano corrette
- Controlla che siano esportate: `echo $VT_API_KEY`
- Se una API fallisce, il servizio continuerà comunque con i dati disponibili

## 🚀 Build e Esecuzione del Binario

Invece di `go run`, puoi compilare un binario:

```bash
# Compila
go build -o server main.go

# Esegui il binario
./server
```

Oppure usa lo script:
```bash
chmod +x build.sh
./build.sh
./server
```

## 📝 Test Rapido con Script

Crea un file `test.sh`:

```bash
#!/bin/bash
echo "Testing IP Lookup API..."
curl -s "http://localhost:8080/lookup?ip=8.8.8.8" | jq .
```

Esegui:
```bash
chmod +x test.sh
./test.sh
```

(Nota: richiede `jq` per formattare JSON: `brew install jq`)

