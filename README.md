# IP Lookup & Reputation Checker

Un servizio web completo in Go per cercare informazioni su indirizzi IP e verificare la loro reputazione utilizzando VirusTotal e AbuseIPDB.

## 🎯 Funzionalità

- **Informazioni IP**: ISP, ASN, Domain Name, Country, City, Usage Type
- **Reputazione**: Controllo tramite VirusTotal e AbuseIPDB
- **Cache in memoria**: Risultati cachati per 30 minuti per migliorare le performance
- **Interfaccia moderna**: Bootstrap 5 con tema dark, completamente responsive
- **API RESTful**: Endpoint `/lookup?ip=...` per integrazioni

## 📋 Requisiti

- Go >= 1.21
- Chiavi API (opzionali ma consigliate):
  - VirusTotal API Key: [Ottieni qui](https://www.virustotal.com/gui/join-us)
  - AbuseIPDB API Key: [Ottieni qui](https://www.abuseipdb.com/pricing)

## 🚀 Setup Locale

### 1. Clona o scarica il progetto

```bash
cd whois_reputation
```

### 2. Installa le dipendenze

```bash
go mod tidy
```

### 3. Configura le variabili d'ambiente

**Opzione A: Usa un file `.env` (consigliato per sviluppo locale)**

Crea un file `.env` nella root del progetto:

```bash
VT_API_KEY=your_virustotal_api_key
ABUSE_API_KEY=your_abuseipdb_api_key
```

Il server caricherà automaticamente le variabili dal file `.env` all'avvio.

**Opzione B: Esporta le variabili d'ambiente**

```bash
export VT_API_KEY="your_virustotal_api_key"
export ABUSE_API_KEY="your_abuseipdb_api_key"
```

**Nota**: 
- Le chiavi API sono opzionali. Se non configurate, il servizio funzionerà comunque ma senza dati di reputazione da VirusTotal e AbuseIPDB.
- Le variabili d'ambiente del sistema hanno sempre priorità rispetto al file `.env`.
- Il file `.env` è già incluso nel `.gitignore`, quindi non verrà committato nel repository.

### 4. Avvia il server

```bash
go run main.go
```

Il server sarà disponibile su `http://localhost:8080`

## 🌐 Deployment

### Render.com

1. Crea un nuovo account su [Render](https://render.com)
2. Crea un nuovo "Web Service"
3. Connetti il tuo repository Git
4. Configurazione:
   - **Build Command**: `go build -o server`
   - **Start Command**: `./server`
   - **Environment Variables**:
     - `VT_API_KEY`: la tua chiave VirusTotal
     - `ABUSE_API_KEY`: la tua chiave AbuseIPDB
     - `PORT`: Render imposterà automaticamente questa variabile
5. Deploy!

### Railway

1. Crea un account su [Railway](https://railway.app)
2. Crea un nuovo progetto e connetti il repository
3. Railway rileverà automaticamente che è un progetto Go
4. Aggiungi le variabili d'ambiente:
   - `VT_API_KEY`
   - `ABUSE_API_KEY`
5. Deploy!

### Vercel

**Nota**: Vercel è ottimizzato per progetti serverless. Per questo progetto, Render o Railway sono più adatti. Se vuoi usare Vercel, potresti dover adattare il codice per un ambiente serverless.

1. Installa Vercel CLI: `npm i -g vercel`
2. Nel progetto, esegui: `vercel`
3. Segui le istruzioni e configura le variabili d'ambiente

## 📁 Struttura del Progetto

```
whois_reputation/
├── main.go              # Server Go principale
├── templates/
│   └── index.html       # Template HTML frontend
├── static/
│   └── style.css        # Stili CSS personalizzati
├── go.mod               # Modulo Go
├── go.sum               # Dipendenze (generato automaticamente)
├── Procfile             # Configurazione per Render/Railway
└── README.md            # Questo file
```

## 🔌 API Endpoint

### GET /lookup?ip=<ip_address>

Cerca informazioni su un indirizzo IP.

**Parametri**:
- `ip` (required): Indirizzo IP da cercare (es. `8.8.8.8`)

**Risposta** (JSON):
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

**Codici di stato**:
- `200`: Successo
- `400`: IP non valido o parametro mancante
- `500`: Errore interno del server

## 🛠️ Sviluppo

### Eseguire i test

```bash
go test ./...
```

### Build del binario

```bash
go build -o server main.go
```

### Eseguire il binario

```bash
./server
```

## 📝 Note

- La cache in memoria mantiene i risultati per 30 minuti
- Se una chiamata API fallisce, il servizio restituisce comunque i dati disponibili
- Le chiavi API non sono obbligatorie ma fortemente consigliate per dati completi
- Il servizio è completamente stateless (eccetto la cache in memoria)

## 🔒 Sicurezza

- **NON** committare le chiavi API nel repository
- Usa variabili d'ambiente per le chiavi sensibili
- Il servizio valida gli indirizzi IP prima di processarli
- Considera di aggiungere rate limiting per produzione

## 📄 Licenza

Questo progetto è rilasciato sotto licenza MIT. Sentiti libero di usarlo e modificarlo come preferisci.

## 🤝 Contributi

I contributi sono benvenuti! Apri una issue o una pull request se vuoi migliorare il progetto.

## 📞 Supporto

Per problemi o domande, apri una issue sul repository.

---

**Sviluppato con ❤️ in Go**

