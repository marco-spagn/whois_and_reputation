# 🐛 Debug AbuseIPDB

## Problema: "Abuseipdb: Errore nel recupero dati"

### Check List

1. **Verifica che la chiave API sia configurata**
   ```bash
   echo $ABUSE_API_KEY
   ```
   Oppure controlla il file `.env`:
   ```bash
   cat .env | grep ABUSE_API_KEY
   ```

2. **Verifica che la chiave API sia valida**
   - Vai su https://www.abuseipdb.com/account/api
   - Verifica che la chiave sia attiva
   - Controlla i limiti di rate (gratis: 1000 richieste/giorno)

3. **Testa la chiave API manualmente**
   ```bash
   curl "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90" \
     -H "Key: YOUR_API_KEY" \
     -H "Accept: application/json"
   ```

4. **Controlla i log del server**
   Quando esegui il server, i log mostreranno:
   - L'URL della richiesta
   - Lo status code della risposta
   - Il body della risposta
   - Eventuali errori di parsing

   Esempio:
   ```bash
   go run main.go
   # Poi fai una richiesta e controlla i log
   ```

### Errori Comuni

#### 1. Chiave API mancante o non valida
**Sintomo**: Status code 401 o 403
**Soluzione**: Verifica la chiave API nel file `.env` o nelle variabili d'ambiente

#### 2. Rate limit superato
**Sintomo**: Status code 429
**Soluzione**: Aspetta o aggiorna il piano AbuseIPDB

#### 3. IP non valido
**Sintomo**: Status code 422
**Soluzione**: Verifica che l'IP sia formattato correttamente

#### 4. Problemi di rete
**Sintomo**: Timeout o errori di connessione
**Soluzione**: Verifica la connettività a Internet

### Test Manuale

```bash
# Sostituisci YOUR_API_KEY con la tua chiave
export ABUSE_API_KEY="YOUR_API_KEY"

# Test con IPv4
curl "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90" \
  -H "Key: $ABUSE_API_KEY" \
  -H "Accept: application/json"

# Test con IPv6 (se necessario)
curl "https://api.abuseipdb.com/api/v2/check?ipAddress=2001:4860:4860::8888&maxAgeInDays=90" \
  -H "Key: $ABUSE_API_KEY" \
  -H "Accept: application/json"
```

### Risposta Attesa

Una risposta di successo dovrebbe essere:
```json
{
  "data": {
    "ipAddress": "8.8.8.8",
    "isPublic": true,
    "ipVersion": 4,
    "isWhitelisted": false,
    "abuseConfidencePercentage": 0,
    "countryCode": "US",
    "usageType": "CDN",
    "isp": "Google LLC",
    "domain": "dns.google",
    "hostnames": [],
    "isTor": false,
    "count": 0,
    "lastReportedAt": null
  }
}
```

### Verifica nel Codice

Il codice ora logga:
- L'URL della richiesta completa
- Lo status code
- Il body della risposta (primi 500 caratteri)
- Eventuali errori di parsing

Controlla i log quando fai una richiesta per vedere cosa restituisce l'API.

