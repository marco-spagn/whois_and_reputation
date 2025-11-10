package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// IPLookupResult contiene tutte le informazioni raccolte su un IP
type IPLookupResult struct {
	IP          string `json:"ip"`
	ISP         string `json:"isp,omitempty"`
	UsageType   string `json:"usage_type,omitempty"`
	ASN         string `json:"asn,omitempty"`
	DomainName  string `json:"domain_name,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	City        string `json:"city,omitempty"`
	Region      string `json:"region,omitempty"`
	VirusTotal  struct {
		Malicious int    `json:"malicious"`
		Total     int    `json:"total"`
		Status    string `json:"status,omitempty"` // "ok", "error", "no_key"
	} `json:"virustotal"`
	AbuseIPDB struct {
		AbuseConfidence int    `json:"abuse_confidence"`
		Status          string `json:"status,omitempty"` // "ok", "error", "no_key"
	} `json:"abuseipdb"`
	Error string `json:"error,omitempty"`
}

// CacheEntry contiene un risultato con timestamp per invalidazione
type CacheEntry struct {
	Result    IPLookupResult
	Timestamp time.Time
}

var (
	// Cache in memoria con mutex per thread-safety
	cache      = make(map[string]CacheEntry)
	cacheMutex sync.RWMutex
	cacheTTL   = 30 * time.Minute // Time-to-live della cache
)

// validateIP verifica se una stringa è un indirizzo IP valido
func validateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// fetchIPAPI interroga ipapi.co per ottenere informazioni geografiche e ISP
func fetchIPAPI(ip string) (IPLookupResult, error) {
	result := IPLookupResult{IP: ip}

	url := fmt.Sprintf("https://ipapi.co/%s/json/", ip)
	resp, err := http.Get(url)
	if err != nil {
		return result, fmt.Errorf("errore nella richiesta a ipapi.co: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("ipapi.co ha restituito status %d", resp.StatusCode)
	}

	var data struct {
		ISP         string `json:"org"`
		ASN         string `json:"asn"`
		DomainName  string `json:"hostname"`
		Country     string `json:"country_name"`
		CountryCode string `json:"country_code"`
		City        string `json:"city"`
		Region      string `json:"region"`
		UsageType   string `json:"type"`
		Error       bool   `json:"error"`
		Reason      string `json:"reason"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return result, fmt.Errorf("errore nel parsing della risposta: %w", err)
	}

	if data.Error {
		return result, fmt.Errorf("ipapi.co error: %s", data.Reason)
	}

	result.ISP = data.ISP
	result.ASN = data.ASN
	result.DomainName = data.DomainName
	result.Country = data.Country
	result.CountryCode = data.CountryCode
	result.City = data.City
	result.Region = data.Region
	result.UsageType = data.UsageType

	return result, nil
}

// fetchVirusTotal interroga VirusTotal per la reputazione dell'IP
func fetchVirusTotal(ip, apiKey string, result *IPLookupResult) {
	if apiKey == "" {
		result.VirusTotal.Status = "no_key"
		return
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.VirusTotal.Status = "error"
		return
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		result.VirusTotal.Status = "error"
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.VirusTotal.Status = "error"
		return
	}

	var data struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Harmless   int `json:"harmless"`
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		result.VirusTotal.Status = "error"
		return
	}

	stats := data.Data.Attributes.LastAnalysisStats
	result.VirusTotal.Malicious = stats.Malicious
	// Calcola il totale sommando tutti i risultati
	result.VirusTotal.Total = stats.Harmless + stats.Malicious + stats.Suspicious + stats.Undetected
	result.VirusTotal.Status = "ok"
}

// fetchAbuseIPDB interroga AbuseIPDB per la reputazione dell'IP
func fetchAbuseIPDB(ip, apiKey string, result *IPLookupResult) {
	if apiKey == "" {
		result.AbuseIPDB.Status = "no_key"
		return
	}

	// Costruisci l'URL con i parametri (usa url.Values per encoding corretto)
	apiURL := "https://api.abuseipdb.com/api/v2/check"
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("AbuseIPDB: errore nella creazione della richiesta: %v", err)
		result.AbuseIPDB.Status = "error"
		return
	}

	// Aggiungi i parametri alla query string con encoding corretto
	q := req.URL.Query()
	q.Add("ipAddress", ip)
	q.Add("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()
	
	// Log dell'URL finale per debug
	log.Printf("AbuseIPDB: richiesta a %s", req.URL.String())

	// Imposta gli header corretti secondo la documentazione AbuseIPDB
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "IP-Lookup-Service/1.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("AbuseIPDB: errore nella richiesta HTTP: %v", err)
		result.AbuseIPDB.Status = "error"
		return
	}
	defer resp.Body.Close()

	// Leggi il body completo
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("AbuseIPDB: errore nella lettura del body: %v", err)
		result.AbuseIPDB.Status = "error"
		return
	}

	bodyStr := string(bodyBytes)

	// Log della risposta per debug (solo i primi 500 caratteri per non intasare i log)
	if len(bodyStr) > 500 {
		log.Printf("AbuseIPDB: status %d, risposta (primi 500 char): %s", resp.StatusCode, bodyStr[:500])
	} else {
		log.Printf("AbuseIPDB: status %d, risposta: %s", resp.StatusCode, bodyStr)
	}

	// Gestisci diversi codici di stato
	if resp.StatusCode != http.StatusOK {
		// Prova a parsare come errore JSON
		var errorResp struct {
			Errors []struct {
				Detail string `json:"detail"`
				Status int    `json:"status"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(bodyBytes, &errorResp); err == nil && len(errorResp.Errors) > 0 {
			log.Printf("AbuseIPDB: errore API: %v", errorResp.Errors)
		}
		result.AbuseIPDB.Status = "error"
		return
	}

	// Prova a parsare la risposta JSON
	// L'API restituisce "abuseConfidenceScore" non "abuseConfidencePercentage"
	var data struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
		Errors []struct {
			Detail string `json:"detail"`
			Status int    `json:"status"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		log.Printf("AbuseIPDB: errore nel parsing JSON: %v", err)
		log.Printf("AbuseIPDB: body completo: %s", bodyStr)
		result.AbuseIPDB.Status = "error"
		return
	}

	// Controlla se ci sono errori nella risposta (anche con status 200)
	if len(data.Errors) > 0 {
		log.Printf("AbuseIPDB: errori nella risposta: %v", data.Errors)
		result.AbuseIPDB.Status = "error"
		return
	}

	// Verifica che i dati siano presenti
	if data.Data.AbuseConfidenceScore < 0 || data.Data.AbuseConfidenceScore > 100 {
		log.Printf("AbuseIPDB: valore di confidence non valido: %d", data.Data.AbuseConfidenceScore)
		result.AbuseIPDB.Status = "error"
		return
	}

	result.AbuseIPDB.AbuseConfidence = data.Data.AbuseConfidenceScore
	result.AbuseIPDB.Status = "ok"
	log.Printf("AbuseIPDB: successo, confidence: %d%%", result.AbuseIPDB.AbuseConfidence)
}

// loadEnvFile carica le variabili d'ambiente da un file .env
// Usa solo la standard library, senza dipendenze esterne
func loadEnvFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		// Il file .env non esiste, non è un errore critico
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Ignora commenti e righe vuote
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Separa chiave e valore (formato: KEY=value)
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Rimuovi le virgolette se presenti
		value = strings.Trim(value, `"'`)

		// Imposta la variabile d'ambiente solo se non è già impostata
		// (le env vars del sistema hanno priorità)
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}

	return scanner.Err()
}

// getEnv legge una variabile d'ambiente con fallback
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// lookupIP esegue tutte le query API e restituisce il risultato completo
func lookupIP(ip string) IPLookupResult {
	// Controlla la cache prima
	cacheMutex.RLock()
	if entry, exists := cache[ip]; exists {
		if time.Since(entry.Timestamp) < cacheTTL {
			cacheMutex.RUnlock()
			return entry.Result
		}
	}
	cacheMutex.RUnlock()

	// Leggi le API keys dalle variabili d'ambiente (caricate da .env se presente)
	vtKey := os.Getenv("VT_API_KEY")
	abuseKey := os.Getenv("ABUSE_API_KEY")

	result := IPLookupResult{IP: ip}

	// Fetch dati da ipapi.co
	ipapiResult, err := fetchIPAPI(ip)
	if err != nil {
		result.Error = fmt.Sprintf("Errore nel recupero dati IP: %v", err)
		// Continua comunque con le altre API
	} else {
		result = ipapiResult
	}

	// Fetch dati da VirusTotal (in background, non blocca)
	fetchVirusTotal(ip, vtKey, &result)

	// Fetch dati da AbuseIPDB (in background, non blocca)
	fetchAbuseIPDB(ip, abuseKey, &result)

	// Salva in cache
	cacheMutex.Lock()
	cache[ip] = CacheEntry{
		Result:    result,
		Timestamp: time.Now(),
	}
	cacheMutex.Unlock()

	return result
}

// formatOutput formatta il risultato come testo semplice per copia-incolla
func formatOutput(result IPLookupResult) string {
	var output strings.Builder
	
	output.WriteString("\n\n")
	output.WriteString("WHOIS & REPUTATION:\n\n")
	output.WriteString("\n")
	output.WriteString(fmt.Sprintf("IP: %s\n\n", result.IP))
	output.WriteString("WHOIS\n\n")
	
	if result.ISP != "" {
		output.WriteString(fmt.Sprintf("ISP %s\n", result.ISP))
	}
	if result.UsageType != "" {
		output.WriteString(fmt.Sprintf("Usage Type %s\n", result.UsageType))
	}
	if result.ASN != "" {
		// Assicurati che ASN abbia il prefisso AS se non presente
		asn := result.ASN
		if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
			asn = "AS" + asn
		}
		output.WriteString(fmt.Sprintf("ASN %s\n", asn))
	}
	if result.DomainName != "" {
		output.WriteString(fmt.Sprintf("Domain Name %s\n", result.DomainName))
	}
	if result.Country != "" {
		// Ottieni la bandiera emoji
		flag := getCountryFlagEmoji(result.CountryCode)
		output.WriteString(fmt.Sprintf("Country %s %s\n", flag, result.Country))
	}
	if result.City != "" || result.Region != "" {
		cityStr := result.City
		if result.Region != "" {
			if cityStr != "" {
				cityStr += ", " + result.Region
			} else {
				cityStr = result.Region
			}
		}
		output.WriteString(fmt.Sprintf("City %s\n", cityStr))
	}
	
	output.WriteString("\n")
	output.WriteString("REPUTATION:\n\n")
	
	// VirusTotal (formato: Virutotal: 0/92)
	if result.VirusTotal.Status == "ok" {
		output.WriteString(fmt.Sprintf("Virutotal: %d/%d\n", result.VirusTotal.Malicious, result.VirusTotal.Total))
	} else if result.VirusTotal.Status == "no_key" {
		output.WriteString("Virutotal: API key non configurata\n")
	} else {
		output.WriteString("Virutotal: Errore nel recupero dati\n")
	}
	
	// AbuseIPDB (formato: Abuseipdb:1% - senza spazio dopo i due punti)
	if result.AbuseIPDB.Status == "ok" {
		output.WriteString(fmt.Sprintf("Abuseipdb:%d%%\n", result.AbuseIPDB.AbuseConfidence))
	} else if result.AbuseIPDB.Status == "no_key" {
		output.WriteString("Abuseipdb:0%%\n")
	} else {
		output.WriteString("Abuseipdb: Errore nel recupero dati\n")
	}
	
	output.WriteString("\n\n")
	
	return output.String()
}

// getCountryFlagEmoji restituisce l'emoji della bandiera basata sul country code
func getCountryFlagEmoji(countryCode string) string {
	flags := map[string]string{
		"US": "🇺🇸", "CN": "🇨🇳", "GB": "🇬🇧", "DE": "🇩🇪",
		"FR": "🇫🇷", "IT": "🇮🇹", "ES": "🇪🇸", "NL": "🇳🇱",
		"JP": "🇯🇵", "KR": "🇰🇷", "BR": "🇧🇷", "IN": "🇮🇳",
		"RU": "🇷🇺", "AU": "🇦🇺", "CA": "🇨🇦", "MX": "🇲🇽",
		"AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴", "PE": "🇵🇪",
		"VE": "🇻🇪", "CH": "🇨🇭", "AT": "🇦🇹", "BE": "🇧🇪",
		"SE": "🇸🇪", "NO": "🇳🇴", "DK": "🇩🇰", "FI": "🇫🇮",
		"PL": "🇵🇱", "CZ": "🇨🇿", "IE": "🇮🇪", "PT": "🇵🇹",
		"GR": "🇬🇷", "TR": "🇹🇷", "SA": "🇸🇦", "AE": "🇦🇪",
		"EG": "🇪🇬", "ZA": "🇿🇦", "NZ": "🇳🇿", "SG": "🇸🇬",
		"MY": "🇲🇾", "TH": "🇹🇭", "VN": "🇻🇳", "PH": "🇵🇭",
		"ID": "🇮🇩", "TW": "🇹🇼", "HK": "🇭🇰", "IL": "🇮🇱",
	}
	if flag, ok := flags[strings.ToUpper(countryCode)]; ok {
		return flag
	}
	return "🌐"
}

// handleIndex serve la pagina HTML principale
func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Errore nel caricamento del template", http.StatusInternalServerError)
		log.Printf("Errore template: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "Errore nell'esecuzione del template", http.StatusInternalServerError)
		log.Printf("Errore esecuzione template: %v", err)
	}
}

// handleLookup gestisce la richiesta GET /lookup?ip=...
func handleLookup(w http.ResponseWriter, r *http.Request) {
	// Abilita CORS per sviluppo
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "Parametro IP mancante", http.StatusBadRequest)
		return
	}

	// Valida l'IP
	if !validateIP(ip) {
		http.Error(w, "Indirizzo IP non valido", http.StatusBadRequest)
		return
	}

	// Esegui la lookup
	result := lookupIP(ip)

	// Formatta e restituisci il risultato come testo semplice
	output := formatOutput(result)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(output))
}

func main() {
	// Carica le variabili d'ambiente dal file .env se presente
	// Le variabili d'ambiente del sistema hanno sempre priorità
	if err := loadEnvFile(".env"); err != nil {
		log.Printf("Attenzione: errore nel caricamento del file .env: %v", err)
	}

	// Determina la porta (default 8080, usa PORT per deploy)
	port := getEnv("PORT", "8080")

	// Route handler
	http.HandleFunc("/", handleIndex)      // Pagina HTML con form
	http.HandleFunc("/lookup", handleLookup) // Endpoint API per la lookup

	log.Printf("Server avviato sulla porta %s", port)
	log.Printf("Apri http://localhost:%s nel browser", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Errore nel server: %v", err)
	}
}
