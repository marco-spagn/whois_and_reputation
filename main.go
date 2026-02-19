package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
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
	ThreatIntel struct {
		IsProxy    bool   `json:"is_proxy"`
		IsVPN      bool   `json:"is_vpn"`
		IsTor      bool   `json:"is_tor"`
		IsAbuser   bool   `json:"is_abuser"`
		IsAnonymous bool  `json:"is_anonymous"`
		NetworkType string `json:"network_type,omitempty"`
		Status     string `json:"status,omitempty"` // "ok", "error", "no_key"
	} `json:"threat_intel"`
	Error string `json:"error,omitempty"`
}

// LookupResponse con standard e extended per l'API JSON
type LookupResponse struct {
	Standard string `json:"standard"`
	Extended string `json:"extended"`
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
	
	// Sessioni autenticate (in produzione usa una soluzione più robusta)
	authenticatedSessions = make(map[string]time.Time)
	sessionMutex          sync.RWMutex
	sessionTTL            = 24 * time.Hour // Sessione valida per 24 ore
	sitePassword          = ""             // Password del sito (da variabile d'ambiente)
)

const (
	sessionCookieName = "ip_lookup_session"
	sessionTokenLength = 32
)

// validateIP verifica se una stringa è un indirizzo IP valido
func validateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// generateSessionToken genera un token di sessione casuale
func generateSessionToken() (string, error) {
	bytes := make([]byte, sessionTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// isValidSession verifica se un token di sessione è valido
func isValidSession(token string) bool {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()
	
	expires, exists := authenticatedSessions[token]
	if !exists {
		return false
	}
	
	// Rimuovi sessioni scadute
	if time.Now().After(expires) {
		sessionMutex.RUnlock()
		sessionMutex.Lock()
		delete(authenticatedSessions, token)
		sessionMutex.Unlock()
		sessionMutex.RLock()
		return false
	}
	
	return true
}

// createSession crea una nuova sessione e restituisce il token
func createSession() (string, error) {
	token, err := generateSessionToken()
	if err != nil {
		return "", err
	}
	
	sessionMutex.Lock()
	authenticatedSessions[token] = time.Now().Add(sessionTTL)
	sessionMutex.Unlock()
	
	return token, nil
}

// clearSession rimuove una sessione
func clearSession(token string) {
	sessionMutex.Lock()
	delete(authenticatedSessions, token)
	sessionMutex.Unlock()
}

// isAuthenticated verifica se la richiesta è autenticata
func isAuthenticated(r *http.Request) bool {
	// Se la password non è configurata, non richiedere autenticazione
	if sitePassword == "" {
		return true
	}
	
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	
	return isValidSession(cookie.Value)
}

// requireAuth è un middleware che richiede l'autenticazione
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Se la password non è configurata, procedi senza autenticazione
		if sitePassword == "" {
			next(w, r)
			return
		}
		
		if !isAuthenticated(r) {
			// Reindirizza al login per richieste GET alla root
			if r.URL.Path == "/" && r.Method == "GET" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			// Per altre richieste, restituisci 401
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		next(w, r)
	}
}

// handleLogin gestisce il login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Se la password non è configurata, reindirizza alla home
	if sitePassword == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	
	if r.Method == "GET" {
		// Mostra il form di login
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, "Error loading login template", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.Execute(w, nil)
		return
	}
	
	if r.Method == "POST" {
		// Processa il login
		password := r.FormValue("password")
		
		// Usa constant-time comparison per sicurezza
		if subtle.ConstantTimeCompare([]byte(password), []byte(sitePassword)) == 1 {
			// Password corretta, crea sessione
			token, err := createSession()
			if err != nil {
				http.Error(w, "Error creating session", http.StatusInternalServerError)
				return
			}
			
			// Imposta il cookie
			cookie := http.Cookie{
				Name:     sessionCookieName,
				Value:    token,
				Path:     "/",
				MaxAge:   int(sessionTTL.Seconds()),
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Secure:   false, // Imposta a true se usi HTTPS
			}
			http.SetCookie(w, &cookie)
			
			// Reindirizza alla home
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		
		// Password errata
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, "Error loading login template", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.Execute(w, map[string]string{"Error": "Invalid password"})
		return
	}
	
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleLogout gestisce il logout
func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		clearSession(cookie.Value)
	}
	
	// Rimuovi il cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// fetchIPAPI interroga ip-api.com per ottenere informazioni geografiche e ISP
// API gratuita, senza chiave: https://ip-api.com/
func fetchIPAPI(ip string) (IPLookupResult, error) {
	result := IPLookupResult{IP: ip}

	// fields: solo i campi necessari per ridurre il payload
	fields := "status,message,country,countryCode,region,regionName,city,isp,org,as,mobile,proxy,hosting,query"
	apiURL := fmt.Sprintf("http://ip-api.com/json/%s?fields=%s", ip, fields)
	resp, err := http.Get(apiURL)
	if err != nil {
		return result, fmt.Errorf("errore nella richiesta a ip-api.com: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("ip-api.com ha restituito status %d", resp.StatusCode)
	}

	var data struct {
		Status     string `json:"status"`
		Message    string `json:"message"`
		Country    string `json:"country"`
		CountryCode string `json:"countryCode"`
		Region     string `json:"region"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
		ISP        string `json:"isp"`
		Org        string `json:"org"`
		AS         string `json:"as"`
		Mobile     bool   `json:"mobile"`
		Proxy      bool   `json:"proxy"`
		Hosting    bool   `json:"hosting"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return result, fmt.Errorf("errore nel parsing della risposta: %w", err)
	}

	if data.Status != "success" {
		return result, fmt.Errorf("ip-api.com error: %s", data.Message)
	}

	result.ISP = data.ISP
	if result.ISP == "" {
		result.ISP = data.Org
	}
	// AS è nel formato "AS15169 Google LLC" - estrai solo "AS15169"
	if idx := strings.Index(data.AS, " "); idx > 0 {
		result.ASN = data.AS[:idx]
	} else {
		result.ASN = data.AS
	}
	result.Country = data.Country
	result.CountryCode = data.CountryCode
	result.City = data.City
	result.Region = data.RegionName
	if result.Region == "" {
		result.Region = data.Region
	}

	// Usage Type derivato da mobile, proxy, hosting
	switch {
	case data.Hosting:
		result.UsageType = "Data Center/Web Hosting"
	case data.Proxy:
		result.UsageType = "Proxy/VPN"
	case data.Mobile:
		result.UsageType = "Mobile"
	default:
		result.UsageType = "Fixed Line ISP"
	}

	// ip-api.com non fornisce hostname nel piano free, lasciamo vuoto
	result.DomainName = ""

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

// fetchIPLocate interroga IPLocate.io per threat intelligence (Proxy/VPN/TOR, abuse flags)
// API: https://www.iplocate.io/ - Free 1000 req/day
func fetchIPLocate(ip, apiKey string, result *IPLookupResult) {
	if apiKey == "" {
		result.ThreatIntel.Status = "no_key"
		return
	}

	apiURL := fmt.Sprintf("https://iplocate.io/api/lookup/%s?apikey=%s", ip, apiKey)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		result.ThreatIntel.Status = "error"
		return
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("IPLocate: errore HTTP: %v", err)
		result.ThreatIntel.Status = "error"
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("IPLocate: status %d", resp.StatusCode)
		result.ThreatIntel.Status = "error"
		return
	}

	var data struct {
		Privacy struct {
			IsProxy     bool `json:"is_proxy"`
			IsVPN       bool `json:"is_vpn"`
			IsTor       bool `json:"is_tor"`
			IsAbuser    bool `json:"is_abuser"`
			IsAnonymous bool `json:"is_anonymous"`
			IsHosting   bool `json:"is_hosting"`
		} `json:"privacy"`
		ASN struct {
			Type string `json:"type"`
		} `json:"asn"`
		Company struct {
			Type string `json:"type"`
		} `json:"company"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Printf("IPLocate: errore parsing: %v", err)
		result.ThreatIntel.Status = "error"
		return
	}

	result.ThreatIntel.IsProxy = data.Privacy.IsProxy
	result.ThreatIntel.IsVPN = data.Privacy.IsVPN
	result.ThreatIntel.IsTor = data.Privacy.IsTor
	result.ThreatIntel.IsAbuser = data.Privacy.IsAbuser
	result.ThreatIntel.IsAnonymous = data.Privacy.IsAnonymous

	if data.ASN.Type != "" {
		result.ThreatIntel.NetworkType = data.ASN.Type
	} else if data.Company.Type != "" {
		result.ThreatIntel.NetworkType = data.Company.Type
	}

	result.ThreatIntel.Status = "ok"
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
	iplocateKey := os.Getenv("IPLOCATE_API_KEY")

	result := IPLookupResult{IP: ip}

	// Fetch dati da ip-api.com
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

	// Fetch threat intelligence da IPLocate.io (Proxy/VPN/TOR, abuse flags)
	fetchIPLocate(ip, iplocateKey, &result)

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

// formatOutputExtended come formatOutput ma con sezione THREAT INTELLIGENCE aggiuntiva
func formatOutputExtended(result IPLookupResult) string {
	base := formatOutput(result)

	// Rimuovi gli ultimi \n\n dal base e aggiungi la sezione threat
	base = strings.TrimSuffix(base, "\n\n")

	var ext strings.Builder
	ext.WriteString(base)
	ext.WriteString("\n\n")
	ext.WriteString("THREAT INTELLIGENCE:\n\n")

	if result.ThreatIntel.Status == "ok" {
		// Proxy/VPN/TOR detection
		var anonymity []string
		if result.ThreatIntel.IsProxy {
			anonymity = append(anonymity, "Proxy")
		}
		if result.ThreatIntel.IsVPN {
			anonymity = append(anonymity, "VPN")
		}
		if result.ThreatIntel.IsTor {
			anonymity = append(anonymity, "Tor")
		}
		if result.ThreatIntel.IsAnonymous && len(anonymity) == 0 {
			anonymity = append(anonymity, "Anonymous")
		}
		if len(anonymity) > 0 {
			ext.WriteString(fmt.Sprintf("Anonymity: %s\n", strings.Join(anonymity, ", ")))
		} else {
			ext.WriteString("Anonymity: None detected\n")
		}

		// Abuse flags
		if result.ThreatIntel.IsAbuser {
			ext.WriteString("Abuse Flag: Reported abuser/spammer\n")
		} else {
			ext.WriteString("Abuse Flag: None\n")
		}

		// Network type
		if result.ThreatIntel.NetworkType != "" {
			ext.WriteString(fmt.Sprintf("Network Type: %s\n", result.ThreatIntel.NetworkType))
		}
	} else if result.ThreatIntel.Status == "no_key" {
		ext.WriteString("IPLocate API key not configured\n")
	} else {
		ext.WriteString("Error retrieving threat data\n")
	}

	ext.WriteString("\n\n")
	return ext.String()
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
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Errore template: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		log.Printf("Errore esecuzione template: %v", err)
	}
}

// handleLookup gestisce la richiesta GET /lookup?ip=...
func handleLookup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "Parametro IP mancante", http.StatusBadRequest)
		return
	}

	if !validateIP(ip) {
		http.Error(w, "Indirizzo IP non valido", http.StatusBadRequest)
		return
	}

	result := lookupIP(ip)
	format := r.URL.Query().Get("format")

	if format == "json" {
		// Restituisce JSON con entrambi i formati per la UI
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		resp := LookupResponse{
			Standard: formatOutput(result),
			Extended: formatOutputExtended(result),
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	} else {
		// Formato testo standard (backward compatibility)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		output := formatOutput(result)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(output))
	}
}

func main() {
	// Carica le variabili d'ambiente dal file .env se presente
	// Le variabili d'ambiente del sistema hanno sempre priorità
	if err := loadEnvFile(".env"); err != nil {
		log.Printf("Attenzione: errore nel caricamento del file .env: %v", err)
	}

	// Carica la password del sito
	sitePassword = getEnv("SITE_PASSWORD", "")
	if sitePassword != "" {
		log.Printf("Password protection enabled")
	} else {
		log.Printf("Password protection disabled (SITE_PASSWORD not set)")
	}

	// Determina la porta (default 8080, usa PORT per deploy)
	port := getEnv("PORT", "8080")

	// Route handler
	// Login e logout non protetti
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	
	// Route protette
	http.HandleFunc("/", requireAuth(handleIndex))      // Pagina HTML con form
	http.HandleFunc("/lookup", requireAuth(handleLookup)) // Endpoint API per la lookup

	// Avvia goroutine per pulire sessioni scadute
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			sessionMutex.Lock()
			now := time.Now()
			for token, expires := range authenticatedSessions {
				if now.After(expires) {
					delete(authenticatedSessions, token)
				}
			}
			sessionMutex.Unlock()
		}
	}()

	log.Printf("Server avviato sulla porta %s", port)
	if sitePassword != "" {
		log.Printf("Password protection: ENABLED")
		log.Printf("Apri http://localhost:%s/login per accedere", port)
	} else {
		log.Printf("Apri http://localhost:%s nel browser", port)
	}

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Errore nel server: %v", err)
	}
}
