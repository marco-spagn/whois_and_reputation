# GitHub Repository Description

## Short Description (for GitHub repo description field)
```
🔍 IP Lookup & Reputation Checker - A lightweight Go web service to lookup IP addresses and check their reputation using VirusTotal and AbuseIPDB APIs
```

## Full Description (for README or About section)

**IP Lookup & Reputation Checker** is a lightweight, single-binary web service built with Go that provides IP address information and reputation checking. It integrates with multiple APIs to deliver comprehensive IP intelligence including WHOIS data, geographic information, and security reputation scores.

### Features

- 🔍 **IP Information Lookup**: Retrieve ISP, ASN, domain name, country, city, and usage type
- 🛡️ **Reputation Checking**: Check IP reputation via VirusTotal and AbuseIPDB APIs
- 📋 **Copy-Paste Ready Output**: Formatted text output optimized for easy copying
- 🚀 **Single Binary**: No external dependencies, just the Go standard library
- 💾 **In-Memory Cache**: 30-minute TTL cache for improved performance
- 🌐 **RESTful API**: Simple HTTP endpoint for easy integration
- 🎨 **Modern Web UI**: Clean, dark-themed interface with one-click copy functionality

### Tech Stack

- **Backend**: Go (>=1.21) with standard library only
- **Frontend**: HTML, CSS, JavaScript (Vanilla)
- **APIs**: ip-api.com (geolocation, no API key), VirusTotal API v3, AbuseIPDB API v2

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/whois_reputation.git
cd whois_reputation

# Set up environment variables (optional)
export VT_API_KEY="your_virustotal_api_key"
export ABUSE_API_KEY="your_abuseipdb_api_key"

# Run the server
go run main.go

# Open http://localhost:8080 in your browser
```

### Deployment

Ready for deployment on:
- 🚀 Render
- 🚂 Railway
- ☁️ Vercel
- 🐳 Docker

### License

MIT License - feel free to use and modify as needed.

---

**Built with ❤️ in Go**

