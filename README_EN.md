# IP Lookup & Reputation Checker

A lightweight, single-binary web service built with Go that provides IP address information and reputation checking. It integrates with VirusTotal and AbuseIPDB APIs to deliver comprehensive IP intelligence.

## 🎯 Features

- **IP Information Lookup**: ISP, ASN, Domain Name, Country, City, Usage Type
- **Reputation Checking**: Check IP reputation via VirusTotal and AbuseIPDB APIs
- **Copy-Paste Ready Output**: Formatted text output optimized for easy copying
- **Single Binary**: No external dependencies, just the Go standard library
- **In-Memory Cache**: 30-minute TTL cache for improved performance
- **Modern Web UI**: Clean, dark-themed interface with one-click copy functionality
- **RESTful API**: Simple HTTP endpoint for easy integration

## 📋 Requirements

- Go >= 1.21
- API Keys (optional but recommended):
  - VirusTotal API Key: [Get it here](https://www.virustotal.com/gui/join-us)
  - AbuseIPDB API Key: [Get it here](https://www.abuseipdb.com/pricing)

## 🚀 Local Setup

### 1. Clone or download the project

```bash
cd whois_reputation
```

### 2. Install dependencies

```bash
go mod tidy
```

### 3. Configure environment variables

**Option A: Use a `.env` file (recommended for local development)**

Create a `.env` file in the project root:

```bash
VT_API_KEY=your_virustotal_api_key
ABUSE_API_KEY=your_abuseipdb_api_key
```

The server will automatically load variables from the `.env` file on startup.

**Option B: Export environment variables**

```bash
export VT_API_KEY="your_virustotal_api_key"
export ABUSE_API_KEY="your_abuseipdb_api_key"
```

**Note**: 
- API keys are optional. If not configured, the service will still work but without reputation data from VirusTotal and AbuseIPDB.
- System environment variables always take priority over the `.env` file.
- The `.env` file is already included in `.gitignore`, so it won't be committed to the repository.

### 4. Start the server

```bash
go run main.go
```

The server will be available at `http://localhost:8080`

## 🌐 Deployment

### Render.com

1. Create a new account on [Render](https://render.com)
2. Create a new "Web Service"
3. Connect your Git repository
4. Configuration:
   - **Build Command**: `go build -o server`
   - **Start Command**: `./server`
   - **Environment Variables**:
     - `VT_API_KEY`: your VirusTotal key
     - `ABUSE_API_KEY`: your AbuseIPDB key
     - `PORT`: Render will automatically set this variable
5. Deploy!

### Railway

1. Create an account on [Railway](https://railway.app)
2. Create a new project and connect the repository
3. Railway will automatically detect that it's a Go project
4. Add environment variables:
   - `VT_API_KEY`
   - `ABUSE_API_KEY`
5. Deploy!

### Vercel

**Note**: Vercel is optimized for serverless projects. For this project, Render or Railway are more suitable. If you want to use Vercel, you might need to adapt the code for a serverless environment.

1. Install Vercel CLI: `npm i -g vercel`
2. In the project, run: `vercel`
3. Follow the instructions and configure environment variables

## 📁 Project Structure

```
whois_reputation/
├── main.go              # Main Go server
├── templates/
│   └── index.html       # HTML frontend template
├── static/
│   └── style.css        # Custom CSS styles
├── go.mod               # Go module
├── go.sum               # Dependencies (auto-generated)
├── Procfile             # Configuration for Render/Railway
└── README.md            # This file
```

## 🔌 API Endpoint

### GET /lookup?ip=<ip_address>

Search for information on an IP address.

**Parameters**:
- `ip` (required): IP address to search for (e.g. `8.8.8.8`)

**Response** (Plain Text):
```
WHOIS & REPUTATION:



IP: 8.8.8.8

WHOIS

ISP Google LLC

Usage Type Hosting

ASN AS15169

Domain Name dns.google

Country 🇺🇸 United States

City Mountain View, California

REPUTATION:

Virutotal: 0/92

Abuseipdb:0%
```

**Status Codes**:
- `200`: Success
- `400`: Invalid IP or missing parameter
- `500`: Internal server error

## 🛠️ Development

### Run tests

```bash
go test ./...
```

### Build binary

```bash
go build -o server main.go
```

### Run binary

```bash
./server
```

## 📝 Notes

- In-memory cache keeps results for 30 minutes
- If an API call fails, the service still returns available data
- API keys are not required but strongly recommended for complete data
- The service is completely stateless (except for in-memory cache)

## 🔒 Security

- **DO NOT** commit API keys to the repository
- Use environment variables for sensitive keys
- The service validates IP addresses before processing them
- Consider adding rate limiting for production

## 📄 License

This project is released under the MIT License. Feel free to use and modify as needed.

## 🤝 Contributing

Contributions are welcome! Open an issue or a pull request if you want to improve the project.

## 📞 Support

For issues or questions, open an issue on the repository.

---

**Built with ❤️ in Go**

