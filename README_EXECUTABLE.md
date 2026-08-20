# PLASCOV Security Framework

## Executable Version

This is the standalone executable version of PLASCOV, a comprehensive security vulnerability scanner.

## How to Run

Simply execute the `plascoy` file:

```bash
./plascoy --help
```

## Features

PLASCOV includes the following scanning modules:

- **Core Scans:**
  - TLS/SSL Protocol Analysis
  - Port Scanning
  - Technology Detection
  - HTTP Headers Analysis
  - DNS Enumeration
  - Directory Brute Force
  - Web Vulnerability Scanning
  - General Vulnerability Scanning

- **Advanced Scans:**
  - SQL Injection Detection
  - XSS Scanning
  - CSRF Protection Testing
  - LFI/RFI Vulnerability Checks
  - Command Injection Testing
  - Open Redirect Detection
  - Subdomain Enumeration
  - WHOIS Lookup
  - CVE Checking
  - File Upload Vulnerability Scanning
  - CORS Misconfiguration Testing
  - Host Header Injection
  - SSRF Detection
  - XXE Vulnerability Scanning
  - Deserialization Attacks
  - API Security Testing
  - CMS Scanner
  - OS Fingerprinting
  - Service Detection
  - Firewall Detection
  - Database Vulnerability Scanning

## Usage Examples

```bash
# Show help
./plascoy --help

# Run all scans on a target
./plascoy -u example.com --all

# Run specific scans
./plascoy -u example.com --tls --ports --vuln

# Enable verbose output
./plascoy -u example.com --tls --verbose
```

## Requirements

- Linux environment
- The virtual environment (`plascoy_env`) must be present
- All Python dependencies are pre-installed in the virtual environment

## Notes

- This executable automatically activates the required Python virtual environment
- All scans are non-destructive and safe for testing on authorized targets only
- Use responsibly and only on systems you have permission to test