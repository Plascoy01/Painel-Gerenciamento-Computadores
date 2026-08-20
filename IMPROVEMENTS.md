# PLASCOV Security Framework - Improvements & Fixes

## Issues Fixed

### 1. **Module Loading Deadlock** ❌→✅
   - **Problem**: The tool was freezing when loading optional modules
   - **Solution**: Implemented lazy loading (load modules only when needed, not at startup)
   - **Impact**: Tool now starts instantly and responds immediately

### 2. **Banner Display Bug** ❌→✅
   - **Problem**: Raw string formatting in banner was causing hang
   - **Solution**: Changed from raw string (r"""...""") to regular string with proper formatting
   - **Impact**: Banner displays correctly without delays

### 3. **URL Schema Handling** ❌→✅
   - **Problem**: Many modules failed with "No scheme supplied" error
   - **Solution**: Added automatic HTTPS schema addition to URLs without protocol
   - **Affected Modules**:
     - xss_scan.py
     - csrf_scan.py
     - lfi_rfi_scan.py
     - open_redirect_scan.py
     - web_vuln_scan.py
   - **Impact**: All modules now accept domain names directly without http:// prefix

### 4. **SSL Certificate Verification Warnings** ❌→✅
   - **Problem**: urllib3 InsecureRequestWarning spam in output
   - **Solution**: Added urllib3 warning suppression in plascoy.py
   - **Impact**: Clean, readable output without SSL warnings

### 5. **Error Handling** ❌→✅
   - **Problem**: Silent module failures without feedback
   - **Solution**: Added comprehensive error handling with user-friendly messages
   - **Impact**: Users now know exactly what failed and why

### 6. **Optional Module Mapping** ❌→✅
   - **Problem**: Optional modules weren't accessible due to poor mapping
   - **Solution**: Created reverse mapping dictionary (modules_by_func)
   - **Impact**: All optional modules now work reliably

## New Features Added

### 1. **testssl.sh Integration** 🎉
   - Full integration with testssl.sh for comprehensive SSL/TLS analysis
   - Automatic detection of testssl.sh in system
   - New flag: `--testssl`
   - Example: `python plascoy.py -u example.com --testssl`

### 2. **Improved Help System** 📚
   - Beautiful formatted help with clear sections
   - Complete list of all available scans
   - Usage examples
   - Installation notes

### 3. **New Module**
   - `testssl_integration.py`: Bridges plascoy with testssl.sh capabilities

### 4. **Easy Launcher Script** 🚀
   - `run_plascoy.sh`: Automatic venv activation
   - Usage: `./run_plascoy.sh -u target.com --sqli`

## Module Enhancements

### Core Modules (Working Perfectly)
- `tls_scan.py` - TLS version and cipher scanning
- `port_scan.py` - Port scanning with multi-threading
- `tech_detect.py` - Technology/framework detection
- `headers_scan.py` - Security header analysis
- `dns_scan.py` - DNS enumeration
- `dir_brute.py` - Directory brute force
- `web_vuln_scan.py` - Web vulnerability detection
- `vuln_scan.py` - General vulnerability scanning

### Optional Modules (Now Working)
- `sqli_scan.py` - SQL Injection detection ✅
- `xss_scan.py` - XSS vulnerability detection ✅
- `csrf_scan.py` - CSRF vulnerability detection ✅
- `lfi_rfi_scan.py` - LFI/RFI detection ✅
- `cmd_injection_scan.py` - Command injection detection ✅
- `open_redirect_scan.py` - Open redirect detection ✅
- `subdomain_enum.py` - Subdomain enumeration ✅
- `whois_lookup.py` - WHOIS information ✅
- `cve_checker.py` - CVE database lookup ✅
- `file_upload_scan.py` - File upload vulnerability ✅
- `cors_scan.py` - CORS misconfiguration ✅
- `host_header_scan.py` - Host header injection ✅
- `ssrf_scan.py` - SSRF vulnerability ✅
- `xxe_scan.py` - XXE injection ✅
- `deserialization_scan.py` - Deserialization attacks ✅
- `api_scan.py` - API vulnerability scanning ✅
- `cms_scanner.py` - CMS detection ✅
- `os_fingerprint.py` - OS detection ✅
- `service_detect.py` - Service detection ✅
- `firewall_detect.py` - WAF detection ✅
- `db_vuln_scan.py` - Database vulnerability scanning ✅

## Usage Examples

### Basic Scans
```bash
# SQL Injection scan
python plascoy.py -u target.com --sqli

# XSS and CSRF scans
python plascoy.py -u target.com --xss --csrf

# SSL/TLS analysis
python plascoy.py -u target.com --tls

# testssl.sh integration
python plascoy.py -u target.com --testssl
```

### Multiple Scans
```bash
# Combined vulnerability scanning
python plascoy.py -u target.com --sqli --xss --csrf --lfi --cmdinj

# Full scan
python plascoy.py -u target.com --all

# With verbose output
python plascoy.py -u target.com --sqli --verbose
```

### Using the Launcher
```bash
chmod +x run_plascoy.sh
./run_plascoy.sh -u target.com --sqli
```

## Performance Improvements

- **Lazy Loading**: Modules load only when needed
- **Async Error Handling**: No silent failures
- **Clean Output**: SSL warnings suppressed
- **Fast Response**: Instant startup and execution

## Dependencies

All dependencies are in `requirements.txt`:
- colorama - Colored terminal output
- requests - HTTP requests
- beautifulsoup4 - HTML parsing
- dnspython - DNS operations
- cryptography - SSL/TLS handling
- tqdm - Progress bars

## Future Enhancements

- [ ] Export results to JSON/HTML format
- [ ] Multi-target scanning
- [ ] Database storage of results
- [ ] API integration (Shodan, VirusTotal)
- [ ] Rate limiting and stealth options
- [ ] Custom wordlist support
- [ ] Real-time dashboard

## Installation

```bash
# Create and activate virtual environment
python3 -m venv plascoy_env
source plascoy_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# For testssl.sh integration (optional)
# Download from https://github.com/drwetter/testssl.sh
```

## Getting Help

```bash
python plascoy.py --help
# or
./run_plascoy.sh --help
```

---

**Last Updated**: April 29, 2026
**Status**: ✅ All major issues resolved
**Stability**: Production Ready
