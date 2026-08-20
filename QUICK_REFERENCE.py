#!/usr/bin/env python3
"""
PLASCOV v2.0 - Quick Reference Guide
"""

print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                    PLASCOV v2.0 - QUICK REFERENCE                         ║
╚════════════════════════════════════════════════════════════════════════════╝

INSTALLATION & SETUP
────────────────────────────────────────────────────────────────────────────
cd plascoy\ source
python3 -m venv plascoy_env
source plascoy_env/bin/activate
pip install -r requirements.txt

BASIC USAGE
────────────────────────────────────────────────────────────────────────────
# Show help
python3 plascoy.py --help
python3 plascoy.py -h

# Single scan
python3 plascoy.py -u target.com --tls
python3 plascoy.py -u example.com --sqli

# Multiple scans
python3 plascoy.py -u target.com --sqli --xss --csrf
python3 plascoy.py -u target.com --tls --tech --headers

CORE SCANNING FLAGS (ORIGINAL)
────────────────────────────────────────────────────────────────────────────
python3 plascoy.py -u target.com --tls
python3 plascoy.py -u target.com --ports
python3 plascoy.py -u target.com --tech
python3 plascoy.py -u target.com --headers
python3 plascoy.py -u target.com --dns
python3 plascoy.py -u target.com --dirbrute
python3 plascoy.py -u target.com --webvuln
python3 plascoy.py -u target.com --vuln
python3 plascoy.py -u target.com --testssl

VULNERABILITY SCANNING (ORIGINAL)
────────────────────────────────────────────────────────────────────────────
python3 plascoy.py -u target.com --sqli
python3 plascoy.py -u target.com --xss
python3 plascoy.py -u target.com --csrf
python3 plascoy.py -u target.com --lfi
python3 plascoy.py -u target.com --cmdinj
python3 plascoy.py -u target.com --redirect
python3 plascoy.py -u target.com --subdomain
python3 plascoy.py -u target.com --whois
python3 plascoy.py -u target.com --cve
python3 plascoy.py -u target.com --upload
python3 plascoy.py -u target.com --cors
python3 plascoy.py -u target.com --hostheader
python3 plascoy.py -u target.com --ssrf
python3 plascoy.py -u target.com --xxe
python3 plascoy.py -u target.com --deserial
python3 plascoy.py -u target.com --api
python3 plascoy.py -u target.com --cms
python3 plascoy.py -u target.com --os
python3 plascoy.py -u target.com --services
python3 plascoy.py -u target.com --firewall
python3 plascoy.py -u target.com --db

⭐ NEW ADVANCED SCANNING FLAGS
────────────────────────────────────────────────────────────────────────────
python3 plascoy.py -u target.com --ssti
python3 plascoy.py -u target.com --idor
python3 plascoy.py -u target.com --jwt
python3 plascoy.py -u target.com --http-methods
python3 plascoy.py -u target.com --dirlisting
python3 plascoy.py -u target.com --backup
python3 plascoy.py -u target.com --git
python3 plascoy.py -u target.com --env
python3 plascoy.py -u target.com --robots
python3 plascoy.py -u target.com --sitemap
python3 plascoy.py -u target.com --clickjacking
python3 plascoy.py -u target.com --cors-adv
python3 plascoy.py -u target.com --params
python3 plascoy.py -u target.com --js
python3 plascoy.py -u target.com --cookies

⭐ EXTERNAL TOOLS
────────────────────────────────────────────────────────────────────────────
python3 plascoy.py -u target.com --gobuster
python3 plascoy.py -u target.com --ffuf
python3 plascoy.py -u target.com --nmap
python3 plascoy.py -u target.com --whatweb
python3 plascoy.py -u target.com --gobuster --ffuf --nmap --whatweb

⭐ ADVANCED FEATURES
────────────────────────────────────────────────────────────────────────────
# Web Crawler
python3 plascoy.py -u target.com --crawl
python3 plascoy.py -u target.com --crawl --depth 3
python3 plascoy.py -u target.com --crawl --max-pages 200

# Fuzzing
python3 plascoy.py -u target.com --fuzz xss
python3 plascoy.py -u target.com --fuzz sqli
python3 plascoy.py -u target.com --fuzz lfi
python3 plascoy.py -u target.com --fuzz xxe
python3 plascoy.py -u target.com --fuzz all
python3 plascoy.py -u target.com --fuzz random

# Report Generation
python3 plascoy.py -u target.com --output json
python3 plascoy.py -u target.com --output html
python3 plascoy.py -u target.com --output csv
python3 plascoy.py -u target.com --output txt
python3 plascoy.py -u target.com --output all

# Threading
python3 plascoy.py -u target.com --threads 20

COMPREHENSIVE SCAN EXAMPLES
────────────────────────────────────────────────────────────────────────────
# Full scan (all original modules)
python3 plascoy.py -u target.com --all

# All new modules
python3 plascoy.py -u target.com \\
  --ssti --idor --jwt --http-methods --dirlisting \\
  --backup --git --env --robots --sitemap \\
  --clickjacking --cors-adv --params --js --cookies

# Complete professional assessment
python3 plascoy.py -u target.com \\
  --all \\
  --ssti --idor --jwt --git --env --backup \\
  --js --params --cookies \\
  --crawl --depth 3 \\
  --fuzz xss \\
  --output html \\
  --verbose

# Quick vulnerability scan
python3 plascoy.py -u target.com \\
  --sqli --xss --csrf --lfi --cmdinj \\
  --ssti --idor --jwt

# Infrastructure assessment
python3 plascoy.py -u target.com \\
  --tls --ports --tech --headers --dns \\
  --git --env --backup --robots --sitemap \\
  --nmap --gobuster

COMBINED COMMAND EXAMPLES
────────────────────────────────────────────────────────────────────────────
# Test new features
python3 plascoy.py -u target.com --ssti --idor --jwt

# Crawl + Fuzz
python3 plascoy.py -u target.com --crawl --fuzz xss

# Full assessment with reporting
python3 plascoy.py -u target.com --all --output html

# Advanced security assessment
python3 plascoy.py -u target.com \\
  --tls --tech --js --params \\
  --git --env --backup \\
  --ssti --idor --jwt \\
  --crawl --output html

# External tools integration
python3 plascoy.py -u target.com \\
  --gobuster --ffuf --nmap --whatweb

VERBOSITY & OPTIONS
────────────────────────────────────────────────────────────────────────────
python3 plascoy.py -u target.com --sqli --verbose
python3 plascoy.py -u target.com --all --threads 15
python3 plascoy.py -u target.com --crawl --depth 5 --max-pages 500

OPTIONAL: EXTERNAL TOOLS INSTALLATION
────────────────────────────────────────────────────────────────────────────
sudo apt-get install gobuster ffuf nmap whatweb

QUICK COPY-PASTE COMMANDS
────────────────────────────────────────────────────────────────────────────
# Start scanning
source plascoy_env/bin/activate

# Test single module
python3 plascoy.py -u httpbin.org --jwt

# Get help
python3 plascoy.py --help

# Run all tests
python3 plascoy.py -u target.com --all

# Generate HTML report
python3 plascoy.py -u target.com --all --output html

# Complete assessment
python3 plascoy.py -u target.com --all --crawl --fuzz xss --output all

COMMON WORKFLOWS
────────────────────────────────────────────────────────────────────────────
QUICK SCAN (5 minutes)
python3 plascoy.py -u target.com --tls --tech --git --env --backup

COMPREHENSIVE (30 minutes)
python3 plascoy.py -u target.com --all --crawl --output html

PROFESSIONAL PENTEST (60+ minutes)
python3 plascoy.py -u target.com \\
  --all \\
  --ssti --idor --jwt --git --env --backup \\
  --js --params --cookies \\
  --crawl --depth 3 \\
  --fuzz xss \\
  --gobuster --nmap \\
  --output html \\
  --verbose

TROUBLESHOOTING
────────────────────────────────────────────────────────────────────────────
# Activate venv if not active
source plascoy_env/bin/activate

# Check Python version
python3 --version

# Reinstall dependencies
pip install -r requirements.txt

# Check venv location
which python3

# Clear report files
rm report_*.json

OUTPUT FILES
────────────────────────────────────────────────────────────────────────────
report_*.json       JSON format reports
report_*.html       HTML format reports
report_*.csv        CSV format reports
report_*.txt        Text format reports

STATISTICS
────────────────────────────────────────────────────────────────────────────
Total Modules:        42+
Core Modules:         8
Optional Modules:     20
New Modules:          14
System Modules:       4
External Tools:       4
Report Formats:       5
Fuzzing Payloads:     50+
Startup Time:         ~2 seconds (lazy loading)

VERSION INFO
────────────────────────────────────────────────────────────────────────────
Framework:   PLASCOV
Version:     2.0
Status:      Production Ready
Last Update: 2024
Creator:     plascoy

╔════════════════════════════════════════════════════════════════════════════╗
║               For detailed help: python3 plascoy.py --help                 ║
║             For complete guide: See EVOLUTION_README.md                    ║
╚════════════════════════════════════════════════════════════════════════════╝
""")
