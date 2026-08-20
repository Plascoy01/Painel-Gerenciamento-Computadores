import requests
import socket
import ssl
import datetime
import json
import re
import subprocess
import os
import base64
import hashlib
import time
from colorama import init, Fore, Style
from urllib.parse import urlparse
from bs4 import BeautifulSoup

init(autoreset=True)

class TechDetector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.common_ports = {
            21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
            8080: "HTTP-ALT", 8443: "HTTPS-ALT"
        }

    def add_scheme_if_missing(self, url):
        if not url.startswith(("http://", "https://")):
            return "http://" + url
        return url

    def get_certificate_info(self, domain):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                return {
                    'subject': cert.get('subject', 'Unknown'),
                    'issuer': cert.get('issuer', 'Unknown'),
                    'valid_from': cert.get('notBefore', 'Unknown'),
                    'valid_until': cert.get('notAfter', 'Unknown'),
                    'fingerprint': ':'.join(['{:02x}'.format(b) for b in ssl.cert_digest(cert, 'sha1')])
                }
        except Exception as e:
            return {'error': str(e)}

    def analyze_cms(self, html):
        cms_patterns = {
            "WordPress": ["wp-content", "wordpress"],
            "Joomla": ["joomla"],
            "Drupal": ["drupal"],
            "Shopify": ["shopify"],
            "Magento": ["magento", "mage/"],
            "Ghost": ["ghost"],
            "Wix": ["wix"],
            "Squarespace": ["squarespace"],
            "PrestaShop": ["prestashop"],
            "OpenCart": ["opencart"],
            "Typo3": ["typo3"]
        }
        detected = []
        for cms, patterns in cms_patterns.items():
            if any(p in html for p in patterns):
                detected.append(cms)
        return detected or ["No CMS detected"]

    def analyze_frameworks(self, html):
        frameworks = {
            "React": "react",
            "Vue.js": "vue",
            "Angular": "angular",
            "jQuery": "jquery",
            "Next.js": "nextjs",
            "Nuxt.js": "nuxt",
            "Express.js": "express.js",
            "Django": "django",
            "Flask": "flask",
            "Rails": "rails",
            "Symfony": "symfony",
            "Laravel": "laravel",
            "Ember.js": "ember",
            "Backbone.js": "backbone",
            "Underscore.js": "underscore",
            "Knockout.js": "knockout",
            "Polymer": "polymer",
            "Mithril": "mithril",
            "Preact": "preact",
            "Svelte": "svelte"
        }
        detected = []
        for fw, pattern in frameworks.items():
            if pattern in html:
                detected.append(fw)
        return detected or ["No JS framework detected"]

    def analyze_cdns_wafs(self, server_header):
        cdns = {
            "Cloudflare": "cloudflare",
            "Akamai": "akamai",
            "Fastly": "fastly",
            "Sucuri": "sucuri",
            "Incapsula": "incapsula",
            "Imperva": "imperva",
            "AWS CloudFront": "aws cloudfront",
            "Google Cloud CDN": "google cloud cdn",
            "Azure CDN": "azure cdn",
            "EdgeCast": "edgecast",
            "StackPath": "stackpath"
        }
        detected = []
        server_lower = server_header.lower()
        for cdn, pattern in cdns.items():
            if pattern in server_lower:
                detected.append(cdn)
        return detected or ["No CDN/WAF detected"]

    def analyze_language_backend(self, powered_by_header):
        languages = {
            "PHP": "php",
            "ASP.NET": ["asp.net", "asp"],
            "Node.js / Express": ["express.js", "express"],
            "Python / Django": "django",
            "Python / Flask": "flask",
            "Ruby on Rails": ["rails", "ruby"],
            "Java": ["java", "tomcat", "jetty"],
            "C#": "c#",
            "Go": "go",
            "Rust": "rust",
            "Scala": "scala",
            "Elixir": "elixir",
            "Perl": "perl",
            "R": "r",
            "Julia": "julia",
            "Haskell": "haskell",
            "Lua": "lua"
        }
        detected = []
        powered_by_lower = powered_by_header.lower()
        for lang, patterns in languages.items():
            if isinstance(patterns, list):
                if any(p in powered_by_lower for p in patterns):
                    detected.append(lang)
            elif patterns in powered_by_lower:
                detected.append(lang)
        return detected

    def analyze_dns_records(self, domain):
        try:
            records = {}
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    results = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
                    records[record_type] = [r[4][0] for r in results]
                except Exception:
                    records[record_type] = []
            return records
        except Exception as e:
            return {'error': str(e)}

    def find_common_subdomains(self, domain):
        common_subdomains = ["www", "mail", "ftp", "test", "dev", "stage", "api", "blog", "shop", "admin"]
        found = []
        for sub in common_subdomains:
            try:
                sub_domain = f"{sub}.{domain}"
                socket.gethostbyname(sub_domain)
                found.append(sub_domain)
            except:
                pass
        return found

    def detect_tech(self, url):
        # Add scheme if missing
        url = self.add_scheme_if_missing(url)
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        ip = socket.gethostbyname(domain)

        print(Fore.CYAN + "\nPLASCOV TECH DETECTOR")
        print(Fore.CYAN + "="*60)

        try:
            response = self.session.get(url, timeout=7)
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"Error accessing website: {e}")
            return

        headers = response.headers
        html = response.text.lower()

        # Basic Info
        print(Fore.GREEN + "\n[Basic Information]")
        print(Fore.GREEN + "-"*30)
        print(f"{Fore.YELLOW}URL:{Fore.WHITE} {url}")
        print(f"{Fore.YELLOW}Domain:{Fore.WHITE} {domain}")
        print(f"{Fore.YELLOW}IP Address:{Fore.WHITE} {ip}")

        # Server Info
        print(Fore.GREEN + "\n[Server Information]")
        print(Fore.GREEN + "-"*30)
        print(f"{Fore.YELLOW}Server:{Fore.WHITE} {headers.get('server', 'Unknown')}")
        print(f"{Fore.YELLOW}X-Powered-By:{Fore.WHITE} {headers.get('x-powered-by', 'Unknown')}")
        print(f"{Fore.YELLOW}Content-Type:{Fore.WHITE} {headers.get('content-type', 'Unknown')}")
        print(f"{Fore.YELLOW}Date:{Fore.WHITE} {headers.get('date', 'Unknown')}")

        # SSL Certificate Info
        print(Fore.GREEN + "\n[SSL Certificate Info]")
        print(Fore.GREEN + "-"*30)
        cert_info = self.get_certificate_info(domain)
        if 'error' in cert_info:
            print(Fore.RED + f"SSL Error: {cert_info['error']}")
        else:
            print(f"{Fore.YELLOW}Subject:{Fore.WHITE} {cert_info['subject']}")
            print(f"{Fore.YELLOW}Issuer:{Fore.WHITE} {cert_info['issuer']}")
            print(f"{Fore.YELLOW}Valid From:{Fore.WHITE} {cert_info['valid_from']}")
            print(f"{Fore.YELLOW}Valid Until:{Fore.WHITE} {cert_info['valid_until']}")
            print(f"{Fore.YELLOW}SHA-1 Fingerprint:{Fore.WHITE} {cert_info['fingerprint']}")

        # CMS Detection
        print(Fore.GREEN + "\n[CMS Detection]")
        print(Fore.GREEN + "-"*30)
        cms_results = self.analyze_cms(html)
        for cms in cms_results:
            print(Fore.MAGENTA + cms)

        # Framework / JS Detection
        print(Fore.GREEN + "\n[Framework / JS Libraries Detection]")
        print(Fore.GREEN + "-"*45)
        fw_results = self.analyze_frameworks(html)
        for fw in fw_results:
            print(Fore.CYAN + fw)

        # CDN / WAF Detection
        print(Fore.GREEN + "\n[CDN / WAF Detection]")
        print(Fore.GREEN + "-"*35)
        cdn_results = self.analyze_cdns_wafs(headers.get('server', ''))
        for cdn in cdn_results:
            print(Fore.YELLOW + cdn)

        # Language Detection
        print(Fore.GREEN + "\n[Language / Backend Detection]")
        print(Fore.GREEN + "-"*35)
        lang_results = self.analyze_language_backend(headers.get('x-powered-by', ''))
        for lang in lang_results:
            print(Fore.BLUE + lang)

        # Headers Analysis
        print(Fore.GREEN + "\n[Headers Analysis]")
        print(Fore.GREEN + "-"*30)
        sensitive_headers = [
            "x-frame-options", "x-xss-protection", "content-security-policy",
            "strict-transport-security", "referrer-policy", "permissions-policy",
            "cache-control", "pragma", "expires", "last-modified", "etag",
            "accept-ranges", "allow"
        ]
        for header in sensitive_headers:
            value = headers.get(header, "Not Set")
            if value != "Not Set":
                print(Fore.YELLOW + f"{header}: {value}")

        # Cookies Analysis
        print(Fore.GREEN + "\n[Cookie Analysis]")
        print(Fore.GREEN + "-"*30)
        if response.cookies:
            for cookie in response.cookies:
                flags = []
                if getattr(cookie, "secure", False):
                    flags.append("Secure")
                if getattr(cookie, "httponly", False):
                    flags.append("HttpOnly")
                if getattr(cookie, "domain", None):
                    flags.append(f"Domain={cookie.domain}")
                flags_str = ", ".join(flags)
                print(Fore.YELLOW + f"Cookie: {Fore.WHITE}{cookie.name} | Value: {cookie.value} | {flags_str}")
        else:
            print(Fore.RED + "No cookies detected.")

        # DNS Records Analysis
        print(Fore.GREEN + "\n[DNS Records Analysis]")
        print(Fore.GREEN + "-"*30)
        dns_records = self.analyze_dns_records(domain)
        if 'error' in dns_records:
            print(Fore.RED + f"DNS Error: {dns_records['error']}")
        else:
            print(json.dumps(dns_records, indent=2))

        # Common Subdomains
        print(Fore.GREEN + "\n[Common Subdomains]")
        print(Fore.GREEN + "-"*30)
        subdomains = self.find_common_subdomains(domain)
        if subdomains:
            for sd in subdomains:
                print(Fore.YELLOW + sd)
        else:
            print(Fore.RED + "No common subdomains found.")

        print(Fore.CYAN + "\nDetection Complete")
        print(Fore.CYAN + "="*60 + "\n")

def detect_tech(target):
    detector = TechDetector()
    detector.detect_tech(target)

# Example usage:
# detector = TechDetector()
# detector.detect_tech("www.google.com")
