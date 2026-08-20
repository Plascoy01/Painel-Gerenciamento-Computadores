#!/usr/bin/env python3
"""
Security Headers Analysis Module

Analyzes HTTP security headers for misconfigurations through:
- Content-Security-Policy (CSP) validation
- HSTS (Strict-Transport-Security) analysis
- CORS header evaluation
- XSS protection verification
- MIME sniffing prevention checks

Supported headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.

Author: Plascoy Security
Version: 2.0
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import re
import time
from colorama import init, Fore, Style
from typing import Dict, List, Optional, Tuple

init(autoreset=True)

import logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SecurityHeaderAnalyzer:
    """Professional security headers analyzer"""
    
    SECURITY_HEADERS = {
        "Content-Security-Policy": "Protection against XSS and content injection",
        "Strict-Transport-Security": "Force HTTPS usage",
        "X-Frame-Options": "Protection against clickjacking",
        "X-Content-Type-Options": "Prevent MIME sniffing",
        "Referrer-Policy": "Control referrer sending",
        "Permissions-Policy": "Control browser APIs",
        "X-XSS-Protection": "Basic XSS protection",
        "Feature-Policy": "Legacy permissions control",
        "Expect-CT": "Certificate Transparency enforcement",
        "Cross-Origin-Resource-Policy": "Cross-origin resource blocking",
        "Origin-Agent-Cluster": "Isolate origins",
        "Clear-Site-Data": "Clear data on navigation",
        "Access-Control-Allow-Origin": "CORS origin control",
        "Access-Control-Allow-Methods": "CORS method control",
        "Access-Control-Allow-Headers": "CORS header control",
        "Access-Control-Allow-Credentials": "CORS credentials control",
        "Cache-Control": "HTTP caching control",
        "X-UA-Compatible": "IE compatibility mode",
    }
    
    CSP_DIRECTIVES = {
        "default-src": "Default source policy",
        "script-src": "Script execution policy",
        "style-src": "Style loading policy",
        "img-src": "Image loading policy",
        "connect-src": "Connection policy",
        "font-src": "Font loading policy",
        "form-action": "Form submission policy",
        "frame-ancestors": "Allowed parent frames",
    }
    
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False):
        """Initialize header analyzer"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'security_issues': [],
            'missing_headers': [],
            'present_headers': {},
            'total_score': 0,
            'scan_time': 0
        }
        self.session = self._create_session()
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target URL"""
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        return target.rstrip('/')
    
    def _create_session(self) -> requests.Session:
        """Create robust requests session"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=1,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        session.verify = self.verify_ssl
        
        return session
    
    def scan(self, verbose: bool = False) -> Dict:
        """
        Perform security headers analysis scan
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            Dictionary with header analysis results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Security Headers Analysis Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        # Fetch and analyze headers
        self._fetch_and_analyze_headers(verbose)
        
        # Calculate score
        self._calculate_security_score()
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        
        return self.results
    
    def _fetch_and_analyze_headers(self, verbose: bool = False):
        """Fetch and analyze HTTP headers"""
        print(Fore.BLUE + "\n[*] Fetching headers...")
        
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            headers = dict(response.headers)
            
            print(Fore.GREEN + f"[+] Status: {response.status_code}")
            print(Fore.GREEN + f"[+] Content Length: {len(response.content)} bytes")
            
            # Check for security headers
            self._analyze_security_headers(headers, verbose)
            
            # Store all headers for reference
            self.results['all_headers'] = headers
        
        except requests.exceptions.Timeout:
            print(Fore.RED + f"[!] Request timeout")
            logger.warning("Timeout fetching headers")
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] Request error: {str(e)}")
            logger.error(f"Request error: {str(e)}")
        except Exception as e:
            print(Fore.RED + f"[!] Error: {str(e)}")
            logger.error(f"Unexpected error: {str(e)}")
    
    def _analyze_security_headers(self, headers: Dict, verbose: bool = False):
        """Analyze security headers configuration"""
        print(Fore.BLUE + "\n[*] Analyzing security headers...")
        
        for header_name, description in self.SECURITY_HEADERS.items():
            # Case-insensitive header lookup
            header_value = None
            for key, value in headers.items():
                if key.lower() == header_name.lower():
                    header_value = value
                    break
            
            if header_value:
                print(Fore.GREEN + f"[+] {header_name}: Found")
                self.results['present_headers'][header_name] = header_value
                
                # Analyze specific headers
                issues = self._analyze_header_value(header_name, header_value)
                for issue in issues:
                    print(Fore.RED + f"  [!] {issue}")
                    self.results['security_issues'].append(f"{header_name}: {issue}")
                
                if verbose:
                    print(Fore.YELLOW + f"  Value: {str(header_value)[:100]}...")
            else:
                print(Fore.RED + f"[-] {header_name}: Missing")
                self.results['missing_headers'].append(header_name)
    
    def _analyze_header_value(self, header_name: str, value: str) -> List[str]:
        """Analyze specific header value for issues"""
        issues = []
        
        if header_name == "Content-Security-Policy":
            issues.extend(self._analyze_csp(value))
        elif header_name == "Strict-Transport-Security":
            issues.extend(self._analyze_hsts(value))
        elif header_name == "X-Frame-Options":
            issues.extend(self._analyze_xfo(value))
        elif header_name == "X-Content-Type-Options":
            issues.extend(self._analyze_xcto(value))
        elif header_name == "Referrer-Policy":
            issues.extend(self._analyze_referrer_policy(value))
        elif header_name == "Access-Control-Allow-Origin":
            if value == "*":
                issues.append("CORS origin allows all (*) - may expose sensitive data")
        
        return issues
    
    def _analyze_csp(self, value: str) -> List[str]:
        """Analyze CSP directives"""
        issues = []
        dangerous = ["'unsafe-inline'", "'unsafe-eval'", "unsafe-hashes", "*"]
        
        for directive in dangerous:
            if directive in value:
                issues.append(f"Dangerous CSP directive: {directive}")
        
        if "strict-dynamic" in value and not ("nonce-" in value or "sha-" in value):
            issues.append("strict-dynamic without nonce/SHA")
        
        return issues
    
    def _analyze_hsts(self, value: str) -> List[str]:
        """Analyze HSTS configuration"""
        issues = []
        
        max_age_match = re.search(r'max-age=(\d+)', value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # 1 year
                issues.append(f"max-age too short: {max_age}s (recommended: ≥31536000)")
        
        if "includeSubDomains" not in value:
            issues.append("Missing includeSubDomains")
        
        if "preload" not in value:
            issues.append("Missing preload directive")
        
        return issues
    
    def _analyze_xfo(self, value: str) -> List[str]:
        """Analyze X-Frame-Options"""
        valid = ["DENY", "SAMEORIGIN"]
        if value.upper() not in valid:
            return [f"Invalid value: {value}"]
        return []
    
    def _analyze_xcto(self, value: str) -> List[str]:
        """Analyze X-Content-Type-Options"""
        if value.lower() != "nosniff":
            return [f"Invalid value: {value}"]
        return []
    
    def _analyze_referrer_policy(self, value: str) -> List[str]:
        """Analyze Referrer-Policy"""
        valid = [
            "no-referrer", "no-referrer-when-downgrade", "origin",
            "origin-when-cross-origin", "same-origin", "strict-origin"
        ]
        if value.lower() not in valid:
            return [f"Non-standard value: {value}"]
        return []
    
    def _calculate_security_score(self):
        """Calculate security score"""
        total_headers = len(self.SECURITY_HEADERS)
        present = len(self.results['present_headers'])
        issues = len(self.results['security_issues'])
        
        # Score: (present / total) * 100 - (issues * 5)
        self.results['total_score'] = max(0, (present / total_headers * 100) - (issues * 5))
    
    def _print_summary(self):
        """Print analysis summary"""
        print(Fore.CYAN + "\n[*] Security Headers Analysis Summary:")
        print(Fore.GREEN + f"[+] Present headers: {len(self.results['present_headers'])}/{len(self.SECURITY_HEADERS)}")
        print(Fore.RED + f"[-] Missing headers: {len(self.results['missing_headers'])}")
        print(Fore.RED + f"[!] Security issues: {len(self.results['security_issues'])}")
        print(Fore.CYAN + f"[*] Security score: {self.results['total_score']:.1f}/100")
        print(Fore.CYAN + f"[*] Scan time: {self.results['scan_time']:.2f}s")


# Legacy function interface
def scan_headers(url, output_format="text"):
    """Legacy function interface for header scanning"""
    analyzer = SecurityHeaderAnalyzer(url)
    results = analyzer.scan(verbose=True)
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan_headers(sys.argv[1])
    else:
        scan_headers("https://www.google.com")
