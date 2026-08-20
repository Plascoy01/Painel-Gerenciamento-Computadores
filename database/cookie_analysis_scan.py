#!/usr/bin/env python3
"""
Cookie Analysis Scanner Module for Plascoy Security Scanner

This module performs comprehensive cookie security analysis including:
- Cookie attribute validation (Secure, HttpOnly, SameSite)
- Cookie value analysis for sensitive data exposure
- Session cookie security assessment
- Cookie domain and path validation
- Cookie size and entropy analysis
- Third-party cookie detection
- Cookie manipulation testing
- CSRF token validation

Author: Plascoy Team
Version: 2.0
"""

import requests
import logging
import json
import time
import os
import re
import base64
import binascii
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.cookies import SimpleCookie

# Initialize colorama for colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

@dataclass
class CookieVulnerability:
    """Data class for cookie vulnerabilities"""
    cookie_name: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    recommendation: str

@dataclass
class CookieAnalysis:
    """Data class for cookie analysis results"""
    name: str
    value: str
    domain: str
    path: str
    secure: bool
    httponly: bool
    samesite: str
    expires: str
    max_age: str
    size: int
    entropy_score: float
    contains_sensitive_data: bool
    is_session_cookie: bool
    is_third_party: bool

@dataclass
class CookieScanConfig:
    """Configuration for cookie scanning"""
    timeout: int = 10
    max_workers: int = 3
    user_agent: str = 'Plascoy-Cookie-Analyzer/2.0'
    follow_redirects: bool = True
    verify_ssl: bool = False
    delay_between_requests: float = 0.2
    check_multiple_pages: bool = True
    max_pages_to_check: int = 5
    analyze_values: bool = True
    test_manipulation: bool = False

class CookieAnalyzer:
    """
    Professional cookie security analysis scanner with comprehensive features.

    This class provides methods to analyze HTTP cookies for security vulnerabilities
    and best practices compliance.
    """

    def __init__(self, config: CookieScanConfig = None):
        """
        Initialize the cookie analyzer with configuration.

        Args:
            config: CookieScanConfig object with scanning parameters
        """
        self.config = config or CookieScanConfig()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        self.session.verify = self.config.verify_ssl

        # Setup logging
        self.logger = logging.getLogger('CookieAnalyzer')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.vulnerabilities: List[CookieVulnerability] = []
        self.cookie_analyses: List[CookieAnalysis] = []
        self.scanned_urls: Set[str] = set()

    def _log(self, message: str, level: str = 'info', color: str = None):
        """Log message with optional color output"""
        if level == 'info':
            self.logger.info(message)
        elif level == 'warning':
            self.logger.warning(message)
        elif level == 'error':
            self.logger.error(message)
        elif level == 'debug':
            self.logger.debug(message)

        if HAS_COLORAMA and color:
            colored_message = getattr(Fore, color.upper(), '') + message
            print(colored_message)

    def _make_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling.

        Args:
            url: Target URL
            **kwargs: Additional request parameters

        Returns:
            Response object or None if failed
        """
        try:
            time.sleep(self.config.delay_between_requests)
            response = self.session.request(
                url=url,
                timeout=self.config.timeout,
                allow_redirects=self.config.follow_redirects,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            self._log(f"Request failed for {url}: {e}", 'debug')
            return None

    def _parse_cookie_header(self, cookie_header: str) -> Dict[str, str]:
        """
        Parse a Set-Cookie header into attributes.

        Args:
            cookie_header: Raw Set-Cookie header value

        Returns:
            Dictionary of cookie attributes
        """
        attributes = {}
        parts = cookie_header.split(';')

        if parts:
            # First part is name=value
            name_value = parts[0].strip()
            if '=' in name_value:
                name, value = name_value.split('=', 1)
                attributes['name'] = name.strip()
                attributes['value'] = value.strip()

            # Parse other attributes
            for part in parts[1:]:
                part = part.strip()
                if '=' in part:
                    attr_name, attr_value = part.split('=', 1)
                    attributes[attr_name.lower().strip()] = attr_value.strip()
                else:
                    attributes[part.lower().strip()] = True

        return attributes

    def _calculate_entropy(self, value: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            value: String to analyze

        Returns:
            Entropy score (0-8, higher is more random)
        """
        if not value:
            return 0.0

        # Count character frequencies
        char_count = {}
        for char in value:
            char_count[char] = char_count.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        length = len(value)
        for count in char_count.values():
            probability = count / length
            entropy -= probability * (probability.bit_length() - 1)  # Approximation

        return min(entropy, 8.0)  # Cap at 8

    def _analyze_cookie_value(self, name: str, value: str) -> Dict[str, any]:
        """
        Analyze cookie value for security issues.

        Args:
            name: Cookie name
            value: Cookie value

        Returns:
            Analysis results dictionary
        """
        analysis = {
            'contains_sensitive': False,
            'sensitive_keywords': [],
            'is_encoded': False,
            'encoding_type': None,
            'entropy_score': self._calculate_entropy(value),
            'is_weak': False
        }

        if not self.config.analyze_values:
            return analysis

        # Check for sensitive keywords
        sensitive_keywords = [
            'password', 'passwd', 'secret', 'key', 'api_key', 'apikey',
            'token', 'auth', 'session', 'admin', 'root', 'user',
            'email', 'credit', 'card', 'ssn', 'social', 'phone'
        ]

        value_lower = value.lower()
        found_keywords = [kw for kw in sensitive_keywords if kw in value_lower]
        analysis['sensitive_keywords'] = found_keywords
        analysis['contains_sensitive'] = len(found_keywords) > 0

        # Check for encoding
        try:
            # Base64 detection
            if len(value) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', value):
                decoded = base64.b64decode(value)
                if decoded:
                    analysis['is_encoded'] = True
                    analysis['encoding_type'] = 'base64'
                    # Check decoded content
                    decoded_str = decoded.decode('utf-8', errors='ignore')
                    decoded_keywords = [kw for kw in sensitive_keywords if kw in decoded_str.lower()]
                    if decoded_keywords:
                        analysis['contains_sensitive'] = True
                        analysis['sensitive_keywords'].extend(decoded_keywords)
        except:
            pass

        # Check for weak values
        if len(value) < 16 and analysis['entropy_score'] < 3.0:
            analysis['is_weak'] = True

        return analysis

    def _check_cookie_attributes(self, cookie_attrs: Dict) -> List[CookieVulnerability]:
        """
        Check cookie attributes for security issues.

        Args:
            cookie_attrs: Parsed cookie attributes

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        name = cookie_attrs.get('name', 'Unknown')

        # Check Secure flag
        if not cookie_attrs.get('secure', False):
            if cookie_attrs.get('domain', '').startswith('https://'):
                vuln = CookieVulnerability(
                    cookie_name=name,
                    vulnerability_type='Missing Secure Flag',
                    severity='Medium',
                    description='Cookie is not marked as Secure, allowing transmission over HTTP',
                    evidence='Secure attribute not set',
                    recommendation='Add Secure flag to prevent transmission over unencrypted connections'
                )
                vulnerabilities.append(vuln)

        # Check HttpOnly flag
        if not cookie_attrs.get('httponly', False):
            vuln = CookieVulnerability(
                cookie_name=name,
                vulnerability_type='Missing HttpOnly Flag',
                severity='Low',
                description='Cookie is not marked as HttpOnly, allowing JavaScript access',
                evidence='HttpOnly attribute not set',
                recommendation='Add HttpOnly flag to prevent JavaScript access to sensitive cookies'
            )
            vulnerabilities.append(vuln)

        # Check SameSite attribute
        samesite = cookie_attrs.get('samesite', '').lower()
        if not samesite or samesite not in ['strict', 'lax']:
            vuln = CookieVulnerability(
                cookie_name=name,
                vulnerability_type='Missing or Weak SameSite',
                severity='Medium',
                description='Cookie lacks SameSite attribute or uses weak setting',
                evidence=f'SameSite: {samesite or "not set"}',
                recommendation='Set SameSite to Strict or Lax to prevent CSRF attacks'
            )
            vulnerabilities.append(vuln)

        # Check for overly broad domain
        domain = cookie_attrs.get('domain', '')
        if domain and domain.startswith('.'):
            vuln = CookieVulnerability(
                cookie_name=name,
                vulnerability_type='Overly Broad Domain',
                severity='Low',
                description='Cookie domain starts with dot, allowing subdomains',
                evidence=f'Domain: {domain}',
                recommendation='Specify exact domain to limit cookie scope'
            )
            vulnerabilities.append(vuln)

        # Check for overly broad path
        path = cookie_attrs.get('path', '/')
        if path == '/':
            vuln = CookieVulnerability(
                cookie_name=name,
                vulnerability_type='Overly Broad Path',
                severity='Low',
                description='Cookie path is root (/), accessible to all paths',
                evidence=f'Path: {path}',
                recommendation='Specify more restrictive path if possible'
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_session_cookie(self, name: str) -> bool:
        """
        Check if cookie name indicates it's a session cookie.

        Args:
            name: Cookie name

        Returns:
            True if likely a session cookie
        """
        session_indicators = [
            'session', 'sess', 'sid', 'jsessionid', 'phpsessid',
            'asp.net_sessionid', 'auth', 'token', 'jwt'
        ]
        return any(indicator in name.lower() for indicator in session_indicators)

    def _is_third_party_cookie(self, domain: str, target_domain: str) -> bool:
        """
        Check if cookie is from a third party.

        Args:
            domain: Cookie domain
            target_domain: Target website domain

        Returns:
            True if third-party cookie
        """
        if not domain or not target_domain:
            return False

        target_parsed = urlparse(target_domain)
        cookie_domain = domain.lstrip('.')

        return cookie_domain != target_parsed.netloc and not target_parsed.netloc.endswith(cookie_domain)

    def analyze_cookies_from_response(self, response: requests.Response, target_url: str) -> None:
        """
        Analyze cookies from an HTTP response.

        Args:
            response: HTTP response object
            target_url: Target URL for context
        """
        # Get cookies from response headers
        set_cookie_headers = response.headers.getlist('Set-Cookie') if hasattr(response.headers, 'getlist') else []
        if not set_cookie_headers:
            set_cookie = response.headers.get('Set-Cookie')
            if set_cookie:
                set_cookie_headers = [set_cookie]

        parsed_url = urlparse(target_url)

        for cookie_header in set_cookie_headers:
            cookie_attrs = self._parse_cookie_header(cookie_header)
            name = cookie_attrs.get('name', 'Unknown')
            value = cookie_attrs.get('value', '')

            # Value analysis
            value_analysis = self._analyze_cookie_value(name, value)

            # Create cookie analysis object
            analysis = CookieAnalysis(
                name=name,
                value=value[:50] + '...' if len(value) > 50 else value,
                domain=cookie_attrs.get('domain', parsed_url.netloc),
                path=cookie_attrs.get('path', '/'),
                secure=cookie_attrs.get('secure', False),
                httponly=cookie_attrs.get('httponly', False),
                samesite=cookie_attrs.get('samesite', ''),
                expires=cookie_attrs.get('expires', ''),
                max_age=cookie_attrs.get('max-age', ''),
                size=len(value),
                entropy_score=value_analysis['entropy_score'],
                contains_sensitive_data=value_analysis['contains_sensitive'],
                is_session_cookie=self._is_session_cookie(name),
                is_third_party=self._is_third_party_cookie(cookie_attrs.get('domain', ''), target_url)
            )

            self.cookie_analyses.append(analysis)

            # Check for vulnerabilities
            vulnerabilities = self._check_cookie_attributes(cookie_attrs)
            self.vulnerabilities.extend(vulnerabilities)

            # Additional checks based on analysis
            if value_analysis['contains_sensitive']:
                vuln = CookieVulnerability(
                    cookie_name=name,
                    vulnerability_type='Sensitive Data in Cookie',
                    severity='High',
                    description=f'Cookie contains sensitive data: {", ".join(value_analysis["sensitive_keywords"])}',
                    evidence=f'Value contains: {value_analysis["sensitive_keywords"][:3]}',
                    recommendation='Avoid storing sensitive data in cookies'
                )
                self.vulnerabilities.append(vuln)

            if value_analysis['is_weak'] and analysis.is_session_cookie:
                vuln = CookieVulnerability(
                    cookie_name=name,
                    vulnerability_type='Weak Session Cookie',
                    severity='Medium',
                    description='Session cookie has weak value (short length, low entropy)',
                    evidence=f'Length: {len(value)}, Entropy: {value_analysis["entropy_score"]:.2f}',
                    recommendation='Use cryptographically secure random values for session cookies'
                )
                self.vulnerabilities.append(vuln)

    def discover_pages_with_cookies(self, base_url: str) -> List[str]:
        """
        Discover additional pages that might set cookies.

        Args:
            base_url: Base URL to scan

        Returns:
            List of URLs to check
        """
        pages = [base_url]

        if not self.config.check_multiple_pages:
            return pages

        # Common pages that set cookies
        common_pages = [
            '/login', '/signin', '/auth', '/register', '/signup',
            '/admin', '/dashboard', '/profile', '/account', '/settings',
            '/api/login', '/api/auth', '/oauth/authorize'
        ]

        for page in common_pages:
            url = urljoin(base_url, page)
            if url not in pages:
                pages.append(url)

            if len(pages) >= self.config.max_pages_to_check:
                break

        return pages

    def test_cookie_manipulation(self, base_url: str) -> None:
        """
        Test for cookie manipulation vulnerabilities.

        Args:
            base_url: Base URL to test
        """
        if not self.config.test_manipulation:
            return

        self._log("Testing cookie manipulation vulnerabilities", color='cyan')

        # Get initial cookies
        response = self._make_request(base_url)
        if not response:
            return

        initial_cookies = {c.name: c.value for c in self.session.cookies}

        # Test common cookie manipulation
        test_cases = [
            {'session_id': 'admin'},
            {'user_id': '1'},
            {'role': 'admin'},
            {'auth': 'true'},
            {'admin': '1'}
        ]

        for test_cookies in test_cases:
            # Set test cookies
            for name, value in test_cookies.items():
                self.session.cookies.set(name, value, domain=urlparse(base_url).netloc)

            # Test access to protected resource
            test_response = self._make_request(urljoin(base_url, '/admin'))
            if test_response and test_response.status_code == 200:
                content = test_response.text.lower()
                if any(word in content for word in ['admin', 'dashboard', 'control', 'manage']):
                    vuln = CookieVulnerability(
                        cookie_name=list(test_cookies.keys())[0],
                        vulnerability_type='Cookie Manipulation',
                        severity='High',
                        description='Cookie value manipulation grants unauthorized access',
                        evidence=f'Cookie: {test_cookies}, Status: {test_response.status_code}',
                        recommendation='Implement proper cookie validation and server-side session management'
                    )
                    self.vulnerabilities.append(vuln)
                    self._log(f"Cookie manipulation vulnerability found", 'warning', 'red')

            # Reset cookies
            for name in test_cookies:
                self.session.cookies.clear(domain=urlparse(base_url).netloc, name=name)

    def generate_report(self, output_file: str = None) -> Dict:
        """
        Generate comprehensive scan report.

        Args:
            output_file: Optional file path to save JSON report

        Returns:
            Dictionary containing scan results
        """
        # Categorize vulnerabilities by severity
        severity_summary = {
            'Critical': len([v for v in self.vulnerabilities if v.severity == 'Critical']),
            'High': len([v for v in self.vulnerabilities if v.severity == 'High']),
            'Medium': len([v for v in self.vulnerabilities if v.severity == 'Medium']),
            'Low': len([v for v in self.vulnerabilities if v.severity == 'Low'])
        }

        report = {
            'scan_type': 'Cookie Security Analysis Scan',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'cookies_analyzed': len(self.cookie_analyses),
            'vulnerabilities_found': len(self.vulnerabilities),
            'severity_summary': severity_summary,
            'cookie_analyses': [
                {
                    'name': c.name,
                    'domain': c.domain,
                    'path': c.path,
                    'secure': c.secure,
                    'httponly': c.httponly,
                    'samesite': c.samesite,
                    'size': c.size,
                    'entropy_score': round(c.entropy_score, 2),
                    'contains_sensitive_data': c.contains_sensitive_data,
                    'is_session_cookie': c.is_session_cookie,
                    'is_third_party': c.is_third_party
                } for c in self.cookie_analyses
            ],
            'vulnerabilities': [
                {
                    'cookie_name': v.cookie_name,
                    'type': v.vulnerability_type,
                    'severity': v.severity,
                    'description': v.description,
                    'evidence': v.evidence,
                    'recommendation': v.recommendation
                } for v in self.vulnerabilities
            ]
        }

        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            self._log(f"Report saved to {output_file}", color='green')

        return report

    def scan(self, target_url: str, output_file: str = None) -> Dict:
        """
        Perform complete cookie security analysis scan.

        Args:
            target_url: Base URL to scan
            output_file: Optional output file for report

        Returns:
            Scan results dictionary
        """
        self._log(f"Starting comprehensive cookie analysis for {target_url}", color='cyan')

        # Ensure URL has proper format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        # Discover pages to check
        urls_to_check = self.discover_pages_with_cookies(target_url)

        # Analyze cookies from each page
        for url in urls_to_check:
            response = self._make_request(url)
            if response:
                self.analyze_cookies_from_response(response, url)
                self._log(f"Analyzed cookies from: {url}", 'info')

        # Test cookie manipulation if enabled
        if self.config.test_manipulation:
            self.test_cookie_manipulation(target_url)

        self._log(f"Cookie analysis completed. Analyzed {len(self.cookie_analyses)} cookies, found {len(self.vulnerabilities)} issues", color='green')

        return self.generate_report(output_file)

def main():
    """Main function for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(description='Plascoy Cookie Security Analysis Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Skip SSL verification')
    parser.add_argument('--single-page', action='store_true', help='Check only main page')
    parser.add_argument('--no-value-analysis', action='store_true', help='Skip cookie value analysis')
    parser.add_argument('--test-manipulation', action='store_true', help='Test cookie manipulation vulnerabilities')

    args = parser.parse_args()

    config = CookieScanConfig(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        check_multiple_pages=not args.single_page,
        analyze_values=not args.no_value_analysis,
        test_manipulation=args.test_manipulation
    )

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    scanner = CookieAnalyzer(config)
    results = scanner.scan(args.target, args.output)

    print(f"\nScan Summary:")
    print(f"Cookies analyzed: {results['cookies_analyzed']}")
    print(f"Vulnerabilities found: {results['vulnerabilities_found']}")
    print(f"Critical: {results['severity_summary']['Critical']}")
    print(f"High: {results['severity_summary']['High']}")
    print(f"Medium: {results['severity_summary']['Medium']}")
    print(f"Low: {results['severity_summary']['Low']}")

    for vuln in results['vulnerabilities'][:5]:  # Show first 5
        print(f"- {vuln['severity'].upper()}: {vuln['type']} in cookie '{vuln['cookie_name']}'")

if __name__ == '__main__':
    main()
