#!/usr/bin/env python3
"""
Clickjacking Detection Module for Plascoy Security Scanner

This module performs comprehensive clickjacking vulnerability detection including:
- X-Frame-Options header analysis
- Content Security Policy (CSP) frame-ancestors directive checking
- Frame-busting JavaScript detection
- Multiple endpoint testing
- CORS header analysis for framing implications
- Security headers assessment
- Practical clickjacking testing

Author: Plascoy Team
Version: 2.0
"""

import requests
import logging
import json
import time
import os
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama for colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

@dataclass
class ClickjackingVulnerability:
    """Data class for clickjacking vulnerabilities"""
    url: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    recommendation: str

@dataclass
class ClickjackingScanConfig:
    """Configuration for clickjacking scanning"""
    timeout: int = 10
    max_workers: int = 5
    user_agent: str = 'Plascoy-Clickjacking-Scanner/2.0'
    follow_redirects: bool = True
    verify_ssl: bool = False
    delay_between_requests: float = 0.1
    test_multiple_pages: bool = True
    max_pages_to_test: int = 10
    check_javascript: bool = True

class ClickjackingScanner:
    """
    Professional clickjacking vulnerability scanner with comprehensive features.

    This class provides methods to detect clickjacking vulnerabilities through
    header analysis, CSP checking, and practical testing.
    """

    def __init__(self, config: ClickjackingScanConfig = None):
        """
        Initialize the clickjacking scanner with configuration.

        Args:
            config: ClickjackingScanConfig object with scanning parameters
        """
        self.config = config or ClickjackingScanConfig()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        self.session.verify = self.config.verify_ssl

        # Setup logging
        self.logger = logging.getLogger('ClickjackingScanner')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.vulnerabilities: List[ClickjackingVulnerability] = []
        self.tested_urls: List[str] = []

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

    def _analyze_x_frame_options(self, url: str, headers: Dict[str, str]) -> None:
        """
        Analyze X-Frame-Options header for clickjacking protection.

        Args:
            url: URL being analyzed
            headers: Response headers
        """
        x_frame = headers.get('X-Frame-Options', '').strip()

        if not x_frame:
            vuln = ClickjackingVulnerability(
                url=url,
                vulnerability_type='Missing X-Frame-Options',
                severity='High',
                description='X-Frame-Options header is missing, allowing potential clickjacking attacks',
                evidence='Header not present in response',
                recommendation='Add X-Frame-Options header with DENY or SAMEORIGIN value'
            )
            self.vulnerabilities.append(vuln)
            self._log(f"Missing X-Frame-Options: {url}", 'warning', 'red')
        elif x_frame.upper() == 'ALLOW-FROM':
            # Check if ALLOW-FROM has valid origins
            allow_from_match = re.search(r'ALLOW-FROM\s+(.+)', x_frame, re.IGNORECASE)
            if allow_from_match:
                origins = allow_from_match.group(1).strip()
                if origins == '*' or not origins:
                    vuln = ClickjackingVulnerability(
                        url=url,
                        vulnerability_type='Weak X-Frame-Options',
                        severity='Medium',
                        description='X-Frame-Options uses ALLOW-FROM with potentially unsafe origins',
                        evidence=f'ALLOW-FROM: {origins}',
                        recommendation='Use DENY or SAMEORIGIN instead of ALLOW-FROM'
                    )
                    self.vulnerabilities.append(vuln)
                    self._log(f"Weak X-Frame-Options: {url}", 'warning', 'yellow')
            else:
                vuln = ClickjackingVulnerability(
                    url=url,
                    vulnerability_type='Malformed X-Frame-Options',
                    severity='Medium',
                    description='X-Frame-Options ALLOW-FROM directive is malformed',
                    evidence=f'Header: {x_frame}',
                    recommendation='Fix ALLOW-FROM syntax or use DENY/SAMEORIGIN'
                )
                self.vulnerabilities.append(vuln)
        elif x_frame.upper() in ['DENY', 'SAMEORIGIN']:
            self._log(f"Good X-Frame-Options: {x_frame}", 'info', 'green')
        else:
            vuln = ClickjackingVulnerability(
                url=url,
                vulnerability_type='Unknown X-Frame-Options',
                severity='Low',
                description=f'X-Frame-Options contains unknown directive: {x_frame}',
                evidence=f'Header: {x_frame}',
                recommendation='Use standard DENY or SAMEORIGIN values'
            )
            self.vulnerabilities.append(vuln)

    def _analyze_csp_frame_ancestors(self, url: str, headers: Dict[str, str]) -> None:
        """
        Analyze Content Security Policy for frame-ancestors directive.

        Args:
            url: URL being analyzed
            headers: Response headers
        """
        csp = headers.get('Content-Security-Policy', '')

        if not csp:
            self._log(f"No CSP header found: {url}", 'debug')
            return

        # Look for frame-ancestors directive
        frame_ancestors_match = re.search(r'frame-ancestors\s+([^;]+)', csp, re.IGNORECASE)
        if frame_ancestors_match:
            frame_ancestors = frame_ancestors_match.group(1).strip()
            if frame_ancestors == "'none'":
                self._log(f"Good CSP frame-ancestors: {frame_ancestors}", 'info', 'green')
            elif "'self'" in frame_ancestors.lower():
                self._log(f"CSP frame-ancestors allows same origin: {frame_ancestors}", 'info', 'green')
            elif '*' in frame_ancestors:
                vuln = ClickjackingVulnerability(
                    url=url,
                    vulnerability_type='Weak CSP frame-ancestors',
                    severity='High',
                    description='CSP frame-ancestors allows all origins (*) or unsafe origins',
                    evidence=f'frame-ancestors: {frame_ancestors}',
                    recommendation='Restrict frame-ancestors to specific trusted origins or use \'none\''
                )
                self.vulnerabilities.append(vuln)
                self._log(f"Weak CSP frame-ancestors: {url}", 'warning', 'red')
            else:
                self._log(f"CSP frame-ancestors set: {frame_ancestors}", 'info', 'green')
        else:
            self._log(f"No frame-ancestors in CSP: {url}", 'debug')

    def _analyze_cors_headers(self, url: str, headers: Dict[str, str]) -> None:
        """
        Analyze CORS headers that might affect framing.

        Args:
            url: URL being analyzed
            headers: Response headers
        """
        cors_origin = headers.get('Access-Control-Allow-Origin', '')
        cors_credentials = headers.get('Access-Control-Allow-Credentials', '').lower()

        if cors_origin == '*' and cors_credentials == 'true':
            vuln = ClickjackingVulnerability(
                url=url,
                vulnerability_type='CORS Framing Risk',
                severity='Medium',
                description='CORS allows all origins with credentials, increasing clickjacking risk',
                evidence=f'ACAO: {cors_origin}, ACAC: {cors_credentials}',
                recommendation='Restrict CORS origins when using credentials'
            )
            self.vulnerabilities.append(vuln)
            self._log(f"CORS framing risk: {url}", 'warning', 'yellow')

    def _check_frame_busting_javascript(self, url: str, content: str) -> None:
        """
        Check for frame-busting JavaScript in page content.

        Args:
            url: URL being analyzed
            content: Page HTML content
        """
        if not self.config.check_javascript:
            return

        # Common frame-busting techniques
        frame_busters = [
            r'top\.location\s*!==\s*self\.location',
            r'top\.location\s*!=\s*self\.location',
            r'window\.top\s*!==\s*window\.self',
            r'window\.top\s*!=\s*window\.self',
            r'if\s*\(\s*window\s*!=\s*top\s*\)',
            r'if\s*\(\s*self\s*!=\s*top\s*\)',
            r'top\.location\.href\s*=\s*self\.location\.href',
            r'window\.top\.location\s*=\s*window\.self\.location'
        ]

        found_busters = []
        for pattern in frame_busters:
            if re.search(pattern, content, re.IGNORECASE):
                found_busters.append(pattern)

        if found_busters:
            self._log(f"Frame-busting JavaScript detected: {url}", 'info', 'green')
        else:
            vuln = ClickjackingVulnerability(
                url=url,
                vulnerability_type='Missing Frame-Busting',
                severity='Low',
                description='No frame-busting JavaScript detected in page',
                evidence='Page lacks frame-busting protection',
                recommendation='Consider adding frame-busting JavaScript as additional defense'
            )
            self.vulnerabilities.append(vuln)

    def _analyze_security_headers(self, url: str, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Analyze additional security headers.

        Args:
            url: URL being analyzed
            headers: Response headers

        Returns:
            Dictionary of header analysis results
        """
        security_headers = {
            'Strict-Transport-Security': {'present': False, 'value': '', 'recommendation': 'Implement HSTS'},
            'X-Content-Type-Options': {'present': False, 'value': '', 'recommendation': 'Set to nosniff'},
            'X-XSS-Protection': {'present': False, 'value': '', 'recommendation': 'Enable XSS protection'},
            'Referrer-Policy': {'present': False, 'value': '', 'recommendation': 'Set appropriate referrer policy'},
            'Permissions-Policy': {'present': False, 'value': '', 'recommendation': 'Implement permissions policy'},
            'Cross-Origin-Embedder-Policy': {'present': False, 'value': '', 'recommendation': 'Consider COEP'},
            'Cross-Origin-Opener-Policy': {'present': False, 'value': '', 'recommendation': 'Consider COOP'},
            'Cross-Origin-Resource-Policy': {'present': False, 'value': '', 'recommendation': 'Consider CORP'}
        }

        for header_name, info in security_headers.items():
            value = headers.get(header_name)
            if value:
                info['present'] = True
                info['value'] = value

        return security_headers

    def _test_page_framing(self, url: str) -> None:
        """
        Test if a page can be framed (practical clickjacking test).

        Args:
            url: URL to test for framing
        """
        # Create a simple test HTML page that tries to frame the target
        test_html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Framing Test</title></head>
        <body>
            <h1>Testing if {url} can be framed</h1>
            <iframe src="{url}" width="800" height="600" style="border:1px solid black;">
                <p>Your browser does not support iframes.</p>
            </iframe>
        </body>
        </html>
        """

        # In a real implementation, you might host this test page and check if it loads
        # For now, we'll just note that practical testing would require a test server
        self._log(f"Practical framing test would require test server for: {url}", 'debug')

    def scan_single_url(self, url: str) -> None:
        """
        Scan a single URL for clickjacking vulnerabilities.

        Args:
            url: URL to scan
        """
        self._log(f"Scanning {url} for clickjacking vulnerabilities", color='cyan')

        response = self._make_request(url)
        if not response:
            return

        headers = {k.lower(): v for k, v in response.headers.items()}
        content = response.text if self.config.check_javascript else ""

        # Analyze headers
        self._analyze_x_frame_options(url, headers)
        self._analyze_csp_frame_ancestors(url, headers)
        self._analyze_cors_headers(url, headers)

        # Analyze security headers
        security_analysis = self._analyze_security_headers(url, headers)

        # Check for frame-busting JavaScript
        if content:
            self._check_frame_busting_javascript(url, content)

        # Practical framing test (placeholder)
        self._test_page_framing(url)

        self.tested_urls.append(url)

    def discover_pages_to_test(self, base_url: str) -> List[str]:
        """
        Discover additional pages to test for clickjacking.

        Args:
            base_url: Base URL of the target

        Returns:
            List of URLs to test
        """
        pages_to_test = [base_url]

        if not self.config.test_multiple_pages:
            return pages_to_test

        # Common pages to test
        common_pages = [
            '/login', '/admin', '/dashboard', '/profile', '/settings',
            '/account', '/user', '/manage', '/control', '/panel'
        ]

        for page in common_pages:
            full_url = urljoin(base_url, page)
            if full_url not in pages_to_test:
                pages_to_test.append(full_url)

            if len(pages_to_test) >= self.config.max_pages_to_test:
                break

        return pages_to_test[:self.config.max_pages_to_test]

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
            'scan_type': 'Clickjacking Vulnerability Scan',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'urls_tested': len(self.tested_urls),
            'vulnerabilities_found': len(self.vulnerabilities),
            'severity_summary': severity_summary,
            'vulnerabilities': [
                {
                    'url': v.url,
                    'type': v.vulnerability_type,
                    'severity': v.severity,
                    'description': v.description,
                    'evidence': v.evidence,
                    'recommendation': v.recommendation
                } for v in self.vulnerabilities
            ],
            'tested_urls': self.tested_urls
        }

        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            self._log(f"Report saved to {output_file}", color='green')

        return report

    def scan(self, target_url: str, output_file: str = None) -> Dict:
        """
        Perform complete clickjacking vulnerability scan.

        Args:
            target_url: Base URL to scan
            output_file: Optional output file for report

        Returns:
            Scan results dictionary
        """
        self._log(f"Starting comprehensive clickjacking scan for {target_url}", color='cyan')

        # Ensure URL has proper format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        # Discover pages to test
        urls_to_test = self.discover_pages_to_test(target_url)

        # Scan each URL
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = [executor.submit(self.scan_single_url, url) for url in urls_to_test]
            for future in as_completed(futures):
                future.result()  # Wait for completion

        self._log(f"Clickjacking scan completed. Tested {len(self.tested_urls)} URLs, found {len(self.vulnerabilities)} issues", color='green')

        return self.generate_report(output_file)

def main():
    """Main function for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(description='Plascoy Clickjacking Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Skip SSL verification')
    parser.add_argument('--single-page', action='store_true', help='Test only the main page')
    parser.add_argument('--no-js-check', action='store_true', help='Skip JavaScript analysis')

    args = parser.parse_args()

    config = ClickjackingScanConfig(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        test_multiple_pages=not args.single_page,
        check_javascript=not args.no_js_check
    )

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    scanner = ClickjackingScanner(config)
    results = scanner.scan(args.target, args.output)

    print(f"\nScan Summary:")
    print(f"URLs tested: {results['urls_tested']}")
    print(f"Vulnerabilities found: {results['vulnerabilities_found']}")
    print(f"Critical: {results['severity_summary']['Critical']}")
    print(f"High: {results['severity_summary']['High']}")
    print(f"Medium: {results['severity_summary']['Medium']}")
    print(f"Low: {results['severity_summary']['Low']}")

    for vuln in results['vulnerabilities'][:5]:  # Show first 5
        print(f"- {vuln['severity'].upper()}: {vuln['type']} at {vuln['url']}")

if __name__ == '__main__':
    main()
