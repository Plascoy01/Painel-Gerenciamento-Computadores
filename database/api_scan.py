"""
API Scanner Module for Plascoy Security Scanner

This module performs comprehensive API vulnerability scanning including:
- Endpoint discovery and enumeration
- Authentication bypass attempts
- Sensitive data exposure checks
- CORS misconfiguration detection
- Rate limiting assessment
- API documentation exposure
- Common API vulnerabilities

Author: Plascoy Team
Version: 2.0
"""

import requests
import logging
import json
import time
import os
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
class ApiVulnerability:
    """Data class for API vulnerabilities"""
    url: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    recommendation: str

@dataclass
class ScanConfig:
    """Configuration for API scanning"""
    timeout: int = 10
    max_workers: int = 5
    user_agent: str = 'Plascoy-API-Scanner/2.0'
    follow_redirects: bool = True
    verify_ssl: bool = False
    delay_between_requests: float = 0.1
    max_endpoints: int = 100

class ApiScanner:
    """
    Professional API vulnerability scanner with comprehensive features.

    This class provides methods to scan web APIs for common vulnerabilities
    including endpoint enumeration, authentication issues, and configuration problems.
    """

    def __init__(self, config: ScanConfig = None):
        """
        Initialize the API scanner with configuration.

        Args:
            config: ScanConfig object with scanning parameters
        """
        self.config = config or ScanConfig()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        self.session.verify = self.config.verify_ssl

        # Setup logging
        self.logger = logging.getLogger('ApiScanner')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.vulnerabilities: List[ApiVulnerability] = []
        self.discovered_endpoints: List[str] = []

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

    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling and retry logic.

        Args:
            url: Target URL
            method: HTTP method
            **kwargs: Additional request parameters

        Returns:
            Response object or None if failed
        """
        try:
            time.sleep(self.config.delay_between_requests)
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.config.timeout,
                allow_redirects=self.config.follow_redirects,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            self._log(f"Request failed for {url}: {e}", 'debug')
            return None

    def _check_endpoint_accessibility(self, url: str) -> Tuple[bool, int, str]:
        """
        Check if an endpoint is accessible and return status.

        Args:
            url: Endpoint URL to check

        Returns:
            Tuple of (accessible, status_code, content_type)
        """
        response = self._make_request(url)
        if response:
            content_type = response.headers.get('content-type', '').lower()
            return True, response.status_code, content_type
        return False, 0, ''

    def enumerate_endpoints(self, base_url: str) -> List[str]:
        """
        Enumerate common API endpoints.

        Args:
            base_url: Base URL of the target API

        Returns:
            List of discovered endpoints
        """
        self._log("Starting API endpoint enumeration", color='cyan')

        common_endpoints = [
            # REST API endpoints
            '/api/v1/', '/api/v2/', '/api/', '/rest/',
            '/api/v1/users', '/api/v1/admin', '/api/v1/config',
            '/api/v1/debug', '/api/v1/status', '/api/v1/health',
            '/api/v1/auth', '/api/v1/login', '/api/v1/logout',
            '/api/v1/register', '/api/v1/profile', '/api/v1/settings',

            # GraphQL
            '/graphql', '/graphiql', '/api/graphql',

            # Documentation
            '/api/docs', '/swagger.json', '/swagger.yaml',
            '/api/swagger', '/api-docs', '/openapi.json',

            # Admin endpoints
            '/admin/api', '/api/admin', '/api/management',
            '/api/system', '/api/internal', '/api/debug',

            # Common API patterns
            '/api/v1/posts', '/api/v1/comments', '/api/v1/files',
            '/api/v1/uploads', '/api/v1/downloads', '/api/v1/search',
            '/api/v1/export', '/api/v1/import', '/api/v1/backup',

            # Version-specific
            '/api/v3/', '/api/beta/', '/api/dev/', '/api/test/',
        ]

        discovered = []

        def check_endpoint(endpoint: str) -> Optional[str]:
            full_url = urljoin(base_url, endpoint)
            accessible, status, content_type = self._check_endpoint_accessibility(full_url)
            if accessible and status in [200, 201, 401, 403]:
                if 'json' in content_type or 'xml' in content_type or status == 401:
                    return full_url
            return None

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = [executor.submit(check_endpoint, ep) for ep in common_endpoints]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
                    self._log(f"Discovered endpoint: {result}", color='yellow')

        self.discovered_endpoints = discovered[:self.config.max_endpoints]
        return self.discovered_endpoints

    def check_authentication_bypass(self, endpoints: List[str]) -> None:
        """Check for authentication bypass vulnerabilities."""
        self._log("Checking for authentication bypass vulnerabilities", color='cyan')

        bypass_payloads = [
            {'Authorization': 'Bearer invalid_token'},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='},  # admin:admin
            {'api_key': 'invalid_key'},
            {'token': 'invalid_token'},
            {'auth': 'admin'},
            {},  # No auth headers
        ]

        for url in endpoints:
            for payload in bypass_payloads:
                headers = self.session.headers.copy()
                headers.update(payload)
                response = self._make_request(url, headers=headers)
                if response and response.status_code == 200:
                    # Check if response contains sensitive data
                    content = response.text.lower()
                    if any(word in content for word in ['admin', 'config', 'secret', 'password']):
                        vuln = ApiVulnerability(
                            url=url,
                            vulnerability_type='Authentication Bypass',
                            severity='High',
                            description='Endpoint accessible without proper authentication',
                            evidence=f"Status: {response.status_code}, Headers: {payload}",
                            recommendation='Implement proper authentication and authorization checks'
                        )
                        self.vulnerabilities.append(vuln)
                        self._log(f"Auth bypass found: {url}", 'warning', 'red')

    def check_cors_misconfiguration(self, endpoints: List[str]) -> None:
        """Check for CORS misconfiguration vulnerabilities."""
        self._log("Checking for CORS misconfigurations", color='cyan')

        cors_headers = {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'Authorization'
        }

        for url in endpoints:
            response = self._make_request(url, method='OPTIONS', headers=cors_headers)
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()

                if acao == '*' and acac == 'true':
                    vuln = ApiVulnerability(
                        url=url,
                        vulnerability_type='CORS Misconfiguration',
                        severity='Medium',
                        description='CORS allows all origins with credentials',
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        recommendation='Restrict CORS origins and avoid credentials with wildcard'
                    )
                    self.vulnerabilities.append(vuln)
                    self._log(f"CORS issue found: {url}", 'warning', 'red')

    def check_sensitive_data_exposure(self, endpoints: List[str]) -> None:
        """Check for sensitive data exposure in API responses."""
        self._log("Checking for sensitive data exposure", color='cyan')

        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'api_key', 'apikey',
            'admin', 'config', 'database', 'db', 'internal', 'private'
        ]

        for url in endpoints:
            response = self._make_request(url)
            if response and response.status_code == 200:
                content = response.text.lower()
                found_keywords = [kw for kw in sensitive_keywords if kw in content]
                if found_keywords:
                    vuln = ApiVulnerability(
                        url=url,
                        vulnerability_type='Sensitive Data Exposure',
                        severity='High',
                        description=f'Sensitive keywords found in response: {", ".join(found_keywords)}',
                        evidence=f"Response contains: {found_keywords[:3]}...",
                        recommendation='Avoid exposing sensitive information in API responses'
                    )
                    self.vulnerabilities.append(vuln)
                    self._log(f"Sensitive data exposure: {url}", 'warning', 'red')

    def check_rate_limiting(self, url: str) -> None:
        """Check for rate limiting implementation."""
        self._log(f"Checking rate limiting for {url}", color='cyan')

        responses = []
        for i in range(10):  # Send 10 rapid requests
            response = self._make_request(url)
            if response:
                responses.append(response.status_code)
            time.sleep(0.05)  # Small delay

        rate_limited_responses = [code for code in responses if code in [429, 503]]
        if not rate_limited_responses:
            vuln = ApiVulnerability(
                url=url,
                vulnerability_type='Missing Rate Limiting',
                severity='Medium',
                description='No rate limiting detected after multiple requests',
                evidence=f"Response codes: {responses}",
                recommendation='Implement rate limiting to prevent abuse'
            )
            self.vulnerabilities.append(vuln)
            self._log(f"No rate limiting: {url}", 'warning', 'yellow')

    def check_http_methods(self, endpoints: List[str]) -> None:
        """Check for dangerous HTTP methods enabled."""
        self._log("Checking for dangerous HTTP methods", color='cyan')

        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']

        for url in endpoints:
            for method in dangerous_methods:
                response = self._make_request(url, method=method)
                if response and response.status_code not in [405, 501]:
                    vuln = ApiVulnerability(
                        url=url,
                        vulnerability_type='Dangerous HTTP Method',
                        severity='Medium',
                        description=f'Dangerous HTTP method {method} is enabled',
                        evidence=f"Method: {method}, Status: {response.status_code}",
                        recommendation='Disable unnecessary HTTP methods'
                    )
                    self.vulnerabilities.append(vuln)
                    self._log(f"Dangerous method {method} enabled: {url}", 'warning', 'red')

    def generate_report(self, output_file: str = None) -> Dict:
        """
        Generate comprehensive scan report.

        Args:
            output_file: Optional file path to save JSON report

        Returns:
            Dictionary containing scan results
        """
        report = {
            'scan_type': 'API Vulnerability Scan',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_endpoints_scanned': len(self.discovered_endpoints),
            'vulnerabilities_found': len(self.vulnerabilities),
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
            'discovered_endpoints': self.discovered_endpoints
        }

        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            self._log(f"Report saved to {output_file}", color='green')

        return report

    def scan(self, target_url: str, output_file: str = None) -> Dict:
        """
        Perform complete API vulnerability scan.

        Args:
            target_url: Base URL to scan
            output_file: Optional output file for report

        Returns:
            Scan results dictionary
        """
        self._log(f"Starting comprehensive API scan for {target_url}", color='cyan')

        # Ensure URL has proper format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        # Enumerate endpoints
        endpoints = self.enumerate_endpoints(target_url)

        if not endpoints:
            self._log("No API endpoints discovered", 'warning', 'yellow')
            return self.generate_report(output_file)

        # Perform vulnerability checks
        self.check_authentication_bypass(endpoints)
        self.check_cors_misconfiguration(endpoints)
        self.check_sensitive_data_exposure(endpoints)
        self.check_http_methods(endpoints)

        # Check rate limiting on main endpoint
        self.check_rate_limiting(endpoints[0] if endpoints else target_url)

        self._log(f"API scan completed. Found {len(self.vulnerabilities)} vulnerabilities", color='green')

        return self.generate_report(output_file)

def main():
    """Main function for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(description='Plascoy API Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Skip SSL verification')

    args = parser.parse_args()

    config = ScanConfig(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify
    )

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    scanner = ApiScanner(config)
    results = scanner.scan(args.target, args.output)

    print(f"\nScan Summary:")
    print(f"Endpoints discovered: {results['total_endpoints_scanned']}")
    print(f"Vulnerabilities found: {results['vulnerabilities_found']}")

    for vuln in results['vulnerabilities']:
        print(f"- {vuln['severity']}: {vuln['type']} at {vuln['url']}")

if __name__ == '__main__':
    main()