#!/usr/bin/env python3
"""
Advanced CORS Misconfiguration Scanner Module for Plascoy Security Scanner

This module performs comprehensive CORS (Cross-Origin Resource Sharing) security analysis including:
- Origin reflection and wildcard misconfigurations
- Credentialed request vulnerabilities
- Preflight request bypass testing
- Null origin handling issues
- Subdomain and protocol-based bypass attempts
- CORS header validation and security assessment
- Practical CORS exploitation testing

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
from typing import Dict, List, Optional, Tuple, Set
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
class CORSVulnerability:
    """Data class for CORS vulnerabilities"""
    origin_tested: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    recommendation: str

@dataclass
class CORSConfiguration:
    """Data class for CORS configuration analysis"""
    allow_origin: str
    allow_credentials: bool
    allow_methods: List[str]
    allow_headers: List[str]
    expose_headers: List[str]
    max_age: int
    is_wildcard: bool
    allows_credentials_with_wildcard: bool

@dataclass
class CORSAdvScanConfig:
    """Configuration for advanced CORS scanning"""
    timeout: int = 10
    max_workers: int = 5
    user_agent: str = 'Plascoy-CORS-Scanner/2.0'
    follow_redirects: bool = False
    verify_ssl: bool = False
    delay_between_requests: float = 0.1
    test_preflight: bool = True
    test_bypass_techniques: bool = True
    max_origins_to_test: int = 20
    check_multiple_endpoints: bool = True

class CORSAdvancedScanner:
    """
    Professional advanced CORS misconfiguration scanner with comprehensive features.

    This class provides methods to detect various CORS-related security vulnerabilities
    through extensive origin testing and configuration analysis.
    """

    def __init__(self, config: CORSAdvScanConfig = None):
        """
        Initialize the CORS advanced scanner with configuration.

        Args:
            config: CORSAdvScanConfig object with scanning parameters
        """
        self.config = config or CORSAdvScanConfig()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        self.session.verify = self.config.verify_ssl

        # Setup logging
        self.logger = logging.getLogger('CORSAdvancedScanner')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.vulnerabilities: List[CORSVulnerability] = []
        self.cors_configurations: List[CORSConfiguration] = []
        self.tested_origins: Set[str] = set()

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
        Make HTTP request with error handling.

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

    def _generate_test_origins(self, target_url: str) -> List[str]:
        """
        Generate a comprehensive list of test origins.

        Args:
            target_url: Target URL to base origins on

        Returns:
            List of origins to test
        """
        parsed = urlparse(target_url)
        domain = parsed.netloc
        scheme = parsed.scheme

        test_origins = [
            # Basic attacker domains
            'http://attacker.com',
            'https://attacker.com',
            'http://evil.com',
            'https://evil.com',

            # Localhost variations
            'http://localhost',
            'https://localhost',
            'http://localhost:3000',
            'https://localhost:3000',
            'http://127.0.0.1',
            'https://127.0.0.1',

            # Null origin
            'null',

            # Protocol variations
            target_url.replace('https://', 'http://'),
            target_url.replace('http://', 'https://'),

            # Subdomain variations
            f'http://{domain}.attacker.com',
            f'https://{domain}.attacker.com',
            f'http://sub.{domain}',
            f'https://sub.{domain}',

            # Port variations
            f'{scheme}://{domain}:8080',
            f'{scheme}://{domain}:8443',

            # International domain variations
            f'http://attacker.{domain}',
            f'https://attacker.{domain}',

            # Common development domains
            'http://dev.local',
            'https://dev.local',
            'http://test.local',
            'https://test.local',
        ]

        # Add some random-looking domains
        random_domains = [
            'http://cors-test-123.com',
            'https://xss-payload.net',
            'http://callback.hook.io',
            'https://webhook.site',
        ]

        test_origins.extend(random_domains)

        return test_origins[:self.config.max_origins_to_test]

    def _parse_cors_headers(self, response: requests.Response) -> CORSConfiguration:
        """
        Parse CORS-related headers from response.

        Args:
            response: HTTP response

        Returns:
            CORSConfiguration object
        """
        headers = response.headers

        config = CORSConfiguration(
            allow_origin=headers.get('Access-Control-Allow-Origin', ''),
            allow_credentials=headers.get('Access-Control-Allow-Credentials', '').lower() == 'true',
            allow_methods=headers.get('Access-Control-Allow-Methods', '').split(', '),
            allow_headers=headers.get('Access-Control-Allow-Headers', '').split(', '),
            expose_headers=headers.get('Access-Control-Expose-Headers', '').split(', '),
            max_age=int(headers.get('Access-Control-Max-Age', 0)),
            is_wildcard=headers.get('Access-Control-Allow-Origin', '') == '*',
            allows_credentials_with_wildcard=False
        )

        config.allows_credentials_with_wildcard = config.is_wildcard and config.allow_credentials

        return config

    def _analyze_cors_configuration(self, config: CORSConfiguration, origin: str) -> List[CORSVulnerability]:
        """
        Analyze CORS configuration for vulnerabilities.

        Args:
            config: CORS configuration to analyze
            origin: Origin that was tested

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        # Check for wildcard with credentials
        if config.allows_credentials_with_wildcard:
            vuln = CORSVulnerability(
                origin_tested=origin,
                vulnerability_type='Wildcard Origin with Credentials',
                severity='Critical',
                description='Access-Control-Allow-Origin is set to * with Access-Control-Allow-Credentials: true',
                evidence='ACAO: *, ACAC: true',
                recommendation='Never use wildcard (*) origin with credentials enabled'
            )
            vulnerabilities.append(vuln)

        # Check for origin reflection
        elif config.allow_origin == origin and origin not in ['null', '']:
            vuln = CORSVulnerability(
                origin_tested=origin,
                vulnerability_type='Origin Reflection',
                severity='High',
                description=f'CORS allows arbitrary origin reflection: {origin}',
                evidence=f'ACAO: {config.allow_origin}',
                recommendation='Specify trusted origins explicitly, avoid origin reflection'
            )
            vulnerabilities.append(vuln)

        # Check for null origin handling
        elif origin == 'null' and config.allow_origin == 'null':
            vuln = CORSVulnerability(
                origin_tested=origin,
                vulnerability_type='Null Origin Allowed',
                severity='Medium',
                description='CORS allows null origin, potentially vulnerable to sandboxed frames',
                evidence='ACAO: null',
                recommendation='Avoid allowing null origin unless specifically required'
            )
            vulnerabilities.append(vuln)

        # Check for overly permissive methods
        dangerous_methods = ['PUT', 'DELETE', 'PATCH']
        allowed_dangerous = [m for m in config.allow_methods if m.upper() in dangerous_methods]
        if allowed_dangerous and config.allow_origin not in ['', 'null']:
            vuln = CORSVulnerability(
                origin_tested=origin,
                vulnerability_type='Dangerous Methods Allowed',
                severity='Medium',
                description=f'CORS allows dangerous HTTP methods: {", ".join(allowed_dangerous)}',
                evidence=f'ACAM: {", ".join(config.allow_methods)}',
                recommendation='Restrict allowed methods to safe operations only'
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_preflight_request(self, url: str, origin: str) -> Optional[CORSConfiguration]:
        """
        Test CORS preflight request (OPTIONS).

        Args:
            url: Target URL
            origin: Origin to test

        Returns:
            CORS configuration from preflight response
        """
        if not self.config.test_preflight:
            return None

        preflight_headers = {
            'Origin': origin,
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'X-Custom-Header'
        }

        response = self._make_request(url, method='OPTIONS', headers=preflight_headers)
        if response:
            config = self._parse_cors_headers(response)
            self.cors_configurations.append(config)
            return config

        return None

    def _test_cors_bypass_techniques(self, base_url: str) -> None:
        """
        Test various CORS bypass techniques.

        Args:
            base_url: Base URL to test
        """
        if not self.config.test_bypass_techniques:
            return

        self._log("Testing CORS bypass techniques", color='cyan')

        bypass_tests = [
            # JSONP-like endpoints
            {'url': urljoin(base_url, '/api/jsonp'), 'params': {'callback': 'alert'}},
            {'url': urljoin(base_url, '/jsonp'), 'params': {'callback': 'evil'}},

            # CORS with JSONP
            {'url': urljoin(base_url, '/api/data'), 'headers': {'Accept': 'application/json'}},

            # Development endpoints
            {'url': urljoin(base_url, '/api/dev'), 'headers': {'Origin': 'http://localhost:3000'}},

            # Alternative origins
            {'url': base_url, 'headers': {'Origin': 'https://webhook.site/123'}},
        ]

        for test in bypass_tests:
            url = test['url']
            headers = test.get('headers', {})
            params = test.get('params', {})

            response = self._make_request(url, headers=headers, params=params)
            if response:
                config = self._parse_cors_headers(response)
                if config.allow_origin and config.allow_origin != 'null':
                    origin = headers.get('Origin', 'default')
                    vulnerabilities = self._analyze_cors_configuration(config, origin)
                    self.vulnerabilities.extend(vulnerabilities)

                    if vulnerabilities:
                        self._log(f"CORS bypass possible: {url}", 'warning', 'red')

    def _discover_cors_endpoints(self, base_url: str) -> List[str]:
        """
        Discover endpoints that might have CORS enabled.

        Args:
            base_url: Base URL to scan

        Returns:
            List of endpoints to test
        """
        endpoints = [base_url]

        if not self.config.check_multiple_endpoints:
            return endpoints

        # Common API endpoints
        api_endpoints = [
            '/api/', '/api/v1/', '/api/v2/', '/rest/', '/graphql',
            '/api/users', '/api/data', '/api/config', '/api/auth',
            '/api/login', '/api/logout', '/api/register', '/api/profile',
            '/api/admin', '/api/manage', '/api/system', '/api/debug'
        ]

        for endpoint in api_endpoints:
            url = urljoin(base_url, endpoint)
            if url not in endpoints:
                endpoints.append(url)

        return endpoints[:10]  # Limit to prevent too many requests

    def test_origin(self, url: str, origin: str) -> None:
        """
        Test a specific origin against a URL.

        Args:
            url: Target URL
            origin: Origin to test
        """
        if origin in self.tested_origins:
            return

        self.tested_origins.add(origin)

        # Test simple request
        headers = {'Origin': origin}
        response = self._make_request(url, headers=headers)

        if response:
            config = self._parse_cors_headers(response)
            self.cors_configurations.append(config)

            # Analyze configuration
            vulnerabilities = self._analyze_cors_configuration(config, origin)
            self.vulnerabilities.extend(vulnerabilities)

            # Test preflight if configured
            preflight_config = self._test_preflight_request(url, origin)
            if preflight_config:
                preflight_vulns = self._analyze_cors_configuration(preflight_config, origin)
                self.vulnerabilities.extend(preflight_vulns)

            # Log results
            if config.allow_origin:
                self._log(f"CORS configured for origin '{origin}': ACAO={config.allow_origin}", 'info')
                if vulnerabilities:
                    self._log(f"Vulnerabilities found for origin '{origin}'", 'warning', 'red')

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

        # Analyze CORS configurations
        wildcard_count = len([c for c in self.cors_configurations if c.is_wildcard])
        credentials_count = len([c for c in self.cors_configurations if c.allow_credentials])

        report = {
            'scan_type': 'Advanced CORS Misconfiguration Scan',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'origins_tested': len(self.tested_origins),
            'endpoints_tested': len(set(c.__dict__.get('url', '') for c in self.cors_configurations)),
            'vulnerabilities_found': len(self.vulnerabilities),
            'severity_summary': severity_summary,
            'cors_summary': {
                'total_configurations': len(self.cors_configurations),
                'wildcard_origins': wildcard_count,
                'credentials_enabled': credentials_count,
                'dangerous_combinations': len([c for c in self.cors_configurations if c.allows_credentials_with_wildcard])
            },
            'vulnerabilities': [
                {
                    'origin_tested': v.origin_tested,
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
        Perform complete advanced CORS misconfiguration scan.

        Args:
            target_url: Base URL to scan
            output_file: Optional output file for report

        Returns:
            Scan results dictionary
        """
        self._log(f"Starting advanced CORS scan for {target_url}", color='cyan')

        # Ensure URL has proper format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        # Discover endpoints to test
        endpoints = self._discover_cors_endpoints(target_url)

        # Generate test origins
        test_origins = self._generate_test_origins(target_url)

        # Test each origin against each endpoint
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = []
            for endpoint in endpoints:
                for origin in test_origins:
                    futures.append(executor.submit(self.test_origin, endpoint, origin))

            # Wait for all tests to complete
            for future in as_completed(futures):
                future.result()

        # Test bypass techniques
        if self.config.test_bypass_techniques:
            self._test_cors_bypass_techniques(target_url)

        self._log(f"CORS scan completed. Tested {len(self.tested_origins)} origins, found {len(self.vulnerabilities)} vulnerabilities", color='green')

        return self.generate_report(output_file)

def main():
    """Main function for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(description='Plascoy Advanced CORS Misconfiguration Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Skip SSL verification')
    parser.add_argument('--no-preflight', action='store_true', help='Skip preflight request testing')
    parser.add_argument('--no-bypass', action='store_true', help='Skip bypass technique testing')
    parser.add_argument('--single-endpoint', action='store_true', help='Test only main endpoint')

    args = parser.parse_args()

    config = CORSAdvScanConfig(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        test_preflight=not args.no_preflight,
        test_bypass_techniques=not args.no_bypass,
        check_multiple_endpoints=not args.single_endpoint
    )

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    scanner = CORSAdvancedScanner(config)
    results = scanner.scan(args.target, args.output)

    print(f"\nScan Summary:")
    print(f"Origins tested: {results['origins_tested']}")
    print(f"Endpoints tested: {results['endpoints_tested']}")
    print(f"Vulnerabilities found: {results['vulnerabilities_found']}")
    print(f"Critical: {results['severity_summary']['Critical']}")
    print(f"High: {results['severity_summary']['High']}")
    print(f"Medium: {results['severity_summary']['Medium']}")
    print(f"Low: {results['severity_summary']['Low']}")

    cors_summary = results['cors_summary']
    print(f"\nCORS Configuration Summary:")
    print(f"Total configurations: {cors_summary['total_configurations']}")
    print(f"Wildcard origins: {cors_summary['wildcard_origins']}")
    print(f"Credentials enabled: {cors_summary['credentials_enabled']}")
    print(f"Dangerous combinations: {cors_summary['dangerous_combinations']}")

    for vuln in results['vulnerabilities'][:5]:  # Show first 5
        print(f"- {vuln['severity'].upper()}: {vuln['type']} (Origin: {vuln['origin_tested']})")

if __name__ == '__main__':
    main()
