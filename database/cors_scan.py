#!/usr/bin/env python3
"""
CORS (Cross-Origin Resource Sharing) Vulnerability Scanner
Scans for CORS misconfigurations that could lead to security vulnerabilities
"""

import requests
import logging
import json
import time
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class CORSResult:
    """Data class for CORS scan results"""
    url: str
    status_code: int
    cors_headers: Dict[str, str]
    vulnerabilities: List[str]
    recommendations: List[str]
    timestamp: float
    response_time: float

class CORSScanner:
    """
    Advanced CORS vulnerability scanner with comprehensive testing
    """

    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize CORS scanner

        Args:
            target: Target URL to scan
            config: Configuration dictionary
        """
        self.target = self._normalize_url(target)
        self.config = config or self._default_config()
        self.session = self._create_session()
        self.results: List[CORSResult] = []
        self.vulnerable_endpoints: List[str] = []

        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def _default_config(self) -> Dict:
        """Default configuration settings"""
        return {
            'timeout': 10,
            'max_workers': 5,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'verify_ssl': False,
            'test_origins': [
                'https://evil.com',
                'https://attacker.com',
                'null',
                'https://localhost',
                'https://127.0.0.1',
                'https://example.com'
            ],
            'test_methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            'test_headers': [
                'Authorization',
                'Cookie',
                'X-Custom-Header'
            ],
            'rate_limit': 1,  # seconds between requests
            'max_retries': 3
        }

    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.config['user_agent']
        })
        session.verify = self.config['verify_ssl']
        return session

    def scan(self) -> Dict:
        """
        Perform comprehensive CORS scan

        Returns:
            Dictionary containing scan results and summary
        """
        self.logger.info(f"Starting CORS scan for {self.target}")

        try:
            # Test basic CORS configuration
            basic_result = self._test_basic_cors()
            self.results.append(basic_result)

            # Test preflight requests
            preflight_results = self._test_preflight_requests()
            self.results.extend(preflight_results)

            # Test credentialed requests
            credential_results = self._test_credentialed_requests()
            self.results.extend(credential_results)

            # Test wildcard origins
            wildcard_results = self._test_wildcard_origins()
            self.results.extend(wildcard_results)

            # Test null origin
            null_result = self._test_null_origin()
            self.results.append(null_result)

            # Analyze results
            analysis = self._analyze_results()

            self.logger.info(f"CORS scan completed. Found {len(self.vulnerable_endpoints)} vulnerable endpoints")

            return {
                'target': self.target,
                'results': [asdict(result) for result in self.results],
                'vulnerable_endpoints': self.vulnerable_endpoints,
                'analysis': analysis,
                'scan_config': self.config
            }

        except Exception as e:
            self.logger.error(f"Error during CORS scan: {e}")
            raise

    def _test_basic_cors(self) -> CORSResult:
        """Test basic CORS headers"""
        start_time = time.time()

        try:
            response = self.session.get(
                self.target,
                timeout=self.config['timeout'],
                headers={'Origin': self.config['test_origins'][0]}
            )

            cors_headers = self._extract_cors_headers(response.headers)
            vulnerabilities = self._check_basic_vulnerabilities(cors_headers)
            recommendations = self._generate_recommendations(vulnerabilities)

            result = CORSResult(
                url=self.target,
                status_code=response.status_code,
                cors_headers=cors_headers,
                vulnerabilities=vulnerabilities,
                recommendations=recommendations,
                timestamp=time.time(),
                response_time=time.time() - start_time
            )

            if vulnerabilities:
                self.vulnerable_endpoints.append(self.target)

            return result

        except requests.RequestException as e:
            self.logger.warning(f"Request failed for {self.target}: {e}")
            return CORSResult(
                url=self.target,
                status_code=0,
                cors_headers={},
                vulnerabilities=['Request failed'],
                recommendations=['Verify target is accessible'],
                timestamp=time.time(),
                response_time=time.time() - start_time
            )

    def _test_preflight_requests(self) -> List[CORSResult]:
        """Test CORS preflight requests"""
        results = []

        for method in self.config['test_methods']:
            for origin in self.config['test_origins'][:3]:  # Test first 3 origins
                start_time = time.time()

                try:
                    headers = {
                        'Origin': origin,
                        'Access-Control-Request-Method': method,
                        'Access-Control-Request-Headers': ','.join(self.config['test_headers'])
                    }

                    response = self.session.options(
                        self.target,
                        headers=headers,
                        timeout=self.config['timeout']
                    )

                    cors_headers = self._extract_cors_headers(response.headers)
                    vulnerabilities = self._check_preflight_vulnerabilities(cors_headers, method, origin)
                    recommendations = self._generate_recommendations(vulnerabilities)

                    result = CORSResult(
                        url=f"{self.target} (OPTIONS {method} from {origin})",
                        status_code=response.status_code,
                        cors_headers=cors_headers,
                        vulnerabilities=vulnerabilities,
                        recommendations=recommendations,
                        timestamp=time.time(),
                        response_time=time.time() - start_time
                    )

                    results.append(result)

                    if vulnerabilities:
                        self.vulnerable_endpoints.append(result.url)

                    # Rate limiting
                    time.sleep(self.config['rate_limit'])

                except requests.RequestException as e:
                    self.logger.warning(f"Preflight request failed: {e}")

        return results

    def _test_credentialed_requests(self) -> List[CORSResult]:
        """Test CORS with credentials"""
        results = []

        for origin in self.config['test_origins'][:3]:
            start_time = time.time()

            try:
                headers = {
                    'Origin': origin,
                    'Cookie': 'test=value'
                }

                response = self.session.get(
                    self.target,
                    headers=headers,
                    timeout=self.config['timeout']
                )

                cors_headers = self._extract_cors_headers(response.headers)
                vulnerabilities = self._check_credential_vulnerabilities(cors_headers, origin)
                recommendations = self._generate_recommendations(vulnerabilities)

                result = CORSResult(
                    url=f"{self.target} (with credentials from {origin})",
                    status_code=response.status_code,
                    cors_headers=cors_headers,
                    vulnerabilities=vulnerabilities,
                    recommendations=recommendations,
                    timestamp=time.time(),
                    response_time=time.time() - start_time
                )

                results.append(result)

                if vulnerabilities:
                    self.vulnerable_endpoints.append(result.url)

                time.sleep(self.config['rate_limit'])

            except requests.RequestException as e:
                self.logger.warning(f"Credentialed request failed: {e}")

        return results

    def _test_wildcard_origins(self) -> List[CORSResult]:
        """Test wildcard origin configurations"""
        results = []

        # Test with wildcard in origin
        test_urls = [
            self.target,
            f"{self.target}/api",
            f"{self.target}/cors-test"
        ]

        for url in test_urls:
            start_time = time.time()

            try:
                response = self.session.get(
                    url,
                    headers={'Origin': '*'},
                    timeout=self.config['timeout']
                )

                cors_headers = self._extract_cors_headers(response.headers)
                vulnerabilities = self._check_wildcard_vulnerabilities(cors_headers)
                recommendations = self._generate_recommendations(vulnerabilities)

                result = CORSResult(
                    url=f"{url} (wildcard origin)",
                    status_code=response.status_code,
                    cors_headers=cors_headers,
                    vulnerabilities=vulnerabilities,
                    recommendations=recommendations,
                    timestamp=time.time(),
                    response_time=time.time() - start_time
                )

                results.append(result)

                if vulnerabilities:
                    self.vulnerable_endpoints.append(result.url)

                time.sleep(self.config['rate_limit'])

            except requests.RequestException as e:
                self.logger.warning(f"Wildcard test failed for {url}: {e}")

        return results

    def _test_null_origin(self) -> CORSResult:
        """Test null origin handling"""
        start_time = time.time()

        try:
            response = self.session.get(
                self.target,
                headers={'Origin': 'null'},
                timeout=self.config['timeout']
            )

            cors_headers = self._extract_cors_headers(response.headers)
            vulnerabilities = self._check_null_origin_vulnerabilities(cors_headers)
            recommendations = self._generate_recommendations(vulnerabilities)

            result = CORSResult(
                url=f"{self.target} (null origin)",
                status_code=response.status_code,
                cors_headers=cors_headers,
                vulnerabilities=vulnerabilities,
                recommendations=recommendations,
                timestamp=time.time(),
                response_time=time.time() - start_time
            )

            if vulnerabilities:
                self.vulnerable_endpoints.append(result.url)

            return result

        except requests.RequestException as e:
            self.logger.warning(f"Null origin test failed: {e}")
            return CORSResult(
                url=f"{self.target} (null origin)",
                status_code=0,
                cors_headers={},
                vulnerabilities=[],
                recommendations=[],
                timestamp=time.time(),
                response_time=time.time() - start_time
            )

    def _extract_cors_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract CORS-related headers from response"""
        cors_headers = {}
        cors_header_names = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Credentials',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Max-Age',
            'Access-Control-Expose-Headers'
        ]

        for header_name in cors_header_names:
            if header_name in headers:
                cors_headers[header_name] = headers[header_name]

        return cors_headers

    def _check_basic_vulnerabilities(self, cors_headers: Dict[str, str]) -> List[str]:
        """Check for basic CORS vulnerabilities"""
        vulnerabilities = []

        origin = cors_headers.get('Access-Control-Allow-Origin', '')
        credentials = cors_headers.get('Access-Control-Allow-Credentials', '').lower()

        if origin == '*':
            if credentials == 'true':
                vulnerabilities.append("Wildcard origin (*) with credentials enabled - allows any site to make authenticated requests")
            else:
                vulnerabilities.append("Wildcard origin (*) allows any site to read responses")

        if origin and origin != '*':
            # Check if origin reflects user input (potential for header injection)
            if re.search(r'[^\w\.\-\:\/]', origin):
                vulnerabilities.append("Origin header contains suspicious characters - possible header injection")

        return vulnerabilities

    def _check_preflight_vulnerabilities(self, cors_headers: Dict[str, str], method: str, origin: str) -> List[str]:
        """Check preflight request vulnerabilities"""
        vulnerabilities = []

        allowed_methods = cors_headers.get('Access-Control-Allow-Methods', '')
        allowed_headers = cors_headers.get('Access-Control-Allow-Headers', '')
        allow_origin = cors_headers.get('Access-Control-Allow-Origin', '')

        if allow_origin == '*':
            vulnerabilities.append(f"Preflight allows any origin (*) for {method} requests")

        if allowed_methods:
            if 'PUT' in allowed_methods or 'DELETE' in allowed_methods:
                vulnerabilities.append(f"Dangerous methods ({allowed_methods}) allowed in preflight")

        if allowed_headers:
            sensitive_headers = ['authorization', 'cookie', 'x-api-key']
            for header in sensitive_headers:
                if header.lower() in allowed_headers.lower():
                    vulnerabilities.append(f"Sensitive header '{header}' allowed in preflight")

        return vulnerabilities

    def _check_credential_vulnerabilities(self, cors_headers: Dict[str, str], origin: str) -> List[str]:
        """Check credential-related vulnerabilities"""
        vulnerabilities = []

        credentials = cors_headers.get('Access-Control-Allow-Credentials', '').lower()
        allow_origin = cors_headers.get('Access-Control-Allow-Origin', '')

        if credentials == 'true':
            if allow_origin == '*':
                vulnerabilities.append("Credentials enabled with wildcard origin - severe vulnerability")
            elif allow_origin and allow_origin != origin:
                vulnerabilities.append(f"Credentials enabled but origin mismatch: expected {origin}, got {allow_origin}")

        return vulnerabilities

    def _check_wildcard_vulnerabilities(self, cors_headers: Dict[str, str]) -> List[str]:
        """Check wildcard-related vulnerabilities"""
        vulnerabilities = []

        allow_origin = cors_headers.get('Access-Control-Allow-Origin', '')

        if allow_origin == '*':
            vulnerabilities.append("Wildcard origin (*) in response - allows any site to access this resource")

        return vulnerabilities

    def _check_null_origin_vulnerabilities(self, cors_headers: Dict[str, str]) -> List[str]:
        """Check null origin vulnerabilities"""
        vulnerabilities = []

        allow_origin = cors_headers.get('Access-Control-Allow-Origin', '')

        if allow_origin == 'null':
            vulnerabilities.append("Null origin explicitly allowed - potential for sandboxed domain attacks")

        return vulnerabilities

    def _generate_recommendations(self, vulnerabilities: List[str]) -> List[str]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []

        vuln_patterns = {
            'wildcard': "Specify exact origins instead of using '*'",
            'credentials': "Avoid using 'Access-Control-Allow-Credentials: true' with wildcard origins",
            'methods': "Restrict allowed methods to only necessary ones",
            'headers': "Avoid allowing sensitive headers like Authorization or Cookie",
            'null': "Do not explicitly allow 'null' origin unless absolutely necessary"
        }

        for vuln in vulnerabilities:
            for pattern, rec in vuln_patterns.items():
                if pattern.lower() in vuln.lower():
                    if rec not in recommendations:
                        recommendations.append(rec)

        if not recommendations:
            recommendations.append("CORS configuration appears secure")

        return recommendations

    def _analyze_results(self) -> Dict:
        """Analyze all scan results"""
        total_tests = len(self.results)
        vulnerable_tests = len([r for r in self.results if r.vulnerabilities])
        unique_vulnerabilities = set()

        for result in self.results:
            unique_vulnerabilities.update(result.vulnerabilities)

        severity_levels = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        for vuln in unique_vulnerabilities:
            if 'wildcard' in vuln.lower() and 'credentials' in vuln.lower():
                severity_levels['critical'] += 1
            elif 'wildcard' in vuln.lower() or 'credentials' in vuln.lower():
                severity_levels['high'] += 1
            elif 'dangerous' in vuln.lower() or 'sensitive' in vuln.lower():
                severity_levels['medium'] += 1
            else:
                severity_levels['low'] += 1

        return {
            'total_tests': total_tests,
            'vulnerable_tests': vulnerable_tests,
            'unique_vulnerabilities': len(unique_vulnerabilities),
            'severity_breakdown': severity_levels,
            'risk_level': self._calculate_risk_level(severity_levels)
        }

    def _calculate_risk_level(self, severity: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        if severity['critical'] > 0:
            return 'CRITICAL'
        elif severity['high'] > 0:
            return 'HIGH'
        elif severity['medium'] > 0:
            return 'MEDIUM'
        elif severity['low'] > 0:
            return 'LOW'
        else:
            return 'SAFE'

def cors_scan(target: str, verbose: bool = False, config: Optional[Dict] = None) -> Dict:
    """
    Main CORS scanning function

    Args:
        target: Target URL to scan
        verbose: Enable verbose logging
        config: Custom configuration

    Returns:
        Dictionary containing scan results
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scanner = CORSScanner(target, config)
    results = scanner.scan()

    # Print summary
    print(f"\n{'='*60}")
    print(f"CORS SCAN RESULTS FOR: {target}")
    print(f"{'='*60}")
    print(f"Risk Level: {results['analysis']['risk_level']}")
    print(f"Total Tests: {results['analysis']['total_tests']}")
    print(f"Vulnerable Tests: {results['analysis']['vulnerable_tests']}")
    print(f"Unique Vulnerabilities: {results['analysis']['unique_vulnerabilities']}")

    if results['vulnerable_endpoints']:
        print(f"\nVulnerable Endpoints:")
        for endpoint in results['vulnerable_endpoints'][:10]:  # Show first 10
            print(f"  - {endpoint}")

    print(f"{'='*60}")

    return results

if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cors_scan.py <target_url> [--verbose]")
        sys.exit(1)

    target = sys.argv[1]
    verbose = '--verbose' in sys.argv

    try:
        results = cors_scan(target, verbose=verbose)
        print(f"\nScan completed successfully. Check results above.")
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)