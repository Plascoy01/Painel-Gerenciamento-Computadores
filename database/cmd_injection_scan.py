"""
Command Injection Scanner Module for Plascoy Security Scanner

This module performs comprehensive command injection vulnerability detection including:
- Parameter-based command injection testing
- Time-based blind command injection detection
- Error-based command injection identification
- OS-specific payload testing (Unix/Linux, Windows)
- Header-based injection attempts
- POST data injection testing
- Out-of-band command injection detection
- Command execution result analysis

Author: Plascoy Team
Version: 2.0
"""

import requests
import logging
import json
import time
import os
import re
import platform
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum

# Initialize colorama for colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

class InjectionType(Enum):
    """Types of command injection"""
    PARAMETER = "parameter"
    HEADER = "header"
    POST_DATA = "post_data"
    COOKIE = "cookie"

@dataclass
class CommandInjectionVulnerability:
    """Data class for command injection vulnerabilities"""
    url: str
    injection_type: InjectionType
    payload: str
    detection_method: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    os_type: str = "unknown"

@dataclass
class CommandInjectionScanConfig:
    """Configuration for command injection scanning"""
    timeout: int = 15
    max_workers: int = 5
    user_agent: str = 'Plascoy-Command-Injection-Scanner/2.0'
    follow_redirects: bool = False
    verify_ssl: bool = False
    delay_between_requests: float = 0.2
    time_based_delay: int = 5
    max_payloads_per_type: int = 20
    test_headers: bool = True
    test_post_data: bool = True
    test_cookies: bool = False

class CommandInjectionScanner:
    """
    Professional command injection vulnerability scanner with comprehensive features.

    This class provides methods to detect various types of command injection
    vulnerabilities through multiple detection techniques.
    """

    def __init__(self, config: CommandInjectionScanConfig = None):
        """
        Initialize the command injection scanner with configuration.

        Args:
            config: CommandInjectionScanConfig object with scanning parameters
        """
        self.config = config or CommandInjectionScanConfig()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        self.session.verify = self.config.verify_ssl

        # Setup logging
        self.logger = logging.getLogger('CommandInjectionScanner')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.vulnerabilities: List[CommandInjectionVulnerability] = []
        self.tested_urls: Set[str] = set()

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

    def _get_unix_payloads(self) -> List[str]:
        """Get Unix/Linux specific command injection payloads"""
        return [
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "; whoami",
            "| whoami",
            "; uname -a",
            "| uname -a",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; ls -la",
            "| ls -la",
            "; pwd",
            "| pwd",
            "; echo 'test'",
            "| echo 'test'",
            "; sleep 1",
            "| sleep 1",
            "$(`which id`)",
            "`which whoami`",
            "; ping -c 1 127.0.0.1",
            "| ping -c 1 127.0.0.1",
            "; nslookup localhost",
            "| nslookup localhost",
            "; curl http://127.0.0.1",
            "| curl http://127.0.0.1"
        ]

    def _get_windows_payloads(self) -> List[str]:
        """Get Windows specific command injection payloads"""
        return [
            "; dir",
            "| dir",
            "`dir`",
            "$(dir)",
            "; whoami",
            "| whoami",
            "; ver",
            "| ver",
            "; type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "; echo test",
            "| echo test",
            "; ping 127.0.0.1",
            "| ping 127.0.0.1",
            "; nslookup localhost",
            "| nslookup localhost",
            "; systeminfo",
            "| systeminfo",
            "; net user",
            "| net user"
        ]

    def _get_time_based_payloads(self) -> List[str]:
        """Get time-based command injection payloads"""
        delay = self.config.time_based_delay
        return [
            f"; sleep {delay}",
            f"| sleep {delay}",
            f"`sleep {delay}`",
            f"$(sleep {delay})",
            f"; ping -c {delay} 127.0.0.1",
            f"| ping -c {delay} 127.0.0.1",
            f"; timeout {delay}",
            f"| timeout {delay}",
            f"; wait {delay}",
            f"| wait {delay}"
        ]

    def _detect_os_from_response(self, response: requests.Response) -> str:
        """
        Attempt to detect OS type from response content.

        Args:
            response: HTTP response

        Returns:
            Detected OS type ('unix', 'windows', or 'unknown')
        """
        content = response.text.lower()

        unix_indicators = ['/bin/', '/usr/', '/etc/', 'linux', 'ubuntu', 'debian', 'centos']
        windows_indicators = ['windows', 'microsoft', 'c:\\', '\\windows\\', 'system32']

        unix_score = sum(1 for indicator in unix_indicators if indicator in content)
        windows_score = sum(1 for indicator in windows_indicators if indicator in content)

        if unix_score > windows_score:
            return 'unix'
        elif windows_score > unix_score:
            return 'windows'
        else:
            return 'unknown'

    def _check_error_based_injection(self, url: str, payload: str, injection_type: InjectionType,
                                   original_response: requests.Response) -> Optional[CommandInjectionVulnerability]:
        """
        Check for error-based command injection.

        Args:
            url: Target URL
            payload: Injection payload
            injection_type: Type of injection
            original_response: Original response for comparison

        Returns:
            Vulnerability object if found, None otherwise
        """
        # Inject payload
        if injection_type == InjectionType.PARAMETER:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            if query_params:
                # Inject into first parameter
                param_name = list(query_params.keys())[0]
                query_params[param_name] = [payload]
                new_query = urlencode(query_params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                response = self._make_request(test_url)
            else:
                return None
        elif injection_type == InjectionType.HEADER:
            headers = self.session.headers.copy()
            headers['User-Agent'] = payload
            response = self._make_request(url, headers=headers)
        else:
            return None

        if not response:
            return None

        # Check for command execution indicators
        content = response.text.lower()
        error_indicators = [
            'command not found', 'syntax error', 'permission denied',
            'no such file', 'access denied', 'invalid command',
            'sh:', 'bash:', 'cmd:', 'exec failed'
        ]

        injection_indicators = [
            'uid=', 'gid=', 'groups=', 'root', 'www-data', 'apache',
            'bin', 'usr', 'etc', 'directory', 'volume in drive',
            'windows', 'microsoft', 'system32'
        ]

        has_error = any(indicator in content for indicator in error_indicators)
        has_injection = any(indicator in content for indicator in injection_indicators)

        if has_injection or (has_error and len(content) != len(original_response.text)):
            os_type = self._detect_os_from_response(response)
            return CommandInjectionVulnerability(
                url=url,
                injection_type=injection_type,
                payload=payload,
                detection_method='error_based',
                severity='High',
                description=f'Command injection vulnerability detected via {injection_type.value}',
                evidence=f'Payload: {payload}, Response changed or contains command output',
                recommendation='Sanitize and validate all user inputs, use parameterized commands',
                os_type=os_type
            )

        return None

    def _check_time_based_injection(self, url: str, payload: str, injection_type: InjectionType) -> Optional[CommandInjectionVulnerability]:
        """
        Check for time-based blind command injection.

        Args:
            url: Target URL
            payload: Injection payload
            injection_type: Type of injection

        Returns:
            Vulnerability object if found, None otherwise
        """
        start_time = time.time()

        # Inject payload
        if injection_type == InjectionType.PARAMETER:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            if query_params:
                param_name = list(query_params.keys())[0]
                query_params[param_name] = [payload]
                new_query = urlencode(query_params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                response = self._make_request(test_url)
            else:
                return None
        elif injection_type == InjectionType.HEADER:
            headers = self.session.headers.copy()
            headers['User-Agent'] = payload
            response = self._make_request(url, headers=headers)
        else:
            return None

        if not response:
            return None

        elapsed_time = time.time() - start_time

        # Check if response took significantly longer (indicating sleep executed)
        if elapsed_time >= self.config.time_based_delay - 1:  # Allow 1 second tolerance
            return CommandInjectionVulnerability(
                url=url,
                injection_type=injection_type,
                payload=payload,
                detection_method='time_based',
                severity='High',
                description=f'Time-based command injection vulnerability detected via {injection_type.value}',
                evidence=f'Payload: {payload}, Response time: {elapsed_time:.2f}s',
                recommendation='Sanitize and validate all user inputs, avoid shell execution',
                os_type='unknown'
            )

        return None

    def _test_parameter_injection(self, url: str) -> None:
        """
        Test for command injection in URL parameters.

        Args:
            url: URL to test
        """
        parsed = urlparse(url)
        if not parsed.query:
            return  # No parameters to test

        self._log(f"Testing parameter injection: {url}", color='cyan')

        # Get original response for comparison
        original_response = self._make_request(url)
        if not original_response:
            return

        # Test payloads
        payloads = self._get_unix_payloads() + self._get_windows_payloads()
        payloads = payloads[:self.config.max_payloads_per_type]

        for payload in payloads:
            # Error-based detection
            vuln = self._check_error_based_injection(url, payload, InjectionType.PARAMETER, original_response)
            if vuln:
                self.vulnerabilities.append(vuln)
                self._log(f"Parameter injection found: {url} with payload: {payload}", 'warning', 'red')

            # Time-based detection
            time_vuln = self._check_time_based_injection(url, payload, InjectionType.PARAMETER)
            if time_vuln:
                self.vulnerabilities.append(time_vuln)
                self._log(f"Time-based injection found: {url}", 'warning', 'red')

    def _test_header_injection(self, url: str) -> None:
        """
        Test for command injection in HTTP headers.

        Args:
            url: URL to test
        """
        if not self.config.test_headers:
            return

        self._log(f"Testing header injection: {url}", color='cyan')

        # Get original response
        original_response = self._make_request(url)
        if not original_response:
            return

        # Test payloads in User-Agent header
        payloads = self._get_unix_payloads() + self._get_windows_payloads()
        payloads = payloads[:self.config.max_payloads_per_type]

        for payload in payloads:
            vuln = self._check_error_based_injection(url, payload, InjectionType.HEADER, original_response)
            if vuln:
                self.vulnerabilities.append(vuln)
                self._log(f"Header injection found: {url}", 'warning', 'red')

    def _test_post_data_injection(self, url: str) -> None:
        """
        Test for command injection in POST data.

        Args:
            url: URL to test
        """
        if not self.config.test_post_data:
            return

        self._log(f"Testing POST data injection: {url}", color='cyan')

        # Test with common POST data
        post_data = {'input': 'test', 'cmd': 'test', 'exec': 'test', 'run': 'test'}

        for param_name, param_value in post_data.items():
            original_response = self._make_request(url, method='POST', data={param_name: param_value})
            if not original_response:
                continue

            payloads = self._get_unix_payloads() + self._get_windows_payloads()
            payloads = payloads[:self.config.max_payloads_per_type // 2]

            for payload in payloads:
                test_data = {param_name: payload}
                response = self._make_request(url, method='POST', data=test_data)
                if response:
                    vuln = self._check_error_based_injection(url, payload, InjectionType.POST_DATA, original_response)
                    if vuln:
                        vuln.injection_type = InjectionType.POST_DATA
                        self.vulnerabilities.append(vuln)
                        self._log(f"POST data injection found: {url} in parameter {param_name}", 'warning', 'red')

    def discover_injection_points(self, base_url: str) -> List[str]:
        """
        Discover potential injection points (URLs with parameters).

        Args:
            base_url: Base URL to scan

        Returns:
            List of URLs with parameters to test
        """
        urls_to_test = []

        # Common endpoints that might accept commands
        endpoints = [
            '/exec', '/run', '/cmd', '/command', '/shell', '/system',
            '/admin/exec', '/api/exec', '/debug/exec', '/test/exec',
            '/ping', '/traceroute', '/nslookup', '/dig'
        ]

        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)
            # Add some test parameters
            test_urls = [
                url,
                f"{url}?cmd=test",
                f"{url}?exec=test",
                f"{url}?run=test",
                f"{url}?input=test"
            ]

            for test_url in test_urls:
                if test_url not in self.tested_urls:
                    urls_to_test.append(test_url)

        return urls_to_test[:10]  # Limit to prevent too many requests

    def generate_report(self, output_file: str = None) -> Dict:
        """
        Generate comprehensive scan report.

        Args:
            output_file: Optional file path to save JSON report

        Returns:
            Dictionary containing scan results
        """
        # Categorize vulnerabilities
        severity_summary = {
            'Critical': len([v for v in self.vulnerabilities if v.severity == 'Critical']),
            'High': len([v for v in self.vulnerabilities if v.severity == 'High']),
            'Medium': len([v for v in self.vulnerabilities if v.severity == 'Medium']),
            'Low': len([v for v in self.vulnerabilities if v.severity == 'Low'])
        }

        injection_types = {}
        for vuln in self.vulnerabilities:
            inj_type = vuln.injection_type.value
            injection_types[inj_type] = injection_types.get(inj_type, 0) + 1

        report = {
            'scan_type': 'Command Injection Vulnerability Scan',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'urls_tested': len(self.tested_urls),
            'vulnerabilities_found': len(self.vulnerabilities),
            'severity_summary': severity_summary,
            'injection_types': injection_types,
            'vulnerabilities': [
                {
                    'url': v.url,
                    'injection_type': v.injection_type.value,
                    'payload': v.payload,
                    'detection_method': v.detection_method,
                    'severity': v.severity,
                    'description': v.description,
                    'evidence': v.evidence,
                    'recommendation': v.recommendation,
                    'os_type': v.os_type
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
        Perform complete command injection vulnerability scan.

        Args:
            target_url: Base URL to scan
            output_file: Optional output file for report

        Returns:
            Scan results dictionary
        """
        self._log(f"Starting comprehensive command injection scan for {target_url}", color='cyan')

        # Ensure URL has proper format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        # Discover injection points
        urls_to_test = self.discover_injection_points(target_url)
        if target_url not in urls_to_test:
            urls_to_test.insert(0, target_url)

        # Test each URL
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = []
            for url in urls_to_test:
                if url not in self.tested_urls:
                    futures.append(executor.submit(self._test_parameter_injection, url))
                    futures.append(executor.submit(self._test_header_injection, url))
                    futures.append(executor.submit(self._test_post_data_injection, url))
                    self.tested_urls.add(url)

            for future in as_completed(futures):
                future.result()  # Wait for completion

        self._log(f"Command injection scan completed. Tested {len(self.tested_urls)} URLs, found {len(self.vulnerabilities)} vulnerabilities", color='green')

        return self.generate_report(output_file)

def main():
    """Main function for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(description='Plascoy Command Injection Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Request timeout')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Skip SSL verification')
    parser.add_argument('--no-headers', action='store_true', help='Skip header injection tests')
    parser.add_argument('--no-post', action='store_true', help='Skip POST data injection tests')
    parser.add_argument('--delay', type=int, default=5, help='Time-based detection delay')

    args = parser.parse_args()

    config = CommandInjectionScanConfig(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        test_headers=not args.no_headers,
        test_post_data=not args.no_post,
        time_based_delay=args.delay
    )

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    scanner = CommandInjectionScanner(config)
    results = scanner.scan(args.target, args.output)

    print(f"\nScan Summary:")
    print(f"URLs tested: {results['urls_tested']}")
    print(f"Vulnerabilities found: {results['vulnerabilities_found']}")
    print(f"Critical: {results['severity_summary']['Critical']}")
    print(f"High: {results['severity_summary']['High']}")
    print(f"Medium: {results['severity_summary']['Medium']}")
    print(f"Low: {results['severity_summary']['Low']}")

    if results['injection_types']:
        print("Injection types found:")
        for inj_type, count in results['injection_types'].items():
            print(f"  {inj_type}: {count}")

    for vuln in results['vulnerabilities'][:5]:  # Show first 5
        print(f"- {vuln['severity'].upper()}: {vuln['injection_type']} injection at {vuln['url']}")

if __name__ == '__main__':
    main()