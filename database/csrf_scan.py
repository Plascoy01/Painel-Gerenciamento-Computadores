#!/usr/bin/env python3
"""
CSRF (Cross-Site Request Forgery) Vulnerability Scanner
Scans for CSRF vulnerabilities in web applications
"""

import requests
import logging
import json
import time
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
import hashlib
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class CSRFResult:
    """Data class for CSRF scan results"""
    url: str
    form_action: str
    form_method: str
    has_csrf_token: bool
    token_names: List[str]
    vulnerabilities: List[str]
    recommendations: List[str]
    severity: str
    timestamp: float
    response_time: float

@dataclass
class CSRFStats:
    """Statistics for CSRF scan"""
    total_forms: int = 0
    vulnerable_forms: int = 0
    protected_forms: int = 0
    scan_duration: float = 0.0
    start_time: float = 0.0
    end_time: float = 0.0

class CSRFScanner:
    """
    Advanced CSRF vulnerability scanner
    """

    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize CSRF scanner

        Args:
            target: Target URL to scan
            config: Configuration dictionary
        """
        self.target = self._normalize_url(target)
        self.config = config or self._default_config()
        self.session = self._create_session()
        self.results: List[CSRFResult] = []
        self.stats = CSRFStats()

        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def _default_config(self) -> Dict:
        """Default configuration settings"""
        return {
            'timeout': 15,
            'max_workers': 5,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'verify_ssl': False,
            'follow_redirects': True,
            'max_pages': 100,
            'csrf_token_names': [
                'csrf_token', 'csrf', '_csrf', 'token', '_token',
                'authenticity_token', 'xsrf_token', 'xsrf', '_xsrf',
                'csrfmiddlewaretoken', 'anticsrf', 'csrf_token_',
                'verification_token', 'request_token'
            ],
            'check_referer_header': True,
            'check_origin_header': True,
            'test_same_site_cookies': True,
            'crawl_depth': 2,
            'rate_limit': 0.5,  # seconds between requests
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
            'User-Agent': self.config['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        session.verify = self.config['verify_ssl']
        session.max_redirects = 5 if self.config['follow_redirects'] else 0
        return session

    def scan(self) -> Dict[str, Any]:
        """
        Perform comprehensive CSRF scan

        Returns:
            Dictionary containing scan results and analysis
        """
        self.logger.info(f"Starting CSRF scan for {self.target}")
        self.stats.start_time = time.time()

        try:
            # Discover forms
            forms_data = self._discover_forms()

            # Analyze each form for CSRF vulnerabilities
            with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
                futures = []
                for form_data in forms_data:
                    future = executor.submit(self._analyze_form_csrf, form_data)
                    futures.append(future)

                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            self.results.append(result)
                            self._update_stats(result)
                    except Exception as e:
                        self.logger.error(f"Error analyzing form: {e}")

            # Additional checks
            self._check_global_csrf_protections()
            self._test_stateful_csrf_protection()

            # Finalize
            self.stats.end_time = time.time()
            self.stats.scan_duration = self.stats.end_time - self.stats.start_time

            analysis = self._analyze_results()

            self.logger.info(f"CSRF scan completed. Analyzed {len(self.results)} forms")

            return {
                'target': self.target,
                'config': self.config,
                'stats': asdict(self.stats),
                'results': [asdict(result) for result in self.results],
                'analysis': analysis
            }

        except Exception as e:
            self.logger.error(f"Error during CSRF scan: {e}")
            raise

    def _discover_forms(self) -> List[Dict[str, Any]]:
        """
        Discover all forms on the target website

        Returns:
            List of form data dictionaries
        """
        forms_data = []
        visited_urls = set()
        urls_to_visit = [self.target]

        self.logger.info("Discovering forms...")

        for depth in range(self.config['crawl_depth'] + 1):
            next_urls = []

            for url in urls_to_visit:
                if url in visited_urls or len(forms_data) >= self.config['max_pages']:
                    continue

                visited_urls.add(url)

                try:
                    response = self.session.get(url, timeout=self.config['timeout'])
                    if response.status_code != 200:
                        continue

                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Extract forms
                    for form in soup.find_all('form'):
                        form_data = self._extract_form_data(form, url)
                        forms_data.append(form_data)

                    # Extract links for next depth
                    if depth < self.config['crawl_depth']:
                        for link in soup.find_all('a', href=True):
                            full_url = urljoin(url, link['href'])
                            if (urlparse(full_url).netloc == urlparse(self.target).netloc and
                                full_url not in visited_urls):
                                next_urls.append(full_url)

                    # Rate limiting
                    time.sleep(self.config['rate_limit'])

                except requests.RequestException as e:
                    self.logger.warning(f"Error accessing {url}: {e}")

            urls_to_visit = next_urls

        self.logger.info(f"Discovered {len(forms_data)} forms")
        return forms_data

    def _extract_form_data(self, form: BeautifulSoup, page_url: str) -> Dict[str, Any]:
        """Extract comprehensive form data"""
        form_data = {
            'page_url': page_url,
            'action': urljoin(page_url, form.get('action', '')),
            'method': form.get('method', 'GET').upper(),
            'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
            'inputs': [],
            'hidden_inputs': [],
            'password_fields': [],
            'file_inputs': [],
            'submit_buttons': [],
            'textareas': [],
            'selects': []
        }

        # Extract all form elements
        for input_tag in form.find_all('input'):
            input_info = {
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', ''),
                'required': input_tag.get('required') is not None,
                'autocomplete': input_tag.get('autocomplete', '')
            }

            form_data['inputs'].append(input_info)

            if input_info['type'] == 'hidden':
                form_data['hidden_inputs'].append(input_info)
            elif input_info['type'] == 'password':
                form_data['password_fields'].append(input_info)
            elif input_info['type'] == 'file':
                form_data['file_inputs'].append(input_info)
            elif input_info['type'] in ['submit', 'button']:
                form_data['submit_buttons'].append(input_info)

        # Extract textareas
        for textarea in form.find_all('textarea'):
            textarea_info = {
                'name': textarea.get('name', ''),
                'value': textarea.get('text', ''),
                'required': textarea.get('required') is not None
            }
            form_data['textareas'].append(textarea_info)

        # Extract selects
        for select in form.find_all('select'):
            select_info = {
                'name': select.get('name', ''),
                'options': [opt.get('value', opt.get_text()) for opt in select.find_all('option')],
                'required': select.get('required') is not None
            }
            form_data['selects'].append(select_info)

        return form_data

    def _analyze_form_csrf(self, form_data: Dict[str, Any]) -> CSRFResult:
        """Analyze a single form for CSRF vulnerabilities"""
        start_time = time.time()

        vulnerabilities = []
        token_names = []
        has_csrf_token = False

        # Check for CSRF tokens in form inputs
        all_inputs = (form_data['inputs'] + form_data['hidden_inputs'] +
                     form_data['textareas'] + form_data['selects'])

        for input_field in all_inputs:
            input_name = input_field.get('name', '').lower()
            if input_name in self.config['csrf_token_names']:
                has_csrf_token = True
                token_names.append(input_name)

        # Analyze vulnerabilities
        if not has_csrf_token:
            vulnerabilities.append("No CSRF token found in form")

            # Check if form performs state-changing operations
            if self._is_state_changing_form(form_data):
                vulnerabilities.append("State-changing form without CSRF protection")

            # Check for dangerous methods
            if form_data['method'] in ['POST', 'PUT', 'DELETE', 'PATCH']:
                vulnerabilities.append(f"Dangerous HTTP method ({form_data['method']}) without CSRF protection")

        # Check token strength
        if has_csrf_token:
            token_strength = self._analyze_token_strength(form_data, token_names)
            if token_strength['weaknesses']:
                vulnerabilities.extend(token_strength['weaknesses'])

        # Check for other CSRF protections
        other_protections = self._check_other_csrf_protections(form_data)
        if not other_protections and not has_csrf_token:
            vulnerabilities.append("No CSRF protection mechanisms detected")

        # Determine severity
        severity = self._calculate_severity(vulnerabilities)

        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities, form_data)

        result = CSRFResult(
            url=form_data['page_url'],
            form_action=form_data['action'],
            form_method=form_data['method'],
            has_csrf_token=has_csrf_token,
            token_names=token_names,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            severity=severity,
            timestamp=time.time(),
            response_time=time.time() - start_time
        )

        return result

    def _is_state_changing_form(self, form_data: Dict[str, Any]) -> bool:
        """Determine if form performs state-changing operations"""
        # Check method
        if form_data['method'] in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return True

        # Check action URL patterns
        action = form_data['action'].lower()
        state_change_patterns = [
            'create', 'update', 'delete', 'add', 'remove', 'edit', 'save',
            'submit', 'process', 'change', 'modify', 'upload', 'download'
        ]

        for pattern in state_change_patterns:
            if pattern in action:
                return True

        # Check for password fields (login/logout forms)
        if form_data['password_fields']:
            return True

        # Check for file uploads
        if form_data['file_inputs']:
            return True

        return False

    def _analyze_token_strength(self, form_data: Dict[str, Any], token_names: List[str]) -> Dict[str, List[str]]:
        """Analyze strength of CSRF tokens"""
        weaknesses = []

        for token_name in token_names:
            # Find token input
            token_input = None
            for input_field in form_data['inputs'] + form_data['hidden_inputs']:
                if input_field.get('name', '').lower() == token_name:
                    token_input = input_field
                    break

            if token_input:
                token_value = token_input.get('value', '')

                # Check token length
                if len(token_value) < 16:
                    weaknesses.append(f"CSRF token '{token_name}' is too short ({len(token_value)} chars)")

                # Check token entropy (simplified)
                if token_value and not re.search(r'[A-Za-z0-9]{16,}', token_value):
                    weaknesses.append(f"CSRF token '{token_name}' has low entropy")

                # Check if token is predictable
                if token_value in ['123456', 'token', 'csrf', 'default']:
                    weaknesses.append(f"CSRF token '{token_name}' appears predictable")

        return {'weaknesses': weaknesses}

    def _check_other_csrf_protections(self, form_data: Dict[str, Any]) -> List[str]:
        """Check for other CSRF protection mechanisms"""
        protections = []

        # Check for SameSite cookie attributes (would need additional checks)
        # Check for Origin/Referer validation (would need additional checks)

        # Check for custom headers or other protections
        for input_field in form_data['inputs'] + form_data['hidden_inputs']:
            input_name = input_field.get('name', '').lower()
            if 'timestamp' in input_name or 'nonce' in input_name:
                protections.append("Timestamp/nonce-based protection detected")

        return protections

    def _check_global_csrf_protections(self):
        """Check for global CSRF protections"""
        try:
            # Test with suspicious origin
            headers = {'Origin': 'https://evil-attacker.com'}
            response = self.session.get(self.target, headers=headers, timeout=self.config['timeout'])

            # Check if request was blocked
            if response.status_code in [403, 401]:
                self.logger.info("Global CSRF protection detected (Origin header blocking)")

        except requests.RequestException:
            pass

    def _test_stateful_csrf_protection(self):
        """Test for stateful CSRF protection mechanisms"""
        # This would require more complex testing with session state
        # For now, just log that this check exists
        self.logger.debug("Stateful CSRF protection testing would require session analysis")

    def _calculate_severity(self, vulnerabilities: List[str]) -> str:
        """Calculate vulnerability severity"""
        if not vulnerabilities:
            return 'SAFE'

        critical_count = sum(1 for v in vulnerabilities if 'dangerous' in v.lower() or 'state-changing' in v.lower())
        high_count = sum(1 for v in vulnerabilities if 'no csrf' in v.lower() or 'without csrf' in v.lower())

        if critical_count > 0:
            return 'CRITICAL'
        elif high_count > 0:
            return 'HIGH'
        elif vulnerabilities:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_recommendations(self, vulnerabilities: List[str], form_data: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        vuln_types = {
            'no_csrf': "Implement CSRF tokens using synchronized token patterns",
            'weak_token': "Use cryptographically secure random tokens (at least 16 bytes)",
            'dangerous_method': "Ensure all state-changing operations are protected",
            'no_protection': "Implement multiple layers of CSRF protection"
        }

        for vuln in vulnerabilities:
            for vuln_type, rec in vuln_types.items():
                if vuln_type.replace('_', ' ') in vuln.lower():
                    if rec not in recommendations:
                        recommendations.append(rec)

        # General recommendations
        if not recommendations:
            recommendations.append("Regular security audits recommended")

        # Specific to form type
        if form_data['password_fields']:
            recommendations.append("Ensure login forms have additional protections beyond CSRF tokens")

        if form_data['file_inputs']:
            recommendations.append("File upload forms should have additional validation")

        return recommendations

    def _update_stats(self, result: CSRFResult):
        """Update scan statistics"""
        self.stats.total_forms += 1

        if result.vulnerabilities:
            self.stats.vulnerable_forms += 1
        else:
            self.stats.protected_forms += 1

    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze scan results"""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'SAFE': 0}

        for result in self.results:
            severity_counts[result.severity] += 1

        vulnerability_types = {}
        for result in self.results:
            for vuln in result.vulnerabilities:
                vuln_type = vuln.split(':')[0] if ':' in vuln else vuln
                vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1

        return {
            'severity_distribution': severity_counts,
            'vulnerability_types': vulnerability_types,
            'protection_rate': (self.stats.protected_forms / max(1, self.stats.total_forms)) * 100,
            'risk_assessment': self._assess_overall_risk(severity_counts)
        }

    def _assess_overall_risk(self, severity_counts: Dict[str, int]) -> str:
        """Assess overall risk level"""
        total_vulnerable = severity_counts['CRITICAL'] + severity_counts['HIGH'] + severity_counts['MEDIUM']

        if severity_counts['CRITICAL'] > 0:
            return 'CRITICAL'
        elif severity_counts['HIGH'] > 2 or (severity_counts['HIGH'] > 0 and total_vulnerable > 5):
            return 'HIGH'
        elif total_vulnerable > 0:
            return 'MEDIUM'
        else:
            return 'LOW'

def csrf_scan(target: str, verbose: bool = False, config: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main CSRF scanning function

    Args:
        target: Target URL to scan
        verbose: Enable verbose logging
        config: Custom configuration

    Returns:
        Dictionary containing scan results
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scanner = CSRFScanner(target, config)
    results = scanner.scan()

    # Print summary
    stats = results['stats']
    analysis = results['analysis']

    print(f"\n{'='*60}")
    print(f"CSRF SCAN RESULTS FOR: {target}")
    print(f"{'='*60}")
    print(f"Duration: {stats['scan_duration']:.2f} seconds")
    print(f"Total forms analyzed: {stats['total_forms']}")
    print(f"Protected forms: {stats['protected_forms']}")
    print(f"Vulnerable forms: {stats['vulnerable_forms']}")
    print(f"Protection rate: {analysis['protection_rate']:.1f}%")
    print(f"Overall risk: {analysis['risk_assessment']}")

    print(f"\nSeverity Distribution:")
    for severity, count in analysis['severity_distribution'].items():
        if count > 0:
            print(f"  {severity}: {count}")

    if results['results']:
        print(f"\nTop Vulnerabilities:")
        vuln_types = analysis['vulnerability_types']
        sorted_vulns = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)
        for vuln_type, count in sorted_vulns[:5]:
            print(f"  {vuln_type}: {count} occurrences")

    print(f"{'='*60}")

    return results

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python csrf_scan.py <target_url> [--verbose]")
        sys.exit(1)

    target = sys.argv[1]
    verbose = '--verbose' in sys.argv

    try:
        results = csrf_scan(target, verbose=verbose)
        print(f"\nScan completed successfully.")
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)