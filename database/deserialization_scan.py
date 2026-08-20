#!/usr/bin/env python3
"""
Deserialization Vulnerability Scanner
Scans for insecure deserialization vulnerabilities in web applications
"""

import requests
import logging
import json
import time
import base64
import pickle
import yaml
import re
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
import threading
import marshal
import codecs

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class DeserializationVuln:
    """Data class for deserialization vulnerabilities"""
    url: str
    parameter: str
    payload_type: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    recommendations: List[str]
    timestamp: float
    response_time: float

@dataclass
class DeserializationResult:
    """Data class for deserialization scan results"""
    url: str
    parameters_tested: int
    vulnerabilities_found: List[DeserializationVuln]
    scan_duration: float

class DeserializationScanner:
    """
    Advanced deserialization vulnerability scanner
    """

    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize deserialization scanner

        Args:
            target: Target URL to scan
            config: Configuration dictionary
        """
        self.target = self._normalize_url(target)
        self.config = config or self._default_config()
        self.session = self._create_session()
        self.results: List[DeserializationResult] = []
        self.vulnerabilities: List[DeserializationVuln] = []

        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def _default_config(self) -> Dict:
        """Default configuration settings"""
        return {
            'timeout': 15,
            'max_workers': 3,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'verify_ssl': False,
            'follow_redirects': True,
            'rate_limit': 0.5,  # seconds between requests
            'max_payloads_per_param': 10,
            'test_all_methods': True,
            'test_headers': True,
            'test_cookies': False,
            'detect_framework': True,
            'custom_payloads': [],
            'safe_mode': True  # Don't send potentially dangerous payloads
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
            'Accept-Encoding': 'gzip, deflate'
        })
        session.verify = self.config['verify_ssl']
        session.max_redirects = 5 if self.config['follow_redirects'] else 0
        return session

    def scan(self) -> Dict[str, Any]:
        """
        Perform comprehensive deserialization vulnerability scan

        Returns:
            Dictionary containing scan results and analysis
        """
        self.logger.info(f"Starting deserialization scan for {self.target}")

        start_time = time.time()

        try:
            # Detect framework and parameters
            framework_info = self._detect_framework()
            parameters = self._discover_parameters()

            # Test deserialization vulnerabilities
            with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
                futures = []

                # Test URL parameters
                for param in parameters['url_params']:
                    future = executor.submit(self._test_parameter_deserialization,
                                           self.target, param, 'url')
                    futures.append(future)

                # Test body parameters (POST)
                if self.config['test_all_methods']:
                    for param in parameters['body_params']:
                        future = executor.submit(self._test_parameter_deserialization,
                                               self.target, param, 'body')
                        futures.append(future)

                # Test headers
                if self.config['test_headers']:
                    for header in parameters['headers']:
                        future = executor.submit(self._test_header_deserialization, header)
                        futures.append(future)

                # Wait for completion
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result and result.vulnerabilities_found:
                            self.results.append(result)
                            self.vulnerabilities.extend(result.vulnerabilities_found)
                    except Exception as e:
                        self.logger.error(f"Error in parameter test: {e}")

            # Additional checks
            self._check_magic_bytes()
            self._check_error_patterns()

            # Finalize
            duration = time.time() - start_time
            analysis = self._analyze_results()

            self.logger.info(f"Deserialization scan completed. Found {len(self.vulnerabilities)} vulnerabilities")

            return {
                'target': self.target,
                'config': self.config,
                'framework_info': framework_info,
                'parameters_discovered': parameters,
                'results': [asdict(result) for result in self.results],
                'vulnerabilities': [asdict(vuln) for vuln in self.vulnerabilities],
                'analysis': analysis,
                'scan_duration': duration
            }

        except Exception as e:
            self.logger.error(f"Error during deserialization scan: {e}")
            raise

    def _detect_framework(self) -> Dict[str, Any]:
        """Detect web framework and deserialization libraries"""
        self.logger.info("Detecting framework and libraries...")

        try:
            response = self.session.get(self.target, timeout=self.config['timeout'])

            framework_indicators = {
                'Java': [
                    'java', 'jsp', 'servlet', 'spring', 'struts',
                    'jboss', 'tomcat', 'weblogic', 'websphere'
                ],
                'PHP': [
                    'php', 'laravel', 'symfony', 'codeigniter', 'zend',
                    'wordpress', 'drupal', 'joomla'
                ],
                'Python': [
                    'python', 'django', 'flask', 'tornado', 'bottle',
                    'cherrypy', 'web2py'
                ],
                'Ruby': [
                    'ruby', 'rails', 'sinatra', 'puma', 'unicorn'
                ],
                'Node.js': [
                    'node', 'express', 'koa', 'sails', 'meteor'
                ],
                '.NET': [
                    'asp.net', 'csharp', 'vb.net', 'nancy', 'servicestack'
                ]
            }

            detected_frameworks = []
            text_lower = response.text.lower()
            server_header = response.headers.get('server', '').lower()
            powered_by = response.headers.get('x-powered-by', '').lower()

            for framework, indicators in framework_indicators.items():
                confidence = 0
                for indicator in indicators:
                    if indicator in text_lower or indicator in server_header or indicator in powered_by:
                        confidence += 1

                if confidence > 0:
                    detected_frameworks.append({
                        'framework': framework,
                        'confidence': min(confidence / len(indicators), 1.0),
                        'indicators_found': confidence
                    })

            # Sort by confidence
            detected_frameworks.sort(key=lambda x: x['confidence'], reverse=True)

            return {
                'detected_frameworks': detected_frameworks,
                'server_header': response.headers.get('server', ''),
                'powered_by': response.headers.get('x-powered-by', ''),
                'content_type': response.headers.get('content-type', '')
            }

        except requests.RequestException as e:
            self.logger.warning(f"Framework detection failed: {e}")
            return {'detected_frameworks': [], 'error': str(e)}

    def _discover_parameters(self) -> Dict[str, Any]:
        """Discover parameters that might accept serialized data"""
        self.logger.info("Discovering parameters...")

        parameters = {
            'url_params': [],
            'body_params': [],
            'headers': [],
            'cookies': []
        }

        try:
            # Get main page to discover forms and links
            response = self.session.get(self.target, timeout=self.config['timeout'])

            # Extract URL parameters from links
            url_patterns = [
                r'href=["\']([^"\']*\?[^"\']*)["\']',
                r'src=["\']([^"\']*\?[^"\']*)["\']'
            ]

            for pattern in url_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    parsed = urlparse(match)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        parameters['url_params'].extend(params.keys())

            # Extract form parameters
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            for form in soup.find_all('form'):
                method = form.get('method', 'GET').upper()
                param_list = parameters['body_params'] if method == 'POST' else parameters['url_params']

                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    param_name = input_tag.get('name')
                    if param_name:
                        param_list.append(param_name)

            # Remove duplicates
            parameters['url_params'] = list(set(parameters['url_params']))
            parameters['body_params'] = list(set(parameters['body_params']))

            # Common deserialization parameter names
            common_params = [
                'data', 'object', 'obj', 'serialized', 'pickle', 'yaml',
                'json', 'xml', 'config', 'settings', 'state', 'session',
                'cache', 'store', 'payload', 'input', 'content'
            ]

            # Prioritize common parameter names
            for param_list_name in ['url_params', 'body_params']:
                prioritized = []
                for param in common_params:
                    if param in parameters[param_list_name]:
                        prioritized.append(param)
                for param in parameters[param_list_name]:
                    if param not in prioritized:
                        prioritized.append(param)
                parameters[param_list_name] = prioritized

            # Limit parameters to test
            for param_list_name in ['url_params', 'body_params']:
                parameters[param_list_name] = parameters[param_list_name][:20]  # Max 20 params

            # Common headers that might accept serialized data
            parameters['headers'] = [
                'X-Data', 'X-Object', 'X-Payload', 'X-Config',
                'X-Serialized', 'X-Custom-Data'
            ]

        except Exception as e:
            self.logger.warning(f"Parameter discovery failed: {e}")

        return parameters

    def _test_parameter_deserialization(self, url: str, param: str, param_type: str) -> Optional[DeserializationResult]:
        """Test a parameter for deserialization vulnerabilities"""
        vulnerabilities = []
        payloads_tested = 0

        # Generate payloads for different serialization formats
        payload_sets = self._generate_payloads()

        for payload_type, payloads in payload_sets.items():
            if payloads_tested >= self.config['max_payloads_per_param']:
                break

            for payload in payloads[:3]:  # Test max 3 payloads per type
                if payloads_tested >= self.config['max_payloads_per_param']:
                    break

                try:
                    vuln = self._send_payload_and_check(url, param, payload, payload_type, param_type)
                    if vuln:
                        vulnerabilities.append(vuln)

                    payloads_tested += 1

                    # Rate limiting
                    time.sleep(self.config['rate_limit'])

                except Exception as e:
                    self.logger.debug(f"Error testing {param} with {payload_type}: {e}")

        result = DeserializationResult(
            url=url,
            parameters_tested=payloads_tested,
            vulnerabilities_found=vulnerabilities,
            scan_duration=0.0  # Will be set by caller
        )

        return result if vulnerabilities else None

    def _test_header_deserialization(self, header: str) -> Optional[DeserializationResult]:
        """Test a header for deserialization vulnerabilities"""
        vulnerabilities = []

        # Simple test with basic payload
        payload = self._generate_payloads()['json'][0]

        try:
            headers = {header: payload}
            response = self.session.get(self.target, headers=headers, timeout=self.config['timeout'])

            if self._is_vulnerable_response(response, 'json'):
                vuln = DeserializationVuln(
                    url=self.target,
                    parameter=header,
                    payload_type='json',
                    vulnerability_type='Header Deserialization',
                    severity='HIGH',
                    description=f'Header {header} appears vulnerable to deserialization attacks',
                    evidence=f'Unusual response to JSON payload in {header} header',
                    recommendations=[
                        'Validate and sanitize header input',
                        'Use safe deserialization methods',
                        'Implement input validation'
                    ],
                    timestamp=time.time(),
                    response_time=response.elapsed.total_seconds()
                )
                vulnerabilities.append(vuln)

        except requests.RequestException:
            pass

        result = DeserializationResult(
            url=self.target,
            parameters_tested=1,
            vulnerabilities_found=vulnerabilities,
            scan_duration=0.0
        )

        return result if vulnerabilities else None

    def _generate_payloads(self) -> Dict[str, List[str]]:
        """Generate test payloads for different serialization formats"""
        payloads = {}

        if not self.config['safe_mode']:
            # PHP serialized objects
            payloads['php'] = [
                'O:8:"stdClass":0:{}',
                'a:2:{i:0;s:4:"test";i:1;s:4:"data";}',
                'O:8:"DateTime":0:{}'
            ]

            # Java serialized objects (base64 encoded)
            java_payload = 'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eHiBZG9Y2N8LAQABeHAAAAACdAAQZ3Jvd3M='
            payloads['java'] = [java_payload]

            # Python pickle (base64 encoded) - DANGEROUS
            try:
                pickle_data = pickle.dumps({'test': 'data'})
                pickle_b64 = base64.b64encode(pickle_data).decode()
                payloads['pickle'] = [pickle_b64]
            except:
                payloads['pickle'] = []

        # JSON payloads
        payloads['json'] = [
            '{"test": "data"}',
            '{"__proto__": {"isAdmin": true}}',
            '{"constructor": {"prototype": {"isAdmin": true}}}'
        ]

        # YAML payloads
        payloads['yaml'] = [
            'test: data',
            '!!python/object:__main__.TestClass {test: data}'
        ] if not self.config['safe_mode'] else ['test: data']

        # XML payloads
        payloads['xml'] = [
            '<?xml version="1.0"?><test>data</test>',
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>'
        ]

        # Base64 encoded payloads
        payloads['base64'] = [
            base64.b64encode(b'test data').decode(),
            base64.b64encode(b'{"test": "data"}').decode()
        ]

        return payloads

    def _send_payload_and_check(self, url: str, param: str, payload: str,
                              payload_type: str, param_type: str) -> Optional[DeserializationVuln]:
        """Send payload and check for vulnerability indicators"""
        try:
            if param_type == 'url':
                # URL parameter
                separator = '&' if '?' in url else '?'
                test_url = f"{url}{separator}{param}={payload}"
                response = self.session.get(test_url, timeout=self.config['timeout'])
            else:
                # Body parameter
                data = {param: payload}
                response = self.session.post(url, data=data, timeout=self.config['timeout'])

            if self._is_vulnerable_response(response, payload_type):
                severity = self._determine_severity(payload_type, response)

                vuln = DeserializationVuln(
                    url=url,
                    parameter=param,
                    payload_type=payload_type,
                    vulnerability_type=f'{param_type.title()} Parameter Deserialization',
                    severity=severity,
                    description=f'Parameter {param} appears vulnerable to {payload_type} deserialization',
                    evidence=self._get_evidence(response, payload_type),
                    recommendations=self._get_recommendations(payload_type),
                    timestamp=time.time(),
                    response_time=response.elapsed.total_seconds()
                )
                return vuln

        except requests.RequestException as e:
            self.logger.debug(f"Request failed: {e}")

        return None

    def _is_vulnerable_response(self, response: requests.Response, payload_type: str) -> bool:
        """Check if response indicates a deserialization vulnerability"""
        text = response.text.lower()
        status = response.status_code

        # Error indicators
        error_patterns = {
            'php': ['fatal error', 'unserialize', 'object', 'class', 'stdclass'],
            'java': ['deserialization', 'objectinputstream', 'classnotfound', 'invalidclass'],
            'python': ['pickle', 'unpicklingerror', '_pickle', 'cPickle'],
            'yaml': ['yaml', 'constructor', 'composer', 'resolver'],
            'json': ['json', 'parse', 'syntax error', 'unexpected token'],
            'xml': ['xml', 'parser', 'entity', 'doctype']
        }

        if payload_type in error_patterns:
            for pattern in error_patterns[payload_type]:
                if pattern in text:
                    return True

        # Unusual response codes
        if status in [500, 502, 503]:
            return True

        # Response size changes significantly
        if len(response.content) > 10000:  # Large response might indicate data dump
            return True

        # Time-based detection (response took unusually long)
        if response.elapsed.total_seconds() > 5:
            return True

        return False

    def _determine_severity(self, payload_type: str, response: requests.Response) -> str:
        """Determine vulnerability severity"""
        if payload_type in ['php', 'java', 'python', 'yaml'] and not self.config['safe_mode']:
            if response.status_code == 500:
                return 'CRITICAL'
            else:
                return 'HIGH'
        elif payload_type == 'xml':
            return 'HIGH'
        else:
            return 'MEDIUM'

    def _get_evidence(self, response: requests.Response, payload_type: str) -> str:
        """Extract evidence from vulnerable response"""
        evidence = f"HTTP {response.status_code}"

        # Look for specific error messages
        text = response.text[:500]  # First 500 chars
        if 'error' in text.lower():
            evidence += f" - Error in response: {text[:100]}..."

        return evidence

    def _get_recommendations(self, payload_type: str) -> List[str]:
        """Get recommendations based on payload type"""
        base_recs = [
            'Use safe deserialization methods',
            'Validate input data before deserialization',
            'Implement proper error handling',
            'Keep libraries updated'
        ]

        specific_recs = {
            'php': ['Use json_decode() instead of unserialize()', 'Enable suhosin.patch'],
            'java': ['Use safe deserialization libraries', 'Implement serialVersionUID'],
            'python': ['Avoid pickle for untrusted data', 'Use json or msgpack'],
            'yaml': ['Use safe_load() instead of load()', 'Limit yaml.load() usage'],
            'xml': ['Disable entity processing', 'Use safe XML parsers'],
            'json': ['Use strict JSON parsing', 'Validate JSON schema']
        }

        if payload_type in specific_recs:
            return specific_recs[payload_type] + base_recs
        else:
            return base_recs

    def _check_magic_bytes(self):
        """Check for magic bytes that indicate serialization formats"""
        try:
            response = self.session.get(self.target, timeout=self.config['timeout'])

            content = response.content

            # Check for serialization magic bytes
            magic_bytes = {
                b'\x80\x03': 'Python pickle',
                b'\xac\xed\x00\x05': 'Java serialization',
                b'\x4f\x3a': 'PHP serialized object',
                b'%PDF-': 'PDF (potential XXE)',
                b'PK\x03\x04': 'ZIP (potential XXE)'
            }

            for magic, format_name in magic_bytes.items():
                if content.startswith(magic):
                    vuln = DeserializationVuln(
                        url=self.target,
                        parameter='response_body',
                        payload_type=format_name,
                        vulnerability_type='Magic Bytes Detection',
                        severity='MEDIUM',
                        description=f'Detected {format_name} magic bytes in response',
                        evidence=f'Response starts with {format_name} magic bytes',
                        recommendations=[
                            'Avoid sending serialized data in responses',
                            'Use safe serialization formats',
                            'Implement content-type validation'
                        ],
                        timestamp=time.time(),
                        response_time=response.elapsed.total_seconds()
                    )
                    self.vulnerabilities.append(vuln)
                    break

        except requests.RequestException:
            pass

    def _check_error_patterns(self):
        """Check for error patterns that indicate deserialization issues"""
        error_endpoints = ['/?data=invalid', '/?object=bad', '/?payload=test']

        for endpoint in error_endpoints:
            try:
                url = urljoin(self.target, endpoint)
                response = self.session.get(url, timeout=self.config['timeout'])

                if 'deserialization' in response.text.lower() or 'unserialize' in response.text.lower():
                    vuln = DeserializationVuln(
                        url=url,
                        parameter='query_parameters',
                        payload_type='unknown',
                        vulnerability_type='Error Pattern Detection',
                        severity='LOW',
                        description='Deserialization error messages detected',
                        evidence='Error message containing deserialization keywords',
                        recommendations=[
                            'Disable detailed error messages',
                            'Use generic error pages',
                            'Log errors securely'
                        ],
                        timestamp=time.time(),
                        response_time=response.elapsed.total_seconds()
                    )
                    self.vulnerabilities.append(vuln)
                    break

            except requests.RequestException:
                pass

    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze scan results"""
        total_vulnerabilities = len(self.vulnerabilities)
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] += 1

        # Group by payload type
        by_type = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.payload_type
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(asdict(vuln))

        # Calculate risk score
        risk_score = (
            severity_counts['CRITICAL'] * 4 +
            severity_counts['HIGH'] * 3 +
            severity_counts['MEDIUM'] * 2 +
            severity_counts['LOW'] * 1
        )

        # Determine overall risk level
        if severity_counts['CRITICAL'] > 0:
            risk_level = 'CRITICAL'
        elif severity_counts['HIGH'] > 0:
            risk_level = 'HIGH'
        elif severity_counts['MEDIUM'] > 0:
            risk_level = 'MEDIUM'
        elif total_vulnerabilities > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'

        return {
            'total_vulnerabilities': total_vulnerabilities,
            'severity_distribution': severity_counts,
            'by_payload_type': by_type,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'parameters_tested': sum(r.parameters_tested for r in self.results)
        }

def deserialization_scan(target: str, verbose: bool = False, config: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main deserialization scanning function

    Args:
        target: Target URL to scan
        verbose: Enable verbose logging
        config: Custom configuration

    Returns:
        Dictionary containing scan results
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scanner = DeserializationScanner(target, config)
    results = scanner.scan()

    # Print summary
    analysis = results['analysis']

    print(f"\n{'='*60}")
    print(f"DESERIALIZATION SCAN RESULTS FOR: {target}")
    print(f"{'='*60}")
    print(f"Parameters tested: {analysis['parameters_tested']}")
    print(f"Total vulnerabilities: {analysis['total_vulnerabilities']}")
    print(f"Risk level: {analysis['risk_level']}")

    print(f"\nSeverity Distribution:")
    for severity, count in analysis['severity_distribution'].items():
        if count > 0:
            print(f"  {severity}: {count}")

    if results['vulnerabilities']:
        print(f"\nTop Vulnerabilities:")
        # Sort by severity
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        sorted_vulns = sorted(results['vulnerabilities'],
                            key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
        for vuln in sorted_vulns[:5]:
            print(f"  {vuln['severity']} - {vuln['payload_type']} - {vuln['parameter']}")

    print(f"{'='*60}")

    return results

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python deserialization_scan.py <target_url> [--verbose] [--unsafe]")
        sys.exit(1)

    target = sys.argv[1]
    verbose = '--verbose' in sys.argv
    unsafe = '--unsafe' in sys.argv

    config = {'safe_mode': not unsafe} if unsafe else None

    try:
        results = deserialization_scan(target, verbose=verbose, config=config)
        print(f"\nScan completed successfully.")
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)