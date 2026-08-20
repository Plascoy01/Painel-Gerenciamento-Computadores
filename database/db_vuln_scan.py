#!/usr/bin/env python3
"""
Database Vulnerability Scanner
Scans for exposed database interfaces and related vulnerabilities
"""

import requests
import logging
import json
import time
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
import threading
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class DBVulnerability:
    """Data class for database vulnerabilities"""
    url: str
    db_type: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    recommendations: List[str]
    timestamp: float
    response_time: float

@dataclass
class DBInterface:
    """Data class for detected database interfaces"""
    url: str
    db_type: str
    status_code: int
    title: str
    version: str
    is_accessible: bool
    vulnerabilities: List[DBVulnerability] = field(default_factory=list)

class DBVulnScanner:
    """
    Advanced database vulnerability scanner
    """

    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize database vulnerability scanner

        Args:
            target: Target URL to scan
            config: Configuration dictionary
        """
        self.target = self._normalize_url(target)
        self.config = config or self._default_config()
        self.session = self._create_session()
        self.results: List[DBInterface] = []
        self.vulnerabilities: List[DBVulnerability] = []

        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def _default_config(self) -> Dict:
        """Default configuration settings"""
        return {
            'timeout': 10,
            'max_workers': 5,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'verify_ssl': False,
            'follow_redirects': False,
            'rate_limit': 0.2,  # seconds between requests
            'max_retries': 2,
            'test_credentials': False,
            'brute_force': False,
            'wordlist_path': None,
            'check_default_creds': True,
            'scan_subdomains': False
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
        session.max_redirects = 0 if not self.config['follow_redirects'] else 5
        return session

    def scan(self) -> Dict[str, Any]:
        """
        Perform comprehensive database vulnerability scan

        Returns:
            Dictionary containing scan results and analysis
        """
        self.logger.info(f"Starting database vulnerability scan for {self.target}")

        start_time = time.time()

        try:
            # Discover database interfaces
            interfaces = self._discover_db_interfaces()

            # Analyze each interface
            with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
                futures = []
                for interface in interfaces:
                    future = executor.submit(self._analyze_db_interface, interface)
                    futures.append(future)

                for future in as_completed(futures):
                    try:
                        analyzed_interface = future.result()
                        if analyzed_interface:
                            self.results.append(analyzed_interface)
                            self.vulnerabilities.extend(analyzed_interface.vulnerabilities)
                    except Exception as e:
                        self.logger.error(f"Error analyzing interface: {e}")

            # Additional checks
            self._check_db_exposure_indicators()
            self._check_db_error_disclosure()

            # Finalize
            duration = time.time() - start_time
            analysis = self._analyze_results()

            self.logger.info(f"Database scan completed. Found {len(self.results)} interfaces")

            return {
                'target': self.target,
                'config': self.config,
                'interfaces': [asdict(interface) for interface in self.results],
                'vulnerabilities': [asdict(vuln) for vuln in self.vulnerabilities],
                'analysis': analysis,
                'scan_duration': duration
            }

        except Exception as e:
            self.logger.error(f"Error during database scan: {e}")
            raise

    def _discover_db_interfaces(self) -> List[Dict[str, Any]]:
        """Discover database administration interfaces"""
        self.logger.info("Discovering database interfaces...")

        interfaces = []

        # Common database interface endpoints
        db_endpoints = {
            # phpMyAdmin
            'phpmyadmin': [
                '/phpmyadmin/',
                '/phpMyAdmin/',
                '/pma/',
                '/admin/phpmyadmin/',
                '/mysql/',
                '/dbadmin/',
                '/database/'
            ],
            # Adminer
            'adminer': [
                '/adminer.php',
                '/adminer/',
                '/adminer/adminer.php'
            ],
            # phpPgAdmin
            'phppgadmin': [
                '/phppgadmin/',
                '/postgres/'
            ],
            # SQLite Manager
            'sqlitemanager': [
                '/SQLiteManager/',
                '/sqlite/'
            ],
            # MongoDB interfaces
            'mongodb': [
                '/mongo/',
                '/db/_utils/',
                '/_utils/'
            ],
            # Redis interfaces
            'redis': [
                '/redis/',
                '/redisdashboard/'
            ],
            # Generic database
            'generic': [
                '/db/',
                '/database/',
                '/sql/',
                '/data/',
                '/admin/db/',
                '/manage/db/'
            ]
        }

        discovered = []

        for db_type, endpoints in db_endpoints.items():
            for endpoint in endpoints:
                url = urljoin(self.target, endpoint)

                try:
                    response = self.session.get(
                        url,
                        timeout=self.config['timeout'],
                        allow_redirects=self.config['follow_redirects']
                    )

                    if self._is_db_interface(response, db_type):
                        interface = {
                            'url': url,
                            'db_type': db_type,
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text),
                            'version': self._extract_version(response.text, db_type),
                            'response': response
                        }
                        discovered.append(interface)

                    # Rate limiting
                    time.sleep(self.config['rate_limit'])

                except requests.RequestException as e:
                    self.logger.debug(f"Request failed for {url}: {e}")

        self.logger.info(f"Discovered {len(discovered)} potential database interfaces")
        return discovered

    def _is_db_interface(self, response: requests.Response, db_type: str) -> bool:
        """Determine if response indicates a database interface"""
        if response.status_code not in [200, 301, 302, 401, 403]:
            return False

        text = response.text.lower()
        content_type = response.headers.get('content-type', '').lower()

        # Check for database-specific indicators
        indicators = {
            'phpmyadmin': [
                'phpmyadmin', 'mysql', 'database', 'server: localhost',
                'phpmyadmin.css', 'phpmyadmin.js'
            ],
            'adminer': [
                'adminer', 'login', 'database', 'sqlite', 'mysql', 'postgresql'
            ],
            'phppgadmin': [
                'phppgadmin', 'postgresql', 'postgres'
            ],
            'mongodb': [
                'mongodb', 'mongo', 'couchdb', 'document database'
            ],
            'redis': [
                'redis', 'key-value', 'cache'
            ]
        }

        if db_type in indicators:
            for indicator in indicators[db_type]:
                if indicator in text:
                    return True

        # Generic checks
        if 'database' in text or 'db' in text:
            if 'login' in text or 'password' in text or 'connect' in text:
                return True

        # Check for common database ports in redirects
        if response.status_code in [301, 302]:
            location = response.headers.get('location', '')
            if ':3306' in location or ':5432' in location or ':27017' in location:
                return True

        return False

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else ''

    def _extract_version(self, html: str, db_type: str) -> str:
        """Extract version information from HTML"""
        version_patterns = {
            'phpmyadmin': r'phpMyAdmin\s+([\d.]+)',
            'adminer': r'Adminer\s+([\d.]+)',
            'phppgadmin': r'phpPgAdmin\s+([\d.]+)'
        }

        if db_type in version_patterns:
            match = re.search(version_patterns[db_type], html, re.IGNORECASE)
            if match:
                return match.group(1)

        return 'Unknown'

    def _analyze_db_interface(self, interface_data: Dict[str, Any]) -> Optional[DBInterface]:
        """Analyze a database interface for vulnerabilities"""
        url = interface_data['url']
        db_type = interface_data['db_type']
        response = interface_data['response']

        start_time = time.time()

        vulnerabilities = []

        # Check for default credentials
        if self.config['check_default_creds']:
            cred_vulns = self._check_default_credentials(url, db_type)
            vulnerabilities.extend(cred_vulns)

        # Check for exposed information
        exposure_vulns = self._check_information_exposure(url, response, db_type)
        vulnerabilities.extend(exposure_vulns)

        # Check for misconfigurations
        config_vulns = self._check_misconfigurations(url, response, db_type)
        vulnerabilities.extend(config_vulns)

        # Check for known vulnerabilities
        known_vulns = self._check_known_vulnerabilities(url, db_type, interface_data.get('version', 'Unknown'))
        vulnerabilities.extend(known_vulns)

        # Determine accessibility
        is_accessible = response.status_code in [200, 401, 403] and not self._requires_auth(response)

        interface = DBInterface(
            url=url,
            db_type=db_type,
            status_code=response.status_code,
            title=interface_data['title'],
            version=interface_data['version'],
            is_accessible=is_accessible,
            vulnerabilities=vulnerabilities
        )

        return interface

    def _check_default_credentials(self, url: str, db_type: str) -> List[DBVulnerability]:
        """Check for default credentials"""
        vulnerabilities = []

        if not self.config['test_credentials']:
            return vulnerabilities

        default_creds = {
            'phpmyadmin': [
                ('root', ''), ('root', 'root'), ('admin', 'admin'),
                ('root', 'password'), ('admin', '')
            ],
            'adminer': [
                ('root', ''), ('admin', 'admin')
            ],
            'phppgadmin': [
                ('postgres', 'postgres'), ('admin', 'admin')
            ]
        }

        if db_type not in default_creds:
            return vulnerabilities

        for username, password in default_creds[db_type][:3]:  # Test first 3 pairs
            try:
                # Attempt login (simplified - would need form parsing in real implementation)
                data = {
                    'pma_username': username,
                    'pma_password': password,
                    'server': '1'
                } if db_type == 'phpmyadmin' else {}

                if data:
                    response = self.session.post(url, data=data, timeout=self.config['timeout'])

                    if 'access denied' not in response.text.lower() and response.status_code == 200:
                        vuln = DBVulnerability(
                            url=url,
                            db_type=db_type,
                            vulnerability_type='Default Credentials',
                            severity='CRITICAL',
                            description=f'Default credentials work: {username}:{password}',
                            evidence=f'Successful login with {username}:{password}',
                            recommendations=[
                                'Change default credentials immediately',
                                'Use strong, unique passwords',
                                'Implement account lockout policies'
                            ],
                            timestamp=time.time(),
                            response_time=time.time() - time.time()
                        )
                        vulnerabilities.append(vuln)
                        break

                time.sleep(self.config['rate_limit'])

            except requests.RequestException:
                pass

        return vulnerabilities

    def _check_information_exposure(self, url: str, response: requests.Response, db_type: str) -> List[DBVulnerability]:
        """Check for information exposure vulnerabilities"""
        vulnerabilities = []

        # Check for version disclosure
        if 'version' in response.text.lower() or 'release' in response.text.lower():
            vuln = DBVulnerability(
                url=url,
                db_type=db_type,
                vulnerability_type='Information Disclosure',
                severity='MEDIUM',
                description='Version information is disclosed',
                evidence='Version string found in response',
                recommendations=[
                    'Remove version information from public interfaces',
                    'Use generic error pages'
                ],
                timestamp=time.time(),
                response_time=0.0
            )
            vulnerabilities.append(vuln)

        # Check for database structure exposure
        if 'database' in response.text.lower() and ('table' in response.text.lower() or 'schema' in response.text.lower()):
            vuln = DBVulnerability(
                url=url,
                db_type=db_type,
                vulnerability_type='Information Disclosure',
                severity='HIGH',
                description='Database structure information exposed',
                evidence='Database schema or table information visible',
                recommendations=[
                    'Restrict access to database administration interfaces',
                    'Use proper authentication and authorization'
                ],
                timestamp=time.time(),
                response_time=0.0
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_misconfigurations(self, url: str, response: requests.Response, db_type: str) -> List[DBVulnerability]:
        """Check for misconfiguration vulnerabilities"""
        vulnerabilities = []

        # Check for missing authentication
        if response.status_code == 200 and not self._requires_auth(response):
            vuln = DBVulnerability(
                url=url,
                db_type=db_type,
                vulnerability_type='Misconfiguration',
                severity='CRITICAL',
                description='Database interface accessible without authentication',
                evidence=f'HTTP {response.status_code} without authentication required',
                recommendations=[
                    'Implement proper authentication',
                    'Restrict access to trusted networks only',
                    'Use VPN or SSH tunneling for administration'
                ],
                timestamp=time.time(),
                response_time=0.0
            )
            vulnerabilities.append(vuln)

        # Check for weak SSL/TLS
        if url.startswith('http://'):
            vuln = DBVulnerability(
                url=url,
                db_type=db_type,
                vulnerability_type='Misconfiguration',
                severity='HIGH',
                description='Database interface served over unencrypted HTTP',
                evidence='URL uses HTTP instead of HTTPS',
                recommendations=[
                    'Enable HTTPS/TLS encryption',
                    'Redirect HTTP to HTTPS',
                    'Use strong SSL/TLS certificates'
                ],
                timestamp=time.time(),
                response_time=0.0
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_known_vulnerabilities(self, url: str, db_type: str, version: str) -> List[DBVulnerability]:
        """Check for known vulnerabilities in the detected version"""
        vulnerabilities = []

        # Known vulnerabilities database (simplified)
        known_vulns = {
            'phpmyadmin': {
                '4.8.0': [
                    ('CVE-2018-12613', 'HIGH', 'File inclusion vulnerability'),
                    ('CVE-2018-19968', 'MEDIUM', 'CSRF vulnerability')
                ],
                '4.9.0': [
                    ('CVE-2019-12922', 'HIGH', 'SQL injection vulnerability')
                ]
            },
            'adminer': {
                '4.6.0': [
                    ('CVE-2019-10200', 'HIGH', 'Remote code execution')
                ]
            }
        }

        if db_type in known_vulns and version in known_vulns[db_type]:
            for cve_id, severity, description in known_vulns[db_type][version]:
                vuln = DBVulnerability(
                    url=url,
                    db_type=db_type,
                    vulnerability_type='Known Vulnerability',
                    severity=severity,
                    description=f'{cve_id}: {description}',
                    evidence=f'Version {version} detected with known vulnerability',
                    recommendations=[
                        f'Upgrade {db_type} to latest version',
                        'Apply security patches',
                        'Monitor for exploits'
                    ],
                    timestamp=time.time(),
                    response_time=0.0
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _requires_auth(self, response: requests.Response) -> bool:
        """Check if response indicates authentication is required"""
        if response.status_code in [401, 403]:
            return True

        text = response.text.lower()
        if 'login' in text or 'password' in text or 'authenticate' in text:
            return True

        return False

    def _check_db_exposure_indicators(self):
        """Check for other indicators of database exposure"""
        # Check for database files
        db_files = ['/db.sql', '/database.sql', '/dump.sql', '/backup.sql']

        for db_file in db_files:
            try:
                url = urljoin(self.target, db_file)
                response = self.session.get(url, timeout=self.config['timeout'])

                if response.status_code == 200:
                    vuln = DBVulnerability(
                        url=url,
                        db_type='Generic',
                        vulnerability_type='Exposed Database File',
                        severity='CRITICAL',
                        description='Database dump file exposed',
                        evidence=f'Database file accessible at {url}',
                        recommendations=[
                            'Remove exposed database files',
                            'Restrict access to sensitive files',
                            'Use proper file permissions'
                        ],
                        timestamp=time.time(),
                        response_time=0.0
                    )
                    self.vulnerabilities.append(vuln)

                time.sleep(self.config['rate_limit'])

            except requests.RequestException:
                pass

    def _check_db_error_disclosure(self):
        """Check for database error disclosure"""
        # Try to trigger database errors
        error_payloads = [
            '/?id=1\'',
            '/?query=SELECT * FROM nonexistent',
            '/?db=invalid_database'
        ]

        for payload in error_payloads:
            try:
                url = urljoin(self.target, payload)
                response = self.session.get(url, timeout=self.config['timeout'])

                if self._contains_db_error(response.text):
                    vuln = DBVulnerability(
                        url=url,
                        db_type='Generic',
                        vulnerability_type='Error Disclosure',
                        severity='MEDIUM',
                        description='Database error information disclosed',
                        evidence='Database error message in response',
                        recommendations=[
                            'Disable detailed error reporting',
                            'Use generic error pages',
                            'Log errors securely'
                        ],
                        timestamp=time.time(),
                        response_time=0.0
                    )
                    self.vulnerabilities.append(vuln)
                    break

                time.sleep(self.config['rate_limit'])

            except requests.RequestException:
                pass

    def _contains_db_error(self, text: str) -> bool:
        """Check if text contains database error indicators"""
        error_patterns = [
            r'mysql.*error',
            r'postgresql.*error',
            r'sqlite.*error',
            r'odbc.*error',
            r'sql syntax',
            r'unknown column',
            r'table.*doesn\'t exist'
        ]

        text_lower = text.lower()
        for pattern in error_patterns:
            if re.search(pattern, text_lower):
                return True

        return False

    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze scan results"""
        total_interfaces = len(self.results)
        accessible_interfaces = len([r for r in self.results if r.is_accessible])
        total_vulnerabilities = len(self.vulnerabilities)

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] += 1

        # Group by database type
        by_type = {}
        for result in self.results:
            if result.db_type not in by_type:
                by_type[result.db_type] = []
            by_type[result.db_type].append(asdict(result))

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
        elif severity_counts['HIGH'] > 0 or accessible_interfaces > 0:
            risk_level = 'HIGH'
        elif severity_counts['MEDIUM'] > 0:
            risk_level = 'MEDIUM'
        elif total_vulnerabilities > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'

        return {
            'total_interfaces': total_interfaces,
            'accessible_interfaces': accessible_interfaces,
            'total_vulnerabilities': total_vulnerabilities,
            'severity_distribution': severity_counts,
            'by_database_type': by_type,
            'risk_score': risk_score,
            'risk_level': risk_level
        }

def db_vuln_scan(target: str, verbose: bool = False, config: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main database vulnerability scanning function

    Args:
        target: Target URL to scan
        verbose: Enable verbose logging
        config: Custom configuration

    Returns:
        Dictionary containing scan results
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scanner = DBVulnScanner(target, config)
    results = scanner.scan()

    # Print summary
    analysis = results['analysis']

    print(f"\n{'='*60}")
    print(f"DATABASE VULNERABILITY SCAN RESULTS FOR: {target}")
    print(f"{'='*60}")
    print(f"Database interfaces found: {analysis['total_interfaces']}")
    print(f"Accessible interfaces: {analysis['accessible_interfaces']}")
    print(f"Total vulnerabilities: {analysis['total_vulnerabilities']}")
    print(f"Risk level: {analysis['risk_level']}")

    print(f"\nSeverity Distribution:")
    for severity, count in analysis['severity_distribution'].items():
        if count > 0:
            print(f"  {severity}: {count}")

    if results['interfaces']:
        print(f"\nDetected Interfaces:")
        for interface in results['interfaces']:
            vuln_count = len(interface['vulnerabilities'])
            accessible = "Accessible" if interface['is_accessible'] else "Protected"
            print(f"  {interface['db_type']} - {interface['url']} ({accessible}) - {vuln_count} vulnerabilities")

    if results['vulnerabilities']:
        print(f"\nTop Vulnerabilities:")
        # Sort by severity
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        sorted_vulns = sorted(results['vulnerabilities'],
                            key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
        for vuln in sorted_vulns[:5]:
            print(f"  {vuln['severity']} - {vuln['vulnerability_type']} - {vuln['url']}")

    print(f"{'='*60}")

    return results

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python db_vuln_scan.py <target_url> [--verbose]")
        sys.exit(1)

    target = sys.argv[1]
    verbose = '--verbose' in sys.argv

    try:
        results = db_vuln_scan(target, verbose=verbose)
        print(f"\nScan completed successfully.")
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)