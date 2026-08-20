#!/usr/bin/env python3
"""
CVE (Common Vulnerabilities and Exposures) Checker
Checks for known vulnerabilities in detected software versions
"""

import requests
import logging
import json
import time
import re
import sqlite3
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
import threading
import os
import gzip
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class CVEMatch:
    """Data class for CVE matches"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    affected_software: str
    affected_versions: List[str]
    published_date: str
    last_modified: str
    references: List[str]

@dataclass
class SoftwareDetection:
    """Data class for detected software"""
    name: str
    version: str
    detection_method: str
    confidence: float
    cves: List[CVEMatch] = field(default_factory=list)

@dataclass
class CVECache:
    """Data class for CVE cache"""
    cve_id: str
    data: Dict[str, Any]
    last_updated: datetime
    hash: str

class CVEChecker:
    """
    Advanced CVE checker with NVD integration and local caching
    """

    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize CVE checker

        Args:
            target: Target URL to check
            config: Configuration dictionary
        """
        self.target = self._normalize_url(target)
        # Merge user config with defaults (avoid KeyError on missing keys)
        base_cfg = self._default_config()
        if config:
            base_cfg.update(config)
        self.config = base_cfg

        self.session = self._create_session()

        # Data structures
        self.detected_software: List[SoftwareDetection] = []
        self.cve_matches: List[CVEMatch] = []
        self.cache_db_path = self.config['cache_db_path']

        # Initialize cache
        self._init_cache_db()

        # Setup logging (must exist before any method use)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")


    def _default_config(self) -> Dict:
        """Default configuration settings"""
        return {
            'timeout': 15,
            'max_workers': 3,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'verify_ssl': False,
            'nvd_api_key': None,  # Set your NVD API key here
            'nvd_api_base': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'cache_db_path': os.path.join(os.path.dirname(__file__), 'cve_cache.db'),
            'cache_expiry_days': 7,
            'max_cve_results': 100,
            'severity_threshold': 'MEDIUM',  # LOW, MEDIUM, HIGH, CRITICAL
            'include_experimental': False,
            'rate_limit': 0.5,  # seconds between API calls
            'offline_mode': False
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

    def _init_cache_db(self):
        """Initialize SQLite cache database"""
        # Ensure logger exists even if db init fails early
        if not hasattr(self, 'logger'):
            self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        try:
            with sqlite3.connect(self.cache_db_path) as conn:

                conn.execute('''
                    CREATE TABLE IF NOT EXISTS cve_cache (
                        cve_id TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        last_updated TIMESTAMP NOT NULL,
                        hash TEXT NOT NULL
                    )
                ''')
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_last_updated
                    ON cve_cache(last_updated)
                ''')
                self.logger.debug("CVE cache database initialized")
        except Exception as e:
            self.logger.warning(f"Could not initialize cache database: {e}")

    def check(self) -> Dict[str, Any]:
        """
        Perform comprehensive CVE check

        Returns:
            Dictionary containing check results and analysis
        """
        self.logger.info(f"Starting CVE check for {self.target}")

        start_time = time.time()

        try:
            # Detect software versions
            self._detect_software()

            # Check for CVEs
            self._check_cves()

            # Analyze results
            analysis = self._analyze_results()

            duration = time.time() - start_time
            self.logger.info(f"CVE check completed in {duration:.2f} seconds")

            return {
                'target': self.target,
                'config': self.config,
                'detected_software': [asdict(sw) for sw in self.detected_software],
                'cve_matches': [asdict(cve) for cve in self.cve_matches],
                'analysis': analysis,
                'scan_duration': duration
            }

        except Exception as e:
            self.logger.error(f"Error during CVE check: {e}")
            raise

    def _detect_software(self):
        """Detect software versions from target"""
        self.logger.info("Detecting software versions...")

        try:
            # Get main page
            response = self.session.get(self.target, timeout=self.config['timeout'])
            server_header = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')

            # Detect from headers
            self._detect_from_headers(server_header, powered_by)

            # Detect from HTML content
            self._detect_from_html(response.text)

            # Check common endpoints
            self._check_common_endpoints()

            # Detect from error pages
            self._check_error_pages()

        except requests.RequestException as e:
            self.logger.warning(f"Error detecting software: {e}")

        self.logger.info(f"Detected {len(self.detected_software)} software components")

    def _detect_from_headers(self, server: str, powered_by: str):
        """Detect software from HTTP headers"""
        detections = []

        # Server header analysis
        if server:
            if 'apache' in server.lower():
                version = self._extract_version(server, r'Apache/([\d.]+)')
                detections.append(('Apache HTTP Server', version or 'Unknown', 'Server header', 0.9))
            elif 'nginx' in server.lower():
                version = self._extract_version(server, r'nginx/([\d.]+)')
                detections.append(('nginx', version or 'Unknown', 'Server header', 0.9))
            elif 'iis' in server.lower():
                version = self._extract_version(server, r'IIS/([\d.]+)')
                detections.append(('Microsoft IIS', version or 'Unknown', 'Server header', 0.8))

        # X-Powered-By header
        if powered_by:
            if 'php' in powered_by.lower():
                version = self._extract_version(powered_by, r'PHP/([\d.]+)')
                detections.append(('PHP', version or 'Unknown', 'X-Powered-By header', 0.9))
            elif 'asp.net' in powered_by.lower():
                detections.append(('ASP.NET', 'Unknown', 'X-Powered-By header', 0.7))

        for name, version, method, confidence in detections:
            detection = SoftwareDetection(name, version, method, confidence)
            self.detected_software.append(detection)

    def _detect_from_html(self, html: str):
        """Detect software from HTML content"""
        detections = []

        # Common patterns
        patterns = {
            'WordPress': [
                (r'wp-content', 0.8),
                (r'wp-includes', 0.9),
                (r'WordPress ([.\d]+)', 0.95)
            ],
            'Joomla': [
                (r'Joomla! ([.\d]+)', 0.95),
                (r'/media/jui/', 0.8)
            ],
            'Drupal': [
                (r'Drupal ([.\d]+)', 0.95),
                (r'/sites/default/', 0.8)
            ],
            'jQuery': [
                (r'jquery[.-]([.\d]+)', 0.9)
            ],
            'Bootstrap': [
                (r'bootstrap[.-]([.\d]+)', 0.8)
            ]
        }

        for software, pattern_list in patterns.items():
            for pattern, confidence in pattern_list:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else 'Unknown'
                    detections.append((software, version, 'HTML content', confidence))
                    break

        for name, version, method, confidence in detections:
            # Avoid duplicates
            if not any(d.name == name for d in self.detected_software):
                detection = SoftwareDetection(name, version, method, confidence)
                self.detected_software.append(detection)

    def _check_common_endpoints(self):
        """Check common software-specific endpoints"""
        endpoints = {
            '/wp-admin/': ('WordPress', 'Admin panel detection', 0.9),
            '/administrator/': ('Joomla', 'Admin panel detection', 0.9),
            '/user/login': ('Drupal', 'Login page detection', 0.8),
            '/phpmyadmin/': ('phpMyAdmin', 'Database admin detection', 0.9),
            '/adminer.php': ('Adminer', 'Database admin detection', 0.9),
            '/webmail/': ('Webmail', 'Mail interface detection', 0.7)
        }

        for endpoint, (software, method, confidence) in endpoints.items():
            try:
                url = urljoin(self.target, endpoint)
                response = self.session.get(url, timeout=5)

                if response.status_code == 200:
                    # Avoid duplicates
                    if not any(d.name == software for d in self.detected_software):
                        detection = SoftwareDetection(software, 'Unknown', method, confidence)
                        self.detected_software.append(detection)

            except requests.RequestException:
                pass

    def _check_error_pages(self):
        """Check error pages for software information"""
        error_endpoints = ['/404', '/error', '/error.php', '/err.html']

        for endpoint in error_endpoints:
            try:
                url = urljoin(self.target, endpoint)
                response = self.session.get(url, timeout=5)

                if response.status_code in [404, 500]:
                    # Look for software signatures in error pages
                    if 'apache' in response.text.lower():
                        detection = SoftwareDetection('Apache HTTP Server', 'Unknown', 'Error page', 0.6)
                        self._add_detection(detection)
                    elif 'nginx' in response.text.lower():
                        detection = SoftwareDetection('nginx', 'Unknown', 'Error page', 0.6)
                        self._add_detection(detection)

            except requests.RequestException:
                pass

    def _add_detection(self, detection: SoftwareDetection):
        """Add detection avoiding duplicates"""
        if not any(d.name == detection.name for d in self.detected_software):
            self.detected_software.append(detection)

    def _extract_version(self, text: str, pattern: str) -> Optional[str]:
        """Extract version from text using regex"""
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1) if match else None

    def _check_cves(self):
        """Check for CVEs in detected software"""
        self.logger.info("Checking for CVEs...")

        with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
            futures = []
            for software in self.detected_software:
                future = executor.submit(self._check_software_cves, software)
                futures.append(future)

            for future in as_completed(futures):
                try:
                    cves = future.result()
                    # CVEs are already added to software.cves in the function
                except Exception as e:
                    self.logger.error(f"Error checking CVEs: {e}")

    def _check_software_cves(self, software: SoftwareDetection) -> List[CVEMatch]:
        """Check CVEs for specific software"""
        cves = []

        # Query NVD API
        if not self.config['offline_mode']:
            cves.extend(self._query_nvd_api(software))

        # Check local cache
        cves.extend(self._check_cache(software))

        # Remove duplicates
        seen_cves = set()
        unique_cves = []
        for cve in cves:
            if cve.cve_id not in seen_cves:
                unique_cves.append(cve)
                seen_cves.add(cve.cve_id)

        software.cves = unique_cves
        self.cve_matches.extend(unique_cves)

        return unique_cves

    def _query_nvd_api(self, software: SoftwareDetection) -> List[CVEMatch]:
        """Query NVD API for CVEs"""
        cves = []

        try:
            # Build search query
            query = f"cpeName=cpe:2.3:a:{software.name.lower().replace(' ', '_')}:*:*:*:*:*:*:*"
            if software.version != 'Unknown':
                query += f"&versionEndIncluding={software.version}"

            params = {
                'keywordSearch': software.name,
                'resultsPerPage': min(20, self.config['max_cve_results']),
                'startIndex': 0
            }

            headers = {}
            if self.config['nvd_api_key']:
                headers['apiKey'] = self.config['nvd_api_key']

            response = self.session.get(
                self.config['nvd_api_base'],
                params=params,
                headers=headers,
                timeout=self.config['timeout']
            )

            if response.status_code == 200:
                data = response.json()
                cves.extend(self._parse_nvd_response(data, software))

            # Rate limiting
            time.sleep(self.config['rate_limit'])

        except requests.RequestException as e:
            self.logger.warning(f"NVD API query failed: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing NVD response: {e}")

        return cves

    def _parse_nvd_response(self, data: Dict[str, Any], software: SoftwareDetection) -> List[CVEMatch]:
        """Parse NVD API response"""
        cves = []

        for vuln in data.get('vulnerabilities', []):
            cve_data = vuln.get('cve', {})

            cve_id = cve_data.get('id', '')
            descriptions = cve_data.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')

            # Get CVSS score
            metrics = cve_data.get('metrics', {})
            cvss_score = 0.0
            severity = 'UNKNOWN'

            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')

            # Check severity threshold
            severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
            threshold_level = severity_levels.get(self.config['severity_threshold'], 2)

            if severity_levels.get(severity, 0) < threshold_level:
                continue

            # Get references
            references = [ref['url'] for ref in cve_data.get('references', [])]

            # Get published/modified dates
            published = cve_data.get('published', '')
            last_modified = cve_data.get('lastModified', '')

            cve_match = CVEMatch(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                affected_software=software.name,
                affected_versions=[software.version] if software.version != 'Unknown' else [],
                published_date=published,
                last_modified=last_modified,
                references=references
            )

            cves.append(cve_match)

            # Cache the CVE
            self._cache_cve(cve_match)

        return cves

    def _check_cache(self, software: SoftwareDetection) -> List[CVEMatch]:
        """Check local cache for CVEs"""
        cves = []

        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()

                # Get CVEs from cache (not expired)
                expiry_date = datetime.now() - timedelta(days=self.config['cache_expiry_days'])
                cursor.execute('''
                    SELECT cve_id, data FROM cve_cache
                    WHERE last_updated > ?
                ''', (expiry_date.isoformat(),))

                for row in cursor.fetchall():
                    cve_id, data_str = row
                    try:
                        cve_data = json.loads(data_str)
                        # Check if relevant to software
                        if software.name.lower() in cve_data.get('description', '').lower():
                            cve_match = CVEMatch(**cve_data)
                            cves.append(cve_match)
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            self.logger.warning(f"Cache query failed: {e}")

        return cves

    def _cache_cve(self, cve: CVEMatch):
        """Cache CVE in database"""
        try:
            data = asdict(cve)
            data_str = json.dumps(data)
            data_hash = hashlib.md5(data_str.encode()).hexdigest()

            with sqlite3.connect(self.cache_db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO cve_cache (cve_id, data, last_updated, hash)
                    VALUES (?, ?, ?, ?)
                ''', (cve.cve_id, data_str, datetime.now().isoformat(), data_hash))

        except Exception as e:
            self.logger.warning(f"Failed to cache CVE {cve.cve_id}: {e}")

    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze CVE check results"""
        total_cves = len(self.cve_matches)
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}

        for cve in self.cve_matches:
            severity_counts[cve.severity] += 1

        # Calculate risk score
        # Calculate risk score based on severity distribution
        sev_weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
        risk_score = sum(severity_counts.get(sev, 0) * weight for sev, weight in sev_weights.items())


        # Determine overall risk level
        if severity_counts['CRITICAL'] > 0 or risk_score >= 10:
            risk_level = 'CRITICAL'
        elif severity_counts['HIGH'] > 0 or risk_score >= 5:
            risk_level = 'HIGH'
        elif severity_counts['MEDIUM'] > 0 or risk_score >= 2:
            risk_level = 'MEDIUM'
        elif total_cves > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'

        # Group CVEs by software
        cves_by_software = {}
        for software in self.detected_software:
            cves_by_software[software.name] = [asdict(cve) for cve in software.cves]

        return {
            'total_cves': total_cves,
            'severity_distribution': severity_counts,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'cves_by_software': cves_by_software,
            'software_count': len(self.detected_software),
            'detection_confidence_avg': sum(s.confidence for s in self.detected_software) / max(1, len(self.detected_software))
        }

def cve_checker(target: str, verbose: bool = False, config: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main CVE checking function

    Args:
        target: Target URL to check
        verbose: Enable verbose logging
        config: Custom configuration

    Returns:
        Dictionary containing check results
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    checker = CVEChecker(target, config)
    results = checker.check()

    # Print summary
    analysis = results['analysis']

    print(f"\n{'='*60}")
    print(f"CVE CHECK RESULTS FOR: {target}")
    print(f"{'='*60}")
    print(f"Software detected: {analysis['software_count']}")
    print(f"Total CVEs found: {analysis['total_cves']}")
    print(f"Risk level: {analysis['risk_level']}")
    print(f"Average detection confidence: {analysis['detection_confidence_avg']:.2f}")

    print(f"\nSeverity Distribution:")
    for severity, count in analysis['severity_distribution'].items():
        if count > 0:
            print(f"  {severity}: {count}")

    if results['detected_software']:
        print(f"\nDetected Software:")
        for software in results['detected_software']:
            cve_count = len(software['cves'])
            print(f"  {software['name']} {software['version']} ({software['detection_method']}) - {cve_count} CVEs")

    if results['cve_matches']:
        print(f"\nTop CVEs:")
        # Sort by CVSS score
        sorted_cves = sorted(results['cve_matches'], key=lambda x: x['cvss_score'], reverse=True)
        for cve in sorted_cves[:5]:
            print(f"  {cve['cve_id']} ({cve['severity']}, {cve['cvss_score']})")

    print(f"{'='*60}")

    return results

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cve_checker.py <target_url> [--verbose] [--offline]")
        sys.exit(1)

    target = sys.argv[1]
    verbose = '--verbose' in sys.argv
    offline = '--offline' in sys.argv

    config = {'offline_mode': offline} if offline else None

    try:
        results = cve_checker(target, verbose=verbose, config=config)
        print(f"\nCheck completed successfully.")
    except Exception as e:
        print(f"Error during check: {e}")
        sys.exit(1)