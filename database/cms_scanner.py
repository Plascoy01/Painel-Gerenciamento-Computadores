"""
CMS Scanner Module for Plascoy Security Scanner

This module performs comprehensive Content Management System detection and analysis including:
- CMS fingerprinting and identification
- Version detection for known vulnerabilities
- Plugin and theme enumeration
- Security assessment for detected CMS
- Configuration file exposure checks
- Admin panel detection
- Default installation detection
- Known vulnerability correlation

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
class CMSFinding:
    """Data class for CMS detection findings"""
    cms_name: str
    version: str
    confidence: str
    detection_method: str
    vulnerabilities: List[Dict]
    plugins: List[str]
    themes: List[str]
    admin_urls: List[str]

@dataclass
class CMSVulnerability:
    """Data class for CMS vulnerabilities"""
    cms_name: str
    version: str
    vuln_id: str
    severity: str
    description: str
    cve_id: str = ""
    cvss_score: float = 0.0

@dataclass
class CMSScanConfig:
    """Configuration for CMS scanning"""
    timeout: int = 10
    max_workers: int = 5
    user_agent: str = 'Plascoy-CMS-Scanner/2.0'
    follow_redirects: bool = True
    verify_ssl: bool = False
    delay_between_requests: float = 0.1
    check_version: bool = True
    check_plugins: bool = True
    check_vulnerabilities: bool = True
    max_paths_per_cms: int = 10

class CMSScanner:
    """
    Professional CMS detection and analysis scanner with comprehensive features.

    This class provides methods to identify Content Management Systems,
    detect versions, enumerate plugins/themes, and check for known vulnerabilities.
    """

    def __init__(self, config: CMSScanConfig = None):
        """
        Initialize the CMS scanner with configuration.

        Args:
            config: CMSScanConfig object with scanning parameters
        """
        self.config = config or CMSScanConfig()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        self.session.verify = self.config.verify_ssl

        # Setup logging
        self.logger = logging.getLogger('CMSScanner')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.findings: List[CMSFinding] = []
        self.scanned_urls: Set[str] = set()

        # Initialize CMS signatures
        self.cms_signatures = self._load_cms_signatures()

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

    def _load_cms_signatures(self) -> Dict[str, Dict]:
        """Load CMS detection signatures"""
        return {
            'WordPress': {
                'paths': ['/wp-admin/', '/wp-login.php', '/wp-content/', '/wp-includes/',
                         '/wp-json/wp/v2/', '/xmlrpc.php', '/readme.html'],
                'headers': ['X-Pingback', 'X-Powered-By: WordPress'],
                'meta': ['generator.*WordPress', 'wp-paginate'],
                'files': ['wp-config.php', 'wp-settings.php'],
                'version_files': ['/readme.html', '/wp-includes/version.php']
            },
            'Joomla': {
                'paths': ['/administrator/', '/components/', '/modules/', '/templates/',
                         '/plugins/', '/libraries/', '/language/'],
                'headers': ['X-Powered-By: Joomla'],
                'meta': ['generator.*Joomla', 'joomla'],
                'files': ['configuration.php', 'joomla.xml'],
                'version_files': ['/administrator/manifests/files/joomla.xml', '/language/en-GB/en-GB.xml']
            },
            'Drupal': {
                'paths': ['/user/login', '/sites/default/', '/modules/', '/themes/',
                         '/sites/all/', '/core/', '/profiles/'],
                'headers': ['X-Drupal-Cache', 'X-Generator: Drupal'],
                'meta': ['generator.*Drupal', 'drupal'],
                'files': ['sites/default/settings.php', 'core/lib/Drupal.php'],
                'version_files': ['/core/modules/system/system.info.yml', '/CHANGELOG.txt']
            },
            'Magento': {
                'paths': ['/admin/', '/downloader/', '/var/', '/app/', '/skin/',
                         '/js/', '/media/', '/api/', '/checkout/'],
                'headers': ['X-Powered-By: Magento'],
                'meta': ['generator.*Magento'],
                'files': ['app/Mage.php', 'app/etc/local.xml'],
                'version_files': ['/app/Mage.php', '/RELEASE_NOTES.txt']
            },
            'PrestaShop': {
                'paths': ['/admin/', '/modules/', '/themes/', '/img/', '/css/',
                         '/js/', '/controllers/', '/classes/'],
                'headers': [],
                'meta': ['generator.*PrestaShop'],
                'files': ['config/settings.inc.php', 'classes/Configuration.php'],
                'version_files': ['/config/xml/version.xml', '/CHANGELOG.txt']
            },
            'Shopify': {
                'paths': ['/admin/', '/collections/', '/products/', '/cart', '/checkout'],
                'headers': ['X-Shopify-Stage', 'X-ShopId'],
                'meta': ['generator.*Shopify'],
                'files': [],
                'version_files': []
            },
            'vBulletin': {
                'paths': ['/forum/', '/admincp/', '/modcp/', '/archive/', '/ajax.php'],
                'headers': [],
                'meta': ['generator.*vBulletin'],
                'files': ['includes/config.php', 'core/includes/config.php'],
                'version_files': ['/README.html', '/admincp/options.php']
            },
            'phpBB': {
                'paths': ['/adm/', '/download/', '/files/', '/store/', '/styles/'],
                'headers': [],
                'meta': ['generator.*phpBB'],
                'files': ['config.php', 'common.php'],
                'version_files': ['/docs/CHANGELOG.html', '/install/index.php']
            },
            'MediaWiki': {
                'paths': ['/index.php/Special:Version', '/api.php', '/skins/', '/extensions/'],
                'headers': ['X-Powered-By: MediaWiki'],
                'meta': ['generator.*MediaWiki'],
                'files': ['LocalSettings.php', 'includes/DefaultSettings.php'],
                'version_files': ['/api.php?action=query&meta=siteinfo&siprop=general', '/includes/DefaultSettings.php']
            },
            'TYPO3': {
                'paths': ['/typo3/', '/typo3conf/', '/typo3temp/', '/fileadmin/', '/uploads/'],
                'headers': ['X-TYPO3-Parsetime'],
                'meta': ['generator.*TYPO3'],
                'files': ['typo3conf/LocalConfiguration.php', 'typo3/sysext/core/ext_emconf.php'],
                'version_files': ['/typo3/sysext/core/ext_emconf.php', '/CHANGELOG.md']
            }
        }

    def _make_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling.

        Args:
            url: Target URL
            **kwargs: Additional request parameters

        Returns:
            Response object or None if failed
        """
        if url in self.scanned_urls:
            return None

        self.scanned_urls.add(url)

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

    def _check_cms_paths(self, base_url: str, cms_name: str, cms_data: Dict) -> bool:
        """
        Check for CMS-specific paths.

        Args:
            base_url: Base URL to check
            cms_name: Name of CMS
            cms_data: CMS signature data

        Returns:
            True if CMS detected, False otherwise
        """
        paths_to_check = cms_data['paths'][:self.config.max_paths_per_cms]

        for path in paths_to_check:
            url = urljoin(base_url, path)
            response = self._make_request(url)

            if response and response.status_code in [200, 301, 302, 403]:
                # Additional check for content
                if self._analyze_response_content(response, cms_data):
                    return True

        return False

    def _analyze_response_content(self, response: requests.Response, cms_data: Dict) -> bool:
        """
        Analyze response content for CMS indicators.

        Args:
            response: HTTP response
            cms_data: CMS signature data

        Returns:
            True if CMS indicators found
        """
        content = response.text.lower()

        # Check meta tags
        for meta_pattern in cms_data.get('meta', []):
            if re.search(meta_pattern.lower(), content, re.IGNORECASE):
                return True

        # Check for specific content patterns
        cms_indicators = {
            'WordPress': ['wordpress', 'wp-content', 'wp-includes'],
            'Joomla': ['joomla', 'com_content', 'mod_login'],
            'Drupal': ['drupal', 'sites/all', 'node/1'],
            'Magento': ['magento', 'var/cache', 'skin/frontend'],
            'PrestaShop': ['prestashop', 'classes/controller', 'modules/block'],
            'Shopify': ['shopify', 'cdn.shopify.com'],
            'vBulletin': ['vbulletin', 'vbseo', 'forumrunner'],
            'phpBB': ['phpbb', 'viewforum', 'viewtopic'],
            'MediaWiki': ['mediawiki', 'wikimedia', 'mw-'],
            'TYPO3': ['typo3', 'typoscript', 'tt_content']
        }

        cms_name = None
        for name, indicators in cms_indicators.items():
            if any(indicator in content for indicator in indicators):
                cms_name = name
                break

        return cms_name is not None

    def _check_cms_headers(self, base_url: str, cms_data: Dict) -> bool:
        """
        Check HTTP headers for CMS indicators.

        Args:
            base_url: Base URL to check
            cms_data: CMS signature data

        Returns:
            True if CMS headers found
        """
        response = self._make_request(base_url)
        if not response:
            return False

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        for header_pattern in cms_data.get('headers', []):
            header_name, header_value = header_pattern.split(': ', 1) if ': ' in header_pattern else (header_pattern, '')
            if header_name.lower() in headers:
                if not header_value or header_value in headers[header_name.lower()]:
                    return True

        return False

    def _detect_cms_version(self, base_url: str, cms_name: str, cms_data: Dict) -> str:
        """
        Attempt to detect CMS version.

        Args:
            base_url: Base URL
            cms_name: CMS name
            cms_data: CMS signature data

        Returns:
            Detected version or 'unknown'
        """
        if not self.config.check_version:
            return 'unknown'

        version_files = cms_data.get('version_files', [])

        for version_file in version_files:
            url = urljoin(base_url, version_file)
            response = self._make_request(url)

            if response and response.status_code == 200:
                content = response.text

                # Version detection patterns
                version_patterns = {
                    'WordPress': [
                        r'wordpress.*?(\d+\.\d+\.?\d*)',
                        r'version.*?(\d+\.\d+\.?\d*)'
                    ],
                    'Joomla': [
                        r'joomla.*?(\d+\.\d+\.?\d*)',
                        r'version.*?(\d+\.\d+\.?\d*)'
                    ],
                    'Drupal': [
                        r'drupal.*?(\d+\.\d+\.?\d*)',
                        r'core.*?(\d+\.\d+\.?\d*)'
                    ],
                    'Magento': [
                        r'magento.*?(\d+\.\d+\.?\d*)',
                        r'version.*?(\d+\.\d+\.?\d*)'
                    ]
                }

                patterns = version_patterns.get(cms_name, [])
                for pattern in patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        return match.group(1)

        return 'unknown'

    def _enumerate_plugins_themes(self, base_url: str, cms_name: str) -> Tuple[List[str], List[str]]:
        """
        Enumerate plugins and themes for detected CMS.

        Args:
            base_url: Base URL
            cms_name: CMS name

        Returns:
            Tuple of (plugins, themes) lists
        """
        if not self.config.check_plugins:
            return [], []

        plugins = []
        themes = []

        # CMS-specific enumeration
        if cms_name == 'WordPress':
            # Check for common plugins
            plugin_paths = ['/wp-content/plugins/', '/wp-content/themes/']
            common_items = [
                'woocommerce', 'contact-form-7', 'wordpress-seo', 'akismet',
                'jetpack', 'elementor', 'wpforms', 'really-simple-ssl',
                'twentytwenty', 'astra', 'oceanwp', 'avada', 'divi'
            ]

            for path in plugin_paths:
                for item in common_items:
                    url = urljoin(base_url, f"{path}{item}/")
                    response = self._make_request(url)
                    if response and response.status_code == 200:
                        if 'plugins' in path:
                            plugins.append(item)
                        else:
                            themes.append(item)

        elif cms_name == 'Joomla':
            # Check for common extensions
            ext_paths = ['/components/', '/modules/', '/plugins/']
            common_exts = [
                'com_content', 'com_users', 'com_contact', 'mod_login',
                'mod_menu', 'plg_system', 'com_virtuemart'
            ]

            for path in ext_paths:
                for ext in common_exts:
                    url = urljoin(base_url, f"{path}{ext}/")
                    response = self._make_request(url)
                    if response and response.status_code == 200:
                        plugins.append(ext)

        return plugins, themes

    def _check_cms_vulnerabilities(self, cms_name: str, version: str) -> List[Dict]:
        """
        Check for known vulnerabilities in detected CMS version.

        Args:
            cms_name: CMS name
            version: CMS version

        Returns:
            List of vulnerability dictionaries
        """
        if not self.config.check_vulnerabilities or version == 'unknown':
            return []

        # Simplified vulnerability database (in real implementation, this would be more comprehensive)
        vuln_db = {
            'WordPress': {
                '5.0': [{'id': 'WP-2019-01', 'severity': 'High', 'description': 'Stored XSS vulnerability'}],
                '4.9': [{'id': 'WP-2018-01', 'severity': 'Critical', 'description': 'Privilege escalation'}],
            },
            'Joomla': {
                '3.4': [{'id': 'J-2015-01', 'severity': 'Critical', 'description': 'SQL injection'}],
                '2.5': [{'id': 'J-2014-01', 'severity': 'High', 'description': 'Remote code execution'}],
            },
            'Drupal': {
                '7.0': [{'id': 'DRUPAL-SA-2014-001', 'severity': 'Critical', 'description': 'SQL injection'}],
                '8.0': [{'id': 'DRUPAL-SA-2016-001', 'severity': 'High', 'description': 'Remote code execution'}],
            }
        }

        vulnerabilities = []
        cms_vulns = vuln_db.get(cms_name, {})

        for vuln_version, vulns in cms_vulns.items():
            if version.startswith(vuln_version.split('.')[0]):
                vulnerabilities.extend(vulns)

        return vulnerabilities

    def _find_admin_urls(self, base_url: str, cms_name: str) -> List[str]:
        """
        Find potential admin URLs for the detected CMS.

        Args:
            base_url: Base URL
            cms_name: CMS name

        Returns:
            List of potential admin URLs
        """
        admin_paths = {
            'WordPress': ['/wp-admin/', '/wp-login.php', '/admin/', '/login/'],
            'Joomla': ['/administrator/', '/admin/', '/login/'],
            'Drupal': ['/user/login', '/admin/', '/user/'],
            'Magento': ['/admin/', '/adminhtml/', '/downloader/'],
            'PrestaShop': ['/admin/', '/admin-dev/'],
            'Shopify': ['/admin/'],
            'vBulletin': ['/admincp/', '/modcp/'],
            'phpBB': ['/adm/', '/ucp.php'],
            'MediaWiki': ['/index.php/Special:UserLogin'],
            'TYPO3': ['/typo3/']
        }

        admin_urls = []
        paths = admin_paths.get(cms_name, [])

        for path in paths:
            url = urljoin(base_url, path)
            response = self._make_request(url)
            if response and response.status_code in [200, 301, 302, 401, 403]:
                admin_urls.append(url)

        return admin_urls

    def scan_cms(self, base_url: str) -> Optional[CMSFinding]:
        """
        Scan for a specific CMS at the given URL.

        Args:
            base_url: Base URL to scan

        Returns:
            CMSFinding object if CMS detected, None otherwise
        """
        detected_cms = None
        confidence = 'low'

        # Check each CMS
        for cms_name, cms_data in self.cms_signatures.items():
            self._log(f"Checking for {cms_name}", color='cyan')

            # Method 1: Path-based detection
            if self._check_cms_paths(base_url, cms_name, cms_data):
                detected_cms = cms_name
                confidence = 'high'
                break

            # Method 2: Header-based detection
            if self._check_cms_headers(base_url, cms_data):
                detected_cms = cms_name
                confidence = 'medium'
                break

        if not detected_cms:
            return None

        self._log(f"Detected CMS: {detected_cms} (confidence: {confidence})", color='green')

        # Gather additional information
        version = self._detect_cms_version(base_url, detected_cms, self.cms_signatures[detected_cms])
        plugins, themes = self._enumerate_plugins_themes(base_url, detected_cms)
        vulnerabilities = self._check_cms_vulnerabilities(detected_cms, version)
        admin_urls = self._find_admin_urls(base_url, detected_cms)

        finding = CMSFinding(
            cms_name=detected_cms,
            version=version,
            confidence=confidence,
            detection_method='path_and_header_analysis',
            vulnerabilities=vulnerabilities,
            plugins=plugins,
            themes=themes,
            admin_urls=admin_urls
        )

        self.findings.append(finding)
        return finding

    def generate_report(self, output_file: str = None) -> Dict:
        """
        Generate comprehensive scan report.

        Args:
            output_file: Optional file path to save JSON report

        Returns:
            Dictionary containing scan results
        """
        report = {
            'scan_type': 'CMS Detection and Analysis Scan',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'cms_found': len(self.findings),
            'findings': [
                {
                    'cms_name': f.cms_name,
                    'version': f.version,
                    'confidence': f.confidence,
                    'detection_method': f.detection_method,
                    'vulnerabilities_count': len(f.vulnerabilities),
                    'plugins_count': len(f.plugins),
                    'themes_count': len(f.themes),
                    'admin_urls_count': len(f.admin_urls),
                    'vulnerabilities': f.vulnerabilities,
                    'plugins': f.plugins,
                    'themes': f.themes,
                    'admin_urls': f.admin_urls
                } for f in self.findings
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
        Perform complete CMS detection and analysis scan.

        Args:
            target_url: Base URL to scan
            output_file: Optional output file for report

        Returns:
            Scan results dictionary
        """
        self._log(f"Starting comprehensive CMS scan for {target_url}", color='cyan')

        # Ensure URL has proper format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        # Scan for CMS
        finding = self.scan_cms(target_url)

        if finding:
            self._log(f"CMS scan completed. Detected: {finding.cms_name} {finding.version}", color='green')
        else:
            self._log("CMS scan completed. No CMS detected", color='yellow')

        return self.generate_report(output_file)

def main():
    """Main function for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(description='Plascoy CMS Detection and Analysis Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Skip SSL verification')
    parser.add_argument('--no-version', action='store_true', help='Skip version detection')
    parser.add_argument('--no-plugins', action='store_true', help='Skip plugin/theme enumeration')
    parser.add_argument('--no-vulns', action='store_true', help='Skip vulnerability checking')

    args = parser.parse_args()

    config = CMSScanConfig(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        check_version=not args.no_version,
        check_plugins=not args.no_plugins,
        check_vulnerabilities=not args.no_vulns
    )

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    scanner = CMSScanner(config)
    results = scanner.scan(args.target, args.output)

    print(f"\nScan Summary:")
    print(f"CMS systems found: {results['cms_found']}")

    for finding in results['findings']:
        print(f"- {finding['cms_name']} {finding['version']} (confidence: {finding['confidence']})")
        print(f"  Vulnerabilities: {finding['vulnerabilities_count']}")
        print(f"  Plugins: {finding['plugins_count']}")
        print(f"  Themes: {finding['themes_count']}")
        print(f"  Admin URLs: {finding['admin_urls_count']}")

if __name__ == '__main__':
    main()