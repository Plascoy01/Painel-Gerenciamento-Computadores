#!/usr/bin/env python3
"""
Backup Files Detection Module for Plascoy Security Scanner

This module performs comprehensive backup file detection including:
- Common backup file extensions scanning
- Version control system backups (.git, .svn, .hg)
- Database backup files
- Configuration file backups
- Archive file detection
- Directory enumeration for backup locations
- Content analysis for sensitive data

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
from pathlib import Path

# Initialize colorama for colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

@dataclass
class BackupFinding:
    """Data class for backup file findings"""
    url: str
    file_type: str
    size: int
    content_type: str
    risk_level: str
    description: str
    recommendation: str

@dataclass
class BackupScanConfig:
    """Configuration for backup file scanning"""
    timeout: int = 10
    max_workers: int = 10
    user_agent: str = 'Plascoy-Backup-Scanner/2.0'
    follow_redirects: bool = False
    verify_ssl: bool = False
    delay_between_requests: float = 0.05
    max_files_per_type: int = 50
    check_content: bool = True
    content_sample_size: int = 1024

class BackupScanner:
    """
    Professional backup file detection scanner with comprehensive features.

    This class provides methods to detect exposed backup files and archives
    that may contain sensitive information or source code.
    """

    def __init__(self, config: BackupScanConfig = None):
        """
        Initialize the backup scanner with configuration.

        Args:
            config: BackupScanConfig object with scanning parameters
        """
        self.config = config or BackupScanConfig()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        self.session.verify = self.config.verify_ssl

        # Setup logging
        self.logger = logging.getLogger('BackupScanner')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.findings: List[BackupFinding] = []
        self.scanned_urls: Set[str] = set()

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

    def _make_request(self, url: str, method: str = 'HEAD', **kwargs) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling.

        Args:
            url: Target URL
            method: HTTP method (HEAD for efficiency, GET for content)
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

    def _analyze_backup_content(self, url: str, response: requests.Response) -> Dict:
        """
        Analyze the content of a potential backup file.

        Args:
            url: URL of the backup file
            response: HTTP response object

        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'contains_sensitive': False,
            'sensitive_keywords': [],
            'file_type': 'unknown',
            'risk_level': 'low'
        }

        if not self.config.check_content:
            return analysis

        try:
            content = response.text[:self.config.content_sample_size].lower()

            # Sensitive keywords to check
            sensitive_keywords = [
                'password', 'passwd', 'secret', 'key', 'api_key', 'apikey',
                'token', 'auth', 'admin', 'root', 'database', 'db',
                'config', 'configuration', 'settings', 'credentials',
                'private', 'internal', 'backup', 'sql', 'dump'
            ]

            found_keywords = [kw for kw in sensitive_keywords if kw in content]
            analysis['sensitive_keywords'] = found_keywords
            analysis['contains_sensitive'] = len(found_keywords) > 0

            # Determine file type and risk
            url_lower = url.lower()
            if any(ext in url_lower for ext in ['.sql', '.db', '.sqlite', '.dump']):
                analysis['file_type'] = 'database'
                analysis['risk_level'] = 'high'
            elif any(ext in url_lower for ext in ['.tar.gz', '.zip', '.rar', '.7z', '.bz2']):
                analysis['file_type'] = 'archive'
                analysis['risk_level'] = 'high'
            elif any(ext in url_lower for ext in ['.bak', '.backup', '.old', '.orig']):
                analysis['file_type'] = 'backup'
                analysis['risk_level'] = 'medium'
            elif any(ext in url_lower for ext in ['.git', '.svn', '.hg']):
                analysis['file_type'] = 'version_control'
                analysis['risk_level'] = 'high'

            if analysis['contains_sensitive']:
                analysis['risk_level'] = 'critical'

        except Exception as e:
            self._log(f"Content analysis failed for {url}: {e}", 'debug')

        return analysis

    def _check_backup_file(self, base_url: str, filename: str, extension: str) -> Optional[BackupFinding]:
        """
        Check for a specific backup file.

        Args:
            base_url: Base URL to check
            filename: Base filename
            extension: File extension

        Returns:
            BackupFinding object if found, None otherwise
        """
        url = urljoin(base_url, f"{filename}{extension}")

        # First try HEAD request
        response = self._make_request(url, method='HEAD')
        if not response or response.status_code != 200:
            return None

        content_type = response.headers.get('content-type', '').lower()
        content_length = int(response.headers.get('content-length', 0))

        # Skip very large files or non-relevant content types
        if content_length > 100 * 1024 * 1024:  # 100MB
            return None

        if any(skip_type in content_type for skip_type in ['text/html', 'text/css', 'application/javascript']):
            return None

        # Get content for analysis
        content_response = self._make_request(url, method='GET')
        if not content_response:
            return None

        analysis = self._analyze_backup_content(url, content_response)

        finding = BackupFinding(
            url=url,
            file_type=analysis['file_type'],
            size=content_length,
            content_type=content_type,
            risk_level=analysis['risk_level'],
            description=f"Backup file detected: {filename}{extension}",
            recommendation="Remove exposed backup files from web server"
        )

        if analysis['contains_sensitive']:
            finding.description += f" (contains sensitive data: {', '.join(analysis['sensitive_keywords'][:3])})"

        return finding

    def scan_common_backup_files(self, base_url: str) -> None:
        """
        Scan for common backup files with various extensions.

        Args:
            base_url: Base URL to scan
        """
        self._log("Scanning for common backup files", color='cyan')

        # Common backup extensions
        backup_extensions = [
            '.bak', '.backup', '.old', '.orig', '.copy', '.tmp', '.temp',
            '.tar', '.tar.gz', '.tar.bz2', '.tar.xz', '.zip', '.rar', '.7z',
            '.sql', '.sql.gz', '.db', '.sqlite', '.sqlite3', '.dump',
            '~', '.swp', '.swo', '.swn', '.swm', '.1', '.2', '.3',
            '-old', '-backup', '-bak', '-copy', '_old', '_backup', '_bak',
            '.bak1', '.bak2', '.orig1', '.orig2'
        ]

        # Common filenames to check
        common_filenames = [
            'index', 'admin', 'config', 'configuration', 'settings',
            'database', 'db', 'backup', 'site', 'web', 'www',
            'wp-config', 'config', 'htaccess', '.htaccess', '.env',
            'application', 'system', 'data', 'users', 'passwords'
        ]

        # Common paths
        common_paths = [
            '/', '/backup/', '/backups/', '/old/', '/archive/',
            '/downloads/', '/files/', '/upload/', '/tmp/', '/temp/',
            '/admin/backup/', '/db/', '/database/', '/sql/'
        ]

        tasks = []

        for path in common_paths:
            for filename in common_filenames:
                for ext in backup_extensions:
                    if len(tasks) >= self.config.max_files_per_type:
                        break
                    tasks.append((base_url, path + filename, ext))
                if len(tasks) >= self.config.max_files_per_type:
                    break
            if len(tasks) >= self.config.max_files_per_type:
                break

        findings_count = 0

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = [executor.submit(self._check_backup_file, base, name, ext)
                      for base, name, ext in tasks]

            for future in as_completed(futures):
                finding = future.result()
                if finding:
                    self.findings.append(finding)
                    findings_count += 1
                    color = 'red' if finding.risk_level in ['high', 'critical'] else 'yellow'
                    self._log(f"Backup file found: {finding.url} (Risk: {finding.risk_level})",
                             'warning', color)

        self._log(f"Found {findings_count} potential backup files", color='yellow')

    def scan_version_control(self, base_url: str) -> None:
        """
        Scan for exposed version control system files.

        Args:
            base_url: Base URL to scan
        """
        self._log("Scanning for version control exposures", color='cyan')

        vc_files = [
            # Git
            '.git/', '.git/config', '.git/HEAD', '.git/index', '.git/logs/',
            '.gitignore', '.gitattributes', '.gitmodules',
            # SVN
            '.svn/', '.svn/entries', '.svn/wc.db',
            # Mercurial
            '.hg/', '.hg/store/', '.hgrc',
            # CVS
            'CVS/', 'CVS/Root', 'CVS/Entries'
        ]

        for vc_file in vc_files:
            url = urljoin(base_url, vc_file)
            response = self._make_request(url)

            if response and response.status_code == 200:
                risk_level = 'high'
                file_type = 'version_control'

                if '.git' in vc_file:
                    description = "Git repository exposed"
                elif '.svn' in vc_file:
                    description = "SVN repository exposed"
                elif '.hg' in vc_file:
                    description = "Mercurial repository exposed"
                else:
                    description = "Version control system exposed"

                finding = BackupFinding(
                    url=url,
                    file_type=file_type,
                    size=int(response.headers.get('content-length', 0)),
                    content_type=response.headers.get('content-type', ''),
                    risk_level=risk_level,
                    description=description,
                    recommendation="Remove version control directories from web root"
                )

                self.findings.append(finding)
                self._log(f"Version control exposure: {url}", 'warning', 'red')

    def scan_directory_enumeration(self, base_url: str) -> None:
        """
        Perform directory enumeration for backup-related directories.

        Args:
            base_url: Base URL to scan
        """
        self._log("Performing directory enumeration for backups", color='cyan')

        backup_directories = [
            'backup', 'backups', 'old', 'archive', 'archives',
            'db', 'database', 'sql', 'data', 'files', 'upload',
            'tmp', 'temp', 'cache', 'logs', 'admin', 'management'
        ]

        for dirname in backup_directories:
            # Check for directory listing
            url = urljoin(base_url, f"{dirname}/")
            response = self._make_request(url)

            if response and response.status_code == 200:
                content = response.text.lower()
                # Check for directory listing indicators
                if any(indicator in content for indicator in [
                    'index of', 'parent directory', 'directory listing',
                    '[to parent directory]', 'name', 'last modified', 'size'
                ]):
                    finding = BackupFinding(
                        url=url,
                        file_type='directory_listing',
                        size=0,
                        content_type='text/html',
                        risk_level='medium',
                        description=f"Directory listing enabled for /{dirname}/",
                        recommendation="Disable directory listing in web server configuration"
                    )
                    self.findings.append(finding)
                    self._log(f"Directory listing found: {url}", 'warning', 'yellow')

    def generate_report(self, output_file: str = None) -> Dict:
        """
        Generate comprehensive scan report.

        Args:
            output_file: Optional file path to save JSON report

        Returns:
            Dictionary containing scan results
        """
        # Categorize findings by risk level
        risk_summary = {
            'critical': len([f for f in self.findings if f.risk_level == 'critical']),
            'high': len([f for f in self.findings if f.risk_level == 'high']),
            'medium': len([f for f in self.findings if f.risk_level == 'medium']),
            'low': len([f for f in self.findings if f.risk_level == 'low'])
        }

        report = {
            'scan_type': 'Backup Files Detection Scan',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_findings': len(self.findings),
            'risk_summary': risk_summary,
            'findings': [
                {
                    'url': f.url,
                    'file_type': f.file_type,
                    'size': f.size,
                    'content_type': f.content_type,
                    'risk_level': f.risk_level,
                    'description': f.description,
                    'recommendation': f.recommendation
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
        Perform complete backup file detection scan.

        Args:
            target_url: Base URL to scan
            output_file: Optional output file for report

        Returns:
            Scan results dictionary
        """
        self._log(f"Starting comprehensive backup scan for {target_url}", color='cyan')

        # Ensure URL has proper format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        # Perform different scan types
        self.scan_common_backup_files(target_url)
        self.scan_version_control(target_url)
        self.scan_directory_enumeration(target_url)

        self._log(f"Backup scan completed. Found {len(self.findings)} potential issues", color='green')

        return self.generate_report(output_file)

def main():
    """Main function for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(description='Plascoy Backup Files Detection Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Skip SSL verification')
    parser.add_argument('--no-content-check', action='store_true', help='Skip content analysis')

    args = parser.parse_args()

    config = BackupScanConfig(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        check_content=not args.no_content_check
    )

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    scanner = BackupScanner(config)
    results = scanner.scan(args.target, args.output)

    print(f"\nScan Summary:")
    print(f"Total findings: {results['total_findings']}")
    print(f"Critical: {results['risk_summary']['critical']}")
    print(f"High: {results['risk_summary']['high']}")
    print(f"Medium: {results['risk_summary']['medium']}")
    print(f"Low: {results['risk_summary']['low']}")

    for finding in results['findings'][:5]:  # Show first 5
        print(f"- {finding['risk_level'].upper()}: {finding['url']}")

if __name__ == '__main__':
    main()
