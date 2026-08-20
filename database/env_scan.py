#!/usr/bin/env python3
"""
Environment File Exposure Scanner

Detects exposed configuration and environment files that may contain
sensitive information like API keys, database credentials, and secrets.

Author: Plascoy Security
Version: 2.0
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init
from typing import Dict, List, Tuple, Optional
import time
import logging
import re

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EnvironmentScannerEnhanced:
    """Professional environment file scanner"""
    
    # Environment file paths
    ENV_FILES = [
        '/.env',
        '/.env.local',
        '/.env.staging',
        '/.env.prod',
        '/.env.production',
        '/.env.development',
        '/.env.example',
        '/.env.test',
        '/config/.env',
        '/config/env.php',
        '/.env.backup',
        '/.env.bak',
        '/.env.old',
        '/web.config',
        '/web.config.bak',
        '/web.config.old',
        '/.htaccess',
        '/.htpasswd',
        '/config.php',
        '/config/config.php',
        '/database.yml',
        '/config/database.yml',
        '/Gemfile.lock',
        '/package-lock.json',
        '/yarn.lock',
        '/.git/config',
        '/.gitlab-ci.yml',
        '/.github/workflows/',
        '/docker-compose.yml',
        '/docker-compose.yaml',
        '/.docker/config.json',
        '/Dockerfile',
        '/kubernetes/config',
        '/.kube/config',
        '/terraform/vars.tf',
        '/.aws/credentials',
        '/settings.ini',
        '/settings.xml',
        '/application.properties',
        '/application.yml',
        '/.env.json',
        '/secrets.json',
        '/credentials.json',
        '/config.json',
        '/server.xml',
        '/web.xml',
        '/.well-known/jwks.json',
    ]
    
    # Sensitive patterns to detect
    SENSITIVE_PATTERNS = {
        'api_keys': r'(?i)(api[_-]?key|apikey|api-key)\s*[=:]\s*["\']?[\w\-]+["\']?',
        'passwords': r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^"\']*["\']?',
        'database': r'(?i)(db|database)[_-]?(password|user|host|url)\s*[=:]\s*["\']?[^"\']*["\']?',
        'tokens': r'(?i)(token|auth[_-]?token|access[_-]?token|refresh[_-]?token)\s*[=:]\s*["\']?[\w\-]+["\']?',
        'secrets': r'(?i)(secret|SECRET_KEY|SECRET_KEY_BASE)\s*[=:]\s*["\']?[^"\']*["\']?',
        'credentials': r'(?i)(username|user|login|credential)\s*[=:]\s*["\']?[^"\']*["\']?',
        'aws': r'(?i)(aws[_-]?(access|secret|key))\s*[=:]\s*["\']?[\w/+]+["\']?',
        'google': r'(?i)(google[_-]?(api[_-]?key|project|client[_-]?id))\s*[=:]\s*["\']?[^"\']*["\']?',
        'stripe': r'(?i)(stripe[_-]?(key|token|secret))\s*[=:]\s*["\']?[\w_\-]+["\']?',
        'github': r'(?i)(github[_-]?token)\s*[=:]\s*["\']?[a-z0-9_]+["\']?',
        'private_key': r'(?i)(private[_-]?key|rsa[_-]?private|private[_-]?key[_-]?id)\s*[=:]\s*["\']?[^"\']*["\']?',
    }
    
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False):
        """Initialize environment scanner"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'exposed_files': [],
            'sensitive_data': [],
            'files_checked': 0,
            'scan_time': 0
        }
        self.session = self._create_session()
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target URL"""
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        return target.rstrip('/')
    
    def _create_session(self) -> requests.Session:
        """Create robust requests session"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        session.verify = self.verify_ssl
        
        return session
    
    def scan(self, verbose: bool = False) -> Dict:
        """Perform environment file scan"""
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Environment File Exposure Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        for env_file in self.ENV_FILES:
            self.results['files_checked'] += 1
            url = self.target.rstrip('/') + env_file
            
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code == 200:
                    self._analyze_file(url, response.text, verbose)
                elif verbose and response.status_code not in [404, 403]:
                    print(Fore.BLUE + f"[*] {url} (HTTP {response.status_code})")
                    
            except Exception as e:
                if verbose:
                    logger.debug(f"Error checking {url}: {str(e)}")
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        return self.results
    
    def _analyze_file(self, url: str, content: str, verbose: bool = False):
        """Analyze file for sensitive data"""
        print(Fore.RED + Style.BRIGHT + f"[!] EXPOSED: {url}")
        
        self.results['exposed_files'].append({
            'url': url,
            'size': len(content)
        })
        
        # Search for sensitive patterns
        sensitive_found = False
        
        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
            if matches:
                sensitive_found = True
                print(Fore.RED + f"    [!] {pattern_name.upper()} detected:")
                
                # Show matches (safely)
                for match in matches[:3]:
                    if isinstance(match, tuple):
                        match = match[0]
                    sanitized = match[:50] if len(match) < 50 else match[:47] + "..."
                    print(Fore.RED + f"        └─ {sanitized}")
                
                self.results['sensitive_data'].append({
                    'file': url,
                    'type': pattern_name,
                    'count': len(matches)
                })
        
        if not sensitive_found and verbose:
            print(Fore.YELLOW + f"    [*] File found but no obvious sensitive patterns")
        
        # Show content preview
        lines = content.split('\n')
        preview = '\n    '.join(lines[:5])
        print(Fore.YELLOW + f"    Preview:\n    {preview}")
    
    def _print_summary(self):
        """Print scan summary"""
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Environment Scan Summary")
        print(Fore.CYAN + f"[*] Files checked: {self.results['files_checked']}")
        print(Fore.CYAN + f"[*] Scan duration: {self.results['scan_time']:.2f} seconds")
        
        exposed = len(self.results['exposed_files'])
        if exposed > 0:
            print(Fore.RED + Style.BRIGHT + f"[!] Exposed files: {exposed}")
            for file_info in self.results['exposed_files']:
                print(Fore.RED + f"    - {file_info['url']} ({file_info['size']} bytes)")
        else:
            print(Fore.GREEN + "[+] No exposed environment files found")
        
        sensitive = len(self.results['sensitive_data'])
        if sensitive > 0:
            print(Fore.RED + f"[!] Sensitive data patterns found: {sensitive}")


def env_scan(target: str, verbose: bool = False, timeout: int = 10) -> bool:
    """
    Standalone environment file scan function
    
    Args:
        target: Target URL or domain
        verbose: Enable verbose output
        timeout: Request timeout in seconds
        
    Returns:
        True if exposed files found, False otherwise
    """
    scanner = EnvironmentScannerEnhanced(target, timeout=timeout)
    results = scanner.scan(verbose=verbose)
    
    return len(results['exposed_files']) > 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 env_scan.py <target> [--verbose]")
        sys.exit(1)
    
    target = sys.argv[1]
    verbose = '--verbose' in sys.argv
    
    env_scan(target, verbose=verbose)
