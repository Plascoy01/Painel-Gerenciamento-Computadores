#!/usr/bin/env python3
"""
Directory Listing Vulnerability Scanner

Detects directory listing vulnerabilities by checking common directories
for directory listing indicators and analyzinga exposed files/directories.

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
from urllib.parse import urljoin
import re

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DirectoryListingScanner:
    """Professional directory listing vulnerability scanner"""
    
    # Directory listing indicators - Apache/Nginx/IIS patterns
    LISTING_INDICATORS = [
        'Index of',
        '<title>Index of',
        '[ICO]',
        '<h1>Index of',
        '| Parent Directory',
        'Name Last modified',
        'modified  Size',
        'Directory listing for',
        '<h1>Directory listing',
        'Parent Directory',
    ]
    
    # Common directories to test
    DIRECTORIES = [
        '/', '/admin/', '/uploads/', '/files/', '/static/', '/public/',
        '/assets/', '/download/', '/media/', '/backup/', '/old/',
        '/temp/', '/tmp/', '/test/', '/bak/', '/archive/', '/logs/',
        '/log/', '/doc/', '/docs/', '/help/', '/images/', '/img/',
        '/css/', '/js/', '/scripts/', '/include/', '/includes/',
        '/lib/', '/libs/', '/modules/', '/plugins/', '/themes/',
        '/data/', '/database/', '/db/', '/sql/', '/config/', '/configs/',
        '/settings/', '/setup/', '/install/', '/installer/',
        '/release/', '/releases/', '/versions/', '/version/',
        '/beta/', '/staging/', '/stage/', '/dev/', '/development/',
        '/uat/', '/qa/', '/test/', '/testing/', '/sandbox/',
    ]
    
    # File patterns to look for when listing is found
    FILE_PATTERNS = [
        r'config',
        r'\.env',
        r'\.bak',
        r'\.sql',
        r'password',
        r'secret',
        r'key',
        r'\.txt',
        r'\.xml',
        r'\.json',
    ]
    
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False):
        """
        Initialize scanner
        
        Args:
            target: Target URL or domain
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'vulnerabilities': [],
            'safe_directories': [],
            'suspicious_files': [],
            'total_checked': 0,
            'scan_time': 0
        }
        self.session = self._create_session()
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target URL"""
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        return target.rstrip('/')
    
    def _create_session(self) -> requests.Session:
        """Create robust requests session with retries"""
        session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        # Headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        session.verify = self.verify_ssl
        
        return session
    
    def scan(self, verbose: bool = False) -> Dict:
        """
        Perform complete directory listing scan
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            Dictionary with scan results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Directory Listing Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        for directory in self.DIRECTORIES:
            self.results['total_checked'] += 1
            url = urljoin(self.target, directory)
            
            try:
                response = self.session.get(url, timeout=self.timeout)
                self._analyze_response(url, response, verbose)
                
            except requests.exceptions.Timeout:
                if verbose:
                    print(Fore.YELLOW + f"[!] Timeout: {url}")
                logger.warning(f"Timeout on {url}")
                
            except requests.exceptions.ConnectionError:
                if verbose:
                    print(Fore.YELLOW + f"[!] Connection error: {url}")
                logger.warning(f"Connection error on {url}")
                
            except Exception as e:
                if verbose:
                    print(Fore.YELLOW + f"[!] Error: {url} - {str(e)}")
                logger.error(f"Error scanning {url}: {str(e)}")
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        return self.results
    
    def _analyze_response(self, url: str, response: requests.Response, verbose: bool = False):
        """Analyze response for directory listing"""
        
        # Check for directory listing
        if self._is_directory_listing(response.text):
            print(Fore.RED + Style.BRIGHT + f"[!] VULNERABLE: {url}")
            self.results['vulnerabilities'].append({
                'url': url,
                'status_code': response.status_code,
                'type': 'directory_listing'
            })
            
            # Extract files from listing
            suspicious = self._extract_files(response.text)
            if suspicious:
                print(Fore.RED + f"    Files found: {len(suspicious)}")
                self.results['suspicious_files'].extend(suspicious)
                for file_info in suspicious[:5]:
                    print(Fore.RED + f"    └─ {file_info}")
        
        elif response.status_code == 200:
            if verbose:
                print(Fore.GREEN + f"[+] Safe: {url}")
            self.results['safe_directories'].append(url)
        
        elif response.status_code == 403:
            if verbose:
                print(Fore.BLUE + f"[+] Forbidden: {url}")
        
        elif response.status_code == 404:
            if verbose:
                print(Fore.BLUE + f"[+] Not Found: {url}")
    
    def _is_directory_listing(self, response_text: str) -> bool:
        """Check if response indicates directory listing"""
        return any(indicator in response_text for indicator in self.LISTING_INDICATORS)
    
    def _extract_files(self, html: str) -> List[str]:
        """Extract files/folders from directory listing"""
        files = []
        
        # Match href patterns
        href_pattern = r'href=["\']([^"\']+)["\']'
        matches = re.findall(href_pattern, html)
        
        for match in matches:
            if match.startswith(('http://', 'https://')):
                continue
            if match in ['/', '.', '..', '../']:
                continue
            
            files.append(match)
        
        return files
    
    def _print_summary(self):
        """Print scan summary"""
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Directory Listing Scan Summary")
        print(Fore.CYAN + f"[*] Total directories checked: {self.results['total_checked']}")
        print(Fore.CYAN + f"[*] Scan duration: {self.results['scan_time']:.2f} seconds")
        
        vulns = len(self.results['vulnerabilities'])
        if vulns > 0:
            print(Fore.RED + Style.BRIGHT + f"[!] Vulnerabilities found: {vulns}")
            for vuln in self.results['vulnerabilities']:
                print(Fore.RED + f"    - {vuln['url']} (HTTP {vuln['status_code']})")
        else:
            print(Fore.GREEN + "[+] No directory listing vulnerabilities found")
        
        print(Fore.CYAN + f"[*] Safe directories: {len(self.results['safe_directories'])}")


def dir_listing_scan(target: str, verbose: bool = False, timeout: int = 10) -> bool:
    """
    Standalone function for directory listing scan
    
    Args:
        target: Target URL or domain
        verbose: Enable verbose output
        timeout: Request timeout in seconds
        
    Returns:
        True if vulnerabilities found, False otherwise
    """
    scanner = DirectoryListingScanner(target, timeout=timeout)
    results = scanner.scan(verbose=verbose)
    
    return len(results['vulnerabilities']) > 0


# For backward compatibility
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 dir_listing_scan.py <target> [--verbose]")
        sys.exit(1)
    
    target = sys.argv[1]
    verbose = '--verbose' in sys.argv
    
    dir_listing_scan(target, verbose=verbose)
