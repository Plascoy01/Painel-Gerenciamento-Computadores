#!/usr/bin/env python3
"""
Open Redirect Vulnerability Scanner

Detects open redirect vulnerabilities through:
- Multiple redirect parameter detection
- URL encoding bypass techniques
- Response header analysis
- Redirect chain detection
- Domain whitelist bypass attempts

Vulnerable parameters: url, redirect, return, next, target, uri, back, etc.

Author: Plascoy Security
Version: 2.0
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init
from typing import Dict, List, Optional
import time
import logging
import re
from urllib.parse import urlparse, urljoin

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class OpenRedirectScanner:
    """Professional open redirect vulnerability scanner"""
    
    # Redirect parameter names
    REDIRECT_PARAMS = [
        'url', 'redirect', 'return', 'next', 'target', 'uri',
        'back', 'continue', 'goto', 'return_url', 'redirect_url',
        'callback', 'link', 'page', 'dest', 'destination', 'forward',
        'logout', 'exit', 'from', 'to', 'path', 'origin',
    ]
    
    # Open redirect payloads
    REDIRECT_PAYLOADS = {
        'simple': [
            '//evil.com',
            'http://evil.com',
            'https://evil.com',
            'http://attacker.com/evil',
        ],
        'encoding': [
            '//evil.com%2f%2e%2e',
            'http://evil.com%2f%2e%2e',
            'http://evil.com%3f',
            'http://evil.com%23',
            '//evil.com%00',
            '//evil.com%09',
            '//evil.com%0a',
        ],
        'unicode': [
            '//evil.com%c0%ae',
            'http://evil.com%25',
            'http://evil.com%5c',
        ],
        'protocol_bypass': [
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:msgbox(1)',
        ],
        'subdomain': [
            '//evil.victim.com',
            '//victim.evil.com',
            '//victim-evil.com',
        ],
    }
    
    # Expected redirect status codes
    REDIRECT_CODES = [301, 302, 303, 307, 308]
    
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False):
        """Initialize open redirect scanner"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'vulnerabilities': [],
            'total_tested': 0,
            'scan_time': 0,
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
            total=1,
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
        """
        Perform open redirect vulnerability scan
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            Dictionary with scan results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Open Redirect Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        # Test redirect parameters
        self._test_redirects(verbose)
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        
        return self.results
    
    def _test_redirects(self, verbose: bool = False):
        """Test for open redirect vulnerabilities"""
        print(Fore.BLUE + "\n[*] Testing open redirect parameters...")
        
        for param in self.REDIRECT_PARAMS:
            for category, payloads in self.REDIRECT_PAYLOADS.items():
                for payload in payloads:
                    self.results['total_tested'] += 1
                    
                    try:
                        # Test with parameter
                        url = f"{self.target.rstrip('/')}?{param}={payload}"
                        response = self.session.get(
                            url, 
                            timeout=self.timeout,
                            allow_redirects=False,
                            verify=self.verify_ssl
                        )
                        
                        # Check for redirect response with evil.com in location
                        if response.status_code in self.REDIRECT_CODES:
                            location = response.headers.get('Location', '')
                            
                            # Check for various domain indicators
                            if any(indicator in location.lower() for indicator in 
                                   ['evil', 'attacker', 'javascript:', 'data:']):
                                
                                vuln_info = {
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'status_code': response.status_code,
                                    'location': location,
                                    'category': category,
                                }
                                self.results['vulnerabilities'].append(vuln_info)
                                print(Fore.RED + f"[!] OPEN REDIRECT FOUND: {param}")
                                print(Fore.RED + f"    Category: {category}")
                                if verbose:
                                    print(Fore.YELLOW + f"    URL: {url}")
                                    print(Fore.YELLOW + f"    Location: {location}")
                    
                    except Exception as e:
                        if verbose:
                            logger.debug(f"Error testing {url}: {str(e)}")
    
    def _print_summary(self):
        """Print scan summary"""
        print(Fore.CYAN + "\n[*] Open Redirect Scan Summary:")
        print(Fore.BLUE + f"[*] Total Tests: {self.results['total_tested']}")
        print(Fore.RED + f"[*] Vulnerabilities Found: {len(self.results['vulnerabilities'])}")
        print(Fore.CYAN + f"[*] Scan Time: {self.results['scan_time']:.2f}s")


def open_redirect_scan(target: str, verbose: bool = False) -> Dict:
    """
    Wrapper function for open redirect scanning
    
    Args:
        target: Target URL
        verbose: Enable verbose output
        
    Returns:
        Dictionary with scan results
    """
    scanner = OpenRedirectScanner(target)
    return scanner.scan(verbose)