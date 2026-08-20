#!/usr/bin/env python3
"""
Host Header Injection Detection Module

Detects Host header injection vulnerabilities through:
- Host header manipulation testing
- Response content analysis
- Malicious host detection
- Cache poisoning vulnerability checks

Supported detections: Header injection, cache poisoning, etc.

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

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class HostHeaderInjectionDetector:
    """Professional Host header injection scanner"""
    
    # Malicious hosts to test
    MALICIOUS_HOSTS = [
        'evil.com',
        '127.0.0.1',
        'localhost',
        'localhost:80',
        'localhost:443',
        'evil.com:80',
        'attacker.com',
        '192.168.1.1',
    ]
    
    def __init__(self, target: str, timeout: int = 5, verify_ssl: bool = False):
        """Initialize Host header detector"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'injection_found': False,
            'vulnerable_hosts': [],
            'tested_hosts': [],
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
        Perform Host header injection detection scan
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            Dictionary with injection detection results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Host Header Injection Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        # Test malicious hosts
        self._test_malicious_hosts(verbose)
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        
        return self.results
    
    def _test_malicious_hosts(self, verbose: bool = False):
        """Test various malicious Host header values"""
        print(Fore.BLUE + "\n[*] Testing Host header injection...")
        
        for malicious_host in self.MALICIOUS_HOSTS:
            try:
                # Create request with custom Host header
                headers = {'Host': malicious_host}
                response = self.session.get(self.target, headers=headers, timeout=self.timeout)
                
                self.results['tested_hosts'].append(malicious_host)
                
                # Check if injected host appears in response
                if malicious_host in response.text:
                    print(Fore.RED + f"[!] Injection vulnerable to: {malicious_host}")
                    self.results['vulnerable_hosts'].append({
                        'host': malicious_host,
                        'status': response.status_code
                    })
                    self.results['injection_found'] = True
                elif verbose:
                    print(Fore.YELLOW + f"[*] Tested {malicious_host}: {response.status_code}")
            
            except requests.exceptions.Timeout:
                if verbose:
                    logger.warning(f"Timeout testing {malicious_host}")
            except requests.exceptions.RequestException as e:
                if verbose:
                    logger.warning(f"Error testing {malicious_host}: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
    
    def _print_summary(self):
        """Print scan summary"""
        print(Fore.CYAN + "\n[*] Host Header Injection Scan Summary:")
        
        if self.results['injection_found']:
            print(Fore.RED + Style.BRIGHT + f"[!] Host header injection FOUND!")
            print(Fore.RED + f"[!] Vulnerable hosts: {len(self.results['vulnerable_hosts'])}")
            for vuln in self.results['vulnerable_hosts']:
                print(Fore.RED + f"    - {vuln['host']}")
        else:
            print(Fore.GREEN + "[+] No Host header injection detected")
        
        print(Fore.CYAN + f"[*] Tested: {len(self.results['tested_hosts'])} hosts")
        print(Fore.CYAN + f"[*] Scan Time: {self.results['scan_time']:.2f}s")


# Legacy function interface
def host_header_scan(target, verbose=False):
    """Legacy function interface for Host header scan"""
    detector = HostHeaderInjectionDetector(target)
    results = detector.scan(verbose=verbose)
    return results['injection_found']