#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) Detection Module

Detects IDOR vulnerabilities through:
- ID parameter enumeration and testing
- Response content comparison
- Status code pattern analysis
- Access control validation

Supported detections: id, user_id, order_id, account_id, post_id, etc.

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


class IDORDetector:
    """Professional IDOR vulnerability scanner"""
    
    # Common ID parameter names
    ID_PARAMETERS = [
        'id', 'user_id', 'uid', 'userid',
        'order_id', 'orderId',
        'account_id', 'accountId',
        'post_id', 'postId',
        'product_id', 'productId',
        'item_id', 'itemId',
        'profile_id', 'profileId',
        'invoice_id', 'invoiceId',
    ]
    
    # Test ID values
    TEST_IDS = ['1', '2', '10', '100', '999', '0', '-1']
    
    def __init__(self, target: str, timeout: int = 5, verify_ssl: bool = False):
        """Initialize IDOR detector"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'idor_found': False,
            'vulnerable_params': [],
            'tested_params': [],
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
        Perform IDOR vulnerability detection scan
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            Dictionary with IDOR detection results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] IDOR Detection Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        # Test ID parameters
        self._test_id_parameters(verbose)
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        
        return self.results
    
    def _test_id_parameters(self, verbose: bool = False):
        """Test ID parameters for IDOR vulnerabilities"""
        print(Fore.BLUE + "\n[*] Testing ID parameters...")
        
        for param in self.ID_PARAMETERS:
            try:
                responses = []
                
                # Test multiple ID values
                for test_id in self.TEST_IDS:
                    try:
                        params = {param: test_id}
                        response = self.session.get(self.target, params=params, timeout=self.timeout)
                        
                        responses.append({
                            'id': test_id,
                            'status': response.status_code,
                            'length': len(response.text),
                            'content_hash': hash(response.text)
                        })
                        
                        if verbose:
                            print(Fore.YELLOW + f"[*] {param}={test_id}: {response.status_code} ({len(response.text)} bytes)")
                    
                    except requests.exceptions.Timeout:
                        if verbose:
                            logger.warning(f"Timeout testing {param}={test_id}")
                    except Exception as e:
                        if verbose:
                            logger.warning(f"Error testing {param}={test_id}: {str(e)}")
                
                # Analyze responses
                if self._analyze_responses(param, responses):
                    self.results['idor_found'] = True
                    self.results['vulnerable_params'].append(param)
                
                self.results['tested_params'].append(param)
            
            except Exception as e:
                logger.error(f"Unexpected error testing {param}: {str(e)}")
    
    def _analyze_responses(self, param: str, responses: List[Dict]) -> bool:
        """Analyze responses for IDOR indicators"""
        if not responses:
            return False
        
        # Check for varying status codes
        status_codes = [r['status'] for r in responses if r]
        unique_statuses = len(set(status_codes))
        
        if unique_statuses > 1:
            print(Fore.YELLOW + f"[*] {param}: Different status codes - Possible IDOR")
            for r in responses:
                print(Fore.YELLOW + f"    ID {r['id']}: {r['status']}")
            return True
        
        # Check for varying content lengths
        lengths = [r['length'] for r in responses if r]
        unique_lengths = len(set(lengths))
        
        if unique_lengths > 2:  # Allow small variance
            print(Fore.RED + f"[!] {param}: IDOR VULNERABILITY - Different content for different IDs")
            for r in responses:
                print(Fore.RED + f"    ID {r['id']}: {r['length']} bytes")
            return True
        
        return False
    
    def _print_summary(self):
        """Print scan summary"""
        print(Fore.CYAN + "\n[*] IDOR Detection Scan Summary:")
        
        if self.results['idor_found']:
            print(Fore.RED + Style.BRIGHT + f"[!] IDOR VULNERABILITY FOUND!")
            print(Fore.RED + f"[!] Vulnerable parameters: {len(self.results['vulnerable_params'])}")
            for param in self.results['vulnerable_params']:
                print(Fore.RED + f"    - {param}")
        else:
            print(Fore.GREEN + "[+] No IDOR vulnerabilities detected")
        
        print(Fore.CYAN + f"[*] Parameters tested: {len(self.results['tested_params'])}")
        print(Fore.CYAN + f"[*] Scan Time: {self.results['scan_time']:.2f}s")


# Legacy function interface
def idor_scan(target, verbose=False):
    """Legacy function interface for IDOR scan"""
    detector = IDORDetector(target)
    results = detector.scan(verbose=verbose)
    return results['idor_found']
