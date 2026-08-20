#!/usr/bin/env python3
"""
Web Application Firewall (WAF) Detection Module

Detects and identifies various WAF solutions through:
- Response headers analysis
- Response time patterns
- HTTP status code patterns
- HTML content signatures

Supported WAFs: CloudFlare, ModSecurity, Sucuri, Imperva, F5, Palo Alto, etc.

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


class WAFDetector:
    """Professional WAF detection scanner"""
    
    # WAF signatures in headers
    WAF_HEADERS = {
        'Cloudflare': ['CF-RAY', 'CF-Request-ID', 'X-Frame-Options'],
        'ModSecurity': ['X-Mod-Security', 'X-ModSecurity-Message'],
        'Sucuri': ['X-Sucuri-ID', 'X-Sucuri-Cache'],
        'Imperva': ['X-Forwarded-For', 'X-Original-IP'],
        'Akamai': ['AkamaiGHost', 'X-Akamai-Transformed'],
        'AWS WAF': ['X-Amzn-RequestId', 'x-amzn-requestid'],
        'Barracuda': ['X-Barracuda-Forwarded', 'X-Barracuda-WAF-RuleID'],
        'Fortinet': ['X-Fortinet-FortiGate', 'X-Fortinet-FortiWeb'],
        'F5': ['Server', 'X-Powered-By', 'X-Frame-Options'],
        'Palo Alto': ['X-PaloAlto-WAF-State', 'X-PaloAlto-VPN-Identifier'],
        'Juniper': ['X-Juniper-WAF'],
        'NAXSI': ['X-NAXSI-BLOCK'],
    }
    
    # WAF signatures in HTML content
    WAF_CONTENT_SIGNATURES = {
        'Cloudflare': [
            'challenges.cloudflare.com',
            'Ray ID:',
            'cf_challenge',
            'Checking your browser',
        ],
        'ModSecurity': [
            'ModSecurity',
            'mod_security',
            'Rule Engine',
        ],
        'Sucuri': [
            'Sucuri WebSecurity',
            'Access Denied',
            'Administrator',
        ],
        'AWS WAF': [
            'AWS WAF',
            'This AWS WAF web ACL',
            '403 Forbidden',
        ],
        'Imperva': [
            'Imperva',
            'Incapsula',
            'Ray ID',
            'Blocked by Imperva',
        ],
    }
    
    # Test payloads that trigger WAF
    TRIGGER_PAYLOADS = [
        '../../../etc/passwd',
        "' OR '1'='1",
        '<script>alert(1)</script>',
        'union select',
        'drop table',
        '; rm -rf /',
        '<?php system($_GET["cmd"]); ?>',
    ]
    
    # Suspicious response codes from WAF
    WAF_STATUS_CODES = {
        403: 'Forbidden',
        401: 'Unauthorized',
        429: 'Too Many Requests',
        418: "I'm a teapot",
        509: 'Bandwidth Limit Exceeded',
    }
    
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False):
        """Initialize WAF detector"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'waf_detected': False,
            'waf_names': [],
            'confidence': 0,
            'indicators': [],
            'response_times': [],
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
        Perform WAF detection scan
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            Dictionary with WAF detection results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] WAF Detection Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        # Test normal request
        self._test_normal_request(verbose)
        
        # Check response headers
        self._check_headers(verbose)
        
        # Test WAF trigger with payloads
        self._test_waf_triggers(verbose)
        
        # Analyze response patterns
        self._analyze_patterns(verbose)
        
        self.results['scan_time'] = time.time() - start_time
        self._calculate_confidence()
        self._print_summary()
        
        return self.results
    
    def _test_normal_request(self, verbose: bool = False):
        """Test normal request to baseline"""
        try:
            start = time.time()
            response = self.session.get(self.target, timeout=self.timeout)
            elapsed = time.time() - start
            
            self.results['response_times'].append(elapsed)
            
            if verbose:
                print(Fore.BLUE + f"[*] Normal request: {response.status_code} ({elapsed:.2f}s)")
            
            # Store headers for analysis
            self.baseline_headers = dict(response.headers)
            self.baseline_status = response.status_code
            self.baseline_content = response.text
            
        except Exception as e:
            print(Fore.RED + f"[!] Error in normal request: {str(e)}")
    
    def _check_headers(self, verbose: bool = False):
        """Check response headers for WAF signatures"""
        print(Fore.BLUE + "\n[*] Analyzing response headers...")
        
        headers = self.baseline_headers
        found_wafs = set()
        
        for waf_name, waf_headers in self.WAF_HEADERS.items():
            for waf_header in waf_headers:
                # Case-insensitive header check
                for header_name, header_value in headers.items():
                    if waf_header.lower() == header_name.lower():
                        print(Fore.RED + f"[!] {waf_name} detected in header: {header_name}")
                        self.results['indicators'].append({
                            'type': 'header',
                            'waf': waf_name,
                            'indicator': header_name,
                            'value': str(header_value)[:100]
                        })
                        found_wafs.add(waf_name)
        
        if found_wafs:
            self.results['waf_names'].extend(list(found_wafs))
            self.results['waf_detected'] = True
        elif verbose:
            print(Fore.YELLOW + "[*] No WAF headers detected")
    
    def _test_waf_triggers(self, verbose: bool = False):
        """Test malicious payloads to trigger WAF"""
        print(Fore.BLUE + "\n[*] Testing WAF triggers with payloads...")
        
        for payload in self.TRIGGER_PAYLOADS[:3]:  # Test first 3 payloads
            try:
                start = time.time()
                response = self.session.get(
                    self.target,
                    params={'test': payload},
                    timeout=self.timeout
                )
                elapsed = time.time() - start
                
                self.results['response_times'].append(elapsed)
                
                # Check if WAF blocked
                if response.status_code in self.WAF_STATUS_CODES:
                    print(Fore.RED + f"[!] Blocked (HTTP {response.status_code}): {payload[:30]}")
                    self.results['indicators'].append({
                        'type': 'blocking',
                        'payload': payload[:50],
                        'status': response.status_code
                    })
                    self.results['waf_detected'] = True
                elif verbose:
                    print(Fore.YELLOW + f"[*] Payload passed: {payload[:30]}")
                    
            except Exception as e:
                if verbose:
                    logger.debug(f"Error testing payload: {str(e)}")
    
    def _analyze_patterns(self, verbose: bool = False):
        """Analyze content for WAF signatures"""
        print(Fore.BLUE + "\n[*] Analyzing content signatures...")
        
        content = self.baseline_content.lower()
        found_wafs = set()
        
        for waf_name, signatures in WAFDetector.WAF_CONTENT_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in content:
                    print(Fore.RED + f"[!] {waf_name} signature found: {signature}")
                    self.results['indicators'].append({
                        'type': 'content',
                        'waf': waf_name,
                        'signature': signature
                    })
                    found_wafs.add(waf_name)
                    self.results['waf_detected'] = True
        
        if found_wafs:
            self.results['waf_names'].extend(list(found_wafs))
        elif verbose:
            print(Fore.YELLOW + "[*] No content signatures matched")
    
    def _calculate_confidence(self):
        """Calculate WAF detection confidence"""
        if not self.results['waf_detected']:
            self.results['confidence'] = 0
            return
        
        indicator_count = len(self.results['indicators'])
        
        if indicator_count >= 3:
            self.results['confidence'] = 95
        elif indicator_count == 2:
            self.results['confidence'] = 75
        elif indicator_count == 1:
            self.results['confidence'] = 50
        else:
            self.results['confidence'] = 25
    
    def _print_summary(self):
        """Print detection summary"""
        print(Fore.CYAN + Style.BRIGHT + "\n[*] WAF Detection Summary")
        print(Fore.CYAN + f"[*] Scan duration: {self.results['scan_time']:.2f} seconds")
        
        if self.results['waf_detected']:
            print(Fore.RED + Style.BRIGHT + f"[!] WAF DETECTED")
            print(Fore.RED + f"[!] Confidence: {self.results['confidence']}%")
            
            # Get unique WAF names
            unique_wafs = list(set(self.results['waf_names']))
            if unique_wafs:
                print(Fore.RED + f"[!] Detected WAFs: {', '.join(unique_wafs)}")
            
            print(Fore.RED + f"\n[!] Indicators ({len(self.results['indicators'])} found):")
            for indicator in self.results['indicators'][:5]:
                if indicator['type'] == 'header':
                    print(Fore.RED + f"    - {indicator['waf']}: {indicator['indicator']}")
                elif indicator['type'] == 'content':
                    print(Fore.RED + f"    - {indicator['waf']}: {indicator['signature']}")
                else:
                    print(Fore.RED + f"    - {indicator['type']}: {indicator.get('payload', '')[:30]}")
        else:
            print(Fore.GREEN + "[+] No WAF detected")


def firewall_detect(target: str, verbose: bool = False, timeout: int = 10) -> bool:
    """
    Standalone firewall detection function
    
    Args:
        target: Target URL or domain
        verbose: Enable verbose output
        timeout: Request timeout in seconds
        
    Returns:
        True if WAF detected, False otherwise
    """
    detector = WAFDetector(target, timeout=timeout)
    results = detector.scan(verbose=verbose)
    
    return results['waf_detected']


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 firewall_detect.py <target> [--verbose]")
        sys.exit(1)
    
    target = sys.argv[1]
    verbose = '--verbose' in sys.argv
    
    firewall_detect(target, verbose=verbose)