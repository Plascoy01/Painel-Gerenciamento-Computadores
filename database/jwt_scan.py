#!/usr/bin/env python3
"""
JWT (JSON Web Token) Analysis Module

Analyzes JWT tokens for vulnerabilities through:
- Token detection in cookies, headers, and responses
- JWT structure validation
- Signature algorithm analysis
- Expiration time verification
- Algorithm vulnerabilities (none, HS256, etc.)

Supported detections: Invalid algorithms, missing expiration, weak algorithms, etc.

Author: Plascoy Security
Version: 2.0
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import base64
from colorama import Fore, Style, init
from typing import Dict, List, Optional
import time
import logging

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class JWTAnalyzer:
    """Professional JWT vulnerability scanner"""
    
    # Weak algorithms
    WEAK_ALGORITHMS = ['none', 'HS256', 'HS384', 'HS512']
    STRONG_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']
    
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False):
        """Initialize JWT analyzer"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'tokens_found': [],
            'vulnerabilities': [],
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
        Perform JWT analysis scan
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            Dictionary with JWT analysis results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] JWT Analysis Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        # Fetch and analyze
        self._fetch_and_analyze(verbose)
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        
        return self.results
    
    def _fetch_and_analyze(self, verbose: bool = False):
        """Fetch target and analyze for JWT tokens"""
        print(Fore.BLUE + "\n[*] Fetching target page...")
        
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            # Check for JWT in cookies
            self._check_cookies(verbose)
            
            # Check for JWT in Authorization header
            self._check_auth_header(response, verbose)
            
            # Check for JWT in response body
            self._check_response_body(response, verbose)
        
        except requests.exceptions.Timeout:
            print(Fore.RED + "[!] Request timeout")
            logger.warning("Timeout fetching target page")
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] Request error: {str(e)}")
            logger.error(f"Request error: {str(e)}")
        except Exception as e:
            print(Fore.RED + f"[!] Error: {str(e)}")
            logger.error(f"Unexpected error: {str(e)}")
    
    def _check_cookies(self, verbose: bool = False):
        """Check for JWT in cookies"""
        print(Fore.BLUE + "\n[*] Checking cookies for JWT tokens...")
        
        for cookie in self.session.cookies:
            if self._is_jwt(cookie.value):
                print(Fore.YELLOW + f"[*] JWT found in cookie: {cookie.name}")
                self._analyze_jwt_token(cookie.value, f"Cookie: {cookie.name}", verbose)
                self.results['tokens_found'].append({
                    'location': f'Cookie: {cookie.name}',
                    'token': cookie.value[:50]
                })
    
    def _check_auth_header(self, response: requests.Response, verbose: bool = False):
        """Check Authorization header for JWT"""
        print(Fore.BLUE + "\n[*] Checking Authorization header...")
        
        auth_header = response.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.replace('Bearer ', '')
            if self._is_jwt(token):
                print(Fore.YELLOW + f"[*] JWT found in Authorization header")
                self._analyze_jwt_token(token, "Authorization Header", verbose)
                self.results['tokens_found'].append({
                    'location': 'Authorization Header',
                    'token': token[:50]
                })
    
    def _check_response_body(self, response: requests.Response, verbose: bool = False):
        """Check response body for JWT tokens"""
        print(Fore.BLUE + "\n[*] Checking response body for JWT tokens...")
        
        if 'token' in response.text or 'jwt' in response.text.lower():
            try:
                data = response.json()
                for key, value in data.items():
                    if isinstance(value, str) and self._is_jwt(value):
                        print(Fore.YELLOW + f"[*] JWT found in response field: {key}")
                        self._analyze_jwt_token(value, f"Response field: {key}", verbose)
                        self.results['tokens_found'].append({
                            'location': f'Field: {key}',
                            'token': value[:50]
                        })
            except json.JSONDecodeError:
                if verbose:
                    logger.debug("Response is not valid JSON")
    
    def _is_jwt(self, value: str) -> bool:
        """Check if value looks like a JWT token"""
        return (isinstance(value, str) and 
                len(value) > 20 and 
                value.count('.') == 2)
    
    def _analyze_jwt_token(self, token: str, location: str, verbose: bool = False):
        """Analyze JWT token for vulnerabilities"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            
            # Decode header
            header = self._decode_jwt_part(parts[0])
            if not header:
                return
            
            payload = self._decode_jwt_part(parts[1])
            if not payload:
                return
            
            print(Fore.BLUE + f"\n[*] JWT Analysis for {location}:")
            print(Fore.BLUE + f"  Header: {json.dumps(header)}")
            
            # Check algorithm
            alg = header.get('alg')
            if alg == 'none':
                print(Fore.RED + "[!] VULNERABILITY: Algorithm set to 'none' - Token can be forged!")
                self.results['vulnerabilities'].append({
                    'location': location,
                    'type': 'Algorithm: none',
                    'severity': 'Critical'
                })
            elif alg in ['HS256', 'HS384', 'HS512']:
                print(Fore.YELLOW + f"[*] Using symmetric algorithm {alg} - Ensure secret is strong")
            elif alg in self.STRONG_ALGORITHMS:
                print(Fore.GREEN + f"[+] Using strong algorithm: {alg}")
            
            # Check expiration
            if 'exp' in payload:
                print(Fore.BLUE + f"  Expiration: {payload.get('exp')}")
            else:
                print(Fore.RED + "[!] VULNERABILITY: No expiration time - Token valid indefinitely!")
                self.results['vulnerabilities'].append({
                    'location': location,
                    'type': 'Missing expiration',
                    'severity': 'High'
                })
            
            # Check issued at
            if 'iat' in payload:
                print(Fore.BLUE + f"  Issued at: {payload.get('iat')}")
            
            # Display payload
            if verbose:
                print(Fore.BLUE + f"  Payload: {json.dumps(payload)}")
        
        except Exception as e:
            logger.debug(f"Could not analyze JWT: {str(e)}")
    
    def _decode_jwt_part(self, part: str) -> Optional[Dict]:
        """Decode JWT part (header or payload)"""
        try:
            # Add padding if necessary
            padding = 4 - len(part) % 4
            if padding != 4:
                part += '=' * padding
            
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded)
        except Exception as e:
            logger.debug(f"Could not decode JWT part: {str(e)}")
            return None
    
    def _print_summary(self):
        """Print analysis summary"""
        print(Fore.CYAN + "\n[*] JWT Analysis Summary:")
        
        if self.results['tokens_found']:
            print(Fore.YELLOW + f"[*] Tokens Found: {len(self.results['tokens_found'])}")
            for token_info in self.results['tokens_found']:
                print(Fore.YELLOW + f"    - {token_info['location']}")
        else:
            print(Fore.GREEN + "[+] No JWT tokens found")
        
        if self.results['vulnerabilities']:
            print(Fore.RED + f"[!] Vulnerabilities: {len(self.results['vulnerabilities'])}")
            for vuln in self.results['vulnerabilities']:
                print(Fore.RED + f"    - {vuln['type']} ({vuln['severity']})")
        
        print(Fore.CYAN + f"[*] Scan Time: {self.results['scan_time']:.2f}s")


# Legacy function interface
def jwt_scan(target, verbose=False):
    """Legacy function interface for JWT scan"""
    analyzer = JWTAnalyzer(target)
    results = analyzer.scan(verbose=verbose)
    return len(results['tokens_found']) > 0
