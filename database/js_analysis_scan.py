#!/usr/bin/env python3
"""
JavaScript Analysis Module

Analyzes JavaScript files for sensitive information through:
- API endpoint discovery
- Secret/API key detection
- Code comment extraction
- Variable analysis
- Exposed sensitive data identification

Supported detections: API endpoints, API keys, hardcoded secrets, etc.

Author: Plascoy Security
Version: 2.0
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init
import re
import json
from typing import Dict, List, Optional
import time
import logging

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class JavaScriptAnalyzer:
    """Professional JavaScript analysis scanner"""
    
    # Patterns for sensitive data detection
    API_ENDPOINT_PATTERN = r'["\']([/a-zA-Z0-9_-]+/[a-zA-Z0-9_/:-]+)["\']'
    API_KEY_PATTERN = r'([a-zA-Z_]*key[a-zA-Z_]*)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']'
    SECRET_PATTERN = r'([a-zA-Z_]*secret[a-zA-Z_]*)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']'
    TOKEN_PATTERN = r'([a-zA-Z_]*token[a-zA-Z_]*)\s*[=:]\s*["\']([a-zA-Z0-9._-]{20,})["\']'
    COMMENT_PATTERN = r'//\s*(.+)'
    FETCH_PATTERN = r'fetch\(["\']([^"\']+)'
    
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False):
        """Initialize JavaScript analyzer"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'endpoints': [],
            'api_keys': [],
            'secrets': [],
            'tokens': [],
            'comments': [],
            'scripts_analyzed': 0,
            'findings': 0,
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
        Perform JavaScript analysis scan
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            Dictionary with analysis results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] JavaScript Analysis Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        # Fetch and analyze
        self._analyze_target_page(verbose)
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        
        return self.results
    
    def _analyze_target_page(self, verbose: bool = False):
        """Analyze target page for JavaScript"""
        print(Fore.BLUE + "\n[*] Fetching target page...")
        
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            # Extract script sources
            scripts = self._extract_scripts(response.text)
            print(Fore.BLUE + f"[*] Found {len(scripts)} external scripts")
            
            # Analyze external scripts
            for script_url in scripts[:10]:  # Limit to 10 scripts
                self._analyze_script(script_url, verbose)
            
            # Analyze inline scripts
            self._analyze_inline_scripts(response.text, verbose)
        
        except requests.exceptions.Timeout:
            print(Fore.RED + "[!] Request timeout")
            logger.warning("Timeout fetching target page")
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] Request error: {str(e)}")
            logger.error(f"Request error: {str(e)}")
        except Exception as e:
            print(Fore.RED + f"[!] Error: {str(e)}")
            logger.error(f"Unexpected error: {str(e)}")
    
    def _extract_scripts(self, html: str) -> List[str]:
        """Extract script source URLs from HTML"""
        script_pattern = r'<script[^>]*src=["\']([^"\']+)'
        scripts = re.findall(script_pattern, html)
        return scripts
    
    def _analyze_script(self, script_path: str, verbose: bool = False):
        """Analyze individual script file"""
        try:
            # Construct full URL
            script_url = self._construct_url(script_path)
            
            response = self.session.get(script_url, timeout=self.timeout)
            content = response.text
            
            # Extract sensitive data
            self._extract_sensitive_data(content, verbose)
            self.results['scripts_analyzed'] += 1
            
            if verbose:
                print(Fore.BLUE + f"[*] Analyzed: {script_path}")
        
        except Exception as e:
            if verbose:
                logger.warning(f"Could not analyze {script_path}: {str(e)}")
    
    def _construct_url(self, path: str) -> str:
        """Construct full URL from path"""
        if path.startswith('http'):
            return path
        elif path.startswith('/'):
            base = self.target.split('?')[0].rsplit('/', 1)[0]
            return base + path
        else:
            base = self.target.split('?')[0]
            return base.rstrip('/') + '/' + path
    
    def _extract_sensitive_data(self, content: str, verbose: bool = False):
        """Extract sensitive data from content"""
        # Extract endpoints
        endpoints = re.findall(self.API_ENDPOINT_PATTERN, content)
        self.results['endpoints'].extend(endpoints)
        
        # Extract API keys
        keys = re.findall(self.API_KEY_PATTERN, content, re.IGNORECASE)
        self.results['api_keys'].extend(keys)
        
        # Extract secrets
        secrets = re.findall(self.SECRET_PATTERN, content, re.IGNORECASE)
        self.results['secrets'].extend(secrets)
        
        # Extract tokens
        tokens = re.findall(self.TOKEN_PATTERN, content, re.IGNORECASE)
        self.results['tokens'].extend(tokens)
        
        # Extract comments
        comments = re.findall(self.COMMENT_PATTERN, content)
        self.results['comments'].extend(comments[:10])
    
    def _analyze_inline_scripts(self, html: str, verbose: bool = False):
        """Analyze inline JavaScript"""
        print(Fore.BLUE + "\n[*] Analyzing inline scripts...")
        
        # Extract inline fetch calls
        inline_apis = re.findall(self.FETCH_PATTERN, html)
        self.results['endpoints'].extend(inline_apis)
        
        # Extract sensitive data from HTML
        self._extract_sensitive_data(html, verbose)
    
    def _print_summary(self):
        """Print analysis summary"""
        # Deduplicate results
        self.results['endpoints'] = list(set(self.results['endpoints']))
        self.results['api_keys'] = list(set(self.results['api_keys']))
        self.results['secrets'] = list(set(self.results['secrets']))
        self.results['tokens'] = list(set(self.results['tokens']))
        
        self.results['findings'] = (len(self.results['endpoints']) +
                                   len(self.results['api_keys']) +
                                   len(self.results['secrets']) +
                                   len(self.results['tokens']))
        
        print(Fore.CYAN + "\n[*] JavaScript Analysis Summary:")
        
        if self.results['endpoints']:
            print(Fore.GREEN + f"[+] API Endpoints: {len(self.results['endpoints'])}")
            for endpoint in self.results['endpoints'][:5]:
                print(Fore.GREEN + f"    - {endpoint}")
        
        if self.results['api_keys']:
            print(Fore.RED + f"[!] API Keys Found: {len(self.results['api_keys'])}")
            for key_name, key_value in self.results['api_keys'][:3]:
                print(Fore.RED + f"    - {key_name}: {key_value[:20]}...")
        
        if self.results['secrets']:
            print(Fore.RED + f"[!] Secrets Found: {len(self.results['secrets'])}")
            for secret_name, secret_value in self.results['secrets'][:3]:
                print(Fore.RED + f"    - {secret_name}: {secret_value[:20]}...")
        
        if self.results['tokens']:
            print(Fore.YELLOW + f"[*] Tokens Found: {len(self.results['tokens'])}")
            for token_name, token_value in self.results['tokens'][:3]:
                print(Fore.YELLOW + f"    - {token_name}: {token_value[:20]}...")
        
        print(Fore.CYAN + f"[*] Scripts Analyzed: {self.results['scripts_analyzed']}")
        print(Fore.CYAN + f"[*] Total Findings: {self.results['findings']}")
        print(Fore.CYAN + f"[*] Scan Time: {self.results['scan_time']:.2f}s")


# Legacy function interface
def js_analysis_scan(target, verbose=False):
    """Legacy function interface for JavaScript analysis"""
    analyzer = JavaScriptAnalyzer(target)
    results = analyzer.scan(verbose=verbose)
    return results['findings'] > 0
