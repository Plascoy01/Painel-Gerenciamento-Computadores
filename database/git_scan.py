#!/usr/bin/env python3
"""
Git Repository Detection Module

Detects exposed .git directories and files through:
- Common git paths enumeration
- Git configuration file detection
- Git metadata exposure
- Repository information gathering

Supported detections: .git/, .git/config, .git/HEAD, .github/, etc.

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


class GitRepoDetector:
    """Professional Git repository exposure scanner"""
    
    # Common git paths to test
    GIT_PATHS = [
        '/.git/',
        '/.git/config',
        '/.git/HEAD',
        '/.git/index',
        '/.gitignore',
        '/.github/',
        '/.git/objects/',
        '/.git/refs/',
        '/.git/logs/',
        '/.git/hooks/',
        '/.git/info/',
        '/.git/description',
        '/.git/packed-refs',
        '/.gitmodules',
        '/.git-credentials',
        '/.env.git',
    ]
    
    # Sensitive git files
    SENSITIVE_FILES = {
        '.git/config': 'Repository configuration',
        '.git/HEAD': 'Current HEAD reference',
        '.gitignore': 'Git ignore rules',
        '.env': 'Environment variables',
        '.env.local': 'Local environment variables',
    }
    
    def __init__(self, target: str, timeout: int = 5, verify_ssl: bool = False):
        """Initialize Git detector"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'git_exposed': False,
            'exposed_paths': [],
            'git_info': {},
            'confidence': 0,
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
        Perform Git exposure detection scan
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            Dictionary with Git detection results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Git Repository Exposure Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        # Enumerate git paths
        self._enumerate_git_paths(verbose)
        
        # Analyze exposed information
        if self.results['exposed_paths']:
            self._analyze_git_info(verbose)
        
        self.results['scan_time'] = time.time() - start_time
        self._calculate_confidence()
        self._print_summary()
        
        return self.results
    
    def _enumerate_git_paths(self, verbose: bool = False):
        """Enumerate common Git paths"""
        print(Fore.BLUE + "\n[*] Enumerating common Git paths...")
        
        for git_path in self.GIT_PATHS:
            try:
                url = self.target + git_path
                response = self.session.head(url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code == 200:
                    print(Fore.RED + f"[!] Exposed: {git_path} (HTTP {response.status_code})")
                    self.results['exposed_paths'].append({
                        'path': git_path,
                        'status': response.status_code,
                        'url': url
                    })
                    self.results['git_exposed'] = True
                    
                    # Try to fetch content
                    self._fetch_path_content(url, git_path, verbose)
                
                elif response.status_code == 403:
                    if verbose:
                        print(Fore.YELLOW + f"[*] Path exists but forbidden: {git_path}")
                
                elif verbose and response.status_code != 404:
                    print(Fore.YELLOW + f"[*] Path {git_path}: HTTP {response.status_code}")
            
            except requests.exceptions.Timeout:
                if verbose:
                    logger.warning(f"Timeout accessing {git_path}")
            except requests.exceptions.RequestException as e:
                if verbose:
                    logger.warning(f"Error accessing {git_path}: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error for {git_path}: {str(e)}")
    
    def _fetch_path_content(self, url: str, path: str, verbose: bool = False):
        """Fetch and analyze content of exposed paths"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200 and response.text:
                content_preview = response.text[:200].replace('\n', ' ')
                self.results['git_info'][path] = {
                    'status': response.status_code,
                    'content_length': len(response.text),
                    'preview': content_preview
                }
                
                if verbose:
                    print(Fore.YELLOW + f"  Content preview: {content_preview[:100]}...")
        
        except Exception as e:
            logger.debug(f"Could not fetch {path}: {str(e)}")
    
    def _analyze_git_info(self, verbose: bool = False):
        """Analyze extracted Git information"""
        if verbose:
            print(Fore.BLUE + "\n[*] Analyzing Git information...")
            for path, info in self.results['git_info'].items():
                print(Fore.YELLOW + f"[*] {path}: {info['content_length']} bytes")
    
    def _calculate_confidence(self):
        """Calculate detection confidence"""
        exposed_count = len(self.results['exposed_paths'])
        
        if exposed_count >= 5:
            self.results['confidence'] = 95
        elif exposed_count >= 3:
            self.results['confidence'] = 85
        elif exposed_count >= 1:
            self.results['confidence'] = 75
        else:
            self.results['confidence'] = 0
    
    def _print_summary(self):
        """Print scan summary"""
        print(Fore.CYAN + "\n[*] Git Exposure Scan Summary:")
        
        if self.results['git_exposed']:
            print(Fore.RED + Style.BRIGHT + f"[!] Git repository EXPOSED!")
            print(Fore.RED + f"[!] Exposed paths: {len(self.results['exposed_paths'])}")
            print(Fore.RED + f"[!] Confidence: {self.results['confidence']}%")
            print(Fore.RED + f"[!] Scan Time: {self.results['scan_time']:.2f}s")
        else:
            print(Fore.GREEN + "[+] No Git exposure detected")
            print(Fore.GREEN + f"[+] Scan Time: {self.results['scan_time']:.2f}s")


# Legacy function interface
def git_scan(target, verbose=False):
    """Legacy function interface for Git scan"""
    detector = GitRepoDetector(target)
    results = detector.scan(verbose=verbose)
    return results['git_exposed']
