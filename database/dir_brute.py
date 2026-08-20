#!/usr/bin/env python3
"""
Directory Bruteforce Scanner
Advanced directory and file enumeration tool
"""

import requests
import logging
import json
import time
import os
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict, field
from queue import Queue
import threading
import itertools
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class DirResult:
    """Data class for directory bruteforce results"""
    url: str
    status_code: int
    content_type: str
    content_length: int
    title: str
    response_time: float
    discovered_type: str  # 'directory', 'file', 'backup', etc.
    interesting: bool
    timestamp: float

@dataclass
class DirScanStats:
    """Statistics for directory scan"""
    total_requests: int = 0
    directories_found: int = 0
    files_found: int = 0
    interesting_files: int = 0
    errors: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    scan_duration: float = 0.0

class AdvancedDirBrute:
    """
    Advanced directory bruteforce scanner with comprehensive features
    """

    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize directory bruteforce scanner

        Args:
            target: Target URL to scan
            config: Configuration dictionary
        """
        self.target = self._normalize_url(target)
        self.config = config or self._default_config()
        self.session = self._create_session()

        # Results storage
        self.results: List[DirResult] = []
        self.found_paths: Set[str] = set()
        self.interesting_files: List[DirResult] = []

        # Wordlists
        self.wordlist: List[str] = []
        self.extensions: List[str] = []

        # Statistics
        self.stats = DirScanStats()

        # Threading
        self.request_queue: Queue = Queue()
        self.result_lock = threading.Lock()

        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def _default_config(self) -> Dict:
        """Default configuration settings"""
        return {
            'timeout': 10,
            'max_workers': 10,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'verify_ssl': False,
            'follow_redirects': False,
            'rate_limit': 0.1,  # seconds between requests
            'max_retries': 3,
            'wordlist_path': os.path.join(os.path.dirname(__file__), 'wordlist.txt'),
            'extensions': [
                '', '.php', '.html', '.htm', '.txt', '.bak', '.old', '.backup',
                '.zip', '.rar', '.7z', '.tar.gz', '.sql', '.db', '.sqlite',
                '.config', '.conf', '.ini', '.log', '.xml', '.json'
            ],
            'recursive_depth': 2,
            'case_sensitive': False,
            'include_parent_paths': True,
            'exclude_status_codes': [404],
            'include_status_codes': [200, 201, 301, 302, 403, 401, 500],
            'detect_backups': True,
            'detect_configs': True,
            'detect_logs': True,
            'detect_admin': True,
            'save_responses': False,
            'response_dir': 'dirbrute_responses',
            'max_content_length': 1024 * 1024,  # 1MB
            'randomize_order': True
        }

    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.config['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive'
        })
        session.verify = self.config['verify_ssl']
        session.max_redirects = 0 if not self.config['follow_redirects'] else 5
        return session

    def load_wordlist(self, wordlist_path: Optional[str] = None) -> bool:
        """Load wordlist from file"""
        path = wordlist_path or self.config['wordlist_path']

        try:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.wordlist = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(self.wordlist)} words from {path}")
                return True
            else:
                self.logger.warning(f"Wordlist not found: {path}")
                # Use default wordlist
                self.wordlist = self._get_default_wordlist()
                return True
        except Exception as e:
            self.logger.error(f"Error loading wordlist: {e}")
            return False

    def _get_default_wordlist(self) -> List[str]:
        """Get default wordlist if file not found"""
        return [
            'admin', 'administrator', 'login', 'logon', 'signin', 'auth',
            'backup', 'backups', 'bak', 'old', 'new', 'temp', 'tmp',
            'config', 'configuration', 'conf', 'settings', 'setup',
            'install', 'installation', 'update', 'upgrade', 'patch',
            'test', 'testing', 'demo', 'example', 'sample',
            'db', 'database', 'data', 'sql', 'mysql', 'postgres',
            'api', 'rest', 'graphql', 'soap', 'xml', 'json',
            'upload', 'uploads', 'download', 'downloads', 'files',
            'images', 'img', 'pics', 'photos', 'assets', 'static',
            'css', 'js', 'javascript', 'scripts', 'styles',
            'private', 'secret', 'hidden', 'internal',
            'debug', 'dev', 'development', 'staging', 'production',
            'status', 'info', 'information', 'about', 'help',
            'dashboard', 'panel', 'control', 'manage', 'management',
            'user', 'users', 'profile', 'account', 'accounts',
            'session', 'sessions', 'token', 'tokens', 'auth',
            'password', 'passwd', 'pwd', 'credentials', 'keys',
            'log', 'logs', 'error', 'errors', 'access', 'audit',
            'cache', 'temp', 'temporary', 'trash', 'deleted'
        ]

    def scan(self) -> Dict[str, Any]:
        """
        Perform comprehensive directory bruteforce scan

        Returns:
            Dictionary containing scan results and analysis
        """
        self.logger.info(f"Starting directory bruteforce scan for {self.target}")
        self.stats.start_time = time.time()

        try:
            # Load wordlist
            if not self.load_wordlist():
                raise Exception("Failed to load wordlist")

            # Generate scan queue
            self._generate_scan_queue()

            # Perform scan
            with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
                futures = []

                while not self.request_queue.empty():
                    # Submit batch of tasks
                    batch_size = min(self.config['max_workers'] * 2, self.request_queue.qsize())

                    for _ in range(batch_size):
                        if self.request_queue.empty():
                            break

                        path = self.request_queue.get()
                        future = executor.submit(self._test_path, path)
                        futures.append(future)

                    # Wait for batch completion
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            if result:
                                with self.result_lock:
                                    self.results.append(result)
                                    self._update_stats(result)

                                    if result.interesting:
                                        self.interesting_files.append(result)

                        except Exception as e:
                            self.logger.error(f"Error processing result: {e}")
                            with self.result_lock:
                                self.stats.errors += 1

                    futures.clear()

            # Finalize
            self.stats.end_time = time.time()
            self.stats.scan_duration = self.stats.end_time - self.stats.start_time

            analysis = self._analyze_results()

            self.logger.info(f"Directory scan completed. Found {len(self.results)} paths")

            return {
                'target': self.target,
                'config': self.config,
                'stats': asdict(self.stats),
                'results': [asdict(result) for result in self.results],
                'interesting_files': [asdict(result) for result in self.interesting_files],
                'analysis': analysis
            }

        except Exception as e:
            self.logger.error(f"Error during directory scan: {e}")
            raise

    def _generate_scan_queue(self):
        """Generate queue of paths to test"""
        paths = set()

        # Generate base paths
        for word in self.wordlist:
            if self.config['case_sensitive']:
                paths.add(word)
            else:
                paths.add(word.lower())

        # Add extensions
        extended_paths = set()
        for path in paths:
            for ext in self.config['extensions']:
                extended_paths.add(f"{path}{ext}")

        # Add parent paths if enabled
        if self.config['include_parent_paths']:
            parent_paths = set()
            for path in extended_paths:
                parts = path.split('/')
                for i in range(1, len(parts) + 1):
                    parent_path = '/'.join(parts[:i])
                    if parent_path:
                        parent_paths.add(parent_path)
            extended_paths.update(parent_paths)

        # Randomize order if requested
        if self.config['randomize_order']:
            extended_paths = list(extended_paths)
            import random
            random.shuffle(extended_paths)
        else:
            extended_paths = sorted(extended_paths)

        # Add to queue
        for path in extended_paths:
            self.request_queue.put(path)

        self.logger.info(f"Generated {len(extended_paths)} paths to test")

    def _test_path(self, path: str) -> Optional[DirResult]:
        """Test a single path"""
        url = urljoin(self.target + '/', path)

        # Skip if already tested
        if url in self.found_paths:
            return None

        self.found_paths.add(url)

        retries = 0
        while retries <= self.config['max_retries']:
            try:
                start_time = time.time()
                response = self.session.get(
                    url,
                    timeout=self.config['timeout'],
                    allow_redirects=self.config['follow_redirects']
                )
                response_time = time.time() - start_time

                # Check if we should include this result
                if response.status_code in self.config['exclude_status_codes']:
                    return None

                if response.status_code not in self.config['include_status_codes']:
                    if not self.config.get('include_all_status', False):
                        return None

                # Check content length
                content_length = len(response.content)
                if content_length > self.config['max_content_length']:
                    return None

                # Extract information
                content_type = response.headers.get('content-type', '').split(';')[0].lower()
                title = self._extract_title(response.text)

                # Determine discovery type
                discovered_type = self._classify_path(path, response)

                # Check if interesting
                interesting = self._is_interesting(path, response, discovered_type)

                result = DirResult(
                    url=url,
                    status_code=response.status_code,
                    content_type=content_type,
                    content_length=content_length,
                    title=title,
                    response_time=response_time,
                    discovered_type=discovered_type,
                    interesting=interesting,
                    timestamp=time.time()
                )

                # Save response if requested
                if self.config['save_responses'] and interesting:
                    self._save_response(response, path)

                # Rate limiting
                time.sleep(self.config['rate_limit'])

                return result

            except requests.RequestException as e:
                retries += 1
                if retries > self.config['max_retries']:
                    self.logger.debug(f"Failed to test {url} after {retries} retries: {e}")
                    return None
                time.sleep(self.config['rate_limit'] * retries)

        return None

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]  # Limit length
        return ''

    def _classify_path(self, path: str, response: requests.Response) -> str:
        """Classify the type of discovered path"""
        if path.endswith('/'):
            return 'directory'

        # Check extensions
        if any(path.endswith(ext) for ext in ['.php', '.jsp', '.asp', '.aspx']):
            return 'script'

        if any(path.endswith(ext) for ext in ['.html', '.htm']):
            return 'page'

        if any(path.endswith(ext) for ext in ['.txt', '.log', '.conf', '.config', '.ini']):
            return 'config'

        if any(path.endswith(ext) for ext in ['.bak', '.backup', '.old', '.orig']):
            return 'backup'

        if any(path.endswith(ext) for ext in ['.sql', '.db', '.sqlite', '.dump']):
            return 'database'

        if any(path.endswith(ext) for ext in ['.zip', '.rar', '.7z', '.tar.gz', '.tar.bz2']):
            return 'archive'

        if any(path.endswith(ext) for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx']):
            return 'document'

        if any(path.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico']):
            return 'image'

        if any(path.endswith(ext) for ext in ['.css', '.js', '.scss', '.sass']):
            return 'asset'

        # Check content type
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' in content_type:
            return 'page'
        elif 'application/json' in content_type:
            return 'api'
        elif 'text/plain' in content_type:
            return 'text'

        return 'file'

    def _is_interesting(self, path: str, response: requests.Response, discovered_type: str) -> bool:
        """Determine if a discovered path is interesting"""
        # Always interesting status codes
        if response.status_code in [200, 201, 301, 302]:
            # Check for specific interesting types
            if self.config['detect_backups'] and discovered_type == 'backup':
                return True
            if self.config['detect_configs'] and discovered_type == 'config':
                return True
            if self.config['detect_logs'] and 'log' in path.lower():
                return True
            if self.config['detect_admin'] and any(word in path.lower() for word in ['admin', 'login', 'auth', 'dashboard']):
                return True

            # Check for sensitive keywords in path
            sensitive_keywords = [
                'password', 'passwd', 'pwd', 'secret', 'key', 'token',
                'credential', 'auth', 'session', 'private', 'internal',
                'debug', 'test', 'dev', 'staging', 'backup', 'old',
                'config', 'conf', 'setting', 'database', 'db', 'sql'
            ]

            if any(keyword in path.lower() for keyword in sensitive_keywords):
                return True

            # Check response content for sensitive information
            content = response.text.lower()
            if any(keyword in content for keyword in ['password', 'username', 'email', 'api_key']):
                return True

        # Forbidden/unauthorized might indicate protected resources
        if response.status_code in [403, 401]:
            if any(word in path.lower() for word in ['admin', 'root', 'private', 'internal']):
                return True

        return False

    def _save_response(self, response: requests.Response, path: str):
        """Save response content to file"""
        try:
            os.makedirs(self.config['response_dir'], exist_ok=True)

            # Create safe filename
            safe_path = re.sub(r'[^\w\-_\.]', '_', path)
            filename = os.path.join(self.config['response_dir'], f"{safe_path}_{int(time.time())}.html")

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(response.text)

        except Exception as e:
            self.logger.warning(f"Failed to save response for {path}: {e}")

    def _update_stats(self, result: DirResult):
        """Update scan statistics"""
        self.stats.total_requests += 1

        if result.discovered_type == 'directory':
            self.stats.directories_found += 1
        elif result.discovered_type in ['file', 'script', 'page', 'config', 'backup', 'database', 'archive', 'document']:
            self.stats.files_found += 1

        if result.interesting:
            self.stats.interesting_files += 1

    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze scan results"""
        # Group by status code
        status_codes = {}
        for result in self.results:
            status_codes[result.status_code] = status_codes.get(result.status_code, 0) + 1

        # Group by discovery type
        discovery_types = {}
        for result in self.results:
            discovery_types[result.discovered_type] = discovery_types.get(result.discovered_type, 0) + 1

        # Group by content type
        content_types = {}
        for result in self.results:
            content_types[result.content_type] = content_types.get(result.content_type, 0) + 1

        # Calculate response time statistics
        response_times = [r.response_time for r in self.results]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0

        # Find most interesting findings
        top_findings = sorted(
            self.interesting_files,
            key=lambda x: (x.status_code == 200, len(x.title), -x.content_length),
            reverse=True
        )[:10]

        return {
            'total_paths_tested': len(self.found_paths),
            'successful_requests': len(self.results),
            'error_rate': self.stats.errors / max(1, self.stats.total_requests),
            'status_code_distribution': status_codes,
            'discovery_type_distribution': discovery_types,
            'content_type_distribution': content_types,
            'average_response_time': avg_response_time,
            'top_findings': [asdict(f) for f in top_findings],
            'scan_efficiency': len(self.results) / max(1, self.stats.scan_duration)
        }

    def export_results(self, filename: str):
        """Export results to JSON file"""
        data = {
            'summary': asdict(self.stats),
            'results': [asdict(r) for r in self.results],
            'interesting_files': [asdict(r) for r in self.interesting_files],
            'analysis': self._analyze_results()
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        self.logger.info(f"Results exported to {filename}")

def dir_brute(target: str, wordlist: Optional[str] = None, threads: int = 10,
              extensions: Optional[List[str]] = None, verbose: bool = False,
              config: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main directory bruteforce function

    Args:
        target: Target URL to scan
        wordlist: Path to wordlist file
        threads: Number of threads
        extensions: File extensions to test
        verbose: Enable verbose logging
        config: Custom configuration

    Returns:
        Dictionary containing scan results
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Update config with parameters
    # Merge provided config with module defaults to avoid missing required keys.
    base_config = AdvancedDirBrute(target, None)._default_config()
    if config:
        base_config.update(config)

    base_config.update({
        'max_workers': threads,
        'wordlist_path': wordlist
    })
    if extensions:
        config['extensions'] = extensions

    scanner = AdvancedDirBrute(target, config)
    results = scanner.scan()

    # Print summary
    stats = results['stats']
    analysis = results['analysis']

    print(f"\n{'='*60}")
    print(f"DIRECTORY BRUTEFORCE RESULTS FOR: {target}")
    print(f"{'='*60}")
    print(f"Duration: {stats['scan_duration']:.2f} seconds")
    print(f"Paths tested: {analysis['total_paths_tested']}")
    print(f"Successful requests: {analysis['successful_requests']}")
    print(f"Directories found: {stats['directories_found']}")
    print(f"Files found: {stats['files_found']}")
    print(f"Interesting files: {stats['interesting_files']}")
    print(f"Errors: {stats['errors']}")
    print(f"Average response time: {analysis['average_response_time']:.3f}s")
    print(f"Scan efficiency: {analysis['scan_efficiency']:.2f} req/sec")

    print(f"\nStatus Code Distribution:")
    for status, count in analysis['status_code_distribution'].items():
        print(f"  {status}: {count}")

    if results['interesting_files']:
        print(f"\nInteresting Findings:")
        for finding in results['interesting_files'][:10]:  # Show first 10
            print(f"  [{finding['status_code']}] {finding['url']} ({finding['discovered_type']})")

    print(f"{'='*60}")

    return results

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dir_brute.py <target_url> [--wordlist FILE] [--threads N] [--ext .ext] [--verbose]")
        sys.exit(1)

    target = sys.argv[1]
    wordlist = None
    threads = 10
    extensions = None
    verbose = False

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--wordlist' and i + 1 < len(sys.argv):
            wordlist = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--threads' and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--ext' and i + 1 < len(sys.argv):
            extensions = [sys.argv[i + 1]]
            i += 2
        elif sys.argv[i] == '--verbose':
            verbose = True
            i += 1
        else:
            i += 1

    try:
        results = dir_brute(target, wordlist, threads, extensions, verbose)
        print(f"\nScan completed successfully.")
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)