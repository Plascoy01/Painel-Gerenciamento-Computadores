#!/usr/bin/env python3
"""plascoy modules.http_methods_scan

Detect enabled HTTP methods that could increase attack surface.

Exports:
  - http_methods_scan(target: str, verbose: bool=False) -> Dict[str, Any]
"""

from __future__ import annotations

import time
import logging
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init

init(autoreset=True)

logger = logging.getLogger(__name__)

SAFE_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS']
DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
ALL_METHODS = SAFE_METHODS + DANGEROUS_METHODS


class HTTPMethodsScanner:
    def __init__(self, target: str, timeout: int = 5, verify_ssl: bool = False):
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self.results: Dict[str, Any] = {
            'vulnerabilities': [],
            'allowed_methods': [],
            'dangerous_methods_enabled': [],
            'scan_time': 0.0,
        }

        self.session = self._create_session()

    @staticmethod
    def _normalize_target(target: str) -> str:
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        return target.rstrip('/')

    def _create_session(self) -> requests.Session:
        s = requests.Session()

        retry_strategy = Retry(
            total=1,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=[
                'GET', 'POST', 'HEAD', 'OPTIONS',
                'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'
            ],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        s.mount('http://', adapter)
        s.mount('https://', adapter)

        s.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        s.verify = self.verify_ssl
        return s

    def scan(self, verbose: bool = False) -> Dict[str, Any]:
        print(Fore.CYAN + Style.BRIGHT + "\n[*] HTTP Methods Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")

        start = time.time()
        self._test_http_methods(verbose)
        self.results['scan_time'] = time.time() - start

        self._print_summary()
        return self.results

    def _test_http_methods(self, verbose: bool = False) -> None:
        print(Fore.BLUE + "\n[*] Testing HTTP methods...")

        for method in ALL_METHODS:
            try:
                resp = self._request_method(method)
                if resp is None:
                    if verbose:
                        print(Fore.YELLOW + f"[*] {method}: no response")
                    continue

                status = resp.status_code

                # Consider enabled if not blocked and not method-not-allowed
                if status < 500 and status != 405:
                    if method in DANGEROUS_METHODS:
                        print(Fore.RED + f"[!] {method} method enabled (HTTP {status})")
                        if method not in self.results['dangerous_methods_enabled']:
                            self.results['dangerous_methods_enabled'].append(method)
                        self.results['vulnerabilities'].append({
                            'type': 'HTTP_METHOD',
                            'method': method,
                            'status': status,
                            'severity': 'High',
                        })
                    else:
                        if method not in self.results['allowed_methods']:
                            self.results['allowed_methods'].append(method)
                        print(Fore.GREEN + f"[+] {method} method: {status}")

                # XST heuristic
                if method == 'TRACE' and resp.text and 'TRACE' in resp.text.upper():
                    print(Fore.RED + "[!] TRACE reflected - XST possible")
                    self.results['vulnerabilities'].append({
                        'type': 'XST',
                        'method': 'TRACE',
                        'severity': 'High',
                    })

                allow = resp.headers.get('Allow')
                if allow:
                    self._parse_allow_header(allow)

            except requests.exceptions.Timeout:
                if verbose:
                    logger.warning("Timeout testing %s", method)
            except requests.exceptions.RequestException as e:
                if verbose:
                    logger.warning("Error testing %s: %s", method, e)
            except Exception as e:
                logger.debug("Unexpected error testing %s: %s", method, e)

    def _request_method(self, method: str) -> Optional[requests.Response]:
        try:
            if method == 'GET':
                return self.session.get(self.target, timeout=self.timeout)
            if method == 'POST':
                return self.session.post(self.target, timeout=self.timeout)
            if method == 'HEAD':
                return self.session.head(self.target, timeout=self.timeout)
            if method == 'OPTIONS':
                return self.session.options(self.target, timeout=self.timeout)
            if method == 'PUT':
                return self.session.put(self.target, timeout=self.timeout)
            if method == 'DELETE':
                return self.session.delete(self.target, timeout=self.timeout)
            if method == 'TRACE':
                return self.session.request('TRACE', self.target, timeout=self.timeout)
            if method == 'CONNECT':
                return self.session.request('CONNECT', self.target, timeout=self.timeout)
            if method == 'PATCH':
                return self.session.request('PATCH', self.target, timeout=self.timeout)
        except Exception:
            return None
        return None

    def _parse_allow_header(self, allow_header: str) -> None:
        methods = [m.strip() for m in allow_header.split(',') if m.strip()]
        # Update dangerous list if present
        for m in methods:
            if m in DANGEROUS_METHODS and m not in self.results['dangerous_methods_enabled']:
                self.results['dangerous_methods_enabled'].append(m)
        print(Fore.BLUE + f"[*] Allow header methods: {', '.join(methods)}")

    def _print_summary(self) -> None:
        print(Fore.CYAN + "\n[*] HTTP Methods Scan Summary:")
        if self.results['dangerous_methods_enabled']:
            print(Fore.RED + Style.BRIGHT + "[!] Dangerous methods ENABLED")
            for m in self.results['dangerous_methods_enabled']:
                print(Fore.RED + f"    - {m}")
        else:
            print(Fore.GREEN + "[+] No dangerous HTTP methods detected")

        print(Fore.GREEN + f"[+] Allowed safe methods observed: {len(self.results['allowed_methods'])}")
        print(Fore.RED + f"[!] Vulnerabilities found: {len(self.results['vulnerabilities'])}")
        print(Fore.CYAN + f"[*] Scan Time: {self.results['scan_time']:.2f}s")


def http_methods_scan(target: str, verbose: bool = False) -> Dict[str, Any]:
    return HTTPMethodsScanner(target).scan(verbose=verbose)


__all__ = ['http_methods_scan']

