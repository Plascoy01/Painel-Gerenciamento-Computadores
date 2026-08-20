"""Operating System Fingerprinting Module
Identifies target OS through multiple techniques including HTTP headers, TTL analysis, and service detection
"""

import requests
from colorama import Fore, Style, init
import logging
import json
import time
from typing import Dict, List, Tuple
import re
import socket
import subprocess
from collections import defaultdict

init(autoreset=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OSFingerprinter:
    """Advanced OS fingerprinting with multiple detection techniques"""
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target if target.startswith(('http://', 'https://')) else f"https://{target}"
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        # OS fingerprint patterns
        self.os_patterns = {
            'Windows': {
                'indicators': ['Windows', 'IIS', 'ASPX', 'ASP.NET', 'WinServer', 'Microsoft'],
                'ports': [3389, 445, 135, 139, 1433],
                'services': ['IIS', 'MSSQL', 'RDP'],
            },
            'Linux': {
                'indicators': ['Linux', 'Apache', 'Nginx', 'Ubuntu', 'Debian', 'CentOS', 'RHEL'],
                'ports': [22, 80, 443, 3306, 5432],
                'services': ['SSH', 'Apache', 'Nginx', 'MySQL', 'PostgreSQL'],
            },
            'macOS': {
                'indicators': ['macOS', 'Darwin', 'Mac', 'OSX'],
                'ports': [22, 80, 443],
                'services': ['SSH', 'Apache'],
            },
            'FreeBSD': {
                'indicators': ['FreeBSD', 'OpenBSD', 'NetBSD', 'BSD'],
                'ports': [22, 80, 443],
                'services': ['SSH', 'Apache'],
            },
        }
        
        self.results = {
            'target': self.target,
            'timestamp': time.time(),
            'detected_os': [],
            'confidence': {},
            'evidence': defaultdict(list),
            'additional_info': {}
        }
    
    def analyze_http_headers(self) -> Dict[str, List[str]]:
        """Analyze HTTP response headers for OS indicators"""
        os_indicators = defaultdict(list)
        
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            headers = response.headers
            
            # Check Server header
            server = headers.get('Server', '').lower()
            if server:
                print(f"{Fore.BLUE}[*] Server header: {server}{Style.RESET_ALL}")
                
                for os_name, indicators in self.os_patterns.items():
                    for indicator in indicators['indicators']:
                        if indicator.lower() in server:
                            os_indicators[os_name].append(f"Server header contains '{indicator}'")
            
            # Check for X-Powered-By
            powered_by = headers.get('X-Powered-By', '').lower()
            if powered_by:
                if 'asp' in powered_by:
                    os_indicators['Windows'].append("X-Powered-By indicates ASP/ASP.NET")
                elif 'php' in powered_by:
                    os_indicators['Linux'].append("X-Powered-By indicates PHP")
            
            # Check for other OS-specific headers
            if 'X-Aspnet-Version' in headers:
                os_indicators['Windows'].append("ASP.NET version header detected")
            
            # Check response body for OS clues
            if 'Windows' in response.text or 'IIS' in response.text:
                os_indicators['Windows'].append("OS mentions in response body")
        
        except Exception as e:
            logger.warning(f"HTTP header analysis failed: {e}")
        
        return dict(os_indicators)
    
    def analyze_port_services(self, target_host: str) -> Dict[str, List[str]]:
        """Analyze open ports and services for OS indicators"""
        os_indicators = defaultdict(list)
        
        common_ports = {
            22: ('SSH', 'Unix-like'),
            80: ('HTTP', 'Any'),
            135: ('RPC', 'Windows'),
            139: ('NetBIOS', 'Windows'),
            443: ('HTTPS', 'Any'),
            445: ('SMB', 'Windows'),
            1433: ('MSSQL', 'Windows'),
            3306: ('MySQL', 'Any'),
            3389: ('RDP', 'Windows'),
            5432: ('PostgreSQL', 'Unix-like'),
        }
        
        for port, (service, os_hint) in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_host, port))
                if result == 0:
                    print(f"{Fore.GREEN}[+] Port {port} ({service}) is open{Style.RESET_ALL}")
                    if 'Windows' in os_hint:
                        os_indicators['Windows'].append(f"Port {port} ({service}) typically Windows")
                    elif 'Unix' in os_hint:
                        os_indicators['Linux'].append(f"Port {port} ({service}) typically Unix-like")
                sock.close()
            except Exception as e:
                logger.debug(f"Port check error: {e}")
        
        return dict(os_indicators)
    
    def analyze_response_timing(self) -> Dict[str, str]:
        """Analyze response timing patterns for OS hints"""
        try:
            start_time = time.time()
            response = self.session.get(self.target, timeout=10, verify=False)
            elapsed = time.time() - start_time
            
            # Different OSes may have different response patterns
            timing_info = {
                'response_time': f"{elapsed:.2f}s",
                'status_code': str(response.status_code),
                'content_length': len(response.content),
            }
            
            # Windows IIS often has certain response characteristics
            if response.headers.get('Server', '').startswith('Microsoft'):
                timing_info['likely_os'] = 'Windows'
            
            return timing_info
        except Exception as e:
            logger.warning(f"Timing analysis failed: {e}")
            return {}
    
    def analyze_http_methods(self) -> Dict[str, List[str]]:
        """Analyze supported HTTP methods for OS hints"""
        os_indicators = defaultdict(list)
        
        try:
            response = self.session.options(self.target, timeout=10, verify=False)
            
            allow_header = response.headers.get('Allow', '')
            if allow_header:
                methods = allow_header.split(',')
                
                # TRACE method is common on Windows servers
                if 'TRACE' in allow_header:
                    os_indicators['Windows'].append("TRACE method supported (IIS characteristic)")
                
                # Check for uncommon method combinations
                if 'CONNECT' in allow_header:
                    os_indicators['Linux'].append("CONNECT method supported (proxy characteristic)")
        
        except Exception as e:
            logger.debug(f"HTTP methods analysis failed: {e}")
        
        return dict(os_indicators)
    
    def generate_report(self) -> Dict:
        """Generate comprehensive OS fingerprinting report"""
        target_host = self.target.replace('http://', '').replace('https://', '').split('/')[0]
        
        print(f"\n{Fore.CYAN}[*] OS Fingerprinting for {target_host}{Style.RESET_ALL}")
        print("=" * 60)
        
        # Run all analysis methods
        header_indicators = self.analyze_http_headers()
        port_indicators = self.analyze_port_services(target_host)
        timing_info = self.analyze_response_timing()
        http_methods = self.analyze_http_methods()
        
        # Combine evidence
        all_evidence = defaultdict(list)
        for evidence_dict in [header_indicators, port_indicators, http_methods]:
            for os_name, evidence_list in evidence_dict.items():
                all_evidence[os_name].extend(evidence_list)
        
        # Calculate confidence scores
        confidence_scores = {}
        for os_name, evidence_list in all_evidence.items():
            confidence = min(100, len(evidence_list) * 25)
            confidence_scores[os_name] = confidence
        
        # Determine most likely OS
        if confidence_scores:
            most_likely = max(confidence_scores, key=confidence_scores.get)
            self.results['detected_os'].append(most_likely)
            self.results['confidence'] = confidence_scores
            self.results['evidence'] = dict(all_evidence)
            self.results['additional_info'] = timing_info
        
        # Display results
        print(f"\n{Fore.BLUE}[*] OS Detection Results:{Style.RESET_ALL}")
        for os_name in sorted(confidence_scores, key=confidence_scores.get, reverse=True):
            confidence = confidence_scores[os_name]
            if confidence > 0:
                print(f"  {os_name}: {confidence}% confidence")
                for evidence in all_evidence.get(os_name, [])[:3]:
                    print(f"    - {evidence}")
        
        return self.results


def os_fingerprint(target: str, verbose: bool = False) -> Dict:
    """Main OS fingerprinting function"""
    try:
        fingerprinter = OSFingerprinter(target, verbose)
        results = fingerprinter.generate_report()
        
        # Save results
        filename = f"os_fingerprint_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        return results
    except Exception as e:
        logger.error(f"OS fingerprinting failed: {e}")
        return {'error': str(e)}