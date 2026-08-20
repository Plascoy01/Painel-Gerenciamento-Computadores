"""Service Detection and Banner Grabbing Module
Identifies services running on open ports with version detection and vulnerability assessment"""

import socket
import requests
from colorama import Fore, Style, init
import logging
import json
import time
from typing import Dict, List, Tuple
import ssl
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServiceDetector:
    """Advanced service detection with version identification and vulnerability assessment"""
    
    def __init__(self, target: str, ports: List[int] = None, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.ports = ports or self._get_default_ports()
        self.services = {
            21: ('FTP', 'File Transfer Protocol'),
            22: ('SSH', 'Secure Shell'),
            25: ('SMTP', 'Simple Mail Transfer'),
            53: ('DNS', 'Domain Name System'),
            80: ('HTTP', 'HyperText Transfer'),
            110: ('POP3', 'Post Office Protocol'),
            143: ('IMAP', 'Internet Message Access'),
            443: ('HTTPS', 'HTTP Secure'),
            465: ('SMTPS', 'SMTP over SSL'),
            587: ('SMTP-TLS', 'SMTP with TLS'),
            993: ('IMAPS', 'IMAP over SSL'),
            995: ('POP3S', 'POP3 over SSL'),
            3306: ('MySQL', 'MySQL Database'),
            3389: ('RDP', 'Remote Desktop'),
            5432: ('PostgreSQL', 'PostgreSQL Database'),
            5984: ('CouchDB', 'CouchDB NoSQL'),
            6379: ('Redis', 'Redis Cache'),
            8080: ('HTTP-Alt', 'HTTP Alternate'),
            8443: ('HTTPS-Alt', 'HTTPS Alternate'),
            9200: ('Elasticsearch', 'Elasticsearch'),
            27017: ('MongoDB', 'MongoDB NoSQL'),
        }
        
        self.results = {
            'target': target,
            'timestamp': time.time(),
            'open_ports': [],
            'services_detected': [],
            'vulnerabilities': [],
            'total_ports_scanned': len(self.ports)
        }
    
    def _get_default_ports(self) -> List[int]:
        """Get default ports to scan"""
        return [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 
                5432, 5984, 6379, 8080, 8443, 9200, 27017]
    
    def check_port(self, port: int, timeout: int = 3) -> Tuple[bool, str]:
        """Check if port is open and grab banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target, port))
            
            banner = ""
            if result == 0:
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
                sock.close()
                return True, banner
            sock.close()
            return False, ""
        except Exception as e:
            logger.debug(f"Port check failed for {port}: {e}")
            return False, ""
    
    def detect_service_version(self, port: int, banner: str) -> Dict:
        """Detect service version from banner"""
        service_name, service_desc = self.services.get(port, ('Unknown', 'Unknown service'))
        version = None
        vulnerability_risk = 'Low'
        
        # Version detection patterns
        patterns = {
            'Apache': r'Apache/(\d+\.\d+\.\d+)',
            'Nginx': r'nginx/(\d+\.\d+\.\d+)',
            'IIS': r'IIS/(\d+\.\d+)',
            'OpenSSH': r'OpenSSH_(\d+\.\d+)',
            'MySQL': r'MySQL Server (\d+\.\d+\.\d+)',
            'PostgreSQL': r'PostgreSQL (\d+\.\d+)',
            'FTP': r'(\d+\.\d+\.\d+)',
        }
        
        for service, pattern in patterns.items():
            if service.lower() in banner.lower():
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    # Simple vulnerability assessment
                    if version and float(version.split('.')[0]) < 2:
                        vulnerability_risk = 'High'
        
        return {
            'port': port,
            'service': service_name,
            'description': service_desc,
            'banner': banner[:100] if banner else 'None',
            'version': version,
            'risk_level': vulnerability_risk
        }
    
    def scan_parallel(self, max_workers: int = 10) -> Dict:
        """Scan ports in parallel for faster execution"""
        print(f"{Fore.CYAN}[*] Scanning {len(self.ports)} ports on {self.target}{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.check_port, port): port for port in self.ports}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        service_info = self.detect_service_version(port, banner)
                        self.results['open_ports'].append(port)
                        self.results['services_detected'].append(service_info)
                        print(f"{Fore.GREEN}[+] Port {port}: {service_info['service']}{Style.RESET_ALL}")
                except Exception as e:
                    logger.debug(f"Error processing port {port}: {e}")
        
        return self.results
    
    def assess_vulnerabilities(self) -> List[Dict]:
        """Assess known vulnerabilities in detected services"""
        vulns = []
        
        for service in self.results['services_detected']:
            # Simple vulnerability assessment based on service and version
            if service['risk_level'] == 'High':
                vuln = {
                    'port': service['port'],
                    'service': service['service'],
                    'issue': f"Old/Outdated version detected: {service['version']}",
                    'severity': 'High',
                    'recommendation': 'Update to latest version'
                }
                vulns.append(vuln)
                self.results['vulnerabilities'].append(vuln)
        
        return vulns
    
    def generate_report(self) -> Dict:
        """Generate service detection report"""
        print(f"\n{Fore.CYAN}[*] Service Detection Report{Style.RESET_ALL}")
        print("=" * 60)
        
        # Run scan
        self.scan_parallel()
        
        # Assess vulnerabilities
        vulns = self.assess_vulnerabilities()
        
        # Display summary
        print(f"\n{Fore.BLUE}[*] Scan Summary:{Style.RESET_ALL}")
        print(f"  Ports Scanned: {len(self.ports)}")
        print(f"  Open Ports: {len(self.results['open_ports'])}")
        print(f"  Services Detected: {len(self.results['services_detected'])}")
        print(f"  Vulnerabilities Found: {len(vulns)}")
        
        if vulns:
            print(f"\n{Fore.RED}[!] Vulnerabilities:{Style.RESET_ALL}")
            for vuln in vulns:
                print(f"  Port {vuln['port']}: {vuln['issue']}")
        
        return self.results


def service_detect(target: str, ports: List[int] = None, verbose: bool = False) -> Dict:
    """Main service detection function"""
    try:
        detector = ServiceDetector(target, ports, verbose)
        results = detector.generate_report()
        
        # Save results
        filename = f"service_detect_{target.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        return results
    except Exception as e:
        logger.error(f"Service detection failed: {e}")
        return {'error': str(e)}