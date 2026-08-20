"""
WHOIS Lookup Module - Advanced Domain Intelligence Gathering
Provides comprehensive WHOIS information, DNS records, and domain security analysis
"""

import requests
from colorama import Fore, Style, init
import json
import logging
from datetime import datetime
import socket
from urllib.parse import urlparse
import dns.resolver
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class WhoisInfo:
    """Data structure for WHOIS information"""
    domain: str
    registrar: str
    created_date: str
    expires_date: str
    updated_date: str
    registrant_country: str
    registrant_email: str
    nameservers: List[str]
    ip_address: str
    dns_records: Dict
    security_issues: List[str]
    historical_data: Dict


class WHOISLookup:
    """Advanced WHOIS and domain information gathering"""
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.domain = self._extract_domain(target)
        self.results = {
            'domain': self.domain,
            'whois_data': {},
            'dns_records': {},
            'ip_info': {},
            'security_analysis': [],
            'findings': []
        }
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Security Scanner)'})
        
    def _extract_domain(self, target: str) -> str:
        """Extract domain from various formats"""
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]
        return domain.split(':')[0]
    
    def lookup_whois_api(self) -> Dict:
        """Fetch WHOIS data from multiple APIs with fallback"""
        apis = [
            f"https://api.ip2whois.com/v2?key=demo&domain={self.domain}",
            f"https://www.whoisxmlapi.com/api/gateway?apikey=at_LCwxDvzpXxNJK0tM7iHp9EsqJvbqF&domain={self.domain}&outputFormat=JSON",
        ]
        
        for api_url in apis:
            try:
                response = self.session.get(api_url, timeout=8)
                if response.status_code == 200:
                    logger.info(f"Successfully fetched WHOIS from {api_url.split('/')[2]}")
                    return response.json()
            except Exception as e:
                logger.warning(f"API failed: {e}")
                continue
        
        return self._parse_whois_text()
    
    def _parse_whois_text(self) -> Dict:
        """Fallback to text-based WHOIS query"""
        try:
            import whois
            w = whois.whois(self.domain)
            return {
                'domain': str(w.domain),
                'registrar': str(w.registrar) if w.registrar else 'N/A',
                'create_date': str(w.creation_date) if w.creation_date else 'N/A',
                'expire_date': str(w.expiration_date) if w.expiration_date else 'N/A',
                'updated_date': str(w.updated_date) if w.updated_date else 'N/A',
                'nameservers': list(w.nameservers) if w.nameservers else [],
                'registrant_email': str(w.registrant_email) if hasattr(w, 'registrant_email') else 'N/A'
            }
        except Exception as e:
            logger.error(f"WHOIS text parsing failed: {e}")
            return {}
    
    def dns_enumeration(self) -> Dict:
        """Comprehensive DNS record enumeration"""
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=3)
                dns_records[rtype] = [str(rdata) for rdata in answers]
            except Exception as e:
                if self.verbose:
                    logger.debug(f"DNS {rtype} query failed: {e}")
        
        return dns_records
    
    def resolve_ip(self) -> str:
        """Resolve domain to IP address"""
        try:
            ip = socket.gethostbyname(self.domain)
            logger.info(f"Domain resolves to: {ip}")
            return ip
        except Exception as e:
            logger.warning(f"IP resolution failed: {e}")
            return "N/A"
    
    def get_ip_reputation(self, ip: str) -> Dict:
        """Check IP reputation and geolocation"""
        try:
            response = self.session.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.warning(f"IP reputation check failed: {e}")
        return {}
    
    def security_analysis(self, whois_data: Dict, dns_data: Dict) -> List[str]:
        """Perform security checks on domain"""
        issues = []
        
        # Check domain age
        try:
            if 'create_date' in whois_data:
                created = datetime.fromisoformat(str(whois_data['create_date']))
                age_days = (datetime.now() - created).days
                if age_days < 30:
                    issues.append(f"[WARNING] Domain is very new ({age_days} days old)")
                elif age_days < 365:
                    issues.append(f"[WARNING] Domain is relatively new ({age_days} days old)")
        except:
            pass
        
        # Check nameservers
        if 'NS' in dns_data:
            ns_count = len(dns_data['NS'])
            if ns_count < 2:
                issues.append(f"[WARNING] Only {ns_count} nameserver(s) found (minimum 2 recommended)")
        
        # Check MX records
        if 'MX' not in dns_data or not dns_data.get('MX'):
            issues.append("[ALERT] No MX records found - mail delivery issues likely")
        
        # Check SPF
        spf_found = any('v=spf1' in txt for txt in dns_data.get('TXT', []))
        if not spf_found:
            issues.append("[ALERT] No SPF record found - vulnerable to email spoofing")
        
        return issues
    
    def generate_report(self) -> Dict:
        """Generate comprehensive WHOIS report"""
        print(f"\n{Fore.CYAN}[*] WHOIS Lookup for {self.domain}{Style.RESET_ALL}")
        print("=" * 60)
        
        # Perform lookups
        whois_data = self.lookup_whois_api()
        dns_data = self.dns_enumeration()
        ip_addr = self.resolve_ip()
        ip_info = self.get_ip_reputation(ip_addr)
        security_issues = self.security_analysis(whois_data, dns_data)
        
        # Store results
        self.results['whois_data'] = whois_data
        self.results['dns_records'] = dns_data
        self.results['ip_info'] = ip_info
        self.results['security_analysis'] = security_issues
        
        # Display results
        if whois_data:
            print(f"{Fore.BLUE}[Domain Information]{Style.RESET_ALL}")
            print(f"  Domain: {whois_data.get('domain', 'N/A')}")
            print(f"  Registrar: {whois_data.get('registrar', 'N/A')}")
            print(f"  Created: {whois_data.get('create_date', 'N/A')}")
            print(f"  Expires: {whois_data.get('expire_date', 'N/A')}")
            print(f"  Updated: {whois_data.get('updated_date', 'N/A')}")
        
        if dns_data:
            print(f"\n{Fore.BLUE}[DNS Records]{Style.RESET_ALL}")
            for rtype, records in dns_data.items():
                print(f"  {rtype}: {', '.join(records)}")
        
        print(f"\n{Fore.BLUE}[IP Information]{Style.RESET_ALL}")
        print(f"  IP: {ip_addr}")
        if ip_info:
            print(f"  Location: {ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')}")
            print(f"  ISP: {ip_info.get('org', 'N/A')}")
        
        if security_issues:
            print(f"\n{Fore.RED}[Security Findings]{Style.RESET_ALL}")
            for issue in security_issues:
                print(f"  {issue}")
                self.results['findings'].append(issue)
        
        return self.results


def whois_lookup(target: str, verbose: bool = False) -> Dict:
    """Main function for WHOIS lookup"""
    try:
        lookup = WHOISLookup(target, verbose)
        results = lookup.generate_report()
        
        # Save report
        filename = f"whois_{lookup.domain.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        
        return results
    except Exception as e:
        logger.error(f"WHOIS lookup failed: {e}")
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        return {}