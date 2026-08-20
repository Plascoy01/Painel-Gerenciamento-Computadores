"""Subdomain Enumeration Module
Comprehensive subdomain discovery using DNS resolution, API queries, and certificate transparency
"""

import requests
from colorama import Fore, Style, init
import logging
import json
import time
from typing import List, Dict, Set
import dns.resolver
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Advanced subdomain enumeration with multiple techniques"""
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target.replace('http://', '').replace('https://', '').split('/')[0]
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.found_subdomains: Set[str] = set()
        
        # Comprehensive subdomain wordlist
        self.subdomain_list = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'app', 'blog',
            'shop', 'store', 'news', 'forum', 'support', 'help', 'docs', 'wiki',
            'staging', 'beta', 'demo', 'portal', 'secure', 'login', 'auth',
            'cdn', 'backup', 'database', 'server', 'vpn', 'intranet', 'extranet',
            'mail2', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'ns3', 'dns',
            'webmail', 'cpanel', 'whm', 'virtualmin', 'plesk',
            'git', 'svn', 'jenkins', 'sonar', 'nexus', 'artifactory',
            'prometheus', 'grafana', 'kibana', 'elastic', 'logstash',
            'mysql', 'postgresql', 'mongodb', 'redis', 'memcached',
            'rabbitmq', 'kafka', 'zookeeper', 'hadoop', 'spark',
            'docker', 'kubernetes', 'swarm', 'consul', 'vault',
            'old', 'new', 'temp', 'tmp', 'test', 'sandbox', 'lab',
            'public', 'private', 'internal', 'external', 'corporate',
            'customer', 'partner', 'supplier', 'vendor', 'client',
            'production', 'development', 'testing', 'staging', 'qa',
            'analytics', 'metrics', 'monitoring', 'logging', 'audit',
            'security', 'compliance', 'legal', 'hr', 'finance',
            'sales', 'marketing', 'product', 'engineering', 'operations',
        ]
        
        self.results = {
            'target': self.target,
            'timestamp': time.time(),
            'subdomains': [],
            'resolved_ips': {},
            'total_found': 0,
            'enumeration_methods': []
        }
    
    def dns_enumeration(self) -> Set[str]:
        """Enumerate subdomains via DNS resolution"""
        found = set()
        print(f"{Fore.BLUE}[*] Performing DNS enumeration...{Style.RESET_ALL}")
        
        def check_subdomain(subdomain_name: str) -> bool:
            try:
                full_domain = f"{subdomain_name}.{self.target}"
                answers = dns.resolver.resolve(full_domain, 'A', lifetime=2)
                for rdata in answers:
                    ip = str(rdata)
                    print(f"{Fore.GREEN}[FOUND] {full_domain} -> {ip}{Style.RESET_ALL}")
                    self.results['resolved_ips'][full_domain] = ip
                    found.add(full_domain)
                return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception as e:
                if self.verbose:
                    logger.debug(f"DNS error for {subdomain_name}: {e}")
            return False
        
        # Use threading for faster enumeration
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in self.subdomain_list}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.debug(f"Threading error: {e}")
        
        self.results['enumeration_methods'].append('DNS Resolution')
        return found
    
    def certificate_transparency(self) -> Set[str]:
        """Enumerate subdomains using Certificate Transparency logs"""
        found = set()
        print(f"{Fore.BLUE}[*] Querying Certificate Transparency logs...{Style.RESET_ALL}")
        
        ct_apis = [
            f"https://crt.sh/?q=%25.{self.target}&output=json",
            f"https://certspotter.com/api/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names",
        ]
        
        for api_url in ct_apis:
            try:
                response = self.session.get(api_url, timeout=10)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            for item in data:
                                if 'name_value' in item:
                                    domains = item['name_value'].split('\n')
                                    for domain in domains:
                                        domain = domain.strip('*.').strip()
                                        if domain.endswith(self.target):
                                            found.add(domain)
                                            print(f"{Fore.GREEN}[CT] {domain}{Style.RESET_ALL}")
                    except:
                        pass
            except Exception as e:
                logger.debug(f"CT API error: {e}")
        
        if found:
            self.results['enumeration_methods'].append('Certificate Transparency')
        return found
    
    def api_enumeration(self) -> Set[str]:
        """Enumerate subdomains using API services"""
        found = set()
        print(f"{Fore.BLUE}[*] Querying DNS API services...{Style.RESET_ALL}")
        
        apis = [
            f"https://api.hackertarget.com/hostsearch/?q={self.target}",
            f"https://api.threatminer.org/v2/domain.php?q={self.target}&rt=5",
        ]
        
        for api_url in apis:
            try:
                response = self.session.get(api_url, timeout=10)
                if response.status_code == 200:
                    # Parse different API response formats
                    lines = response.text.split('\n')
                    for line in lines:
                        if self.target in line:
                            parts = line.split(',')
                            domain = parts[0].strip()
                            if domain.endswith(self.target) and domain not in found:
                                found.add(domain)
                                print(f"{Fore.GREEN}[API] {domain}{Style.RESET_ALL}")
            except Exception as e:
                logger.debug(f"API enumeration error: {e}")
        
        if found:
            self.results['enumeration_methods'].append('DNS APIs')
        return found
    
    def reverse_dns_lookup(self) -> Set[str]:
        """Perform reverse DNS lookups"""
        found = set()
        print(f"{Fore.BLUE}[*] Performing reverse DNS lookups...{Style.RESET_ALL}")
        
        try:
            # Get main domain IP
            main_ip = socket.gethostbyname(self.target)
            print(f"{Fore.BLUE}[*] Main domain IP: {main_ip}{Style.RESET_ALL}")
            
            # Try reverse DNS
            try:
                reverse_info = socket.gethostbyaddr(main_ip)
                if reverse_info[0] != self.target:
                    found.add(reverse_info[0])
                    print(f"{Fore.GREEN}[Reverse] {reverse_info[0]}{Style.RESET_ALL}")
            except:
                pass
        except Exception as e:
            logger.debug(f"Reverse DNS error: {e}")
        
        if found:
            self.results['enumeration_methods'].append('Reverse DNS')
        return found
    
    def generate_report(self) -> Dict:
        """Generate comprehensive subdomain enumeration report"""
        print(f"\n{Fore.CYAN}[*] Subdomain Enumeration Report for {self.target}{Style.RESET_ALL}")
        print("=" * 60)
        
        # Run all enumeration methods
        dns_subs = self.dns_enumeration()
        ct_subs = self.certificate_transparency()
        api_subs = self.api_enumeration()
        reverse_subs = self.reverse_dns_lookup()
        
        # Combine results
        all_subdomains = dns_subs | ct_subs | api_subs | reverse_subs
        self.found_subdomains = all_subdomains
        
        # Update results
        self.results['subdomains'] = sorted(list(all_subdomains))
        self.results['total_found'] = len(all_subdomains)
        
        # Display summary
        print(f"\n{Fore.BLUE}[*] Summary:{Style.RESET_ALL}")
        print(f"  Total Subdomains Found: {len(all_subdomains)}")
        print(f"  Enumeration Methods Used: {', '.join(self.results['enumeration_methods'])}")
        
        return self.results


def subdomain_enum(target: str, verbose: bool = False) -> Dict:
    """Main subdomain enumeration function"""
    try:
        enumerator = SubdomainEnumerator(target, verbose)
        results = enumerator.generate_report()
        
        # Save results
        filename = f"subdomain_enum_{enumerator.target.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        return results
    except Exception as e:
        logger.error(f"Subdomain enumeration failed: {e}")
        return {'error': str(e)}