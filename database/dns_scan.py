#!/usr/bin/env python3
"""
Comprehensive DNS Enumeration and Analysis Scanner

Performs advanced DNS reconnaissance including:
- IP resolution and reverse DNS
- DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, etc.)
- Wildcard detection
- Subdomain enumeration
- Zone transfer attacks
- DNS security analysis
- DNSSEC validation

Author: Plascoy Security
Version: 2.0
"""

import dns.resolver
import dns.query
import dns.zone
import dns.dnssec
import dns.rdatatype
import socket
import concurrent.futures
import time
import logging
from typing import List, Dict, Set, Optional, Tuple
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DNSScanner:
    """Professional DNS enumeration scanner"""
    
    def __init__(self, target_domain: str, timeout: int = 5, verbose: bool = False):
        """
        Initialize DNS scanner
        
        Args:
            target_domain: Target domain name
            timeout: DNS query timeout
            verbose: Enable verbose output
        """
        self.domain = target_domain
        self.timeout = timeout
        self.verbose = verbose
        
        self.results = {
            'domain': target_domain,
            'ip': None,
            'reverse_dns': None,
            'dns_records': {},
            'wildcard_detected': False,
            'zone_transfer': None,
            'subdomains': [],
            'errors': [],
            'mx_records': [],
            'cname_records': [],
            'txt_records': [],
            'ptr_records': [],
            'ns_records': [],
            'soa_record': None,
            'srv_records': [],
            'caa_records': [],
            'spf_records': [],
            'tlsa_records': [],
            'ttl_info': {},
            'dnssec_valid': False,
            'suspicious_patterns': [],
            'scan_time': 0
        }
        
        # Comprehensive subdomain list
        self.common_subdomains = [
            # Web
            "www", "web", "m", "mobile", "app",
            # Mail
            "mail", "email", "imap", "smtp", "pop", "pop3",
            # FTP
            "ftp", "sftp", "ftps",
            # Dev/Test
            "dev", "development", "test", "staging", "stage", "qa", "uat",
            "beta", "sandbox", "demo",
            # DNS
            "ns1", "ns2", "ns3", "ns4", "dns1", "dns2",
            # Admin/Backend
            "admin", "administrator", "cpanel", "plesk", "webmail", "whm",
            # APIs
            "api", "api-v1", "api-v2", "api.v1", "api.v2", "rest", "graphql",
            # VPN/Remote
            "vpn", "openvpn", "wireguard", "remote", "rdp",
            # CDN/Static
            "cdn", "cdn1", "cdn2", "static", "assets", "img", "images",
            # Cloud
            "s3", "azure", "gcs", "cloud", "aws",
            # Services
            "git", "gitlab", "github", "jenkins", "docker",
            "elastic", "elasticsearch", "kibana", "logstash",
            "prometheus", "grafana", "influxdb", "telegraf",
            # Databases
            "db", "database", "mysql", "postgresql", "postgres", "mariadb",
            "mongo", "mongodb", "redis", "memcached",
            # Infrastructure
            "kubernetes", "k8s", "consul", "vault", "etcd",
            # Monitoring
            "nagios", "icinga", "zabbix", "newrelic", "datadog",
            # Documentation
            "doc", "docs", "help", "wiki", "knowledge", "kb",
            # Files/Backup
            "file", "files", "download", "backup", "bak", "archive",
            "old", "data", "shared", "public",
            # Shop
            "shop", "store", "ecommerce", "cart", "checkout",
            # Blog/Content
            "blog", "news", "press", "media",
            # Other common
            "portal", "dashboard", "control", "panel", "forum", "chat"
        ]
        
        self.dns_record_types = [
            "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA",
            "SRV", "PTR", "CAA", "TLSA", "SPF", "SSHFP",
            "DS", "DNSKEY", "NSEC", "NSEC3", "RRSIG",
            "HTTPS", "SVCB", "HINFO", "RP", "NAPTR"
        ]
    
    def scan_all(self, verbose: bool = False) -> Dict:
        """Run comprehensive DNS scan"""
        print(Fore.CYAN + Style.BRIGHT + "\n[*] DNS Enumeration Scanner Starting...")
        print(Fore.CYAN + f"[*] Target Domain: {self.domain}")
        
        start_time = time.time()
        
        # Run scans in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = {
                executor.submit(self._get_ip): "IP Resolution",
                executor.submit(self._dns_records): "DNS Records Enumeration",
                executor.submit(self._wildcard_test): "Wildcard Test",
                executor.submit(self._subdomain_enum): "Subdomain Enumeration",
                executor.submit(self._zone_transfer): "Zone Transfer Test",
                executor.submit(self._mx_records): "MX Records",
                executor.submit(self._cname_records): "CNAME Records",
                executor.submit(self._txt_records): "TXT Records",
                executor.submit(self._ns_records): "NS Records",
                executor.submit(self._soa_record): "SOA Record",
                executor.submit(self._srv_records): "SRV Records",
                executor.submit(self._caa_records): "CAA Records",
                executor.submit(self._spf_records): "SPF Records",
                executor.submit(self._ttl_info): "TTL Information",
                executor.submit(self._analyze_security): "Security Analysis"
            }
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    task_name = futures.get(future, "Unknown")
                    error_msg = f"Error in {task_name}: {str(e)}"
                    logger.error(error_msg)
                    self.results['errors'].append(error_msg)
        
        self.results['scan_time'] = time.time() - start_time
        self._print_summary()
        
        return self.results
    
    def _get_ip(self) -> bool:
        """Get IP address and reverse DNS lookup"""
        try:
            ip = socket.gethostbyname(self.domain)
            self.results['ip'] = ip
            print(Fore.GREEN + f"[+] IP Address: {ip}")
            
            try:
                reverse = socket.gethostbyaddr(ip)
                self.results['reverse_dns'] = reverse[0]
                print(Fore.GREEN + f"[+] Reverse DNS: {reverse[0]}")
            except socket.herror:
                if self.verbose:
                    logger.debug(f"No reverse DNS found for {ip}")
                    
            return True
        except socket.gaierror as e:
            error_msg = f"Could not resolve IP for {self.domain}"
            logger.error(error_msg)
            print(Fore.RED + f"[!] {error_msg}")
            self.results['errors'].append(error_msg)
            return False
    
    def _dns_records(self) -> bool:
        """Enumerate various DNS records"""
        found_records = 0
        for record_type in self.dns_record_types[:10]:  # Limit for performance
            try:
                answers = dns.resolver.resolve(self.domain, record_type, lifetime=self.timeout)
                self.results['dns_records'][record_type] = [
                    r.to_text() for r in answers
                ]
                found_records += 1
                if self.verbose:
                    print(Fore.BLUE + f"[*] Found {record_type} records")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                logger.debug(f"Error resolving {record_type}: {str(e)}")
        
        print(Fore.GREEN + f"[+] DNS Records: {found_records} types found")
        return True
    
    def _wildcard_test(self) -> bool:
        """Test for wildcard DNS configuration"""
        test = f"randomtest{int(time.time())}.{self.domain}"
        try:
            ip = socket.gethostbyname(test)
            self.results['wildcard_detected'] = True
            print(Fore.YELLOW + f"[!] Wildcard DNS detected: {test} -> {ip}")
            return True
        except socket.gaierror:
            if self.verbose:
                print(Fore.GREEN + "[+] No wildcard DNS detected")
            return False
    
    def _subdomain_enum(self) -> bool:
        """Enumerate common subdomains"""
        print(Fore.BLUE + "[*] Enumerating subdomains...")
        found = 0
        
        def resolve(subdomain):
            target = f"{subdomain}.{self.domain}"
            try:
                ip = socket.gethostbyname(target)
                self.results['subdomains'].append((target, ip))
                print(Fore.GREEN + f"[+] Found: {target} -> {ip}")
                return True
            except socket.gaierror:
                return False
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(resolve, self.common_subdomains)
            found = sum(results)
        
        print(Fore.GREEN + f"[+] Subdomains found: {found}")
        return True
    
    def _zone_transfer(self) -> bool:
        """Attempt zone transfer from nameservers"""
        try:
            ns_records = dns.resolver.resolve(self.domain, "NS", lifetime=self.timeout)
            ns_list = [str(ns).rstrip(".") for ns in ns_records]
            
            for ns in ns_list[:5]:  # Test first 5 NS
                logger.info(f"Testing zone transfer against {ns}")
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns, self.domain, timeout=self.timeout)
                    )
                    self.results['zone_transfer'] = {
                        'nameserver': ns,
                        'records_count': len(list(zone.nodes.keys())),
                        'status': 'vulnerable'
                    }
                    print(Fore.RED + Style.BRIGHT + f"[!] Zone transfer successful from {ns}!")
                    return True
                except Exception as e:
                    logger.debug(f"Zone transfer failed from {ns}: {str(e)}")
            
            self.results['zone_transfer'] = {'status': 'protected'}
            if self.verbose:
                print(Fore.GREEN + "[+] Zone transfer protected")
            return False
        except Exception as e:
            logger.error(f"Error in zone transfer test: {str(e)}")
            return False
    
    def _mx_records(self) -> bool:
        """Parse MX records"""
        try:
            mx_answers = dns.resolver.resolve(self.domain, "MX", lifetime=self.timeout)
            for mx in mx_answers:
                self.results['mx_records'].append({
                    'priority': mx.preference,
                    'exchange': str(mx.exchange).rstrip(".")
                })
            
            if self.results['mx_records']:
                print(Fore.GREEN + f"[+] MX Records: {len(self.results['mx_records'])} found")
        except Exception as e:
            logger.debug(f"Error getting MX records: {str(e)}")
        return True
    
    def _cname_records(self) -> bool:
        """Parse CNAME records"""
        try:
            cname_answers = dns.resolver.resolve(self.domain, "CNAME", lifetime=self.timeout)
            for cname in cname_answers:
                self.results['cname_records'].append(str(cname.target).rstrip("."))
            
            if self.results['cname_records']:
                print(Fore.GREEN + f"[+] CNAME Records: {len(self.results['cname_records'])} found")
        except Exception as e:
            logger.debug(f"Error getting CNAME records: {str(e)}")
        return True
    
    def _txt_records(self) -> bool:
        """Parse TXT records"""
        try:
            txt_answers = dns.resolver.resolve(self.domain, "TXT", lifetime=self.timeout)
            for txt in txt_answers:
                record_text = txt.to_text()
                self.results['txt_records'].append(record_text)
                
                # Check for security indicators
                if 'v=spf1' in record_text:
                    print(Fore.BLUE + f"[*] SPF Record found")
                if 'dkim' in record_text.lower():
                    print(Fore.BLUE + f"[*] DKIM Record found")
                if 'dmarc' in record_text.lower():
                    print(Fore.BLUE + f"[*] DMARC Record found")
            
            if self.results['txt_records']:
                print(Fore.GREEN + f"[+] TXT Records: {len(self.results['txt_records'])} found")
        except Exception as e:
            logger.debug(f"Error getting TXT records: {str(e)}")
        return True
    
    def _ns_records(self) -> bool:
        """Parse NS records"""
        try:
            ns_answers = dns.resolver.resolve(self.domain, "NS", lifetime=self.timeout)
            for ns in ns_answers:
                self.results['ns_records'].append(str(ns.target).rstrip("."))
            
            print(Fore.GREEN + f"[+] NS Records: {len(self.results['ns_records'])} found")
        except Exception as e:
            logger.error(f"Error getting NS records: {str(e)}")
        return True
    
    def _soa_record(self) -> bool:
        """Parse SOA record"""
        try:
            soa_answers = dns.resolver.resolve(self.domain, "SOA", lifetime=self.timeout)
            for soa in soa_answers:
                self.results['soa_record'] = {
                    'mname': str(soa.mname).rstrip("."),
                    'rname': str(soa.rname).rstrip("."),
                    'serial': soa.serial,
                    'refresh': soa.refresh,
                    'retry': soa.retry,
                    'expire': soa.expire,
                    'minimum': soa.minimum
                }
                print(Fore.GREEN + "[+] SOA Record retrieved")
        except Exception as e:
            logger.debug(f"Error getting SOA record: {str(e)}")
        return True
    
    def _srv_records(self) -> bool:
        """Parse SRV records"""
        try:
            srv_answers = dns.resolver.resolve(self.domain, "SRV", lifetime=self.timeout)
            for srv in srv_answers:
                self.results['srv_records'].append({
                    'priority': srv.priority,
                    'weight': srv.weight,
                    'port': srv.port,
                    'target': str(srv.target).rstrip(".")
                })
            
            if self.results['srv_records']:
                print(Fore.GREEN + f"[+] SRV Records: {len(self.results['srv_records'])} found")
        except Exception as e:
            logger.debug(f"Error getting SRV records: {str(e)}")
        return True
    
    def _caa_records(self) -> bool:
        """Parse CAA records"""
        try:
            caa_answers = dns.resolver.resolve(self.domain, "CAA", lifetime=self.timeout)
            for caa in caa_answers:
                self.results['caa_records'].append({
                    'flags': caa.flags,
                    'tag': caa.tag.to_text(),
                    'value': caa.value.to_text()
                })
            
            if self.results['caa_records']:
                print(Fore.GREEN + f"[+] CAA Records: {len(self.results['caa_records'])} found")
        except Exception as e:
            logger.debug(f"Error getting CAA records: {str(e)}")
        return True
    
    def _spf_records(self) -> bool:
        """Parse SPF records"""
        try:
            spf_answers = dns.resolver.resolve(self.domain, "SPF", lifetime=self.timeout)
            for spf in spf_answers:
                self.results['spf_records'].append(spf.to_text())
                print(Fore.GREEN + "[+] SPF Record found")
        except Exception as e:
            logger.debug(f"Error getting SPF records: {str(e)}")
        return True
    
    def _ttl_info(self) -> bool:
        """Collect TTL information"""
        try:
            a_records = dns.resolver.resolve(self.domain, "A", lifetime=self.timeout)
            for record in a_records:
                ttl = record.ttl
                self.results['ttl_info'][ttl] = self.results['ttl_info'].get(ttl, 0) + 1
        except Exception:
            pass
        
        try:
            aaaa_records = dns.resolver.resolve(self.domain, "AAAA", lifetime=self.timeout)
            for record in aaaa_records:
                ttl = record.ttl
                self.results['ttl_info'][ttl] = self.results['ttl_info'].get(ttl, 0) + 1
        except Exception:
            pass
        
        return True
    
    def _analyze_security(self) -> bool:
        """Analyze DNS security aspects"""
        # Check for security indicators
        if self.results['caa_records']:
            print(Fore.GREEN + "[+] CAA records configured (good)")
        else:
            print(Fore.YELLOW + "[!] No CAA records (allows all CAs to issue)")
            self.results['suspicious_patterns'].append("Missing CAA records")
        
        # Check for DNSSEC
        if self.results['dns_records'].get('DS'):
            print(Fore.GREEN + "[+] DNSSEC appears configured")
        else:
            print(Fore.YELLOW + "[!] DNSSEC not detected")
        
        # Check zone transfer protection
        if self.results['zone_transfer'].get('status') == 'vulnerable':
            print(Fore.RED + "[!] Zone transfer enabled (vulnerability)")
            self.results['suspicious_patterns'].append("Zone transfer enabled")
        
        return True
    
    def _print_summary(self):
        """Print scan summary"""
        print(Fore.CYAN + Style.BRIGHT + "\n[*] DNS Enumeration Summary")
        print(Fore.CYAN + f"[*] Domain: {self.domain}")
        print(Fore.CYAN + f"[*] Scan time: {self.results['scan_time']:.2f}s")
        
        if self.results['ip']:
            print(Fore.CYAN + f"\n[IP] {self.results['ip']}")
        
        # Record summary
        total_records = sum(len(v) for k, v in self.results['dns_records'].items())
        print(Fore.BLUE + f"\n[DNS Records] {total_records} records found")
        
        if self.results['subdomains']:
            print(Fore.BLUE + f"[Subdomains] {len(self.results['subdomains'])} found")
        
        if self.results['errors']:
            print(Fore.YELLOW + f"\n[Errors] {len(self.results['errors'])} errors occurred")



def scan_dns(domain: str, timeout: int = 5, verbose: bool = False) -> Dict:
    """
    Wrapper function for backwards compatibility
    
    Args:
        domain: Target domain
        timeout: DNS query timeout
        verbose: Enable verbose output
        
    Returns:
        Dictionary with scan results
    """
    scanner = DNSScanner(domain, timeout=timeout, verbose=verbose)
    return scanner.scan_all(verbose=verbose)


def print_results(results: Dict):
    """Print formatted DNS scan results"""
    print(Fore.CYAN + Style.BRIGHT + "\n" + "="*70)
    print("DNS ENUMERATION RESULTS")
    print("="*70 + "\n")
    
    # IP Information
    print(Fore.BLUE + Style.BRIGHT + "[IP RESOLUTION]")
    if results.get('ip'):
        print(Fore.BLUE + f"  Domain: {results.get('domain')}")
        print(Fore.GREEN + f"  IP Address: {results['ip']}")
        if results.get('reverse_dns'):
            print(Fore.GREEN + f"  Reverse DNS: {results['reverse_dns']}")
    else:
        print(Fore.RED + "  IP resolution failed")
    
    # Wildcard Detection
    if results.get('wildcard_detected'):
        print(Fore.YELLOW + "\n[!] Wildcard DNS Detected")
    
    # DNS Records Summary
    print(Fore.BLUE + Style.BRIGHT + "\n[DNS RECORDS]")
    if results.get('dns_records'):
        for record_type, records in results['dns_records'].items():
            if records:
                print(Fore.BLUE + f"  {record_type}: {len(records)} record(s)")
    
    # MX Records
    if results.get('mx_records'):
        print(Fore.BLUE + Style.BRIGHT + "\n[MX RECORDS]")
        for mx in results['mx_records']:
            print(Fore.BLUE + f"  Priority {mx['priority']}: {mx['exchange']}")
    
    # Subdomains Found
    if results.get('subdomains'):
        print(Fore.BLUE + Style.BRIGHT + f"\n[SUBDOMAINS] ({len(results['subdomains'])} found)")
        for subdomain, ip in results['subdomains'][:10]:
            print(Fore.GREEN + f"  {subdomain}: {ip}")
        if len(results['subdomains']) > 10:
            print(Fore.BLUE + f"  ... and {len(results['subdomains']) - 10} more")
    
    # Security Analysis
    if results.get('suspicious_patterns'):
        print(Fore.RED + Style.BRIGHT + "\n[SECURITY ISSUES]")
        for pattern in results['suspicious_patterns']:
            print(Fore.RED + f"  [!] {pattern}")
    
    # Scan Statistics
    print(Fore.CYAN + Style.BRIGHT + "\n[SCAN STATISTICS]")
    print(Fore.CYAN + f"  Scan Duration: {results.get('scan_time', 0):.2f} seconds")
    print(Fore.CYAN + f"  Errors: {len(results.get('errors', []))}")
    
    print(Fore.CYAN + "\n" + "="*70 + "\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 dns_scan.py <domain> [--verbose]")
        sys.exit(1)
    
    domain = sys.argv[1]
    verbose = '--verbose' in sys.argv
    
    results = scan_dns(domain, verbose=verbose)
    print_results(results)
    
    print("\n[NS RECORDS]")
    if results['ns_records']:
        for ns in results['ns_records']:
            print(f"  {ns}")
    else:
        print("No NS records found")
    
    print("\n[SOA RECORD]")
    if results['soa_record']:
        soa = results['soa_record']
        print(f"  MNAME: {soa['mname']}")
        print(f"  RNAME: {soa['rname']}")
        print(f"  SERIAL: {soa['serial']}")
        print(f"  REFRESH: {soa['refresh']}")
        print(f"  RETRY: {soa['retry']}")
        print(f"  EXPIRE: {soa['expire']}")
        print(f"  MINIMUM: {soa['minimum']}")
    else:
        print("No SOA record found")
    
    print("\n[SRV RECORDS]")
    if results['srv_records']:
        for srv in results['srv_records']:
            print(f"  Priority: {srv['priority']}, Weight: {srv['weight']}, Port: {srv['port']}, Target: {srv['target']}")
    else:
        print("No SRV records found")
    
    print("\n[CAA RECORDS]")
    if results['caa_records']:
        for caa in results['caa_records']:
            print(f"  Flags: {caa['flags']}, Tag: {caa['tag']}, Value: {caa['value']}")
    else:
        print("No CAA records found")
    
    print("\n[SPF RECORDS]")
    if results['spf_records']:
        for spf in results['spf_records']:
            print(f"  {spf}")
    else:
        print("No SPF records found")
    
    print("\n[WILDCARD DNS]")
    print("Detected" if results['wildcard_detected'] else "Not detected")
    
    print("\n[SUBDOMAINS]")
    if results['subdomains']:
        for subdomain, ip in results['subdomains']:
            print(f"  {subdomain} -> {ip}")
    else:
        print("No subdomains found")
    
    print("\n[ZONE TRANSFER]")
    if results['zone_transfer']:
        status = results['zone_transfer']['status']
        if status == 'allowed':
            print(f"Zone transfer allowed from {results['zone_transfer']['nameserver']}")
            print(f"Records found: {len(results['zone_transfer']['records'])}")
        else:
            print("Zone transfer refused")
    else:
        print("Zone transfer test failed")
    
    print("\n[TTL INFORMATION]")
    if results['ttl_info']:
        print("TTL distribution:")
        for ttl, count in sorted(results['ttl_info'].items()):
            print(f"  {ttl}s: {count} records")
    else:
        print("No TTL information available")
    
    if results['errors']:
        print("\n[ERRORS]")
        for error in results['errors']:
            print(f"  {error}")

def main():
    parser = argparse.ArgumentParser(description='Advanced DNS Scanner')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-t', '--threads', type=int, default=40, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout in seconds')
    args = parser.parse_args()
    
    scanner = DNSScanner(args.domain)
    scanner.timeout = args.timeout
    results = scanner.scan_all()
    print_results(results)

if __name__ == "__main__":
    main()

# Export the function for plascoy.py
__all__ = ['scan_dns', '_zone_transfer']
