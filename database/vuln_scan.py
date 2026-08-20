"""General Vulnerability Scanner Module - 300+ Lines"""
import requests, logging, json, time, socket, ssl, re
from colorama import Fore, Style, init
from typing import Dict, List

init(autoreset=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GeneralVulnerabilityScanner:
    def __init__(self, target: str, verbose: bool = False):
        self.target = target if target.startswith(('http://', 'https://')) else f"https://{target}"
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Security Scanner)'})
        self.vulnerabilities = []
        self.results = {'target': self.target, 'timestamp': time.time(), 'vulnerabilities': [], 'port_issues': [], 'web_issues': [], 'ssl_issues': [], 'header_issues': []}
    
    def check_open_ports_vulns(self, ports: List[int] = None) -> Dict:
        ports = ports or [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
        vuln_ports = {21: ('FTP', 'Critical', 'Anonymous login'), 23: ('Telnet', 'Critical', 'Use SSH'), 25: ('SMTP', 'High', 'Open relay'), 53: ('DNS', 'High', 'Zone transfer'), 80: ('HTTP', 'Medium', 'HSTS'), 110: ('POP3', 'High', 'Use POP3S'), 135: ('RPC', 'Critical', 'RCE'), 139: ('NetBIOS', 'High', 'Share enum'), 143: ('IMAP', 'High', 'Use IMAPS'), 443: ('HTTPS', 'Low', 'Check certs'), 445: ('SMB', 'Critical', 'RCE/data theft'), 1433: ('MSSQL', 'Critical', 'Default creds'), 3306: ('MySQL', 'Critical', 'Weak passwords'), 3389: ('RDP', 'Critical', 'High value'), 5432: ('PostgreSQL', 'Critical', 'Check creds'), 6379: ('Redis', 'Critical', 'No auth'), 8080: ('HTTP-ALT', 'High', 'Encryption'), 9200: ('Elasticsearch', 'Critical', 'Exposed'), 27017: ('MongoDB', 'Critical', 'Misconfigured')}
        host = self.target.replace('http://', '').replace('https://', '').split('/')[0]
        print(f"{Fore.BLUE}[*] Checking open ports vulnerabilities...{Style.RESET_ALL}")
        port_results = {}
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service, severity, issue = vuln_ports.get(port, ('Unknown', 'Low', 'Unknown'))
                    port_results[port] = {'service': service, 'severity': severity, 'issue': issue}
                    print(f"{Fore.RED}[!] Port {port} ({service}) OPEN - {severity}{Style.RESET_ALL}")
                    self.vulnerabilities.append({'type': f'Open Port: {service}', 'port': port, 'severity': severity, 'description': issue})
                sock.close()
            except Exception as e:
                logger.debug(f"Port check error: {e}")
        self.results['port_issues'] = port_results
        return port_results
    
    def check_web_vulns(self) -> Dict:
        print(f"{Fore.BLUE}[*] Checking for exposed files and directories...{Style.RESET_ALL}")
        sensitive_paths = [('/crossdomain.xml', 'Flash policy'), ('/robots.txt', 'Robots disclosure'), ('/sitemap.xml', 'Sitemap'), ('/.git/', 'Git exposure'), ('/.env', 'Environment variables'), ('/admin/', 'Admin panel'), ('/wp-admin/', 'WordPress admin'), ('/phpinfo.php', 'PHP info'), ('/config.php', 'Configuration'), ('/backup/', 'Backup files'), ('/upload/', 'Upload directory')]
        web_results = {}
        for path, desc in sensitive_paths:
            try:
                url = self.target.rstrip('/') + path
                response = self.session.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    severity = 'Critical' if 'env' in path.lower() or 'config' in path.lower() else 'High'
                    print(f"{Fore.RED}[!] Exposed: {path} ({response.status_code}){Style.RESET_ALL}")
                    web_results[path] = {'status': response.status_code, 'desc': desc, 'severity': severity}
                    self.vulnerabilities.append({'type': 'Exposed File', 'path': path, 'severity': severity, 'description': desc})
            except Exception as e:
                logger.debug(f"Web check error: {e}")
        self.results['web_issues'] = web_results
        return web_results
    
    def check_ssl_tls(self) -> Dict:
        print(f"{Fore.BLUE}[*] Checking SSL/TLS configuration...{Style.RESET_ALL}")
        host = self.target.replace('http://', '').replace('https://', '').split('/')[0]
        ssl_results = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, 443), timeout=5)
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert and cert.get('subject') == cert.get('issuer'):
                    print(f"{Fore.RED}[!] Self-signed certificate detected{Style.RESET_ALL}")
                    self.vulnerabilities.append({'type': 'SSL Issue', 'issue': 'Self-signed cert', 'severity': 'Medium'})
                ssl_results = {'has_cert': cert is not None}
        except Exception as e:
            logger.debug(f"SSL check error: {e}")
        self.results['ssl_issues'] = ssl_results
        return ssl_results
    
    def check_security_headers(self) -> Dict:
        print(f"{Fore.BLUE}[*] Checking security headers...{Style.RESET_ALL}")
        required_headers = {'Strict-Transport-Security': 'Critical', 'X-Frame-Options': 'High', 'X-Content-Type-Options': 'High', 'Content-Security-Policy': 'High', 'X-XSS-Protection': 'Medium'}
        header_results = {}
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            headers = response.headers
            for header, severity in required_headers.items():
                if header not in headers:
                    print(f"{Fore.YELLOW}[!] Missing header: {header}{Style.RESET_ALL}")
                    header_results[header] = 'Missing'
                    self.vulnerabilities.append({'type': 'Missing Header', 'header': header, 'severity': severity})
                else:
                    header_results[header] = headers[header][:50]
        except Exception as e:
            logger.debug(f"Header check error: {e}")
        self.results['header_issues'] = header_results
        return header_results
    
    def generate_report(self) -> Dict:
        print(f"\n{Fore.CYAN}[*] General Vulnerability Scan{Style.RESET_ALL}")
        print("=" * 60)
        self.check_open_ports_vulns()
        self.check_web_vulns()
        self.check_ssl_tls()
        self.check_security_headers()
        self.results['vulnerabilities'] = self.vulnerabilities
        self.results['total_found'] = len(self.vulnerabilities)
        critical = [v for v in self.vulnerabilities if v.get('severity') == 'Critical']
        high = [v for v in self.vulnerabilities if v.get('severity') == 'High']
        print(f"\n{Fore.BLUE}[*] Summary:{Style.RESET_ALL}")
        print(f"  Total Issues: {len(self.vulnerabilities)}")
        print(f"  Critical: {len(critical)}")
        print(f"  High: {len(high)}")
        return self.results

def vuln_scan(target: str, verbose: bool = False) -> Dict:
    try:
        scanner = GeneralVulnerabilityScanner(target, verbose)
        results = scanner.generate_report()
        filename = f"vuln_scan_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        return results
    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
        return {'error': str(e)}
