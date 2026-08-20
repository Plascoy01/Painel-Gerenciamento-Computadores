#!/usr/bin/env python3

import sys
import os
import time
import threading
from colorama import Fore, Style, init

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

# ---------------------------------
# PATH
# ---------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.join(BASE_DIR, "modules")

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, MODULES_DIR)

# ---------------------------------
# CORE IMPORTS
# ---------------------------------

try:
    from help import show_help
except Exception as e:
    print(Fore.RED + f"[IMPORT ERROR] help.py not loaded: {e}")
    sys.exit(1)

# Core scans are imported lazily to avoid hard-crash if any optional dependency is missing.
# plascoy.py will fail gracefully per-module when executed.

def _load_core(attr: str, fallback: str):
    try:
        mod = __import__(fallback, fromlist=[attr])
        return getattr(mod, attr)
    except Exception as e:
        print(Fore.YELLOW + f"[CORE NOT LOADED] {fallback}.{attr}: {e}")
        return None


# ---------------------------------
# OPTIONAL MODULE LOADER
# ---------------------------------

optional_modules = {}
scan_log = []

def load_optional(module, func):
    """Lazy load optional modules"""
    if func in optional_modules:
        return optional_modules[func]
    
    try:
        mod = __import__(module, fromlist=[func])
        optional_modules[func] = getattr(mod, func)
        return optional_modules[func]
    except Exception as e:
        optional_modules[func] = None
        print(Fore.RED + f"[DEBUG] Failed to load {func} from {module}: {e}")
        return None

def load_optional_multi(module, func):
    """Load optional module with specific function (for multi-function modules)"""
    if func in optional_modules:
        return optional_modules[func]
    
    try:
        mod = __import__(module, fromlist=[func])
        optional_modules[func] = getattr(mod, func)
        return optional_modules[func]
    except Exception as e:
        optional_modules[func] = None
        print(Fore.RED + f"[DEBUG] Failed to load {func} from {module}: {e}")
        return None


modules_list = {
    "modules.sqli_scan":"sqli_scan",
    "modules.xss_scan":"xss_scan",
    "modules.csrf_scan":"csrf_scan",
    "modules.lfi_rfi_scan":"lfi_rfi_scan",
    "modules.cmd_injection_scan":"cmd_injection_scan",
    "modules.open_redirect_scan":"open_redirect_scan",
    "modules.subdomain_enum":"subdomain_enum",
    "modules.whois_lookup":"whois_lookup",
    "modules.cve_checker":"cve_checker",
    "modules.file_upload_scan":"file_upload_scan",
    "modules.cors_scan":"cors_scan",
    "modules.host_header_scan":"host_header_scan",
    "modules.ssrf_scan":"ssrf_scan",
    "modules.xxe_scan":"xxe_scan",
    "modules.deserialization_scan":"deserialization_scan",
    "modules.api_scan":"api_scan",
    "modules.cms_scanner":"cms_scanner",
    "modules.os_fingerprint":"os_fingerprint",
    "modules.service_detect":"service_detect",
    "modules.firewall_detect":"firewall_detect",
    "modules.db_vuln_scan":"db_vuln_scan",
    # NEW MODULES (14 NEW SCANS)
    "modules.ssti_scan":"ssti_scan",
    "modules.idor_scan":"idor_scan",
    "modules.jwt_scan":"jwt_scan",
    "modules.http_methods_scan":"http_methods_scan",
    "modules.dir_listing_scan":"dir_listing_scan",
    "modules.backup_scan":"backup_scan",
    "modules.git_scan":"git_scan",
    "modules.env_scan":"env_scan",
    "modules.clickjacking_scan":"clickjacking_scan",
    "modules.cors_adv_scan":"cors_adv_scan",
    "modules.param_mining_scan":"param_mining_scan",
    "modules.js_analysis_scan":"js_analysis_scan",
    "modules.cookie_analysis_scan":"cookie_analysis_scan",
    "modules.report_gen":"report_gen"
}

# Special mapping for multiple functions in same module
multi_function_modules = {
    "robots_scan": ("modules.sitemap_robots_scan", "robots_scan"),
    "sitemap_scan": ("modules.sitemap_robots_scan", "sitemap_scan")
}

# Create reverse mapping for easy access
modules_by_func = {v: k for k, v in modules_list.items()}
modules_by_func.update(multi_function_modules)

# ---------------------------------
# BANNER
# ---------------------------------

def banner():
    banner_text = """          _                                                  
▓█████▄  ██▓    ▄▄▄        ██████  ▄████▄   ▒█████ ▓██   ██▓
▒██   █ ▓██▒   ▒████▄    ▒██    ▒ ▒██▀ ▀█  ▒██▒  ██▒▒██  ██▒
░█   ██ ▒██░   ▒██  ▀█▄  ░ ▓██▄   ▒▓█    ▄ ▒██░  ██▒ ▒██ ██░
░▓█▄█   ▒██░   ░██▄▄▄▄██   ▒   ██▒▒▓▓▄ ▄██▒▒██   ██░ ░ ▐██▓░
░▒█▓    ░██████▒▓█   ▓██▒▒██████▒▒▒ ▓███▀ ░░ ████▓▒░ ░ ██▒▓░
 ▒▒▓  ▒ ░ ▒░▓  ░▒▒   ▓▒█░▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▒░▒░   ██▒▒▒
 ░ ▒  ▒ ░ ░ ▒  ░ ▒   ▒▒ ░░ ░▒  ░ ░  ░  ▒     ░ ▒ ▒░ ▓██ ░▒░
 ░ ░  ░   ░ ░    ░   ▒   ░  ░  ░  ░        ░ ░ ░ ▒  ▒ ▒ ░░
   ░        ░  ░     ░  ░      ░  ░ ░          ░ ░  ░ ░
 ░                                   ░                 ░ ░ """
    
    print(Fore.CYAN + banner_text)

    print(Fore.BLUE + "═" * 65)

    print(
        Fore.YELLOW + Style.BRIGHT +
        "  PLASC0Y Security Framework"
    )

    print(
        Fore.GREEN +
        "  [+] created by: " +
        Fore.WHITE + "plascoy"
    )

    print(
        Fore.MAGENTA +
        "  [+] discord: " +
        Fore.WHITE + "plasco01"
    )

    print(
        Fore.CYAN +
        "  [+] status: " +
        Fore.GREEN + "online"
    )

    print(Fore.BLUE + "═" * 65 + "\n")
# ---------------------------------
# GET TARGET
# ---------------------------------

def get_target():

    if "-u" in sys.argv:
        try:
            return sys.argv[sys.argv.index("-u")+1]
        except:
            return None

    if "--url" in sys.argv:
        try:
            return sys.argv[sys.argv.index("--url")+1]
        except:
            return None

    return None


def normalize_target(target):
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target

# ---------------------------------
# SAFE RUN
# ---------------------------------

def run(name, func, target):

    print(Fore.MAGENTA + f"\n[{name}]")

    try:
        result = func(target)
        scan_log.append((name, result))
        return result
    except Exception as e:
        print(Fore.RED + f"{name} error: {e}")
        scan_log.append((name, None))
        return None

# ---------------------------------
# SCANS
# ---------------------------------

def run_scans(target):

    target = normalize_target(target)
    # Ensure modules that expect plain host/domain don't receive scheme+path
    parsed = None
    try:
        from urllib.parse import urlparse
        parsed = urlparse(target)
    except Exception:
        parsed = None

    # For many modules, only host/netloc is expected
    if parsed and parsed.netloc:
        host_for_modules = parsed.netloc
    else:
        host_for_modules = target

    print(Fore.GREEN + f"[TARGET] {target}")
    print(Fore.BLUE + "-"*50)

    # Use host/netloc for modules that build sessions based on domain.
    # Use full target for HTTP request based modules.
    modules_target = host_for_modules

    scan_tls_versions = _load_core('scan_tls_versions', 'modules.tls_scan')
    scan_real_session = _load_core('scan_real_session', 'modules.tls_scan')
    scan_ciphers = _load_core('scan_ciphers', 'modules.tls_scan')
    testssl_integration = _load_core('testssl_integration', 'modules.testssl_integration')
    port_scan = _load_core('port_scan', 'modules.port_scan')
    detect_tech = _load_core('detect_tech', 'modules.tech_detect')
    scan_headers = _load_core('scan_headers', 'modules.headers_scan')
    scan_dns = _load_core('scan_dns', 'modules.dns_scan')
    dir_brute = _load_core('dir_brute', 'modules.dir_brute')
    web_vuln_scan = _load_core('web_vuln_scan', 'modules.web_vuln_scan')
    vuln_scan = _load_core('vuln_scan', 'modules.vuln_scan')


    if "--tls" in sys.argv:
        print(Fore.MAGENTA + "\n[TLS SCAN]")
        scan_tls_versions(target,443)
        scan_real_session(target,443)
        scan_ciphers(target,443)

    if "--testssl" in sys.argv:
        testssl_integration(target, verbose="--verbose" in sys.argv)

    if "--ports" in sys.argv:
        run("PORT SCAN", port_scan, modules_target)

    if "--tech" in sys.argv:
        run("TECH DETECT", detect_tech, target)

    if "--headers" in sys.argv:
        run("HEADERS SCAN", scan_headers, target)

    if "--dns" in sys.argv:
        run("DNS ENUM", scan_dns, target)

    if "--dirbrute" in sys.argv:
        run("DIR BRUTE", lambda t: dir_brute(t,True), target)

    if "--webvuln" in sys.argv:
        run("WEB VULN", lambda t: web_vuln_scan(t,True), target)

    if "--vuln" in sys.argv:
        run("VULN SCAN", lambda t: vuln_scan(t,True), target)

    # optional modules

    optional_args = {
        "--sqli":"sqli_scan",
        "--xss":"xss_scan",
        "--csrf":"csrf_scan",
        "--lfi":"lfi_rfi_scan",
        "--cmdinj":"cmd_injection_scan",
        "--redirect":"open_redirect_scan",
        "--subdomain":"subdomain_enum",
        "--whois":"whois_lookup",
        "--cve":"cve_checker",
        "--upload":"file_upload_scan",
        "--cors":"cors_scan",
        "--hostheader":"host_header_scan",
        "--ssrf":"ssrf_scan",
        "--xxe":"xxe_scan",
        "--deserial":"deserialization_scan",
        "--api":"api_scan",
        "--cms":"cms_scanner",
        "--os":"os_fingerprint",
        "--services":"service_detect",
        "--firewall":"firewall_detect",
        "--db":"db_vuln_scan",
        # NEW MODULES
        "--ssti":"ssti_scan",
        "--idor":"idor_scan",
        "--jwt":"jwt_scan",
        "--http-methods":"http_methods_scan",
        "--dirlisting":"dir_listing_scan",
        "--backup":"backup_scan",
        "--git":"git_scan",
        "--env":"env_scan",
        "--robots":"robots_scan",
        "--sitemap":"sitemap_scan",
        "--clickjacking":"clickjacking_scan",
        "--cors-adv":"cors_adv_scan",
        "--params":"param_mining_scan",
        "--js":"js_analysis_scan",
        "--cookies":"cookie_analysis_scan"
    }

    def invoke_optional(func_name):
        module_info = modules_by_func.get(func_name)
        if module_info:
            if isinstance(module_info, tuple):
                module_full_name, func_to_call = module_info
                func = load_optional_multi(module_full_name, func_to_call)
            else:
                func = load_optional(module_info, func_name)
            if func:
                return run(func_name.upper(), func, target)
            else:
                print(Fore.YELLOW + f"[MODULE NOT LOADED] {func_name}")
        else:
            print(Fore.YELLOW + f"[MODULE NOT FOUND] {func_name}")
        return None

    for arg, func_name in optional_args.items():
        if arg in sys.argv:
            invoke_optional(func_name)

    if "--recon" in sys.argv:
        print(Fore.CYAN + "\n[RECON SUITE]")
        run("DNS ENUM", scan_dns, target)
        run("TECH DETECT", detect_tech, target)
        run("HEADERS SCAN", scan_headers, target)
        invoke_optional("subdomain_enum")
        invoke_optional("whois_lookup")
        invoke_optional("robots_scan")
        invoke_optional("sitemap_scan")
        invoke_optional("backup_scan")
        invoke_optional("git_scan")
        invoke_optional("env_scan")

    if "--audit" in sys.argv:
        print(Fore.CYAN + "\n[AUDIT MODE]")
        audit_checks = [
            "sqli_scan", "xss_scan", "csrf_scan", "lfi_rfi_scan",
            "cmd_injection_scan", "open_redirect_scan", "ssrf_scan",
            "xxe_scan", "file_upload_scan", "cors_scan", "host_header_scan"
        ]
        for audit_check in audit_checks:
            invoke_optional(audit_check)

    if "--all" in sys.argv:

        print(Fore.CYAN + "\n[FULL SCAN]")

        if scan_tls_versions:
            scan_tls_versions(target, 443)
        if scan_real_session:
            scan_real_session(target, 443)
        if scan_ciphers:
            scan_ciphers(target, 443)

        if port_scan:
            port_scan(target)
        if detect_tech:
            detect_tech(target)
        if scan_headers:
            scan_headers(target)
        if scan_dns:
            scan_dns(target)
        if dir_brute:
            dir_brute(target, True)
        if web_vuln_scan:
            web_vuln_scan(target, True)
        if vuln_scan:
            vuln_scan(target, True)

        print(Fore.MAGENTA + "\n[FULL SCAN] Running all optional vulnerability modules...")
        for func_name in sorted(set(optional_args.values())):
            module_info = modules_by_func.get(func_name)
            if module_info:
                if isinstance(module_info, tuple):
                    module_full_name, func_to_call = module_info
                    func = load_optional_multi(module_full_name, func_to_call)
                else:
                    func = load_optional(module_info, func_name)
                if func:
                    run(func_name.upper(), func, target)
                else:
                    print(Fore.YELLOW + f"[MODULE NOT LOADED] {func_name}")
            else:
                print(Fore.YELLOW + f"[MODULE NOT FOUND] {func_name}")

    # External Tools Integration
    if "--external" in sys.argv:
        try:
            from modules.external_tools import run_all_external_tools
            run_all_external_tools(target)
        except ImportError as e:
            print(Fore.RED + f"[ERROR] External tools module not loaded: {e}")

    external_tools = ['--gobuster', '--ffuf', '--nmap', '--whatweb']
    
    if any(tool in sys.argv for tool in external_tools):
        try:
            from modules.external_tools import run_gobuster, run_ffuf, run_nmap, run_whatweb
            
            if "--gobuster" in sys.argv:
                run_gobuster(target, threads=10)
            
            if "--ffuf" in sys.argv:
                run_ffuf(target, threads=40)
            
            if "--nmap" in sys.argv:
                run_nmap(target)
            
            if "--whatweb" in sys.argv:
                run_whatweb(target)
        except ImportError as e:
            print(Fore.RED + f"[ERROR] External tools module not loaded: {e}")
    
    # Web Crawler
    if "--crawl" in sys.argv:
        try:
            from modules.crawler import crawl_website
            max_depth = 2
            max_pages = 100
            
            # Check for depth/pages parameters
            if "--depth" in sys.argv:
                try:
                    depth_idx = sys.argv.index("--depth")
                    max_depth = int(sys.argv[depth_idx + 1])
                except:
                    pass
            
            if "--max-pages" in sys.argv:
                try:
                    pages_idx = sys.argv.index("--max-pages")
                    max_pages = int(sys.argv[pages_idx + 1])
                except:
                    pass
            
            crawl_website(target, max_depth=max_depth, max_pages=max_pages)
        except ImportError as e:
            print(Fore.RED + f"[ERROR] Crawler module not loaded: {e}")
    
    # Fuzzing
    if "--fuzz" in sys.argv:
        try:
            from modules.fuzzer import fuzz_target
            
            fuzz_type = 'xss'  # default
            
            try:
                fuzz_idx = sys.argv.index("--fuzz")
                fuzz_type = sys.argv[fuzz_idx + 1] if fuzz_idx + 1 < len(sys.argv) else 'xss'
            except:
                pass
            
            fuzz_target(target, fuzz_type=fuzz_type)
        except ImportError as e:
            print(Fore.RED + f"[ERROR] Fuzzer module not loaded: {e}")
    
    # Report Generation
    if "--output" in sys.argv:
        try:
            from modules.reporting import Report
            
            output_format = 'json'  # default
            
            try:
                output_idx = sys.argv.index("--output")
                output_format = sys.argv[output_idx + 1] if output_idx + 1 < len(sys.argv) else 'json'
            except:
                pass
            
            report = Report(target, output_format=output_format)
            
            # Add example vulnerabilities to report
            report.add_scan_result("TLS Scan", "Completed", severity='info')
            report.add_scan_result("Port Scan", "Completed", severity='info')
            
            # Export report
            if output_format in ['json', 'html', 'csv', 'txt', 'all']:
                if output_format == 'all':
                    report.export_json()
                    report.export_html()
                    report.export_csv()
                    report.export_txt()
                else:
                    report.export(output_format)
            else:
                print(Fore.YELLOW + f"[INFO] Unknown format: {output_format}")
            
            report.print_summary()
        except ImportError as e:
            print(Fore.RED + f"[ERROR] Reporting module not loaded: {e}")

    if "--report-gen" in sys.argv:
        try:
            report_data = [f"{name}: {result}" for name, result in scan_log]
            report = load_optional("modules.report_gen", "report_gen")
            if report:
                report(target, report_data, verbose="--verbose" in sys.argv)
        except Exception as e:
            print(Fore.RED + f"[ERROR] Report generation failed: {e}")

    if "--report" in sys.argv:
        try:
            from modules.reporting import Report
            output_format = 'json'
            if "--output" in sys.argv:
                try:
                    idx = sys.argv.index("--output")
                    if idx + 1 < len(sys.argv):
                        output_format = sys.argv[idx + 1]
                except:
                    pass

            report = Report(target, output_format=output_format)
            for name, result in scan_log:
                report.add_scan_result(name, "Completed", severity='info')
                if isinstance(result, bool) and result:
                    report.add_vulnerability(name, f"Potential positive result from {name}", severity='medium')

            report.export(output_format)
            report.print_summary()
        except ImportError as e:
            print(Fore.RED + f"[ERROR] Reporting module not loaded: {e}")
        except Exception as e:
            print(Fore.RED + f"[ERROR] Report export failed: {e}")

    print(Fore.GREEN + "\nSCAN FINISHED")

# ---------------------------------
# MAIN
# ---------------------------------

def main():
    try:
        if "-h" in sys.argv or "--help" in sys.argv:
            banner()
            show_help()
            return

        banner()

        target = get_target()

        if not target:
            print(Fore.RED + "Target not specified")
            print("Use: python plascoy.py -u target.com")
            return

        run_scans(target)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[INTERRUPTED] Scan cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
