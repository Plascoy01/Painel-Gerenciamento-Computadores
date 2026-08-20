#!/usr/bin/env python3
"""
SSTI (Server-Side Template Injection) Detection
"""

import requests
from colorama import Fore, Style, init
import re
from urllib.parse import urljoin

init(autoreset=True)

# Common template injection payloads
SSTI_PAYLOADS = {
    "Jinja2": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}"
    ],
    "ERB": [
        "<%= 7*7 %>",
        "${7*7 }",
    ],
    "Freemarker": [
        "${7*7}",
        "[=7*7]"
    ],
    "Velocity": [
        "#set($x=7*7)$x"
    ]
}

def ssti_scan(target, verbose=False):
    """
    Detect Server-Side Template Injection vulnerabilities
    """
    print(Fore.CYAN + "[SSTI SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    detected_templates = []
    
    try:
        # Test common parameters
        test_params = ['name', 'q', 'search', 'id', 'msg', 'comment', 'text']
        
        for param in test_params:
            for template_type, payloads in SSTI_PAYLOADS.items():
                for payload in payloads:
                    try:
                        # GET parameter test
                        params = {param: payload}
                        response = session.get(target, params=params, timeout=5)
                        
                        # Check for mathematical evaluation (49 = 7*7)
                        if '49' in response.text and payload.replace('*', '') in response.text[:1000]:
                            print(Fore.RED + f"[SSTI VULN] {template_type} detected in parameter '{param}'")
                            print(Fore.RED + f"  Payload: {payload}")
                            print(Fore.RED + f"  Result: {response.text.split('49')[0][-50:]}49{response.text.split('49')[1][:50]}")
                            vuln_found = True
                            detected_templates.append(template_type)
                        
                        # POST parameter test
                        data = {param: payload}
                        response = session.post(target, data=data, timeout=5)
                        
                        if '49' in response.text and payload.replace('*', '') in response.text[:1000]:
                            print(Fore.RED + f"[SSTI VULN] {template_type} detected in POST parameter '{param}'")
                            vuln_found = True
                            detected_templates.append(template_type)
                    
                    except Exception as e:
                        if verbose:
                            print(Fore.YELLOW + f"[INFO] Error testing {param}: {e}")
        
        if not vuln_found:
            print(Fore.GREEN + "[SSTI] No template injection vulnerabilities found")
        else:
            print(Fore.YELLOW + f"[INFO] Detected templates: {', '.join(set(detected_templates))}")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] SSTI scan failed: {e}")
    
    print(Fore.CYAN + "[SSTI SCAN COMPLETED]")
    return vuln_found

def main():
    if __name__ == "__main__":
        import sys
        if len(sys.argv) > 1:
            ssti_scan(sys.argv[1], verbose=True)
        else:
            ssti_scan("httpbin.org", verbose=True)

if __name__ == "__main__":
    main()
