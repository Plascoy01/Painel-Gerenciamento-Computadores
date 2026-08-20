#!/usr/bin/env python3
"""
Parameter Mining - Discover hidden parameters
"""

import requests
from colorama import Fore, init
import re

init(autoreset=True)

def param_mining_scan(target, verbose=False):
    """
    Mine and discover hidden parameters
    """
    print(Fore.CYAN + "[PARAMETER MINING SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    params_found = []
    
    try:
        response = session.get(target, timeout=5)
        
        # Extract parameters from HTML forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        input_pattern = r'<input[^>]*name=["\']?([^"\'\s>]+)'
        select_pattern = r'<select[^>]*name=["\']?([^"\'\s>]+)'
        textarea_pattern = r'<textarea[^>]*name=["\']?([^"\'\s>]+)'
        
        forms = re.findall(form_pattern, response.text, re.DOTALL)
        print(Fore.YELLOW + f"[PARAMS] Found {len(forms)} forms")
        
        for form in forms:
            # Extract input fields
            inputs = re.findall(input_pattern, form)
            selects = re.findall(select_pattern, form)
            textareas = re.findall(textarea_pattern, form)
            
            params_found.extend(inputs)
            params_found.extend(selects)
            params_found.extend(textareas)
        
        # Extract parameters from links
        link_pattern = r'href=["\']([^"\']*\?[^"\']*)'
        links = re.findall(link_pattern, response.text)
        
        for link in links:
            # Extract query parameters
            if '?' in link:
                query_string = link.split('?')[1]
                for param in query_string.split('&'):
                    if '=' in param:
                        param_name = param.split('=')[0]
                        params_found.append(param_name)
        
        # Extract JavaScript object keys that look like parameters
        js_pattern = r'[{\s,]([a-zA-Z_][a-zA-Z0-9_]*)\s*:'
        js_params = re.findall(js_pattern, response.text)
        
        # Filter out common JS keywords
        js_keywords = {'function', 'return', 'new', 'var', 'let', 'const', 'class', 'if', 'for', 'while'}
        js_params = [p for p in js_params if p not in js_keywords and len(p) < 50]
        
        params_found.extend(js_params)
        
        # Remove duplicates and sort
        params_found = sorted(list(set(params_found)))
        
        if params_found:
            print(Fore.GREEN + f"[PARAMS] Discovered {len(params_found)} parameters:")
            for param in params_found[:30]:  # Show first 30
                print(Fore.GREEN + f"  - {param}")
        else:
            print(Fore.YELLOW + "[PARAMS] No parameters discovered")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] Parameter mining failed: {e}")
    
    print(Fore.CYAN + "[PARAMETER MINING SCAN COMPLETED]")
    return len(params_found) > 0
