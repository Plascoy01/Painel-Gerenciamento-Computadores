#!/usr/bin/env python3
"""
Robots.txt and Sitemap Analysis
"""

import requests
from colorama import Fore, init
from urllib.parse import urljoin

init(autoreset=True)

def robots_scan(target, verbose=False):
    """
    Analyze robots.txt for exposed paths
    """
    print(Fore.CYAN + "[ROBOTS.TXT SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    try:
        url = target.rstrip('/') + '/robots.txt'
        response = session.get(url, timeout=5)
        
        if response.status_code == 200:
            print(Fore.YELLOW + f"[ROBOTS] Found robots.txt at {url}")
            
            # Parse robots.txt
            disallowed_paths = []
            allowed_paths = []
            
            for line in response.text.split('\n'):
                line = line.strip()
                if line.startswith('Disallow:'):
                    path = line.replace('Disallow:', '').strip()
                    if path:
                        disallowed_paths.append(path)
                elif line.startswith('Allow:'):
                    path = line.replace('Allow:', '').strip()
                    if path:
                        allowed_paths.append(path)
            
            if disallowed_paths:
                print(Fore.RED + "[ROBOTS] Disallowed paths (may be sensitive):")
                for path in disallowed_paths[:10]:  # Show first 10
                    print(Fore.RED + f"  - {path}")
            
            if allowed_paths:
                print(Fore.BLUE + "[ROBOTS] Allowed paths:")
                for path in allowed_paths[:5]:
                    print(Fore.BLUE + f"  - {path}")
        else:
            print(Fore.GREEN + "[ROBOTS] robots.txt not found")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] Robots scan failed: {e}")
    
    print(Fore.CYAN + "[ROBOTS.TXT SCAN COMPLETED]")
    return False

def sitemap_scan(target, verbose=False):
    """
    Analyze sitemap.xml for site structure
    """
    print(Fore.CYAN + "[SITEMAP SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    try:
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap1.xml',
            '/sitemap-index.xml'
        ]
        
        for sitemap_path in sitemap_urls:
            try:
                url = target.rstrip('/') + sitemap_path
                response = session.get(url, timeout=5)
                
                if response.status_code == 200 and 'xml' in response.text.lower():
                    print(Fore.YELLOW + f"[SITEMAP] Found at {url}")
                    
                    # Extract URLs from sitemap
                    import re
                    urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                    
                    if urls:
                        print(Fore.BLUE + f"[SITEMAP] Found {len(urls)} URLs:")
                        for url_item in urls[:10]:  # Show first 10
                            print(Fore.BLUE + f"  - {url_item}")
                    return True
            
            except Exception as e:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] {sitemap_path}: {e}")
        
        print(Fore.GREEN + "[SITEMAP] No sitemap.xml found")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] Sitemap scan failed: {e}")
    
    print(Fore.CYAN + "[SITEMAP SCAN COMPLETED]")
    return False
