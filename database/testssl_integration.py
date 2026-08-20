#!/usr/bin/env python3
"""
Integration with testssl.sh - Complete SSL/TLS Testing Tool
"""

import subprocess
import os
import json
import re
from colorama import Fore, Style, init
from pathlib import Path

init(autoreset=True)

# Path to testssl.sh
TESTSSL_PATH = None

def find_testssl():
    """Find testssl.sh in common locations"""
    global TESTSSL_PATH
    
    if TESTSSL_PATH:
        return TESTSSL_PATH
    
    common_paths = [
        "/home/crypt01lord/Documentos/testssl.sh/testssl.sh",
        "/usr/local/bin/testssl.sh",
        "/usr/bin/testssl.sh",
        "./testssl.sh",
        "../testssl.sh/testssl.sh"
    ]
    
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            TESTSSL_PATH = path
            return path
    
    return None

def testssl_integration(target, verbose=False):
    """
    Run testssl.sh for comprehensive SSL/TLS analysis
    """
    print(Fore.CYAN + "[TESTSSL.SH SCAN STARTED]")
    print(Fore.YELLOW + "Running comprehensive SSL/TLS analysis with testssl.sh...")
    
    # Normalize target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    # Extract domain and port
    target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    
    if ":" in target_clean:
        domain, port = target_clean.split(":")
    else:
        domain = target_clean
        port = "443"
    
    testssl_path = find_testssl()
    
    if not testssl_path:
        print(Fore.RED + "[ERROR] testssl.sh not found in system")
        print(Fore.YELLOW + "[INFO] Install testssl.sh from: https://github.com/drwetter/testssl.sh")
        print(Fore.CYAN + "[TESTSSL.SH INTEGRATION COMPLETED]")
        return
    
    try:
        print(Fore.BLUE + f"[TESTSSL] Testing {domain}:{port}...")
        
        # Run testssl.sh with JSON output
        # Format: testssl.sh host:port or testssl.sh http://host:port
        target_str = f"{domain}:{port}"
        
        cmd = [
            testssl_path,
            "--json",
            "--severity=HIGH",
            target_str
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0 or result.returncode == 1:
            # Parse JSON output if available
            try:
                # testssl.sh output might be in stderr
                output = result.stdout + result.stderr
                
                # Extract key findings
                if "protocols" in output.lower():
                    print(Fore.GREEN + "[+] TLS Protocols detected")
                
                if "Certificate" in output or "certificate" in output:
                    print(Fore.GREEN + "[+] Certificate information retrieved")
                
                if "VULNERABLE" in output or "vulnerable" in output:
                    print(Fore.RED + "[!] Vulnerabilities found!")
                    # Extract vulnerability lines
                    for line in output.split('\n'):
                        if 'VULNERABLE' in line or 'vulnerable' in line or 'CVE' in line:
                            print(Fore.RED + f"  {line.strip()}")
                else:
                    print(Fore.GREEN + "[+] No critical vulnerabilities detected")
                
                # Show certificate info
                if "issuer" in output.lower():
                    print(Fore.BLUE + "[+] Certificate issuer information available")
                
                if verbose:
                    print("\n[FULL OUTPUT]")
                    print(output[:2000])  # Print first 2000 chars
                    
            except Exception as e:
                print(Fore.YELLOW + f"[INFO] Could not parse testssl.sh output: {e}")
                if verbose:
                    print(output[:1000])
        else:
            print(Fore.YELLOW + f"[WARNING] testssl.sh returned code {result.returncode}")
            if result.stderr:
                print(Fore.YELLOW + f"[ERROR] {result.stderr[:500]}")
    
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "[TIMEOUT] testssl.sh took too long to complete")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to run testssl.sh: {e}")
    
    finally:
        print(Fore.CYAN + "[TESTSSL.SH INTEGRATION COMPLETED]")

def main():
    """Test the integration"""
    import sys
    if len(sys.argv) > 1:
        testssl_integration(sys.argv[1], verbose=True)
    else:
        testssl_integration("google.com", verbose=True)

if __name__ == "__main__":
    main()
