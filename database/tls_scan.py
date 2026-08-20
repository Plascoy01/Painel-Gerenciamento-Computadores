#!/usr/bin/env python3
import socket
import ssl
import threading
import json
from datetime import datetime
from typing import Dict, List, Tuple, Any
import cryptography.x509 as x509
from cryptography.hazmat.backends import default_backend

TLS_VERSIONS = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3
}

COMMON_CIPHERS = [
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA"
]

def test_cipher(host: str, port: int, cipher: str) -> Tuple[str, bool, str]:
    """Test a single cipher against host"""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers(cipher)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return cipher, True, ssock.version()
    except Exception as e:
        return cipher, False, str(e)

def connect_tls(host: str, port: int, ctx: ssl.SSLContext) -> ssl.SSLSocket:
    """Establish TLS connection with given context"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        return ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        sock.close()
        raise

def test_tls_version(host: str, port: int, version: ssl.TLSVersion) -> Tuple[str, bool, str]:
    """Test a single TLS version against host"""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with connect_tls(host, port, ctx) as ssock:
            negotiated = ssock.version()
            if negotiated == version.name.replace("_", "."):
                return version.name, True, negotiated
            return version.name, False, negotiated
    except Exception as e:
        return version.name, False, str(e)

def scan_tls_versions(host: str, port: int = 443) -> Dict[str, Any]:
    """Scan all TLS versions for host"""
    print("\nTLS VERSION SCAN")
    print("-" * 50)
    results = {}
    for name, version in TLS_VERSIONS.items():
        _, supported, negotiated = test_tls_version(host, port, version)
        results[name] = {
            "supported": supported,
            "negotiated": negotiated
        }
        status = "SUPPORTED" if supported else "NOT SUPPORTED"
        print(f"{name}: {status} (negotiated: {negotiated})")
    
    supported = [name for name, data in results.items() if data["supported"]]
    if supported:
        print("\nSERVER ACCEPTS:", ", ".join(supported))
    else:
        print("\nNO TESTED TLS VERSION ACCEPTED")
    
    return results

def parse_cert(cert_data: bytes) -> Dict:
    """Parse X.509 certificate data"""
    try:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        cert_dict = {
            "subject": {},
            "issuer": {},
            "serial": cert.serial_number,
            "not_valid_before": cert.not_valid_before.isoformat(),
            "not_valid_after": cert.not_valid_after.isoformat(),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "public_key_algorithm": cert.public_key().key_size,
            "extensions": {}
        }
        
        # Parse subject
        for attr in cert.subject:
            cert_dict["subject"][attr.oid._name] = attr.value
            
        # Parse issuer
        for attr in cert.issuer:
            cert_dict["issuer"][attr.oid._name] = attr.value
            
        # Parse extensions
        for ext in cert.extensions:
            cert_dict["extensions"][ext.oid._name] = str(ext.value)
            
        return cert_dict
    except Exception as e:
        return {"error": str(e)}

def scan_real_session(host: str, port: int = 443) -> Dict[str, Any]:
    """Test actual TLS session negotiation"""
    print("\nTLS SESSION NEGOTIATION")
    print("-" * 50)
    results = {
        "connection": {},
        "certificate": {},
        "extensions": {}
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with connect_tls(host, port, ctx) as ssock:
            results["connection"]["protocol"] = ssock.version()
            cipher = ssock.cipher()
            results["connection"]["cipher"] = {
                "name": cipher[0],
                "protocol": cipher[1],
                "bits": cipher[2]
            }
            
            cert_data = ssock.getpeercert(binary_form=True)
            results["certificate"] = parse_cert(cert_data)
            
            print("NEGOTIATED PROTOCOL:", results["connection"]["protocol"])
            print("CIPHER:", results["connection"]["cipher"]["name"])
            print("CIPHER PROTOCOL:", results["connection"]["cipher"]["protocol"])
            print("CIPHER BITS:", results["connection"]["cipher"]["bits"])
            
            print("\nCERTIFICATE INFORMATION")
            print("-" * 50)
            cert = results["certificate"]
            print("ISSUER:", cert["issuer"].get("commonName", "Unknown"))
            print("SUBJECT:", cert["subject"].get("commonName", "Unknown"))
            print("SERIAL:", cert["serial"])
            print("VALID FROM:", cert["not_valid_before"])
            print("VALID UNTIL:", cert["not_valid_after"])
            print("SIGNATURE ALGORITHM:", cert["signature_algorithm"])
            
            print("\nEXTENSIONS")
            print("-" * 50)
            for ext_name, ext_value in cert["extensions"].items():
                print(f"{ext_name}: {ext_value[:100]}{'...' if len(ext_value) > 100 else ''}")
                
            return results
    except Exception as e:
        print("TLS SESSION FAILED:", str(e))
        results["error"] = str(e)
        return results

def scan_ciphers(host: str, port: int = 443) -> Dict[str, Any]:
    """Test all common ciphers against host"""
    print("\nCIPHER TEST")
    print("-" * 50)
    results = {}
    threads = []
    
    def worker(cipher):
        cipher_name, supported, negotiated = test_cipher(host, port, cipher)
        results[cipher_name] = {
            "supported": supported,
            "negotiated": negotiated
        }
        status = "SUPPORTED" if supported else "NOT SUPPORTED"
        print(f"{cipher_name}: {status} (negotiated: {negotiated})")
    
    for cipher in COMMON_CIPHERS:
        thread = threading.Thread(target=worker, args=(cipher,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    supported = [cipher for cipher, data in results.items() if data["supported"]]
    if supported:
        print("\nSUPPORTED CIPHERS:", ", ".join(supported))
    else:
        print("\nNO TESTED CIPHERS SUPPORTED")
    
    return results

def scan_server_config(host: str, port: int = 443) -> Dict[str, Any]:
    """Run all TLS scans and combine results"""
    print(f"\n[TLS CONFIGURATION SCAN FOR {host}:{port}]")
    print("=" * 60)
    
    results = {
        "target": host,
        "port": port,
        "tls_versions": scan_tls_versions(host, port),
        "real_session": scan_real_session(host, port),
        "ciphers": scan_ciphers(host, port)
    }
    
    print("\nSCAN SUMMARY")
    print("=" * 60)
    print(f"Supported TLS Versions: {[v for v, d in results['tls_versions'].items() if d['supported']]}")
    print(f"Supported Ciphers: {[c for c, d in results['ciphers'].items() if d['supported']]}")
    print(f"Certificate Issuer: {results['real_session']['certificate']['issuer'].get('commonName', 'Unknown')}")
    print(f"Certificate Valid Until: {results['real_session']['certificate']['not_valid_after']}")
    
    return results

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Advanced TLS Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target hostname')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port')
    parser.add_argument('--versions', action='store_true', help='Scan TLS versions')
    parser.add_argument('--session', action='store_true', help='Test real session')
    parser.add_argument('--ciphers', action='store_true', help='Test ciphers')
    parser.add_argument('--config', action='store_true', help='Scan entire TLS configuration')
    parser.add_argument('--output', help='Output JSON file')
    args = parser.parse_args()
    
    if args.config:
        results = scan_server_config(args.target, args.port)
    else:
        results = {}
        if args.versions:
            results["tls_versions"] = scan_tls_versions(args.target, args.port)
        if args.session:
            results["real_session"] = scan_real_session(args.target, args.port)
        if args.ciphers:
            results["ciphers"] = scan_ciphers(args.target, args.port)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()
