import socket
import threading
from queue import Queue
from colorama import init, Fore, Style
import time
import datetime
import json
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

class PortScanner:
    def __init__(self, verbose=False):
        self.open_ports = []
        self.verbose = verbose
        self.common_ports = {
            21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
            8080: "HTTP-ALT", 8443: "HTTPS-ALT"
        }
        self.status_codes = {
            0: "OPEN", 1: "REFUSED", 2: "TIMEOUT", 3: "ERROR"
        }
    
    def grab_banner(self, sock, port):
        try:
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else None
        except Exception as e:
            if self.verbose:
                print(f"Error grabbing banner for port {port}: {e}")
            return None
    
    def scan_port(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start_time = time.time()
            result = sock.connect_ex((host, port))
            duration = time.time() - start_time
            
            status = self.status_codes.get(result, "UNKNOWN")
            service = self.common_ports.get(port, "unknown")
            
            if result == 0:
                banner = self.grab_banner(sock, port)
                self.open_ports.append(port)
                
                status_color = Fore.GREEN
                output = f"[{status}] {port} ({service}) - {duration:.2f}s"
                print(f"{status_color}{output}")
                
                if banner:
                    print(f"   └─ Banner: {banner[:80]}")
            else:
                status_color = Fore.YELLOW
                output = f"[{status}] {port} ({service}) - {duration:.2f}s"
                print(f"{status_color}{output}")
                
            sock.close()
            return result
        except Exception as e:
            if self.verbose:
                print(f"Error scanning port {port}: {e}")
            return 3
    
    def worker(self, host, queue, results):
        while not queue.empty():
            port = queue.get()
            result = self.scan_port(host, port)
            results[port] = result
            queue.task_done()
    
    def port_scan(self, host, start=1, end=100, threads=20):
        print("\nPLASCOY PORT SCANNER")
        print(Fore.CYAN + "="*60)
        
        try:
            ip = socket.gethostbyname(host)
            print(Fore.GREEN + f"Target: {host}")
            print(Fore.GREEN + f"IP: {ip}")
        except Exception as e:
            print(Fore.RED + f"Error resolving domain: {e}")
            return []

        print(Fore.GREEN + f"\nScanning ports {start}-{min(end, 100)} (100 max)\n")
        
        queue = Queue()
        for port in range(start, min(end, 100)+1):
            queue.put(port)

        results = {}
        thread_list = []
        for _ in range(min(threads, 20)):
            t = threading.Thread(target=self.worker, args=(ip, queue, results))
            t.daemon = True
            t.start()
            thread_list.append(t)

        queue.join()
        
        print(Fore.CYAN + "\nScan completed in {:.2f}s".format(time.time() - start_time))
        if self.open_ports:
            print(Fore.GREEN + f"Open ports: {sorted(self.open_ports)}")
            print(Fore.YELLOW + f"Total open ports: {len(self.open_ports)}")
        else:
            print(Fore.YELLOW + "No open ports found.")
        
        return sorted(self.open_ports)

def port_scan(target, start=1, end=1024, threads=50):
    scanner = PortScanner(verbose=True)
    open_ports = scanner.port_scan(target, start, end, threads)
    print(Fore.GREEN + f"Open ports: {open_ports}")

def main():
    scanner = PortScanner(verbose=True)
    scanner.port_scan("www.google.com", start=1, end=100, threads=20)

if __name__ == "__main__":
    main()
