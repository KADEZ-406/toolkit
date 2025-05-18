import whois
import socket
import dns.resolver
import requests
import json
from colorama import Fore, Style
import os
import subprocess
import re
from datetime import datetime

def run_nmap_scan(target, output_file):
    """Run Nmap scan with common scripts"""
    try:
        print(Fore.YELLOW + "\n[*] Running Nmap scan...")
        
        # Basic scan with service detection, OS detection, and common scripts
        nmap_cmd = [
            "nmap", "-sC", "-sV", "-O",
            "--min-rate", "1000",
            "-oN", output_file,
            target
        ]
        
        process = subprocess.Popen(
            nmap_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            print(Fore.GREEN + "[+] Nmap scan completed successfully")
            
            # Parse Nmap output
            with open(output_file, 'r') as f:
                nmap_results = f.read()
            
            return nmap_results
        else:
            print(Fore.RED + f"[!] Nmap scan failed: {stderr}")
            return None
            
    except Exception as e:
        print(Fore.RED + f"[!] Error running Nmap scan: {str(e)}")
        return None

def run_amass_enum(domain, output_file):
    """Run Amass enumeration"""
    try:
        print(Fore.YELLOW + "\n[*] Running Amass enumeration...")
        
        # Run Amass with passive enumeration mode
        amass_cmd = [
            "amass", "enum",
            "-passive",
            "-d", domain,
            "-o", output_file
        ]
        
        process = subprocess.Popen(
            amass_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            print(Fore.GREEN + "[+] Amass enumeration completed successfully")
            
            # Read and parse Amass results
            with open(output_file, 'r') as f:
                subdomains = f.read().splitlines()
            
            return subdomains
        else:
            print(Fore.RED + f"[!] Amass enumeration failed: {stderr}")
            return None
            
    except Exception as e:
        print(Fore.RED + f"[!] Error running Amass: {str(e)}")
        return None

def parse_nmap_results(nmap_output):
    """Parse Nmap results into structured format"""
    results = {
        'ports': [],
        'os_detection': [],
        'services': []
    }
    
    if not nmap_output:
        return results
        
    # Parse port information
    port_pattern = r'(\d+)/(\w+)\s+(\w+)\s+(.+)'
    for line in nmap_output.splitlines():
        if '/tcp' in line or '/udp' in line:
            match = re.search(port_pattern, line)
            if match:
                port, protocol, state, service = match.groups()
                results['ports'].append({
                    'port': port,
                    'protocol': protocol,
                    'state': state,
                    'service': service.strip()
                })
    
    # Parse OS detection
    os_pattern = r'OS details: (.+)'
    os_matches = re.findall(os_pattern, nmap_output)
    results['os_detection'] = os_matches
    
    return results

def gather_info():
    print(Fore.CYAN + "\n=== Enhanced Information Gathering Tool ===\n")
    
    domain = input(Fore.GREEN + "Enter domain name (e.g., example.com): " + Style.RESET_ALL)
    
    results = {}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = f"data/results/recon_{timestamp}"
    
    if not os.path.exists(scan_dir):
        os.makedirs(scan_dir)
    
    try:
        # WHOIS Information
        print(Fore.YELLOW + "\n[*] Gathering WHOIS information...")
        whois_info = whois.whois(domain)
        
        # Handle name_servers that might not be iterable
        name_servers = whois_info.name_servers
        if name_servers is None:
            name_servers = []
        elif isinstance(name_servers, str):
            name_servers = [name_servers]
        elif not isinstance(name_servers, (list, tuple)):
            name_servers = []
            
        results['whois'] = {
            'registrar': whois_info.registrar,
            'creation_date': str(whois_info.creation_date),
            'expiration_date': str(whois_info.expiration_date),
            'name_servers': name_servers
        }
        print(Fore.GREEN + "[+] WHOIS information gathered")
        
        # IP Lookup
        print(Fore.YELLOW + "\n[*] Performing IP lookup...")
        ip = socket.gethostbyname(domain)
        results['ip'] = ip
        print(Fore.GREEN + f"[+] IP Address: {ip}")
        
        # DNS Information
        print(Fore.YELLOW + "\n[*] Gathering DNS information...")
        dns_info = {}
        
        # A Record
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            dns_info['A'] = [str(r) for r in a_records]
        except:
            dns_info['A'] = []
            
        # MX Record
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_info['MX'] = [str(r) for r in mx_records]
        except:
            dns_info['MX'] = []
            
        # NS Record
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            dns_info['NS'] = [str(r) for r in ns_records]
        except:
            dns_info['NS'] = []
            
        # TXT Record
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            dns_info['TXT'] = [str(r) for r in txt_records]
        except:
            dns_info['TXT'] = []
            
        results['dns'] = dns_info
        print(Fore.GREEN + "[+] DNS information gathered")
        
        # Run Nmap scan
        nmap_output_file = os.path.join(scan_dir, f"nmap_{domain}.txt")
        nmap_output = run_nmap_scan(ip, nmap_output_file)
        if nmap_output:
            results['nmap'] = parse_nmap_results(nmap_output)
        
        # Run Amass enumeration
        amass_output_file = os.path.join(scan_dir, f"amass_{domain}.txt")
        subdomains = run_amass_enum(domain, amass_output_file)
        if subdomains:
            results['subdomains'] = subdomains
        
        # HTTP Headers
        print(Fore.YELLOW + "\n[*] Gathering HTTP headers...")
        try:
            response = requests.get(f"http://{domain}", timeout=10)
            results['headers'] = dict(response.headers)
            print(Fore.GREEN + "[+] HTTP headers gathered")
        except:
            results['headers'] = {}
            print(Fore.RED + "[!] Could not gather HTTP headers")
        
        # Geo IP Information (using ip-api.com)
        print(Fore.YELLOW + "\n[*] Gathering GeoIP information...")
        try:
            geo_response = requests.get(f"http://ip-api.com/json/{ip}")
            if geo_response.status_code == 200:
                results['geo_ip'] = geo_response.json()
                print(Fore.GREEN + "[+] GeoIP information gathered")
            else:
                results['geo_ip'] = {}
                print(Fore.RED + "[!] Could not gather GeoIP information")
        except:
            results['geo_ip'] = {}
            print(Fore.RED + "[!] Could not gather GeoIP information")
        
        # Save results
        output_file = os.path.join(scan_dir, f"{domain}_recon.json")
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        
        # Print detailed results
        print(Fore.CYAN + "\n=== Detailed Results ===\n")
        
        print(Fore.GREEN + "WHOIS Information:")
        print(Fore.WHITE + f"Registrar: {results['whois']['registrar']}")
        print(Fore.WHITE + f"Creation Date: {results['whois']['creation_date']}")
        print(Fore.WHITE + f"Expiration Date: {results['whois']['expiration_date']}")
        print(Fore.WHITE + f"Name Servers: {', '.join(results['whois']['name_servers'])}")
        
        print(Fore.GREEN + "\nDNS Information:")
        for record_type, records in results['dns'].items():
            if records:
                print(Fore.WHITE + f"{record_type} Records: {', '.join(records)}")
        
        if 'nmap' in results:
            print(Fore.GREEN + "\nNmap Scan Results:")
            if results['nmap']['ports']:
                print(Fore.WHITE + "Open Ports:")
                for port in results['nmap']['ports']:
                    print(Fore.WHITE + f"  {port['port']}/{port['protocol']} - {port['state']} - {port['service']}")
            if results['nmap']['os_detection']:
                print(Fore.WHITE + "\nOS Detection:")
                for os in results['nmap']['os_detection']:
                    print(Fore.WHITE + f"  {os}")
        
        if 'subdomains' in results:
            print(Fore.GREEN + "\nDiscovered Subdomains:")
            for subdomain in results['subdomains']:
                print(Fore.WHITE + f"  {subdomain}")
        
        if results['geo_ip']:
            print(Fore.GREEN + "\nGeoIP Information:")
            geo = results['geo_ip']
            print(Fore.WHITE + f"Country: {geo.get('country', 'N/A')}")
            print(Fore.WHITE + f"City: {geo.get('city', 'N/A')}")
            print(Fore.WHITE + f"ISP: {geo.get('isp', 'N/A')}")
            print(Fore.WHITE + f"Organization: {geo.get('org', 'N/A')}")
        
        print(Fore.GREEN + f"\n[+] Full results saved to {output_file}")
        print(Fore.GREEN + f"[+] Nmap results saved to {nmap_output_file}")
        print(Fore.GREEN + f"[+] Amass results saved to {amass_output_file}")
        
    except Exception as e:
        print(Fore.RED + f"\nError during information gathering: {str(e)}")
        return None
    
    return results 
