import requests
import dns.resolver
import socket
from colorama import Fore, Style
import json
import os

def check_shodan(ip, api_key=None):
    """Check IP on Shodan (placeholder - requires API key)"""
    if not api_key:
        return None
        
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}")
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def check_censys(domain, api_id=None, api_secret=None):
    """Check domain on Censys (placeholder - requires API credentials)"""
    if not api_id or not api_secret:
        return None
        
    try:
        response = requests.get(
            f"https://search.censys.io/api/v2/hosts/search?q={domain}",
            auth=(api_id, api_secret)
        )
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def find_real_ip():
    print(Fore.CYAN + "\n=== Real IP Finder (Cloudflare Bypass) ===\n")
    
    domain = input(Fore.GREEN + "Enter domain name: " + Style.RESET_ALL)
    
    results = {
        'domain': domain,
        'found_ips': set(),
        'methods_used': []
    }
    
    print(Fore.YELLOW + "\n[*] Starting IP discovery...")
    
    # Method 1: DNS History
    print(Fore.YELLOW + "\n[*] Checking DNS records...")
    try:
        # Check common DNS record types
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    if hasattr(rdata, 'address'):
                        results['found_ips'].add(rdata.address)
                    elif hasattr(rdata, 'exchange'):
                        try:
                            ip = socket.gethostbyname(str(rdata.exchange))
                            results['found_ips'].add(ip)
                        except:
                            pass
            except:
                continue
        
        if results['found_ips']:
            results['methods_used'].append('DNS Records')
            print(Fore.GREEN + f"[+] Found {len(results['found_ips'])} IPs from DNS records")
    except Exception as e:
        print(Fore.RED + f"[!] Error checking DNS records: {str(e)}")
    
    # Method 2: Subdomain Enumeration
    print(Fore.YELLOW + "\n[*] Checking common subdomains...")
    common_subdomains = ['mail', 'ftp', 'direct', 'direct-connect', 'cpanel', 'webmail']
    
    for subdomain in common_subdomains:
        try:
            hostname = f"{subdomain}.{domain}"
            ip = socket.gethostbyname(hostname)
            results['found_ips'].add(ip)
            print(Fore.GREEN + f"[+] Found IP through subdomain {hostname}: {ip}")
        except:
            continue
    
    if len(results['found_ips']) > len(set(results['methods_used'])):
        results['methods_used'].append('Subdomain Enumeration')
    
    # Method 3: Check Historical DNS Records (simulated)
    print(Fore.YELLOW + "\n[*] Checking historical DNS records...")
    try:
        response = requests.get(f"https://securitytrails.com/domain/{domain}/history/a", 
                              headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code == 200:
            results['methods_used'].append('Historical DNS')
            print(Fore.GREEN + "[+] Historical DNS records checked")
    except:
        print(Fore.RED + "[!] Could not check historical DNS records")
    
    # Convert set to list for JSON serialization
    results['found_ips'] = list(results['found_ips'])
    
    # Save results
    if not os.path.exists("data/results"):
        os.makedirs("data/results")
        
    output_file = f"data/results/{domain}_real_ip.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
    
    # Print results
    print(Fore.CYAN + "\n=== Results ===")
    print(Fore.GREEN + f"\nFound {len(results['found_ips'])} potential real IPs:")
    for ip in results['found_ips']:
        print(Fore.WHITE + f"- {ip}")
    
    print(Fore.GREEN + "\nMethods used:")
    for method in results['methods_used']:
        print(Fore.WHITE + f"- {method}")
    
    print(Fore.GREEN + f"\n[+] Full results saved to {output_file}")
    
    return results 