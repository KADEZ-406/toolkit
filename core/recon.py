import whois
import socket
import dns.resolver
import requests
import json
from colorama import Fore, Style
import os

def gather_info():
    print(Fore.CYAN + "\n=== Information Gathering Tool ===\n")
    
    domain = input(Fore.GREEN + "Enter domain name (e.g., example.com): " + Style.RESET_ALL)
    
    results = {}
    
    try:
        # WHOIS Information
        print(Fore.YELLOW + "\n[*] Gathering WHOIS information...")
        whois_info = whois.whois(domain)
        results['whois'] = {
            'registrar': whois_info.registrar,
            'creation_date': str(whois_info.creation_date),
            'expiration_date': str(whois_info.expiration_date),
            'name_servers': whois_info.name_servers
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
        if not os.path.exists("data/results"):
            os.makedirs("data/results")
            
        output_file = f"data/results/{domain}_recon.json"
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
        
        if results['geo_ip']:
            print(Fore.GREEN + "\nGeoIP Information:")
            geo = results['geo_ip']
            print(Fore.WHITE + f"Country: {geo.get('country', 'N/A')}")
            print(Fore.WHITE + f"City: {geo.get('city', 'N/A')}")
            print(Fore.WHITE + f"ISP: {geo.get('isp', 'N/A')}")
            print(Fore.WHITE + f"Organization: {geo.get('org', 'N/A')}")
        
        print(Fore.GREEN + f"\n[+] Full results saved to {output_file}")
        
    except Exception as e:
        print(Fore.RED + f"\nError during information gathering: {str(e)}")
        return None
    
    return results 