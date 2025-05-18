import whois
import socket
import dns.resolver
import requests
import json
import os
import subprocess
import re
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def check_tool_exists(tool_name):
    """Check if a command-line tool exists in the system PATH"""
    try:
        if os.name == 'nt':  # Windows
            # Check common Windows installation paths
            common_paths = [
                os.path.join(os.environ.get('ProgramFiles', ''), tool_name),
                os.path.join(os.environ.get('ProgramFiles(x86)', ''), tool_name),
                os.path.join(os.environ.get('ProgramFiles', ''), tool_name, tool_name + '.exe'),
                os.path.join(os.environ.get('ProgramFiles(x86)', ''), tool_name, tool_name + '.exe'),
            ]
            
            # Check if tool exists in PATH or common locations
            for path in common_paths:
                if os.path.exists(path) or os.path.exists(path + '.exe'):
                    return True
                    
            # Try where command as fallback
            try:
                subprocess.run(['where', tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                return True
            except subprocess.CalledProcessError:
                return False
        else:  # Unix-like
            subprocess.run(['which', tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
    except subprocess.CalledProcessError:
        return False
    except Exception:
        return False

def run_nmap_scan(target, output_file):
    """Run enhanced Nmap scan with comprehensive scripts"""
    if not check_tool_exists('nmap'):
        print(Fore.YELLOW + "\n[*] Nmap scan skipped - Nmap not found")
        print(Fore.WHITE + "[*] To enable Nmap scanning, install Nmap from: https://nmap.org/download.html")
        return None
    
    try:
        print(Fore.YELLOW + "\n[*] Running Enhanced Nmap scan...")
        
        # Comprehensive scan with service detection, OS detection, and vulnerability scripts
        nmap_cmd = [
            "nmap",
            "-sS", "-sV", "-O",  # Remove -A flag to reduce errors
            "--min-rate", "1000",
            "-p-",  # Scan all ports
            "-T4",  # Aggressive timing
            "--version-intensity", "5",  # Reduce from 9 to 5 for better stability
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
            print(Fore.GREEN + "[+] Enhanced Nmap scan completed successfully")
            
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
    """Run enhanced Amass enumeration"""
    if not check_tool_exists('amass'):
        print(Fore.YELLOW + "\n[*] Amass enumeration skipped - Amass not found")
        print(Fore.WHITE + "[*] To enable subdomain enumeration, install Amass from:")
        print(Fore.WHITE + "    https://github.com/OWASP/Amass/releases")
        return None
    
    try:
        print(Fore.YELLOW + "\n[*] Running Enhanced Amass enumeration...")
        
        # Enhanced Amass configuration with active enumeration
        amass_cmd = [
            "amass", "enum",
            "-passive",  # Use passive mode instead of active for better compatibility
            "-d", domain,
            "-o", output_file,
            "-timeout", "30"
        ]
        
        process = subprocess.Popen(
            amass_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            print(Fore.GREEN + "[+] Enhanced Amass enumeration completed successfully")
            
            # Read and parse Amass results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    subdomains = f.read().splitlines()
                return subdomains
            return []
        else:
            print(Fore.RED + f"[!] Amass enumeration failed: {stderr}")
            return None
            
    except Exception as e:
        print(Fore.RED + f"[!] Error running Amass: {str(e)}")
        return None

def parse_nmap_results(nmap_output):
    """Enhanced Nmap results parser"""
    results = {
        'ports': [],
        'os_detection': [],
        'services': [],
        'vulnerabilities': [],
        'scripts': []
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
    
    results = {
        'scan_info': {
            'target': domain,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_type': 'Full Reconnaissance'
        },
        'whois_data': {},
        'dns_data': {},
        'network_data': {},
        'subdomain_data': {},
        'web_data': {},
        'geo_data': {}
    }
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = f"data/results/recon_{timestamp}"
    
    try:
        # Create results directory if it doesn't exist
        os.makedirs(scan_dir, exist_ok=True)
        
        # WHOIS Information
        print(Fore.YELLOW + "\n[*] Gathering WHOIS information...")
        try:
            whois_info = whois.whois(domain)
            
            # Handle name_servers that might not be iterable
            name_servers = whois_info.name_servers
            if name_servers is None:
                name_servers = []
            elif isinstance(name_servers, str):
                name_servers = [name_servers]
            elif not isinstance(name_servers, (list, tuple)):
                name_servers = []
                
            results['whois_data'] = {
                'registrar': whois_info.registrar,
                'creation_date': str(whois_info.creation_date),
                'expiration_date': str(whois_info.expiration_date),
                'name_servers': name_servers,
                'registrant': whois_info.registrant,
                'admin_contact': whois_info.admin,
                'tech_contact': whois_info.tech
            }
            print(Fore.GREEN + "[+] WHOIS information gathered")
        except Exception as e:
            print(Fore.RED + f"[!] Error gathering WHOIS information: {str(e)}")
            results['whois_data'] = {'error': str(e)}
        
        # IP Lookup and Reverse DNS
        print(Fore.YELLOW + "\n[*] Performing IP lookup and Reverse DNS...")
        try:
            ip = socket.gethostbyname(domain)
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
            except:
                reverse_dns = None
            
            results['network_data']['main_ip'] = ip
            results['network_data']['reverse_dns'] = reverse_dns
            print(Fore.GREEN + f"[+] IP Address: {ip}")
            if reverse_dns:
                print(Fore.GREEN + f"[+] Reverse DNS: {reverse_dns}")
        except Exception as e:
            print(Fore.RED + f"[!] Error performing IP lookup: {str(e)}")
            results['network_data']['error'] = str(e)
        
        # Enhanced DNS Information
        print(Fore.YELLOW + "\n[*] Gathering comprehensive DNS information...")
        dns_info = {}
        
        # Common record types to check
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV']
        
        for record_type in record_types:
            try:
                records = dns.resolver.resolve(domain, record_type)
                dns_info[record_type] = [str(r) for r in records]
            except:
                dns_info[record_type] = []
                
        results['dns_data'] = dns_info
        print(Fore.GREEN + "[+] Comprehensive DNS information gathered")
        
        # Run Enhanced Nmap scan if available
        nmap_output_file = os.path.join(scan_dir, f"nmap_{domain}.txt")
        nmap_output = run_nmap_scan(ip, nmap_output_file)
        if nmap_output:
            results['network_data']['nmap_results'] = parse_nmap_results(nmap_output)
            results['network_data']['nmap_raw_output'] = nmap_output
        
        # Run Enhanced Amass enumeration if available
        amass_output_file = os.path.join(scan_dir, f"amass_{domain}.txt")
        subdomains = run_amass_enum(domain, amass_output_file)
        if subdomains:
            results['subdomain_data'] = {
                'total_count': len(subdomains),
                'discovery_tool': 'Amass',
                'subdomains': subdomains,
                'verified_subdomains': []
            }
            
            # Verify and gather info for each subdomain
            print(Fore.YELLOW + "\n[*] Verifying discovered subdomains...")
            for subdomain in subdomains:
                try:
                    subdomain_ip = socket.gethostbyname(subdomain)
                    results['subdomain_data']['verified_subdomains'].append({
                        'subdomain': subdomain,
                        'ip': subdomain_ip,
                        'status': 'active'
                    })
                except:
                    results['subdomain_data']['verified_subdomains'].append({
                        'subdomain': subdomain,
                        'ip': None,
                        'status': 'inactive'
                    })
        
        # Enhanced Web Information Gathering
        print(Fore.YELLOW + "\n[*] Gathering detailed web information...")
        try:
            response = requests.get(f"http://{domain}", timeout=10)
            results['web_data']['headers'] = dict(response.headers)
            results['web_data']['status_code'] = response.status_code
            results['web_data']['server'] = response.headers.get('Server', 'Unknown')
            results['web_data']['technologies'] = []
            
            # Detect web technologies
            if 'X-Powered-By' in response.headers:
                results['web_data']['technologies'].append(response.headers['X-Powered-By'])
            if 'php' in response.headers.get('Set-Cookie', '').lower():
                results['web_data']['technologies'].append('PHP')
            if 'asp.net' in response.headers.get('Set-Cookie', '').lower():
                results['web_data']['technologies'].append('ASP.NET')
            if 'jsessionid' in response.headers.get('Set-Cookie', '').lower():
                results['web_data']['technologies'].append('Java')
            
            print(Fore.GREEN + "[+] Web information gathered")
        except Exception as e:
            print(Fore.RED + f"[!] Could not gather web information: {str(e)}")
            results['web_data']['error'] = str(e)
        
        # Enhanced GeoIP Information
        print(Fore.YELLOW + "\n[*] Gathering detailed GeoIP information...")
        try:
            geo_response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,district,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting")
            if geo_response.status_code == 200:
                results['geo_data'] = geo_response.json()
                print(Fore.GREEN + "[+] Detailed GeoIP information gathered")
            else:
                results['geo_data'] = {}
                print(Fore.RED + "[!] Could not gather GeoIP information")
        except Exception as e:
            print(Fore.RED + f"[!] Error gathering GeoIP information: {str(e)}")
            results['geo_data'] = {'error': str(e)}
        
        # Save all results to a single JSON file
        output_file = os.path.join(scan_dir, f"{domain}_full_recon.json")
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        
        # Print detailed results
        print(Fore.CYAN + "\n=== Detailed Results ===\n")
        
        if results['whois_data'] and 'error' not in results['whois_data']:
            print(Fore.GREEN + "WHOIS Information:")
            print(Fore.WHITE + f"Registrar: {results['whois_data']['registrar']}")
            print(Fore.WHITE + f"Creation Date: {results['whois_data']['creation_date']}")
            print(Fore.WHITE + f"Expiration Date: {results['whois_data']['expiration_date']}")
            print(Fore.WHITE + f"Name Servers: {', '.join(results['whois_data']['name_servers'])}")
        
        print(Fore.GREEN + "\nDNS Information:")
        for record_type, records in results['dns_data'].items():
            if records:
                print(Fore.WHITE + f"{record_type} Records: {', '.join(records)}")
        
        if 'nmap_results' in results['network_data']:
            print(Fore.GREEN + "\nNmap Scan Results:")
            nmap_data = results['network_data']['nmap_results']
            if nmap_data['ports']:
                print(Fore.WHITE + "Open Ports:")
                for port in nmap_data['ports']:
                    print(Fore.WHITE + f"  {port['port']}/{port['protocol']} - {port['state']} - {port['service']}")
            if nmap_data['os_detection']:
                print(Fore.WHITE + "\nOS Detection:")
                for operating_system in nmap_data['os_detection']:
                    print(Fore.WHITE + f"  {operating_system}")
        
        if 'subdomains' in results['subdomain_data']:
            print(Fore.GREEN + f"\nDiscovered Subdomains ({results['subdomain_data']['total_count']}):")
            for subdomain_info in results['subdomain_data']['verified_subdomains']:
                status_color = Fore.GREEN if subdomain_info['status'] == 'active' else Fore.RED
                print(status_color + f"  {subdomain_info['subdomain']}")
                if subdomain_info['ip']:
                    print(Fore.WHITE + f"    IP: {subdomain_info['ip']}")
        
        if results['web_data'].get('technologies'):
            print(Fore.GREEN + "\nDetected Web Technologies:")
            for tech in results['web_data']['technologies']:
                print(Fore.WHITE + f"  {tech}")
        
        if results['geo_data'] and 'error' not in results['geo_data']:
            print(Fore.GREEN + "\nGeoIP Information:")
            geo = results['geo_data']
            print(Fore.WHITE + f"Country: {geo.get('country', 'N/A')}")
            print(Fore.WHITE + f"City: {geo.get('city', 'N/A')}")
            print(Fore.WHITE + f"ISP: {geo.get('isp', 'N/A')}")
            print(Fore.WHITE + f"Organization: {geo.get('org', 'N/A')}")
            if geo.get('proxy'):
                print(Fore.YELLOW + "  [!] Proxy/VPN detected")
            if geo.get('hosting'):
                print(Fore.YELLOW + "  [!] Hosting/Datacenter detected")
        
        print(Fore.GREEN + f"\n[+] All scan results saved to: {output_file}")
        if nmap_output:
            print(Fore.GREEN + f"[+] Raw Nmap output saved to: {nmap_output_file}")
        if subdomains:
            print(Fore.GREEN + f"[+] Raw Amass output saved to: {amass_output_file}")
        
    except Exception as e:
        print(Fore.RED + f"\nError during information gathering: {str(e)}")
        return None
    
    return results 
