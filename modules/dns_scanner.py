import dns.zone
import dns.resolver
import socket
from colorama import Fore, Style

class DNSScanner:
    def __init__(self, domain):
        self.domain = domain
        self.vulnerabilities = []
        self.nameservers = []

    def check_zone_transfer(self):
        print(f"\n{Fore.CYAN}[*] Starting DNS Zone Transfer Check...{Style.RESET_ALL}")
        
        try:
            # Get nameservers
            self._get_nameservers()
            
            # Check zone transfer
            self._check_zone_transfer()
            
            # Check DNS records
            self._check_dns_records()
            
            # Check DNS security
            self._check_dns_security()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning DNS: {str(e)}{Style.RESET_ALL}")

    def _get_nameservers(self):
        try:
            answers = dns.resolver.resolve(self.domain, 'NS')
            for rdata in answers:
                self.nameservers.append(str(rdata))
                print(f"{Fore.GREEN}[+] Found nameserver: {str(rdata)}{Style.RESET_ALL}")
        except Exception as e:
            self.vulnerabilities.append({
                'type': 'Nameserver Resolution Failed',
                'severity': 'High',
                'description': f'Could not resolve nameservers: {str(e)}'
            })

    def _check_zone_transfer(self):
        if not self.nameservers:
            return
            
        for nameserver in self.nameservers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(nameserver, self.domain))
                if zone:
                    self.vulnerabilities.append({
                        'type': 'Zone Transfer Allowed',
                        'severity': 'High',
                        'description': f'Zone transfer allowed from nameserver: {nameserver}'
                    })
                    
                    # Print zone contents
                    print(f"\n{Fore.YELLOW}[!] Zone contents from {nameserver}:{Style.RESET_ALL}")
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            print(f"{name} {rdataset}")
            except:
                pass

    def _check_dns_records(self):
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'SRV', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                print(f"\n{Fore.GREEN}[+] {record_type} Records:{Style.RESET_ALL}")
                for rdata in answers:
                    print(f"  {rdata}")
            except:
                pass

    def _check_dns_security(self):
        # Check for DNSSEC
        try:
            answers = dns.resolver.resolve(self.domain, 'DNSKEY')
            if not answers:
                self.vulnerabilities.append({
                    'type': 'DNSSEC Not Configured',
                    'severity': 'Medium',
                    'description': 'Domain does not use DNSSEC for DNS security'
                })
        except:
            self.vulnerabilities.append({
                'type': 'DNSSEC Not Configured',
                'severity': 'Medium',
                'description': 'Domain does not use DNSSEC for DNS security'
            })
        
        # Check for SPF record
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            spf_found = False
            for rdata in answers:
                if 'v=spf1' in str(rdata):
                    spf_found = True
                    break
            if not spf_found:
                self.vulnerabilities.append({
                    'type': 'Missing SPF Record',
                    'severity': 'Medium',
                    'description': 'Domain does not have an SPF record for email authentication'
                })
        except:
            self.vulnerabilities.append({
                'type': 'Missing SPF Record',
                'severity': 'Medium',
                'description': 'Domain does not have an SPF record for email authentication'
            })
        
        # Check for DMARC record
        try:
            answers = dns.resolver.resolve(f'_dmarc.{self.domain}', 'TXT')
            if not answers:
                self.vulnerabilities.append({
                    'type': 'Missing DMARC Record',
                    'severity': 'Medium',
                    'description': 'Domain does not have a DMARC record for email authentication'
                })
        except:
            self.vulnerabilities.append({
                'type': 'Missing DMARC Record',
                'severity': 'Medium',
                'description': 'Domain does not have a DMARC record for email authentication'
            })

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No vulnerabilities found in DNS configuration{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}[!] Found {len(self.vulnerabilities)} potential issues:{Style.RESET_ALL}")
        for vuln in self.vulnerabilities:
            severity_color = {
                'High': Fore.RED,
                'Medium': Fore.YELLOW,
                'Low': Fore.BLUE,
                'Info': Fore.CYAN
            }.get(vuln['severity'], Fore.WHITE)
            
            print(f"\n{severity_color}[{vuln['severity']}] {vuln['type']}{Style.RESET_ALL}")
            print(f"Description: {vuln['description']}") 