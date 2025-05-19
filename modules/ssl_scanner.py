import ssl
import socket
import OpenSSL
from datetime import datetime
from colorama import Fore, Style

class SSLScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.hostname = target_url.split('://')[-1].split('/')[0]
        self.port = 443

    def scan_ssl_vulnerabilities(self):
        print(f"\n{Fore.CYAN}[*] Starting SSL/TLS Vulnerability Scan...{Style.RESET_ALL}")
        
        try:
            # Check certificate
            self._check_certificate()
            
            # Check SSL/TLS version
            self._check_ssl_version()
            
            # Check cipher suites
            self._check_cipher_suites()
            
            # Check for common vulnerabilities
            self._check_common_vulnerabilities()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning SSL/TLS: {str(e)}{Style.RESET_ALL}")

    def _check_certificate(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        self.vulnerabilities.append({
                            'type': 'Expired Certificate',
                            'severity': 'High',
                            'description': f'Certificate expired on {not_after}'
                        })
                    
                    # Check issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    print(f"\n{Fore.GREEN}[+] Certificate Issuer: {issuer.get('organizationName', 'Unknown')}{Style.RESET_ALL}")
                    
                    # Check subject
                    subject = dict(x[0] for x in cert['subject'])
                    print(f"{Fore.GREEN}[+] Certificate Subject: {subject.get('commonName', 'Unknown')}{Style.RESET_ALL}")
                    
                    # Check validity period
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    validity_period = not_after - not_before
                    if validity_period.days > 365:
                        self.vulnerabilities.append({
                            'type': 'Long Certificate Validity',
                            'severity': 'Medium',
                            'description': f'Certificate valid for {validity_period.days} days'
                        })
        except ssl.SSLError as e:
            self.vulnerabilities.append({
                'type': 'SSL Error',
                'severity': 'High',
                'description': f'SSL error: {str(e)}'
            })
        except Exception as e:
            self.vulnerabilities.append({
                'type': 'Certificate Error',
                'severity': 'High',
                'description': f'Error checking certificate: {str(e)}'
            })

    def _check_ssl_version(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    version = ssock.version()
                    print(f"\n{Fore.GREEN}[+] SSL/TLS Version: {version}{Style.RESET_ALL}")
                    
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.vulnerabilities.append({
                            'type': 'Weak SSL/TLS Version',
                            'severity': 'High',
                            'description': f'Using outdated SSL/TLS version: {version}'
                        })
        except:
            pass

    def _check_cipher_suites(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cipher = ssock.cipher()
                    print(f"\n{Fore.GREEN}[+] Cipher Suite: {cipher[0]}{Style.RESET_ALL}")
                    
                    weak_ciphers = [
                        'RC4',
                        'DES',
                        '3DES',
                        'MD5',
                        'NULL',
                        'EXPORT'
                    ]
                    
                    for weak in weak_ciphers:
                        if weak in cipher[0]:
                            self.vulnerabilities.append({
                                'type': 'Weak Cipher Suite',
                                'severity': 'High',
                                'description': f'Using weak cipher suite: {cipher[0]}'
                            })
                            break
        except:
            pass

    def _check_common_vulnerabilities(self):
        # Check for Heartbleed
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    if ssock.version() == 'TLSv1.2':
                        self.vulnerabilities.append({
                            'type': 'Potential Heartbleed',
                            'severity': 'High',
                            'description': 'Server may be vulnerable to Heartbleed (CVE-2014-0160)'
                        })
        except:
            pass
        
        # Check for BEAST
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    if 'CBC' in ssock.cipher()[0]:
                        self.vulnerabilities.append({
                            'type': 'Potential BEAST',
                            'severity': 'Medium',
                            'description': 'Server may be vulnerable to BEAST attack (CVE-2011-3389)'
                        })
        except:
            pass
        
        # Check for POODLE
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    if 'CBC' in ssock.cipher()[0]:
                        self.vulnerabilities.append({
                            'type': 'Potential POODLE',
                            'severity': 'High',
                            'description': 'Server may be vulnerable to POODLE attack (CVE-2014-3566)'
                        })
        except:
            pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No vulnerabilities found in SSL/TLS configuration{Style.RESET_ALL}")
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