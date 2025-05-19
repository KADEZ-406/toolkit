import jwt
import requests
from datetime import datetime
from colorama import Fore, Style

class JWTScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []

    def scan_jwt(self, token):
        print(f"\n{Fore.CYAN}[*] Starting JWT Token Analysis...{Style.RESET_ALL}")
        
        try:
            # Decode token without verification
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # Check header
            header = jwt.get_unverified_header(token)
            self._check_header_vulnerabilities(header)
            
            # Check payload
            self._check_payload_vulnerabilities(decoded)
            
            # Check signature
            self._check_signature_vulnerabilities(token)
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing JWT token: {str(e)}{Style.RESET_ALL}")

    def _check_header_vulnerabilities(self, header):
        # Check for weak algorithms
        if 'alg' in header:
            if header['alg'] == 'none':
                self.vulnerabilities.append({
                    'type': 'Weak Algorithm',
                    'severity': 'High',
                    'description': 'Token uses "none" algorithm which can be exploited'
                })
            elif header['alg'] in ['HS256', 'HS384', 'HS512']:
                self.vulnerabilities.append({
                    'type': 'Symmetric Algorithm',
                    'severity': 'Medium',
                    'description': 'Token uses symmetric algorithm which may be vulnerable to brute force'
                })

    def _check_payload_vulnerabilities(self, payload):
        # Check expiration
        if 'exp' in payload:
            exp_time = datetime.fromtimestamp(payload['exp'])
            if exp_time < datetime.now():
                self.vulnerabilities.append({
                    'type': 'Expired Token',
                    'severity': 'Low',
                    'description': 'Token has expired'
                })
        
        # Check not before
        if 'nbf' in payload:
            nbf_time = datetime.fromtimestamp(payload['nbf'])
            if nbf_time > datetime.now():
                self.vulnerabilities.append({
                    'type': 'Token Not Yet Valid',
                    'severity': 'Low',
                    'description': 'Token is not yet valid'
                })
        
        # Check issuer
        if 'iss' in payload:
            self.vulnerabilities.append({
                'type': 'Issuer Information',
                'severity': 'Info',
                'description': f'Token issued by: {payload["iss"]}'
            })
        
        # Check audience
        if 'aud' in payload:
            self.vulnerabilities.append({
                'type': 'Audience Information',
                'severity': 'Info',
                'description': f'Token intended for: {payload["aud"]}'
            })

    def _check_signature_vulnerabilities(self, token):
        # Try to verify with empty signature
        try:
            jwt.decode(token, '', algorithms=['HS256', 'HS384', 'HS512'], options={"verify_signature": False})
            self.vulnerabilities.append({
                'type': 'Signature Bypass',
                'severity': 'High',
                'description': 'Token may be vulnerable to signature bypass'
            })
        except:
            pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No vulnerabilities found in JWT token{Style.RESET_ALL}")
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