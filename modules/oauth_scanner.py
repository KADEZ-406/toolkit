import requests
from colorama import Fore, Style
import json
import re
from urllib.parse import urlparse, parse_qs

class OAuthScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.common_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9'
        }

    def scan_oauth(self):
        print(f"\n{Fore.CYAN}[*] Starting OAuth Security Scan...{Style.RESET_ALL}")
        
        try:
            # Check for OAuth endpoints
            self._check_oauth_endpoints()
            
            # Check for state parameter
            self._check_state_parameter()
            
            # Check for PKCE implementation
            self._check_pkce()
            
            # Check for scope validation
            self._check_scope_validation()
            
            # Check for token handling
            self._check_token_handling()
            
            # Check for redirect URI validation
            self._check_redirect_uri()
            
            # Check for CSRF protection
            self._check_csrf_protection()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning OAuth implementation: {str(e)}{Style.RESET_ALL}")

    def _check_oauth_endpoints(self):
        endpoints = [
            '/oauth/authorize',
            '/oauth/token',
            '/oauth/revoke',
            '/oauth/introspect',
            '/oauth/userinfo',
            '/oauth/keys',
            '/oauth/.well-known/openid-configuration'
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{self.target_url.rstrip('/')}{endpoint}"
                response = requests.get(url, headers=self.common_headers)
                
                if response.status_code != 404:
                    self.vulnerabilities.append({
                        'type': 'OAuth Endpoint Found',
                        'severity': 'Info',
                        'description': f'OAuth endpoint found: {endpoint}'
                    })
            except:
                pass

    def _check_state_parameter(self):
        try:
            response = requests.get(
                f"{self.target_url}/oauth/authorize",
                params={'response_type': 'code', 'client_id': 'test'},
                headers=self.common_headers
            )
            
            if 'state' not in response.text:
                self.vulnerabilities.append({
                    'type': 'Missing State Parameter',
                    'severity': 'High',
                    'description': 'OAuth implementation does not use state parameter for CSRF protection'
                })
        except:
            pass

    def _check_pkce(self):
        try:
            response = requests.get(
                f"{self.target_url}/oauth/authorize",
                params={
                    'response_type': 'code',
                    'client_id': 'test',
                    'code_challenge': 'test',
                    'code_challenge_method': 'S256'
                },
                headers=self.common_headers
            )
            
            if 'code_challenge' not in response.text:
                self.vulnerabilities.append({
                    'type': 'Missing PKCE Support',
                    'severity': 'High',
                    'description': 'OAuth implementation does not support PKCE for public clients'
                })
        except:
            pass

    def _check_scope_validation(self):
        scopes = [
            'openid',
            'profile',
            'email',
            'address',
            'phone',
            'offline_access',
            'admin',
            'superuser'
        ]
        
        for scope in scopes:
            try:
                response = requests.get(
                    f"{self.target_url}/oauth/authorize",
                    params={
                        'response_type': 'code',
                        'client_id': 'test',
                        'scope': scope
                    },
                    headers=self.common_headers
                )
                
                if scope in response.text:
                    self.vulnerabilities.append({
                        'type': 'Scope Validation Issue',
                        'severity': 'Medium',
                        'description': f'Scope {scope} may be accepted without proper validation'
                    })
            except:
                pass

    def _check_token_handling(self):
        try:
            response = requests.post(
                f"{self.target_url}/oauth/token",
                data={
                    'grant_type': 'authorization_code',
                    'code': 'test',
                    'client_id': 'test',
                    'client_secret': 'test'
                },
                headers=self.common_headers
            )
            
            if response.status_code == 200:
                try:
                    token_data = response.json()
                    if 'access_token' in token_data:
                        if 'expires_in' not in token_data:
                            self.vulnerabilities.append({
                                'type': 'Missing Token Expiration',
                                'severity': 'High',
                                'description': 'Access token does not have expiration time'
                            })
                        if 'refresh_token' not in token_data:
                            self.vulnerabilities.append({
                                'type': 'Missing Refresh Token',
                                'severity': 'Medium',
                                'description': 'No refresh token provided'
                            })
                except:
                    pass
        except:
            pass

    def _check_redirect_uri(self):
        redirect_uris = [
            'https://evil.com/callback',
            'http://localhost/callback',
            'http://127.0.0.1/callback',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>'
        ]
        
        for uri in redirect_uris:
            try:
                response = requests.get(
                    f"{self.target_url}/oauth/authorize",
                    params={
                        'response_type': 'code',
                        'client_id': 'test',
                        'redirect_uri': uri
                    },
                    headers=self.common_headers
                )
                
                if uri in response.text:
                    self.vulnerabilities.append({
                        'type': 'Redirect URI Validation Issue',
                        'severity': 'High',
                        'description': f'Redirect URI {uri} may be accepted without proper validation'
                    })
            except:
                pass

    def _check_csrf_protection(self):
        try:
            response = requests.get(
                f"{self.target_url}/oauth/authorize",
                params={'response_type': 'code', 'client_id': 'test'},
                headers=self.common_headers
            )
            
            if 'csrf' not in response.text.lower() and 'xsrf' not in response.text.lower():
                self.vulnerabilities.append({
                    'type': 'Missing CSRF Protection',
                    'severity': 'High',
                    'description': 'No CSRF protection found in OAuth flow'
                })
        except:
            pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No OAuth vulnerabilities found{Style.RESET_ALL}")
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