import requests
import json
from urllib.parse import urljoin
from colorama import Fore, Style

class APIScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.common_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/json'
        }

    def scan_api_security(self):
        print(f"\n{Fore.CYAN}[*] Starting API Security Scan...{Style.RESET_ALL}")
        
        try:
            # Check for common API endpoints
            self._check_common_endpoints()
            
            # Check authentication methods
            self._check_authentication()
            
            # Check for rate limiting
            self._check_rate_limiting()
            
            # Check for CORS configuration
            self._check_cors()
            
            # Check for HTTP methods
            self._check_http_methods()
            
            # Check for sensitive data exposure
            self._check_sensitive_data()
            
            # Check for input validation
            self._check_input_validation()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning API: {str(e)}{Style.RESET_ALL}")

    def _check_common_endpoints(self):
        common_endpoints = [
            '/api/v1/users',
            '/api/v1/auth',
            '/api/v1/login',
            '/api/v1/register',
            '/api/v1/profile',
            '/api/v1/admin',
            '/api/v1/config',
            '/api/v1/status',
            '/api/v1/health',
            '/api/v1/metrics'
        ]
        
        for endpoint in common_endpoints:
            url = urljoin(self.target_url, endpoint)
            try:
                response = requests.get(url, headers=self.common_headers, timeout=5)
                if response.status_code != 404:
                    self.vulnerabilities.append({
                        'type': 'Exposed API Endpoint',
                        'severity': 'Medium',
                        'description': f'Found accessible endpoint: {endpoint} (Status: {response.status_code})'
                    })
            except:
                pass

    def _check_authentication(self):
        auth_endpoints = [
            '/api/v1/auth',
            '/api/v1/login',
            '/api/v1/register'
        ]
        
        for endpoint in auth_endpoints:
            url = urljoin(self.target_url, endpoint)
            try:
                # Test with empty credentials
                response = requests.post(
                    url,
                    json={},
                    headers=self.common_headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Weak Authentication',
                        'severity': 'High',
                        'description': f'Endpoint {endpoint} accepts empty credentials'
                    })
            except:
                pass

    def _check_rate_limiting(self):
        try:
            # Send multiple requests in quick succession
            for _ in range(10):
                response = requests.get(
                    self.target_url,
                    headers=self.common_headers,
                    timeout=5
                )
            
            # Check if any rate limiting headers are present
            rate_limit_headers = [
                'X-RateLimit-Limit',
                'X-RateLimit-Remaining',
                'X-RateLimit-Reset',
                'Retry-After'
            ]
            
            if not any(header in response.headers for header in rate_limit_headers):
                self.vulnerabilities.append({
                    'type': 'No Rate Limiting',
                    'severity': 'Medium',
                    'description': 'API does not implement rate limiting'
                })
        except:
            pass

    def _check_cors(self):
        try:
            response = requests.options(
                self.target_url,
                headers={
                    **self.common_headers,
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'GET'
                },
                timeout=5
            )
            
            if 'Access-Control-Allow-Origin' in response.headers:
                if response.headers['Access-Control-Allow-Origin'] == '*':
                    self.vulnerabilities.append({
                        'type': 'Insecure CORS',
                        'severity': 'High',
                        'description': 'API allows requests from any origin (Access-Control-Allow-Origin: *)'
                    })
        except:
            pass

    def _check_http_methods(self):
        try:
            response = requests.options(
                self.target_url,
                headers=self.common_headers,
                timeout=5
            )
            
            if 'Allow' in response.headers:
                methods = response.headers['Allow'].split(',')
                if 'PUT' in methods or 'DELETE' in methods:
                    self.vulnerabilities.append({
                        'type': 'Potentially Dangerous Methods',
                        'severity': 'Medium',
                        'description': f'API allows potentially dangerous methods: {", ".join(methods)}'
                    })
        except:
            pass

    def _check_sensitive_data(self):
        try:
            response = requests.get(
                self.target_url,
                headers=self.common_headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.text.lower()
                sensitive_patterns = [
                    'password',
                    'token',
                    'key',
                    'secret',
                    'credential',
                    'api_key',
                    'private',
                    'admin'
                ]
                
                for pattern in sensitive_patterns:
                    if pattern in data:
                        self.vulnerabilities.append({
                            'type': 'Sensitive Data Exposure',
                            'severity': 'High',
                            'description': f'API response contains potentially sensitive data: {pattern}'
                        })
        except:
            pass

    def _check_input_validation(self):
        test_payloads = [
            {"input": "' OR '1'='1"},
            {"input": "<script>alert(1)</script>"},
            {"input": "../../../etc/passwd"},
            {"input": "'; DROP TABLE users; --"}
        ]
        
        for payload in test_payloads:
            try:
                response = requests.post(
                    self.target_url,
                    json=payload,
                    headers=self.common_headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Weak Input Validation',
                        'severity': 'High',
                        'description': f'API accepts potentially malicious input: {payload}'
                    })
            except:
                pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No vulnerabilities found in API{Style.RESET_ALL}")
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