import requests
from colorama import Fore, Style
import urllib.parse

class CachePoisoningScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.common_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9'
        }

    def scan_cache_poisoning(self):
        print(f"\n{Fore.CYAN}[*] Starting Web Cache Poisoning Scan...{Style.RESET_ALL}")
        
        try:
            # Check for cache control headers
            self._check_cache_headers()
            
            # Test for unkeyed headers
            self._check_unkeyed_headers()
            
            # Test for parameter pollution
            self._check_parameter_pollution()
            
            # Test for cache key injection
            self._check_cache_key_injection()
            
            # Test for cache deception
            self._check_cache_deception()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning for cache poisoning: {str(e)}{Style.RESET_ALL}")

    def _check_cache_headers(self):
        try:
            response = requests.get(self.target_url, headers=self.common_headers)
            headers = response.headers
            
            if 'Cache-Control' not in headers:
                self.vulnerabilities.append({
                    'type': 'Missing Cache-Control Header',
                    'severity': 'High',
                    'description': 'Cache-Control header is not set, which may allow cache poisoning'
                })
            elif 'no-store' not in headers['Cache-Control'] and 'private' not in headers['Cache-Control']:
                self.vulnerabilities.append({
                    'type': 'Weak Cache-Control Header',
                    'severity': 'Medium',
                    'description': 'Cache-Control header may allow caching of sensitive content'
                })
        except:
            pass

    def _check_unkeyed_headers(self):
        unkeyed_headers = [
            'X-Forwarded-Host',
            'X-Host',
            'X-Forwarded-Server',
            'X-HTTP-Host-Override',
            'X-Original-URL',
            'X-Rewrite-URL'
        ]
        
        for header in unkeyed_headers:
            try:
                headers = self.common_headers.copy()
                headers[header] = 'evil.com'
                response = requests.get(self.target_url, headers=headers)
                
                if 'evil.com' in response.text:
                    self.vulnerabilities.append({
                        'type': 'Unkeyed Header Found',
                        'severity': 'High',
                        'description': f'Header {header} is not included in cache key'
                    })
            except:
                pass

    def _check_parameter_pollution(self):
        params = {
            'utm_source': 'evil',
            'utm_medium': 'evil',
            'utm_campaign': 'evil',
            'ref': 'evil',
            'source': 'evil',
            'origin': 'evil'
        }
        
        try:
            response = requests.get(self.target_url, params=params)
            if any(param in response.text for param in params.values()):
                self.vulnerabilities.append({
                    'type': 'Parameter Pollution Possible',
                    'severity': 'Medium',
                    'description': 'URL parameters may be used in cache key generation'
                })
        except:
            pass

    def _check_cache_key_injection(self):
        injection_points = [
            '?x=1',
            '?x=1&y=2',
            '?x=1&y=2&z=3',
            '?utm_source=1',
            '?ref=1',
            '?source=1'
        ]
        
        for point in injection_points:
            try:
                url = f"{self.target_url}{point}"
                response1 = requests.get(url, headers=self.common_headers)
                response2 = requests.get(url, headers=self.common_headers)
                
                if response1.text == response2.text and 'Cache-Control' not in response1.headers:
                    self.vulnerabilities.append({
                        'type': 'Cache Key Injection Possible',
                        'severity': 'High',
                        'description': f'URL parameter {point} may be used in cache key'
                    })
            except:
                pass

    def _check_cache_deception(self):
        paths = [
            '/.css',
            '/.js',
            '/.png',
            '/.jpg',
            '/.gif',
            '/.ico'
        ]
        
        for path in paths:
            try:
                url = urllib.parse.urljoin(self.target_url, path)
                response = requests.get(url, headers=self.common_headers)
                
                if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    self.vulnerabilities.append({
                        'type': 'Cache Deception Possible',
                        'severity': 'High',
                        'description': f'Path {path} may be vulnerable to cache deception'
                    })
            except:
                pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No cache poisoning vulnerabilities found{Style.RESET_ALL}")
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