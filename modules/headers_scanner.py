import requests
from colorama import Fore, Style

class HeadersScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.common_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9'
        }

    def scan_security_headers(self):
        print(f"\n{Fore.CYAN}[*] Starting HTTP Security Headers Scan...{Style.RESET_ALL}")
        
        try:
            response = requests.get(self.target_url, headers=self.common_headers, timeout=10)
            headers = response.headers

            # Check Content Security Policy
            self._check_csp(headers)
            
            # Check X-Frame-Options
            self._check_x_frame_options(headers)
            
            # Check X-Content-Type-Options
            self._check_x_content_type_options(headers)
            
            # Check Strict-Transport-Security
            self._check_hsts(headers)
            
            # Check X-XSS-Protection
            self._check_xss_protection(headers)
            
            # Check Referrer-Policy
            self._check_referrer_policy(headers)
            
            # Check Feature-Policy
            self._check_feature_policy(headers)
            
            # Check Permissions-Policy
            self._check_permissions_policy(headers)
            
            # Check Cache-Control
            self._check_cache_control(headers)
            
            # Check Clear-Site-Data
            self._check_clear_site_data(headers)
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning security headers: {str(e)}{Style.RESET_ALL}")

    def _check_csp(self, headers):
        if 'Content-Security-Policy' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing Content Security Policy',
                'severity': 'High',
                'description': 'Content-Security-Policy header is not set, which helps prevent XSS attacks'
            })
        else:
            csp = headers['Content-Security-Policy']
            if "default-src 'none'" not in csp and "default-src 'self'" not in csp:
                self.vulnerabilities.append({
                    'type': 'Weak Content Security Policy',
                    'severity': 'Medium',
                    'description': 'Content-Security-Policy may be too permissive'
                })

    def _check_x_frame_options(self, headers):
        if 'X-Frame-Options' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing X-Frame-Options',
                'severity': 'High',
                'description': 'X-Frame-Options header is not set, which helps prevent clickjacking attacks'
            })
        else:
            xfo = headers['X-Frame-Options']
            if xfo.lower() not in ['deny', 'sameorigin']:
                self.vulnerabilities.append({
                    'type': 'Invalid X-Frame-Options',
                    'severity': 'Medium',
                    'description': f'X-Frame-Options has invalid value: {xfo}'
                })

    def _check_x_content_type_options(self, headers):
        if 'X-Content-Type-Options' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing X-Content-Type-Options',
                'severity': 'Medium',
                'description': 'X-Content-Type-Options header is not set, which helps prevent MIME-sniffing'
            })
        else:
            xcto = headers['X-Content-Type-Options']
            if xcto.lower() != 'nosniff':
                self.vulnerabilities.append({
                    'type': 'Invalid X-Content-Type-Options',
                    'severity': 'Medium',
                    'description': f'X-Content-Type-Options has invalid value: {xcto}'
                })

    def _check_hsts(self, headers):
        if 'Strict-Transport-Security' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing HSTS',
                'severity': 'High',
                'description': 'Strict-Transport-Security header is not set, which helps prevent protocol downgrade attacks'
            })
        else:
            hsts = headers['Strict-Transport-Security']
            if 'max-age=' not in hsts:
                self.vulnerabilities.append({
                    'type': 'Weak HSTS Configuration',
                    'severity': 'Medium',
                    'description': 'HSTS max-age directive is missing'
                })

    def _check_xss_protection(self, headers):
        if 'X-XSS-Protection' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing X-XSS-Protection',
                'severity': 'Medium',
                'description': 'X-XSS-Protection header is not set, which helps prevent XSS attacks in older browsers'
            })
        else:
            xss = headers['X-XSS-Protection']
            if xss != '1; mode=block':
                self.vulnerabilities.append({
                    'type': 'Weak X-XSS-Protection',
                    'severity': 'Low',
                    'description': f'X-XSS-Protection has non-optimal value: {xss}'
                })

    def _check_referrer_policy(self, headers):
        if 'Referrer-Policy' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing Referrer-Policy',
                'severity': 'Medium',
                'description': 'Referrer-Policy header is not set, which helps control referrer information'
            })
        else:
            rp = headers['Referrer-Policy']
            if rp.lower() not in ['no-referrer', 'strict-origin-when-cross-origin', 'same-origin']:
                self.vulnerabilities.append({
                    'type': 'Weak Referrer-Policy',
                    'severity': 'Low',
                    'description': f'Referrer-Policy has potentially weak value: {rp}'
                })

    def _check_feature_policy(self, headers):
        if 'Feature-Policy' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing Feature-Policy',
                'severity': 'Low',
                'description': 'Feature-Policy header is not set, which helps control browser features'
            })

    def _check_permissions_policy(self, headers):
        if 'Permissions-Policy' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing Permissions-Policy',
                'severity': 'Low',
                'description': 'Permissions-Policy header is not set, which helps control browser permissions'
            })

    def _check_cache_control(self, headers):
        if 'Cache-Control' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing Cache-Control',
                'severity': 'Low',
                'description': 'Cache-Control header is not set, which helps control caching behavior'
            })
        else:
            cc = headers['Cache-Control']
            if 'no-store' not in cc and 'private' not in cc:
                self.vulnerabilities.append({
                    'type': 'Weak Cache-Control',
                    'severity': 'Low',
                    'description': 'Cache-Control may allow sensitive content to be cached'
                })

    def _check_clear_site_data(self, headers):
        if 'Clear-Site-Data' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing Clear-Site-Data',
                'severity': 'Low',
                'description': 'Clear-Site-Data header is not set, which helps clear browsing data'
            })

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No security header vulnerabilities found{Style.RESET_ALL}")
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