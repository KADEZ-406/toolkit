import requests
import re
from urllib.parse import urljoin
from colorama import Fore, Style

class SSTIScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.common_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def scan_ssti_vulnerabilities(self):
        print(f"\n{Fore.CYAN}[*] Starting SSTI Vulnerability Scan...{Style.RESET_ALL}")
        
        try:
            # Check for SSTI in GET parameters
            self._check_get_parameters()
            
            # Check for SSTI in POST parameters
            self._check_post_parameters()
            
            # Check for SSTI in cookies
            self._check_cookies()
            
            # Check for SSTI in headers
            self._check_headers()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning for SSTI vulnerabilities: {str(e)}{Style.RESET_ALL}")

    def _check_get_parameters(self):
        # Template engine detection payloads
        template_payloads = {
            'Jinja2': {
                'payloads': [
                    '{{7*7}}',
                    '{{7*\'7\'}}',
                    '{{config}}',
                    '{{self}}',
                    '{{request}}',
                    '{{get_flashed_messages.__globals__.__builtins__}}',
                    '{{url_for.__globals__.__builtins__}}'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'<Config',
                    r'<TemplateReference',
                    r'<Request',
                    r'<built-in function',
                    r'<built-in function'
                ]
            },
            'Twig': {
                'payloads': [
                    '{{7*7}}',
                    '{{7*\'7\'}}',
                    '{{app}}',
                    '{{_self}}',
                    '{{request}}',
                    '{{app.request.server.all|join(\',\')}}'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'<App',
                    r'<TwigTemplate',
                    r'<Request',
                    r'[a-zA-Z0-9_]+'
                ]
            },
            'Django': {
                'payloads': [
                    '{%7*7%}',
                    '{{7*7}}',
                    '{{request}}',
                    '{{settings}}',
                    '{{request|attr(\'__class__\')|attr(\'__init__\')|attr(\'__globals__\')}}'
                ],
                'patterns': [
                    r'49',
                    r'49',
                    r'<WSGIRequest',
                    r'<LazySettings',
                    r'<built-in function'
                ]
            },
            'ERB': {
                'payloads': [
                    '<%=7*7%>',
                    '<%=7*\'7\'%>',
                    '<%=Object.constants%>',
                    '<%=Object.methods%>'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'\[:Object',
                    r'\[:new'
                ]
            },
            'Freemarker': {
                'payloads': [
                    '${7*7}',
                    '${7*\'7\'}',
                    '${.getClass()}',
                    '${.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve(\'../\').normalize().getPath()}'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'class freemarker',
                    r'/[a-zA-Z0-9_/]+'
                ]
            }
        }
        
        for engine, data in template_payloads.items():
            for payload in data['payloads']:
                try:
                    response = requests.get(
                        f"{self.target_url}?q={payload}",
                        headers=self.common_headers,
                        timeout=10
                    )
                    
                    # Check for template engine patterns
                    for pattern in data['patterns']:
                        if re.search(pattern, response.text):
                            self.vulnerabilities.append({
                                'type': f'Server-Side Template Injection ({engine})',
                                'severity': 'High',
                                'description': f'Potential {engine} template injection with payload: {payload}'
                            })
                            break
                except:
                    pass

    def _check_post_parameters(self):
        # Template engine detection payloads
        template_payloads = {
            'Jinja2': {
                'payloads': [
                    '{{7*7}}',
                    '{{7*\'7\'}}',
                    '{{config}}',
                    '{{self}}',
                    '{{request}}',
                    '{{get_flashed_messages.__globals__.__builtins__}}',
                    '{{url_for.__globals__.__builtins__}}'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'<Config',
                    r'<TemplateReference',
                    r'<Request',
                    r'<built-in function',
                    r'<built-in function'
                ]
            },
            'Twig': {
                'payloads': [
                    '{{7*7}}',
                    '{{7*\'7\'}}',
                    '{{app}}',
                    '{{_self}}',
                    '{{request}}',
                    '{{app.request.server.all|join(\',\')}}'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'<App',
                    r'<TwigTemplate',
                    r'<Request',
                    r'[a-zA-Z0-9_]+'
                ]
            },
            'Django': {
                'payloads': [
                    '{%7*7%}',
                    '{{7*7}}',
                    '{{request}}',
                    '{{settings}}',
                    '{{request|attr(\'__class__\')|attr(\'__init__\')|attr(\'__globals__\')}}'
                ],
                'patterns': [
                    r'49',
                    r'49',
                    r'<WSGIRequest',
                    r'<LazySettings',
                    r'<built-in function'
                ]
            },
            'ERB': {
                'payloads': [
                    '<%=7*7%>',
                    '<%=7*\'7\'%>',
                    '<%=Object.constants%>',
                    '<%=Object.methods%>'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'\[:Object',
                    r'\[:new'
                ]
            },
            'Freemarker': {
                'payloads': [
                    '${7*7}',
                    '${7*\'7\'}',
                    '${.getClass()}',
                    '${.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve(\'../\').normalize().getPath()}'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'class freemarker',
                    r'/[a-zA-Z0-9_/]+'
                ]
            }
        }
        
        for engine, data in template_payloads.items():
            for payload in data['payloads']:
                try:
                    response = requests.post(
                        self.target_url,
                        data={'q': payload},
                        headers=self.common_headers,
                        timeout=10
                    )
                    
                    # Check for template engine patterns
                    for pattern in data['patterns']:
                        if re.search(pattern, response.text):
                            self.vulnerabilities.append({
                                'type': f'Server-Side Template Injection ({engine})',
                                'severity': 'High',
                                'description': f'Potential {engine} template injection with payload: {payload}'
                            })
                            break
                except:
                    pass

    def _check_cookies(self):
        # Template engine detection payloads
        template_payloads = {
            'Jinja2': {
                'payloads': [
                    '{{7*7}}',
                    '{{7*\'7\'}}',
                    '{{config}}',
                    '{{self}}',
                    '{{request}}'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'<Config',
                    r'<TemplateReference',
                    r'<Request'
                ]
            },
            'Twig': {
                'payloads': [
                    '{{7*7}}',
                    '{{7*\'7\'}}',
                    '{{app}}',
                    '{{_self}}',
                    '{{request}}'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'<App',
                    r'<TwigTemplate',
                    r'<Request'
                ]
            },
            'Django': {
                'payloads': [
                    '{%7*7%}',
                    '{{7*7}}',
                    '{{request}}',
                    '{{settings}}'
                ],
                'patterns': [
                    r'49',
                    r'49',
                    r'<WSGIRequest',
                    r'<LazySettings'
                ]
            }
        }
        
        for engine, data in template_payloads.items():
            for payload in data['payloads']:
                try:
                    cookies = {
                        'session': payload,
                        'user': payload,
                        'id': payload
                    }
                    
                    response = requests.get(
                        self.target_url,
                        cookies=cookies,
                        headers=self.common_headers,
                        timeout=10
                    )
                    
                    # Check for template engine patterns
                    for pattern in data['patterns']:
                        if re.search(pattern, response.text):
                            self.vulnerabilities.append({
                                'type': f'Server-Side Template Injection ({engine}) in Cookies',
                                'severity': 'High',
                                'description': f'Potential {engine} template injection in cookies with payload: {payload}'
                            })
                            break
                except:
                    pass

    def _check_headers(self):
        # Template engine detection payloads
        template_payloads = {
            'Jinja2': {
                'payloads': [
                    '{{7*7}}',
                    '{{7*\'7\'}}',
                    '{{config}}',
                    '{{self}}',
                    '{{request}}'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'<Config',
                    r'<TemplateReference',
                    r'<Request'
                ]
            },
            'Twig': {
                'payloads': [
                    '{{7*7}}',
                    '{{7*\'7\'}}',
                    '{{app}}',
                    '{{_self}}',
                    '{{request}}'
                ],
                'patterns': [
                    r'49',
                    r'7777777',
                    r'<App',
                    r'<TwigTemplate',
                    r'<Request'
                ]
            },
            'Django': {
                'payloads': [
                    '{%7*7%}',
                    '{{7*7}}',
                    '{{request}}',
                    '{{settings}}'
                ],
                'patterns': [
                    r'49',
                    r'49',
                    r'<WSGIRequest',
                    r'<LazySettings'
                ]
            }
        }
        
        for engine, data in template_payloads.items():
            for payload in data['payloads']:
                try:
                    headers = {
                        **self.common_headers,
                        'X-Forwarded-For': payload,
                        'User-Agent': payload,
                        'Referer': payload
                    }
                    
                    response = requests.get(
                        self.target_url,
                        headers=headers,
                        timeout=10
                    )
                    
                    # Check for template engine patterns
                    for pattern in data['patterns']:
                        if re.search(pattern, response.text):
                            self.vulnerabilities.append({
                                'type': f'Server-Side Template Injection ({engine}) in Headers',
                                'severity': 'High',
                                'description': f'Potential {engine} template injection in headers with payload: {payload}'
                            })
                            break
                except:
                    pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No SSTI vulnerabilities found{Style.RESET_ALL}")
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