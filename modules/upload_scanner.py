import requests
import os
from colorama import Fore, Style
import mimetypes

class UploadScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.test_files = {
            'php': {
                'content': '<?php echo "PHP Test"; ?>',
                'mime': 'application/x-httpd-php',
                'ext': '.php'
            },
            'jsp': {
                'content': '<%@ page language="java" %><% out.println("JSP Test"); %>',
                'mime': 'application/jsp',
                'ext': '.jsp'
            },
            'asp': {
                'content': '<% Response.Write("ASP Test") %>',
                'mime': 'application/asp',
                'ext': '.asp'
            },
            'aspx': {
                'content': '<%@ Page Language="C#" %><% Response.Write("ASPX Test"); %>',
                'mime': 'application/aspx',
                'ext': '.aspx'
            },
            'html': {
                'content': '<html><body>HTML Test</body></html>',
                'mime': 'text/html',
                'ext': '.html'
            },
            'txt': {
                'content': 'Text Test',
                'mime': 'text/plain',
                'ext': '.txt'
            }
        }

    def scan_upload_vulnerabilities(self):
        print(f"\n{Fore.CYAN}[*] Starting File Upload Vulnerability Scan...{Style.RESET_ALL}")
        
        try:
            # Test each file type
            for file_type, file_info in self.test_files.items():
                print(f"{Fore.CYAN}[*] Testing {file_type} upload...{Style.RESET_ALL}")
                self._test_file_upload(file_type, file_info)
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error during upload scan: {str(e)}{Style.RESET_ALL}")

    def _test_file_upload(self, file_type, file_info):
        try:
            # Create test file
            filename = f"test{file_info['ext']}"
            with open(filename, 'w') as f:
                f.write(file_info['content'])
            
            # Prepare file for upload
            files = {
                'file': (filename, open(filename, 'rb'), file_info['mime'])
            }
            
            # Try different parameter names
            param_names = ['file', 'upload', 'fileupload', 'file_upload', 'uploadfile']
            
            for param in param_names:
                try:
                    # Send POST request
                    response = requests.post(
                        self.target_url,
                        files={param: files['file']},
                        allow_redirects=True
                    )
                    
                    # Check if file was uploaded successfully
                    if self._check_upload_success(response, filename):
                        self.vulnerabilities.append({
                            'type': 'File Upload Vulnerability',
                            'severity': 'High',
                            'description': f'Successfully uploaded {file_type} file using parameter: {param}'
                        })
                        
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error testing parameter {param}: {str(e)}{Style.RESET_ALL}")
            
            # Clean up test file
            os.remove(filename)
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error testing {file_type} upload: {str(e)}{Style.RESET_ALL}")

    def _check_upload_success(self, response, filename):
        # Check response status
        if response.status_code == 200:
            # Check if filename appears in response
            if filename in response.text:
                return True
            
            # Check for common success messages
            success_messages = [
                'upload successful',
                'file uploaded',
                'upload complete',
                'successfully uploaded',
                'file has been uploaded'
            ]
            
            for message in success_messages:
                if message.lower() in response.text.lower():
                    return True
        
        return False

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No file upload vulnerabilities found{Style.RESET_ALL}")
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