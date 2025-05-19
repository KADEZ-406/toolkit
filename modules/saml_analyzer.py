import requests
from colorama import Fore, Style
import base64
import xml.etree.ElementTree as ET
import re
from urllib.parse import urlparse, parse_qs

class SAMLAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.common_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9'
        }

    def analyze_saml(self):
        print(f"\n{Fore.CYAN}[*] Starting SAML Security Analysis...{Style.RESET_ALL}")
        
        try:
            # Check for SAML endpoints
            self._check_saml_endpoints()
            
            # Check for XML signature
            self._check_xml_signature()
            
            # Check for encryption
            self._check_encryption()
            
            # Check for message replay
            self._check_message_replay()
            
            # Check for assertion expiration
            self._check_assertion_expiration()
            
            # Check for audience restriction
            self._check_audience_restriction()
            
            # Check for name ID format
            self._check_name_id_format()
            
            # Check for binding security
            self._check_binding_security()
            
            # Print results
            self._print_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing SAML implementation: {str(e)}{Style.RESET_ALL}")

    def _check_saml_endpoints(self):
        endpoints = [
            '/saml2/sso',
            '/saml2/acs',
            '/saml2/slo',
            '/saml2/metadata',
            '/saml2/wsdl',
            '/saml2/entity',
            '/saml2/idp',
            '/saml2/sp'
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{self.target_url.rstrip('/')}{endpoint}"
                response = requests.get(url, headers=self.common_headers)
                
                if response.status_code != 404:
                    self.vulnerabilities.append({
                        'type': 'SAML Endpoint Found',
                        'severity': 'Info',
                        'description': f'SAML endpoint found: {endpoint}'
                    })
            except:
                pass

    def _check_xml_signature(self):
        try:
            response = requests.get(
                f"{self.target_url}/saml2/metadata",
                headers=self.common_headers
            )
            
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.text)
                    if not root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature'):
                        self.vulnerabilities.append({
                            'type': 'Missing XML Signature',
                            'severity': 'High',
                            'description': 'SAML metadata is not signed'
                        })
                except:
                    pass
        except:
            pass

    def _check_encryption(self):
        try:
            response = requests.get(
                f"{self.target_url}/saml2/metadata",
                headers=self.common_headers
            )
            
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.text)
                    if not root.find('.//{http://www.w3.org/2001/04/xmlenc#}EncryptionMethod'):
                        self.vulnerabilities.append({
                            'type': 'Missing Encryption',
                            'severity': 'High',
                            'description': 'SAML assertions are not encrypted'
                        })
                except:
                    pass
        except:
            pass

    def _check_message_replay(self):
        try:
            response = requests.post(
                f"{self.target_url}/saml2/acs",
                data={'SAMLResponse': 'test'},
                headers=self.common_headers
            )
            
            if response.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'Message Replay Possible',
                    'severity': 'High',
                    'description': 'SAML response may be replayed'
                })
        except:
            pass

    def _check_assertion_expiration(self):
        try:
            response = requests.get(
                f"{self.target_url}/saml2/metadata",
                headers=self.common_headers
            )
            
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.text)
                    if not root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions'):
                        self.vulnerabilities.append({
                            'type': 'Missing Assertion Expiration',
                            'severity': 'High',
                            'description': 'SAML assertions do not have expiration conditions'
                        })
                except:
                    pass
        except:
            pass

    def _check_audience_restriction(self):
        try:
            response = requests.get(
                f"{self.target_url}/saml2/metadata",
                headers=self.common_headers
            )
            
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.text)
                    if not root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction'):
                        self.vulnerabilities.append({
                            'type': 'Missing Audience Restriction',
                            'severity': 'High',
                            'description': 'SAML assertions do not have audience restrictions'
                        })
                except:
                    pass
        except:
            pass

    def _check_name_id_format(self):
        try:
            response = requests.get(
                f"{self.target_url}/saml2/metadata",
                headers=self.common_headers
            )
            
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.text)
                    if not root.find('.//{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat'):
                        self.vulnerabilities.append({
                            'type': 'Missing NameID Format',
                            'severity': 'Medium',
                            'description': 'SAML NameID format is not specified'
                        })
                except:
                    pass
        except:
            pass

    def _check_binding_security(self):
        bindings = [
            'HTTP-POST',
            'HTTP-Redirect',
            'HTTP-Artifact',
            'SOAP'
        ]
        
        for binding in bindings:
            try:
                response = requests.get(
                    f"{self.target_url}/saml2/metadata",
                    headers=self.common_headers
                )
                
                if response.status_code == 200:
                    try:
                        root = ET.fromstring(response.text)
                        if not root.find(f'.//{{urn:oasis:names:tc:SAML:2.0:bindings}}{binding}'):
                            self.vulnerabilities.append({
                                'type': 'Insecure Binding',
                                'severity': 'Medium',
                                'description': f'SAML binding {binding} may not be properly secured'
                            })
                    except:
                        pass
            except:
                pass

    def _print_results(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No SAML vulnerabilities found{Style.RESET_ALL}")
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