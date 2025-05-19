import requests
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
import time
from concurrent.futures import ThreadPoolExecutor

class RedirectScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities = []
        self.params = []
        
        # Common redirect parameters
        self.redirect_params = [
            'redirect', 'url', 'next', 'target', 'destination',
            'return', 'returnTo', 'return_to', 'returnUrl',
            'returnURL', 'return_url', 'returnUrl', 'returnURL',
            'redir', 'redirect_uri', 'redirect_url', 'redirectUrl',
            'redirectURL', 'redirect_uri', 'redirect_url', 'redirectUrl',
            'redirectURL', 'rurl', 'r_url', 'rUrl', 'rURL',
            'ruri', 'r_uri', 'rUri', 'rURI', 'rto', 'r_to',
            'rTo', 'rTO', 'rpath', 'r_path', 'rPath', 'rPATH'
        ]
        
        # Common redirect payloads
        self.redirect_payloads = [
            '//google.com',
            '//google.com/',
            '//google.com/%2e%2e',
            '//google.com/%2e%2e/',
            '//google.com/%2e%2e%2f',
            '//google.com/%2e%2e%2f/',
            '//google.com/%2f%2e%2e',
            '//google.com/%2f%2e%2e/',
            '//google.com/%2f%2e%2e%2f',
            '//google.com/%2f%2e%2e%2f/',
            '//google.com/%2f..',
            '//google.com/%2f../',
            '//google.com/%2f..%2f',
            '//google.com/%2f..%2f/',
            '//google.com/%2f%2e%2e',
            '//google.com/%2f%2e%2e/',
            '//google.com/%2f%2e%2e%2f',
            '//google.com/%2f%2e%2e%2f/',
            '//google.com/%2f..',
            '//google.com/%2f../',
            '//google.com/%2f..%2f',
            '//google.com/%2f..%2f/',
            '//google.com/%252e%252e',
            '//google.com/%252e%252e/',
            '//google.com/%252e%252e%252f',
            '//google.com/%252e%252e%252f/',
            '//google.com/%252f%252e%252e',
            '//google.com/%252f%252e%252e/',
            '//google.com/%252f%252e%252e%252f',
            '//google.com/%252f%252e%252e%252f/'
        ]

    def scan_redirects(self) -> Dict[str, List[Dict]]:
        """
        Scan for open redirect vulnerabilities
        """
        results = {
            "vulnerabilities": [],
            "params": [],
            "details": []
        }
        
        try:
            # Find redirect parameters
            self._find_redirect_params()
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
            print(f"Error scanning for redirects: {str(e)}")
            
        return results

    def _find_redirect_params(self) -> None:
        """
        Find potential redirect parameters
        """
        try:
            response = requests.get(self.target_url)
            content = response.text
            
            # Find URL parameters
            parsed = urlparse(self.target_url)
            if parsed.query:
                query_params = parse_qs(parsed.query)
                for param in query_params:
                    if param.lower() in self.redirect_params:
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
                    if param.lower() in self.redirect_params:
                        self.params.append({
                            "url": action,
                            "method": method,
                            "param": param,
                            "type": "form"
                        })
                        
        except Exception as e:
            print(f"Error finding redirect parameters: {str(e)}")

    def _test_parameter(self, param: Dict) -> List[Dict]:
        """
        Test a parameter for open redirect vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for payload in self.redirect_payloads:
                # Send request
                if param["method"] == "GET":
                    test_url = f"{param['url']}?{param['param']}={payload}"
                    response = requests.get(test_url, allow_redirects=False)
                else:
                    data = {param["param"]: payload}
                    response = requests.post(param["url"], data=data, allow_redirects=False)
                    
                # Check response
                if self._check_redirect_success(response, payload):
                    vulnerabilities.append({
                        "url": param["url"],
                        "parameter": param["param"],
                        "method": param["method"],
                        "payload": payload,
                        "type": "Open Redirect",
                        "details": self._get_vulnerability_details(param, payload)
                    })
                    
        except Exception as e:
            print(f"Error testing parameter {param['param']}: {str(e)}")
            
        return vulnerabilities

    def _check_redirect_success(self, response: requests.Response, payload: str) -> bool:
        """
        Check if redirect payload was successful
        """
        try:
            # Check for redirect status code
            if response.status_code in [301, 302, 303, 307, 308]:
                # Check Location header
                location = response.headers.get('Location', '')
                if payload in location:
                    return True
                    
        except:
            pass
            
        return False

    def _get_vulnerability_details(self, param: Dict, payload: str) -> Dict:
        """
        Get detailed information about the vulnerability
        """
        return {
            "risk_level": "Medium",
            "description": "Open redirect vulnerability detected",
            "remediation": "Validate and sanitize redirect URLs, use allowlist for allowed domains",
            "impact": "Can be used for phishing attacks by redirecting users to malicious sites"
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