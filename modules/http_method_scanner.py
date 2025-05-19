import requests
from typing import List, Dict, Optional
from urllib.parse import urlparse

class HTTPMethodScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.allowed_methods = []
        self.vulnerable_methods = []
        
        # Common HTTP methods to test
        self.http_methods = [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "HEAD",
            "OPTIONS",
            "TRACE",
            "CONNECT",
            "PATCH",
            "PROPFIND",
            "PROPPATCH",
            "MKCOL",
            "COPY",
            "MOVE",
            "LOCK",
            "UNLOCK"
        ]

    def check_http_methods(self) -> Dict[str, List[str]]:
        """
        Check which HTTP methods are allowed and potentially vulnerable
        """
        results = {
            "allowed_methods": [],
            "vulnerable_methods": [],
            "details": []
        }
        
        try:
            # First check OPTIONS to get allowed methods
            try:
                response = requests.options(self.target_url)
                if "Allow" in response.headers:
                    allowed = response.headers["Allow"].split(",")
                    results["allowed_methods"] = [method.strip() for method in allowed]
            except Exception as e:
                print(f"Error checking OPTIONS method: {str(e)}")
            
            # Test each method
            for method in self.http_methods:
                try:
                    response = requests.request(method, self.target_url)
                    
                    # If method is allowed (not 405 Method Not Allowed)
                    if response.status_code != 405:
                        if method not in results["allowed_methods"]:
                            results["allowed_methods"].append(method)
                        
                        # Check for potential vulnerabilities
                        if self._is_method_vulnerable(method, response):
                            results["vulnerable_methods"].append(method)
                            results["details"].append({
                                "method": method,
                                "status_code": response.status_code,
                                "vulnerability": self._get_vulnerability_type(method, response)
                            })
                            
                except Exception as e:
                    print(f"Error testing {method} method: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"Error checking HTTP methods: {str(e)}")
            
        return results

    def _is_method_vulnerable(self, method: str, response: requests.Response) -> bool:
        """
        Check if a specific HTTP method is potentially vulnerable
        """
        # Check for dangerous methods
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
        if method in dangerous_methods and response.status_code in [200, 201, 204]:
            return True
            
        # Check for sensitive information in response
        sensitive_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
            "X-Runtime",
            "X-Version",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection"
        ]
        
        for header in sensitive_headers:
            if header in response.headers:
                return True
                
        # Check for sensitive content
        sensitive_content = [
            "error",
            "exception",
            "stack trace",
            "debug",
            "warning",
            "notice",
            "undefined",
            "null",
            "undefined",
            "exception",
            "stack trace",
            "debug",
            "warning",
            "notice"
        ]
        
        content = response.text.lower()
        for term in sensitive_content:
            if term in content:
                return True
                
        return False

    def _get_vulnerability_type(self, method: str, response: requests.Response) -> str:
        """
        Determine the type of vulnerability for a specific method
        """
        if method in ["PUT", "DELETE"]:
            return "Dangerous method allowed"
        elif method == "TRACE":
            return "TRACE method enabled (potential XSS)"
        elif method == "CONNECT":
            return "CONNECT method enabled (potential proxy abuse)"
        elif method == "OPTIONS":
            return "Verbose OPTIONS response"
        else:
            return "Sensitive information disclosure"

    def check_method_fuzzing(self) -> Dict[str, List[str]]:
        """
        Fuzz HTTP methods with variations
        """
        results = {
            "vulnerable_methods": [],
            "details": []
        }
        
        # Common method fuzzing variations
        method_variations = [
            "GeT",
            "PoSt",
            "PuT",
            "DeLeTe",
            "HeAd",
            "OpTiOnS",
            "TrAcE",
            "CoNnEcT",
            "PaTcH",
            "GET ",
            "POST ",
            "PUT ",
            "DELETE ",
            "HEAD ",
            "OPTIONS ",
            "TRACE ",
            "CONNECT ",
            "PATCH ",
            "GET/",
            "POST/",
            "PUT/",
            "DELETE/",
            "HEAD/",
            "OPTIONS/",
            "TRACE/",
            "CONNECT/",
            "PATCH/"
        ]
        
        try:
            for method in method_variations:
                try:
                    response = requests.request(method, self.target_url)
                    
                    # If we get a response that's not 405, it might be vulnerable
                    if response.status_code != 405:
                        results["vulnerable_methods"].append(method)
                        results["details"].append({
                            "method": method,
                            "status_code": response.status_code,
                            "response_length": len(response.text)
                        })
                        
                except Exception as e:
                    print(f"Error testing method variation {method}: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"Error during method fuzzing: {str(e)}")
            
        return results

    def check_method_override(self) -> Dict[str, bool]:
        """
        Check for HTTP method override vulnerabilities
        """
        results = {
            "vulnerable": False,
            "details": []
        }
        
        # Common method override headers
        override_headers = {
            "X-HTTP-Method": "PUT",
            "X-HTTP-Method-Override": "PUT",
            "X-Method-Override": "PUT",
            "X-REST-Method": "PUT",
            "X-HTTP-Method": "DELETE",
            "X-HTTP-Method-Override": "DELETE",
            "X-Method-Override": "DELETE",
            "X-REST-Method": "DELETE"
        }
        
        try:
            for header, method in override_headers.items():
                try:
                    # Send POST request with method override header
                    headers = {header: method}
                    response = requests.post(self.target_url, headers=headers)
                    
                    # If we get a response that matches the overridden method
                    if response.status_code in [200, 201, 204]:
                        results["vulnerable"] = True
                        results["details"].append({
                            "header": header,
                            "method": method,
                            "status_code": response.status_code
                        })
                        
                except Exception as e:
                    print(f"Error testing method override {header}: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"Error checking method override: {str(e)}")
            
        return results 