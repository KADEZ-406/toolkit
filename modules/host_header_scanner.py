import requests
from typing import List, Dict, Optional
from urllib.parse import urlparse

class HostHeaderScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerable = False
        self.vulnerable_headers = []
        
        # Common host header injection payloads
        self.host_payloads = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "example.com",
            "attacker.com",
            "localhost:80",
            "localhost:443",
            "127.0.0.1:80",
            "127.0.0.1:443",
            "localhost:8080",
            "127.0.0.1:8080",
            "localhost:8443",
            "127.0.0.1:8443",
            "localhost:3000",
            "127.0.0.1:3000",
            "localhost:5000",
            "127.0.0.1:5000",
            "localhost:8000",
            "127.0.0.1:8000",
            "localhost:9000",
            "127.0.0.1:9000"
        ]

    def check_host_header(self) -> Dict[str, bool]:
        """
        Check for host header injection vulnerabilities
        """
        results = {
            "vulnerable": False,
            "vulnerable_headers": [],
            "details": []
        }
        
        try:
            # Get original response for comparison
            original_response = requests.get(self.target_url)
            original_content = original_response.text
            original_status = original_response.status_code
            
            for payload in self.host_payloads:
                headers = {
                    "Host": payload,
                    "X-Forwarded-Host": payload,
                    "X-Host": payload,
                    "X-Forwarded-Server": payload,
                    "X-HTTP-Host-Override": payload,
                    "Forwarded": f"host={payload}"
                }
                
                try:
                    response = requests.get(self.target_url, headers=headers)
                    
                    # Check if response differs from original
                    if response.text != original_content or response.status_code != original_status:
                        results["vulnerable"] = True
                        results["vulnerable_headers"].append(payload)
                        results["details"].append({
                            "payload": payload,
                            "status_code": response.status_code,
                            "content_length": len(response.text),
                            "original_content_length": len(original_content)
                        })
                        
                except Exception as e:
                    print(f"Error testing payload {payload}: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"Error checking host header: {str(e)}")
            
        return results

    def check_redirect_vulnerability(self) -> Dict[str, bool]:
        """
        Check if the application is vulnerable to host header injection via redirects
        """
        results = {
            "vulnerable": False,
            "vulnerable_headers": [],
            "details": []
        }
        
        try:
            for payload in self.host_payloads:
                headers = {
                    "Host": payload,
                    "X-Forwarded-Host": payload,
                    "X-Host": payload,
                    "X-Forwarded-Server": payload,
                    "X-HTTP-Host-Override": payload,
                    "Forwarded": f"host={payload}"
                }
                
                try:
                    response = requests.get(self.target_url, headers=headers, allow_redirects=False)
                    
                    # Check if there's a redirect
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("Location", "")
                        if payload in location:
                            results["vulnerable"] = True
                            results["vulnerable_headers"].append(payload)
                            results["details"].append({
                                "payload": payload,
                                "status_code": response.status_code,
                                "location": location
                            })
                            
                except Exception as e:
                    print(f"Error testing redirect with payload {payload}: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"Error checking redirect vulnerability: {str(e)}")
            
        return results

    def check_cache_poisoning(self) -> Dict[str, bool]:
        """
        Check if the application is vulnerable to cache poisoning via host header
        """
        results = {
            "vulnerable": False,
            "vulnerable_headers": [],
            "details": []
        }
        
        try:
            for payload in self.host_payloads:
                headers = {
                    "Host": payload,
                    "X-Forwarded-Host": payload,
                    "X-Host": payload,
                    "X-Forwarded-Server": payload,
                    "X-HTTP-Host-Override": payload,
                    "Forwarded": f"host={payload}",
                    "Cache-Control": "no-cache"
                }
                
                try:
                    response = requests.get(self.target_url, headers=headers)
                    
                    # Check for cache-related headers
                    cache_headers = [
                        "X-Cache",
                        "X-Cache-Hit",
                        "Age",
                        "Cache-Control",
                        "ETag",
                        "Last-Modified"
                    ]
                    
                    for header in cache_headers:
                        if header in response.headers:
                            results["vulnerable"] = True
                            results["vulnerable_headers"].append(payload)
                            results["details"].append({
                                "payload": payload,
                                "header": header,
                                "value": response.headers[header]
                            })
                            
                except Exception as e:
                    print(f"Error testing cache poisoning with payload {payload}: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"Error checking cache poisoning: {str(e)}")
            
        return results 