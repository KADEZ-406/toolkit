import requests
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
import time
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import defaultdict

class RateLimitScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities = []
        self.endpoints = []
        
        # Common rate limit headers
        self.rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'Retry-After',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'RateLimit-Reset'
        ]
        
        # Test configurations
        self.test_configs = {
            "login": {
                "method": "POST",
                "endpoints": ["/login", "/auth", "/signin", "/user/login"],
                "data": {"username": "test", "password": "test"},
                "threshold": 5  # requests per second
            },
            "api": {
                "method": "GET",
                "endpoints": ["/api/", "/api/v1/", "/api/v2/"],
                "threshold": 10  # requests per second
            },
            "search": {
                "method": "GET",
                "endpoints": ["/search", "/find", "/query"],
                "threshold": 3  # requests per second
            }
        }

    def scan_rate_limits(self) -> Dict[str, List[Dict]]:
        """
        Scan for rate limiting vulnerabilities
        """
        results = {
            "vulnerabilities": [],
            "endpoints": [],
            "details": []
        }
        
        try:
            # Find endpoints
            self._find_endpoints()
            results["endpoints"] = self.endpoints
            
            # Test each endpoint
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for endpoint in self.endpoints:
                    futures.append(executor.submit(self._test_endpoint, endpoint))
                    
                for future in futures:
                    vulns = future.result()
                    if vulns:
                        results["vulnerabilities"].extend(vulns)
                        
            # Add detailed information
            results["details"] = self._get_scan_details(results)
            
        except Exception as e:
            print(f"Error scanning for rate limiting vulnerabilities: {str(e)}")
            
        return results

    def _find_endpoints(self) -> None:
        """
        Find potential endpoints to test
        """
        try:
            response = requests.get(self.target_url)
            content = response.text
            
            # Find links
            link_pattern = r'href=[\'"]([^\'"]*)[\'"]'
            links = re.finditer(link_pattern, content)
            
            for link in links:
                url = urljoin(self.target_url, link.group(1))
                parsed = urlparse(url)
                
                # Check if URL is from same domain
                if parsed.netloc == urlparse(self.target_url).netloc:
                    self.endpoints.append({
                        "url": url,
                        "method": "GET",
                        "type": "link"
                    })
                    
            # Add common endpoints
            for config in self.test_configs.values():
                for endpoint in config["endpoints"]:
                    url = urljoin(self.target_url, endpoint)
                    self.endpoints.append({
                        "url": url,
                        "method": config["method"],
                        "type": "common"
                    })
                    
        except Exception as e:
            print(f"Error finding endpoints: {str(e)}")

    def _test_endpoint(self, endpoint: Dict) -> List[Dict]:
        """
        Test an endpoint for rate limiting vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Find matching test configuration
            config = None
            for test_config in self.test_configs.values():
                if any(ep in endpoint["url"] for ep in test_config["endpoints"]):
                    config = test_config
                    break
                    
            if not config:
                return vulnerabilities
                
            # Test rate limiting
            results = self._perform_rate_test(endpoint, config)
            
            if results["vulnerable"]:
                vulnerabilities.append({
                    "url": endpoint["url"],
                    "method": endpoint["method"],
                    "type": "Rate Limiting",
                    "details": self._get_vulnerability_details(endpoint, results)
                })
                
        except Exception as e:
            print(f"Error testing endpoint {endpoint['url']}: {str(e)}")
            
        return vulnerabilities

    def _perform_rate_test(self, endpoint: Dict, config: Dict) -> Dict:
        """
        Perform rate limit testing
        """
        results = {
            "vulnerable": False,
            "requests_sent": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "response_times": [],
            "status_codes": defaultdict(int)
        }
        
        try:
            # Send requests at high rate
            start_time = time.time()
            while time.time() - start_time < 5:  # Test for 5 seconds
                if endpoint["method"] == "GET":
                    response = requests.get(endpoint["url"], timeout=5)
                else:
                    response = requests.post(endpoint["url"], json=config.get("data", {}), timeout=5)
                    
                results["requests_sent"] += 1
                results["response_times"].append(response.elapsed.total_seconds())
                results["status_codes"][response.status_code] += 1
                
                if response.status_code < 400:
                    results["successful_requests"] += 1
                else:
                    results["failed_requests"] += 1
                    
                # Check for rate limit headers
                if any(header in response.headers for header in self.rate_limit_headers):
                    break
                    
                time.sleep(1 / config["threshold"])  # Control request rate
                
            # Analyze results
            if results["requests_sent"] > config["threshold"] * 5:  # More than threshold * duration
                results["vulnerable"] = True
                
        except Exception as e:
            print(f"Error performing rate test: {str(e)}")
            
        return results

    def _get_vulnerability_details(self, endpoint: Dict, results: Dict) -> Dict:
        """
        Get detailed information about the vulnerability
        """
        risk_level = "Medium"
        description = "Rate limiting vulnerability detected"
        remediation = "Implement proper rate limiting"
        impact = "Can lead to DoS attacks and resource exhaustion"
        
        # Calculate request rate
        request_rate = results["requests_sent"] / 5  # requests per second
        
        if request_rate > 20:
            risk_level = "High"
            description = "Severe rate limiting vulnerability detected"
            remediation = "Implement strict rate limiting and request throttling"
        elif request_rate > 10:
            risk_level = "Medium"
            description = "Moderate rate limiting vulnerability detected"
            remediation = "Implement rate limiting with appropriate thresholds"
            
        return {
            "risk_level": risk_level,
            "description": description,
            "remediation": remediation,
            "impact": impact,
            "request_rate": request_rate,
            "success_rate": results["successful_requests"] / results["requests_sent"] if results["requests_sent"] > 0 else 0,
            "avg_response_time": sum(results["response_times"]) / len(results["response_times"]) if results["response_times"] else 0
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
                "total_endpoints": len(results["endpoints"]),
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