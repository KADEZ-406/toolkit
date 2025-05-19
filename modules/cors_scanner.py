import requests
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse
import re
import json
import time
from concurrent.futures import ThreadPoolExecutor

class CORSScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities = []
        
        # Common CORS headers
        self.cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Allow-Credentials',
            'Access-Control-Expose-Headers',
            'Access-Control-Max-Age'
        ]
        
        # Common origins to test
        self.test_origins = [
            'null',
            'http://evil.com',
            'https://evil.com',
            'http://attacker.com',
            'https://attacker.com',
            'http://localhost',
            'http://127.0.0.1',
            'http://example.com',
            'https://example.com'
        ]

    def scan_cors(self) -> Dict[str, List[Dict]]:
        """
        Scan for CORS vulnerabilities
        """
        results = {
            "vulnerabilities": [],
            "details": []
        }
        
        try:
            # Test CORS configuration
            self._test_cors_config()
            results["vulnerabilities"] = self.vulnerabilities
            
            # Add detailed information
            results["details"] = self._get_scan_details(results)
            
        except Exception as e:
            print(f"Error scanning for CORS vulnerabilities: {str(e)}")
            
        return results

    def _test_cors_config(self) -> None:
        """
        Test CORS configuration
        """
        try:
            # Test with different origins
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for origin in self.test_origins:
                    futures.append(executor.submit(self._test_origin, origin))
                    
                for future in futures:
                    vulns = future.result()
                    if vulns:
                        self.vulnerabilities.extend(vulns)
                        
        except Exception as e:
            print(f"Error testing CORS configuration: {str(e)}")

    def _test_origin(self, origin: str) -> List[Dict]:
        """
        Test a specific origin
        """
        vulnerabilities = []
        
        try:
            # Send OPTIONS request
            headers = {
                'Origin': origin,
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'Content-Type'
            }
            
            response = requests.options(self.target_url, headers=headers)
            
            # Check response headers
            if self._check_cors_vulnerability(response, origin):
                vulnerabilities.append({
                    "url": self.target_url,
                    "origin": origin,
                    "type": "CORS Misconfiguration",
                    "details": self._get_vulnerability_details(response, origin)
                })
                
        except Exception as e:
            print(f"Error testing origin {origin}: {str(e)}")
            
        return vulnerabilities

    def _check_cors_vulnerability(self, response: requests.Response, origin: str) -> bool:
        """
        Check if CORS configuration is vulnerable
        """
        try:
            # Get CORS headers
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            # Check for wildcard origin
            if acao == '*':
                return True
                
            # Check for reflected origin
            if acao == origin:
                return True
                
            # Check for credentials with wildcard
            if acac.lower() == 'true' and acao == '*':
                return True
                
            # Check for missing origin validation
            if not acao and origin in response.headers.get('Access-Control-Allow-Origin', ''):
                return True
                
        except:
            pass
            
        return False

    def _get_vulnerability_details(self, response: requests.Response, origin: str) -> Dict:
        """
        Get detailed information about the vulnerability
        """
        risk_level = "High"
        description = "CORS misconfiguration detected"
        remediation = "Implement proper CORS policies"
        impact = "Can lead to unauthorized cross-origin requests"
        
        # Check specific vulnerability type
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == '*':
            description = "Wildcard CORS policy detected"
            remediation = "Restrict Access-Control-Allow-Origin to specific domains"
        elif acao == origin:
            description = "Reflected origin in CORS policy"
            remediation = "Implement strict origin validation"
        elif acac.lower() == 'true' and acao == '*':
            description = "Credentials allowed with wildcard origin"
            remediation = "Restrict Access-Control-Allow-Origin when credentials are allowed"
            
        return {
            "risk_level": risk_level,
            "description": description,
            "remediation": remediation,
            "impact": impact,
            "headers": {
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": acac
            }
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
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Add vulnerability statistics
            vuln_types = {}
            for vuln in results["vulnerabilities"]:
                vuln_type = vuln["type"]
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = 0
                vuln_types[vuln_type] += 1
                
            details.append({
                "vulnerability_types": vuln_types
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