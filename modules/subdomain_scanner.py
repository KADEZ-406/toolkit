import requests
import dns.resolver
import socket
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import re
import json
import time

class SubdomainScanner:
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.subdomains = set()
        self.vulnerable_subdomains = []
        
        # Common DNS record types to check
        self.dns_record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        # Common subdomain takeover indicators
        self.takeover_indicators = {
            'github': ['github.io', 'githubusercontent.com'],
            'heroku': ['herokuapp.com'],
            'aws': ['amazonaws.com', 'cloudfront.net', 's3.amazonaws.com'],
            'azure': ['azurewebsites.net', 'cloudapp.net'],
            'google': ['googleusercontent.com', 'appspot.com'],
            'cloudflare': ['cloudflare.com', 'workers.dev'],
            'netlify': ['netlify.app'],
            'vercel': ['vercel.app', 'now.sh'],
            'firebase': ['firebaseapp.com', 'web.app'],
            'shopify': ['myshopify.com']
        }

    def scan_subdomains(self) -> Dict[str, List[Dict]]:
        """
        Scan for subdomains using multiple techniques
        """
        results = {
            "subdomains": [],
            "vulnerable_subdomains": [],
            "details": []
        }
        
        try:
            # Use multiple enumeration techniques
            self._bruteforce_subdomains()
            self._check_dns_records()
            self._check_certificate_transparency()
            
            # Convert subdomains to list and add details
            results["subdomains"] = [{"subdomain": sub} for sub in self.subdomains]
            
            # Check for subdomain takeover
            results["vulnerable_subdomains"] = self.check_subdomain_takeover()
            
            # Add detailed information
            results["details"] = self._get_scan_details(results)
            
        except Exception as e:
            print(f"Error scanning subdomains: {str(e)}")
            
        return results

    def _bruteforce_subdomains(self) -> None:
        """
        Bruteforce subdomains using common prefixes
        """
        try:
            # Common subdomain prefixes
            prefixes = [
                'www', 'mail', 'ftp', 'smtp', 'pop', 'webmail',
                'admin', 'blog', 'dev', 'test', 'stage', 'staging',
                'api', 'app', 'beta', 'cdn', 'cloud', 'demo',
                'docs', 'download', 'forum', 'help', 'img', 'images',
                'login', 'm', 'mobile', 'new', 'old', 'portal',
                'shop', 'site', 'sites', 'support', 'upload', 'uploads'
            ]
            
            # Try each prefix
            for prefix in prefixes:
                subdomain = f"{prefix}.{self.target_domain}"
                try:
                    socket.gethostbyname(subdomain)
                    self.subdomains.add(subdomain)
                except:
                    continue
                    
        except Exception as e:
            print(f"Error bruteforcing subdomains: {str(e)}")

    def _check_dns_records(self) -> None:
        """
        Check DNS records for subdomains
        """
        try:
            resolver = dns.resolver.Resolver()
            
            # Check each record type
            for record_type in self.dns_record_types:
                try:
                    answers = resolver.resolve(self.target_domain, record_type)
                    for answer in answers:
                        if record_type == 'CNAME':
                            self.subdomains.add(str(answer).rstrip('.'))
                except:
                    continue
                    
        except Exception as e:
            print(f"Error checking DNS records: {str(e)}")

    def _check_certificate_transparency(self) -> None:
        """
        Check certificate transparency logs for subdomains
        """
        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if 'name_value' in entry:
                        subdomain = entry['name_value'].lower()
                        if subdomain.endswith(self.target_domain):
                            self.subdomains.add(subdomain)
                            
        except Exception as e:
            print(f"Error checking certificate transparency: {str(e)}")

    def check_subdomain_takeover(self) -> List[Dict]:
        """
        Check for subdomain takeover vulnerabilities
        """
        vulnerable = []
        
        try:
            for subdomain in self.subdomains:
                # Check DNS records
                try:
                    resolver = dns.resolver.Resolver()
                    cname_records = resolver.resolve(subdomain, 'CNAME')
                    
                    for record in cname_records:
                        cname = str(record).rstrip('.')
                        
                        # Check against takeover indicators
                        for service, domains in self.takeover_indicators.items():
                            if any(domain in cname for domain in domains):
                                # Check if the service is actually vulnerable
                                if self._check_service_vulnerability(service, cname):
                                    vulnerable.append({
                                        "subdomain": subdomain,
                                        "cname": cname,
                                        "service": service,
                                        "vulnerable": True,
                                        "details": self._get_takeover_details(service, cname)
                                    })
                                    
                except:
                    continue
                    
        except Exception as e:
            print(f"Error checking subdomain takeover: {str(e)}")
            
        return vulnerable

    def _check_service_vulnerability(self, service: str, cname: str) -> bool:
        """
        Check if a service is vulnerable to takeover
        """
        try:
            if service == 'github':
                # Check if GitHub Pages site exists
                response = requests.get(f"https://{cname}")
                return response.status_code == 404
                
            elif service == 'heroku':
                # Check if Heroku app exists
                response = requests.get(f"https://{cname}")
                return response.status_code == 404
                
            elif service == 'aws':
                # Check if S3 bucket exists
                response = requests.get(f"https://{cname}")
                return response.status_code == 404
                
            # Add more service-specific checks here
            
        except:
            return False
            
        return False

    def _get_takeover_details(self, service: str, cname: str) -> Dict:
        """
        Get detailed information about potential takeover
        """
        details = {
            "service": service,
            "cname": cname,
            "risk_level": "High",
            "description": "",
            "remediation": ""
        }
        
        if service == 'github':
            details["description"] = "GitHub Pages site is available for takeover"
            details["remediation"] = "Register the GitHub Pages site or remove the CNAME record"
            
        elif service == 'heroku':
            details["description"] = "Heroku app is available for takeover"
            details["remediation"] = "Register the Heroku app or remove the CNAME record"
            
        elif service == 'aws':
            details["description"] = "AWS S3 bucket is available for takeover"
            details["remediation"] = "Register the S3 bucket or remove the CNAME record"
            
        return details

    def _get_scan_details(self, results: Dict) -> List[Dict]:
        """
        Generate detailed scan information
        """
        details = []
        
        try:
            # Add summary information
            details.append({
                "total_subdomains": len(results["subdomains"]),
                "vulnerable_subdomains": len(results["vulnerable_subdomains"]),
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Add service statistics
            service_stats = {}
            for subdomain in results["vulnerable_subdomains"]:
                service = subdomain["service"]
                if service not in service_stats:
                    service_stats[service] = 0
                service_stats[service] += 1
                
            details.append({
                "service_statistics": service_stats
            })
            
            # Add risk assessment
            risk_levels = {
                "High": len([s for s in results["vulnerable_subdomains"] if s["details"]["risk_level"] == "High"]),
                "Medium": len([s for s in results["vulnerable_subdomains"] if s["details"]["risk_level"] == "Medium"]),
                "Low": len([s for s in results["vulnerable_subdomains"] if s["details"]["risk_level"] == "Low"])
            }
            
            details.append({
                "risk_assessment": risk_levels
            })
            
        except Exception as e:
            print(f"Error generating scan details: {str(e)}")
            
        return details 