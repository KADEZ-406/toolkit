import requests
import re
import json
from typing import List, Dict, Optional
from urllib.parse import urlparse
import concurrent.futures
import time

class CVEScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities = []
        self.server_info = {}
        self.technologies = {}
        
        # Common vulnerability databases
        self.cve_dbs = {
            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "vuldb": "https://vuldb.com/?api",
            "exploitdb": "https://www.exploit-db.com/search?q="
        }

    def check_cve(self) -> Dict[str, List[Dict]]:
        """
        Check for known vulnerabilities in the target application
        """
        results = {
            "vulnerabilities": [],
            "server_info": {},
            "technologies": {},
            "details": []
        }
        
        try:
            # First gather server information
            server_info = self._get_server_info()
            results["server_info"] = server_info
            
            # Identify technologies
            technologies = self._identify_technologies()
            results["technologies"] = technologies
            
            # Check for vulnerabilities based on server info and technologies
            vulnerabilities = self._check_vulnerabilities(server_info, technologies)
            results["vulnerabilities"] = vulnerabilities
            
            # Add detailed information
            results["details"] = self._get_vulnerability_details(vulnerabilities)
            
        except Exception as e:
            print(f"Error checking CVE: {str(e)}")
            
        return results

    def _get_server_info(self) -> Dict[str, str]:
        """
        Gather server information from headers and response
        """
        info = {}
        
        try:
            response = requests.get(self.target_url)
            
            # Get server information from headers
            headers = response.headers
            
            if "Server" in headers:
                info["server"] = headers["Server"]
            if "X-Powered-By" in headers:
                info["powered_by"] = headers["X-Powered-By"]
            if "X-AspNet-Version" in headers:
                info["asp_net_version"] = headers["X-AspNet-Version"]
            if "X-AspNetMvc-Version" in headers:
                info["asp_net_mvc_version"] = headers["X-AspNetMvc-Version"]
            if "X-Runtime" in headers:
                info["runtime"] = headers["X-Runtime"]
            if "X-Version" in headers:
                info["version"] = headers["X-Version"]
                
            # Try to identify server from response content
            content = response.text.lower()
            
            # Check for common server signatures
            server_patterns = {
                "apache": r"apache[/\s](\d+\.\d+\.\d+)",
                "nginx": r"nginx[/\s](\d+\.\d+\.\d+)",
                "iis": r"microsoft-iis[/\s](\d+\.\d+)",
                "php": r"php[/\s](\d+\.\d+\.\d+)",
                "python": r"python[/\s](\d+\.\d+\.\d+)",
                "ruby": r"ruby[/\s](\d+\.\d+\.\d+)",
                "node": r"node[/\s](\d+\.\d+\.\d+)"
            }
            
            for server, pattern in server_patterns.items():
                match = re.search(pattern, content)
                if match:
                    info[server] = match.group(1)
                    
        except Exception as e:
            print(f"Error getting server info: {str(e)}")
            
        return info

    def _identify_technologies(self) -> Dict[str, str]:
        """
        Identify technologies used by the application
        """
        technologies = {}
        
        try:
            response = requests.get(self.target_url)
            content = response.text.lower()
            
            # Common technology signatures
            tech_patterns = {
                "wordpress": r"wp-content|wp-includes|wordpress",
                "drupal": r"drupal|sites/default",
                "joomla": r"joomla|com_content",
                "magento": r"magento|skin/frontend",
                "laravel": r"laravel|csrf-token",
                "django": r"django|csrfmiddlewaretoken",
                "rails": r"rails|csrf-token",
                "angular": r"ng-|angular",
                "react": r"react|react-dom",
                "vue": r"vue|v-bind",
                "jquery": r"jquery[/\s](\d+\.\d+\.\d+)",
                "bootstrap": r"bootstrap[/\s](\d+\.\d+\.\d+)",
                "font-awesome": r"font-awesome[/\s](\d+\.\d+\.\d+)"
            }
            
            for tech, pattern in tech_patterns.items():
                match = re.search(pattern, content)
                if match:
                    if len(match.groups()) > 0:
                        technologies[tech] = match.group(1)
                    else:
                        technologies[tech] = "detected"
                        
        except Exception as e:
            print(f"Error identifying technologies: {str(e)}")
            
        return technologies

    def _check_vulnerabilities(self, server_info: Dict[str, str], technologies: Dict[str, str]) -> List[Dict]:
        """
        Check for vulnerabilities based on server info and technologies
        """
        vulnerabilities = []
        
        try:
            # Check server vulnerabilities
            for component, version in server_info.items():
                if version:
                    vulns = self._search_cve_database(component, version)
                    vulnerabilities.extend(vulns)
            
            # Check technology vulnerabilities
            for tech, version in technologies.items():
                if version and version != "detected":
                    vulns = self._search_cve_database(tech, version)
                    vulnerabilities.extend(vulns)
                    
        except Exception as e:
            print(f"Error checking vulnerabilities: {str(e)}")
            
        return vulnerabilities

    def _search_cve_database(self, component: str, version: str) -> List[Dict]:
        """
        Search CVE databases for vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Search NVD database
            params = {
                "keyword": f"{component} {version}",
                "resultsPerPage": 20
            }
            
            response = requests.get(self.cve_dbs["nvd"], params=params)
            if response.status_code == 200:
                data = response.json()
                if "vulnerabilities" in data:
                    for vuln in data["vulnerabilities"]:
                        vulnerabilities.append({
                            "cve_id": vuln.get("cve", {}).get("id"),
                            "description": vuln.get("cve", {}).get("descriptions", [{}])[0].get("value"),
                            "severity": vuln.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore"),
                            "component": component,
                            "version": version
                        })
                        
        except Exception as e:
            print(f"Error searching CVE database: {str(e)}")
            
        return vulnerabilities

    def _get_vulnerability_details(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Get detailed information about each vulnerability
        """
        details = []
        
        try:
            for vuln in vulnerabilities:
                if "cve_id" in vuln:
                    # Get additional details from exploit database
                    exploit_url = f"{self.cve_dbs['exploitdb']}{vuln['cve_id']}"
                    try:
                        response = requests.get(exploit_url)
                        if response.status_code == 200:
                            vuln["exploit_available"] = "exploit" in response.text.lower()
                    except:
                        vuln["exploit_available"] = False
                        
                    details.append(vuln)
                    
        except Exception as e:
            print(f"Error getting vulnerability details: {str(e)}")
            
        return details

    def check_known_exploits(self) -> List[Dict]:
        """
        Check for known exploits for identified vulnerabilities
        """
        exploits = []
        
        try:
            # Get vulnerabilities first
            vuln_results = self.check_cve()
            
            # Check each vulnerability for known exploits
            for vuln in vuln_results["vulnerabilities"]:
                if "cve_id" in vuln:
                    exploit_info = self._check_exploit_availability(vuln["cve_id"])
                    if exploit_info:
                        exploits.append(exploit_info)
                        
        except Exception as e:
            print(f"Error checking known exploits: {str(e)}")
            
        return exploits

    def _check_exploit_availability(self, cve_id: str) -> Optional[Dict]:
        """
        Check if an exploit is available for a specific CVE
        """
        try:
            # Check exploit database
            exploit_url = f"{self.cve_dbs['exploitdb']}{cve_id}"
            response = requests.get(exploit_url)
            
            if response.status_code == 200:
                content = response.text.lower()
                if "exploit" in content:
                    return {
                        "cve_id": cve_id,
                        "exploit_available": True,
                        "source": "exploit-db",
                        "url": exploit_url
                    }
                    
        except Exception as e:
            print(f"Error checking exploit availability: {str(e)}")
            
        return None 