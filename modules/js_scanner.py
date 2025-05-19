import requests
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse
import concurrent.futures
import json

class JSScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.js_files = []
        self.vulnerabilities = []
        
        # Common sensitive patterns to look for in JS files
        self.sensitive_patterns = {
            "api_key": r"(?i)(api[_-]?key|apikey|secret[_-]?key)",
            "password": r"(?i)(password|passwd|pwd)",
            "token": r"(?i)(token|jwt|bearer)",
            "endpoint": r"(?i)(endpoint|url|uri|api[_-]?url)",
            "credentials": r"(?i)(credentials|auth|login)",
            "database": r"(?i)(database|db|connection[_-]?string)",
            "aws": r"(?i)(aws[_-]?key|aws[_-]?secret|amazon[_-]?key)",
            "google": r"(?i)(google[_-]?api[_-]?key|gcp[_-]?key)",
            "firebase": r"(?i)(firebase[_-]?config|firebase[_-]?key)",
            "stripe": r"(?i)(stripe[_-]?key|stripe[_-]?secret)",
            "paypal": r"(?i)(paypal[_-]?client[_-]?id|paypal[_-]?secret)",
            "github": r"(?i)(github[_-]?token|github[_-]?secret)",
            "slack": r"(?i)(slack[_-]?token|slack[_-]?webhook)",
            "twitter": r"(?i)(twitter[_-]?api[_-]?key|twitter[_-]?secret)",
            "facebook": r"(?i)(facebook[_-]?app[_-]?id|facebook[_-]?secret)"
        }

    def scan_js_files(self) -> Dict[str, List[Dict]]:
        """
        Scan JavaScript files for security issues
        """
        results = {
            "js_files": [],
            "vulnerabilities": [],
            "sensitive_data": [],
            "details": []
        }
        
        try:
            # First find all JavaScript files
            self._find_js_files()
            results["js_files"] = self.js_files
            
            # Scan each JS file
            for js_file in self.js_files:
                file_results = self._scan_js_file(js_file)
                if file_results["vulnerabilities"]:
                    results["vulnerabilities"].extend(file_results["vulnerabilities"])
                if file_results["sensitive_data"]:
                    results["sensitive_data"].extend(file_results["sensitive_data"])
                    
            # Add detailed information
            results["details"] = self._get_scan_details(results)
            
        except Exception as e:
            print(f"Error scanning JavaScript files: {str(e)}")
            
        return results

    def _find_js_files(self) -> None:
        """
        Find all JavaScript files on the target website
        """
        try:
            response = requests.get(self.target_url)
            content = response.text.lower()
            
            # Find all script tags
            script_tags = re.findall(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', content)
            
            # Find all JavaScript file references
            js_files = re.findall(r'["\']([^"\']+\.js)["\']', content)
            
            # Combine and normalize URLs
            all_js = set(script_tags + js_files)
            for js in all_js:
                full_url = urljoin(self.target_url, js)
                if full_url not in self.js_files:
                    self.js_files.append(full_url)
                    
        except Exception as e:
            print(f"Error finding JavaScript files: {str(e)}")

    def _scan_js_file(self, js_url: str) -> Dict[str, List[Dict]]:
        """
        Scan a single JavaScript file for security issues
        """
        results = {
            "vulnerabilities": [],
            "sensitive_data": []
        }
        
        try:
            response = requests.get(js_url)
            if response.status_code == 200:
                content = response.text
                
                # Check for sensitive data
                for pattern_name, pattern in self.sensitive_patterns.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Get some context around the match
                        start = max(0, match.start() - 20)
                        end = min(len(content), match.end() + 20)
                        context = content[start:end]
                        
                        results["sensitive_data"].append({
                            "file": js_url,
                            "pattern": pattern_name,
                            "match": match.group(),
                            "context": context,
                            "line": content[:match.start()].count('\n') + 1
                        })
                
                # Check for common vulnerabilities
                vuln_checks = [
                    self._check_eval_usage,
                    self._check_document_write,
                    self._check_innerhtml,
                    self._check_unsafe_regex,
                    self._check_debug_code
                ]
                
                for check in vuln_checks:
                    vulns = check(content, js_url)
                    if vulns:
                        results["vulnerabilities"].extend(vulns)
                        
        except Exception as e:
            print(f"Error scanning JavaScript file {js_url}: {str(e)}")
            
        return results

    def _check_eval_usage(self, content: str, js_url: str) -> List[Dict]:
        """
        Check for unsafe eval() usage
        """
        vulnerabilities = []
        eval_pattern = r'eval\s*\([^)]+\)'
        
        matches = re.finditer(eval_pattern, content)
        for match in matches:
            vulnerabilities.append({
                "file": js_url,
                "type": "unsafe_eval",
                "description": "Potentially unsafe eval() usage detected",
                "line": content[:match.start()].count('\n') + 1,
                "code": match.group()
            })
            
        return vulnerabilities

    def _check_document_write(self, content: str, js_url: str) -> List[Dict]:
        """
        Check for unsafe document.write() usage
        """
        vulnerabilities = []
        write_pattern = r'document\.write\s*\([^)]+\)'
        
        matches = re.finditer(write_pattern, content)
        for match in matches:
            vulnerabilities.append({
                "file": js_url,
                "type": "unsafe_document_write",
                "description": "Potentially unsafe document.write() usage detected",
                "line": content[:match.start()].count('\n') + 1,
                "code": match.group()
            })
            
        return vulnerabilities

    def _check_innerhtml(self, content: str, js_url: str) -> List[Dict]:
        """
        Check for unsafe innerHTML usage
        """
        vulnerabilities = []
        innerhtml_pattern = r'\.innerHTML\s*='
        
        matches = re.finditer(innerhtml_pattern, content)
        for match in matches:
            vulnerabilities.append({
                "file": js_url,
                "type": "unsafe_innerhtml",
                "description": "Potentially unsafe innerHTML assignment detected",
                "line": content[:match.start()].count('\n') + 1,
                "code": match.group()
            })
            
        return vulnerabilities

    def _check_unsafe_regex(self, content: str, js_url: str) -> List[Dict]:
        """
        Check for potentially unsafe regular expressions
        """
        vulnerabilities = []
        regex_pattern = r'new\s+RegExp\s*\([^)]+\)'
        
        matches = re.finditer(regex_pattern, content)
        for match in matches:
            vulnerabilities.append({
                "file": js_url,
                "type": "unsafe_regex",
                "description": "Potentially unsafe RegExp usage detected",
                "line": content[:match.start()].count('\n') + 1,
                "code": match.group()
            })
            
        return vulnerabilities

    def _check_debug_code(self, content: str, js_url: str) -> List[Dict]:
        """
        Check for debug code in production
        """
        vulnerabilities = []
        debug_patterns = [
            r'console\.log\s*\(',
            r'debugger\s*;',
            r'alert\s*\(',
            r'debug\s*=',
            r'DEBUG\s*='
        ]
        
        for pattern in debug_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                vulnerabilities.append({
                    "file": js_url,
                    "type": "debug_code",
                    "description": "Debug code found in production",
                    "line": content[:match.start()].count('\n') + 1,
                    "code": match.group()
                })
                
        return vulnerabilities

    def _get_scan_details(self, results: Dict) -> List[Dict]:
        """
        Generate detailed scan information
        """
        details = []
        
        try:
            # Add summary information
            details.append({
                "total_js_files": len(results["js_files"]),
                "total_vulnerabilities": len(results["vulnerabilities"]),
                "total_sensitive_data": len(results["sensitive_data"])
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
            
            # Add sensitive data statistics
            sensitive_types = {}
            for data in results["sensitive_data"]:
                pattern_type = data["pattern"]
                if pattern_type not in sensitive_types:
                    sensitive_types[pattern_type] = 0
                sensitive_types[pattern_type] += 1
                
            details.append({
                "sensitive_data_types": sensitive_types
            })
            
        except Exception as e:
            print(f"Error generating scan details: {str(e)}")
            
        return details 