import requests
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs
import json
import time

class WaybackScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.snapshots = []
        self.parameters = set()
        
        # Wayback Machine API endpoints
        self.wayback_api = "https://archive.org/wayback/available"
        self.cdx_api = "https://web.archive.org/cdx/search/cdx"

    def extract_params(self) -> Dict[str, List[Dict]]:
        """
        Extract parameters from Wayback Machine snapshots
        """
        results = {
            "snapshots": [],
            "parameters": [],
            "unique_params": [],
            "details": []
        }
        
        try:
            # Get available snapshots
            self._get_snapshots()
            results["snapshots"] = self.snapshots
            
            # Extract parameters from each snapshot
            for snapshot in self.snapshots:
                params = self._extract_snapshot_params(snapshot)
                if params:
                    results["parameters"].extend(params)
                    
            # Get unique parameters
            results["unique_params"] = list(self.parameters)
            
            # Add detailed information
            results["details"] = self._get_scan_details(results)
            
        except Exception as e:
            print(f"Error extracting parameters: {str(e)}")
            
        return results

    def _get_snapshots(self) -> None:
        """
        Get available snapshots from Wayback Machine
        """
        try:
            # First try the availability API
            params = {
                "url": self.target_url,
                "timestamp": "latest"
            }
            
            response = requests.get(self.wayback_api, params=params)
            if response.status_code == 200:
                data = response.json()
                if "archived_snapshots" in data and "closest" in data["archived_snapshots"]:
                    snapshot = data["archived_snapshots"]["closest"]
                    self.snapshots.append({
                        "url": snapshot["url"],
                        "timestamp": snapshot["timestamp"],
                        "status": snapshot["status"]
                    })
            
            # Then try the CDX API for more snapshots
            params = {
                "url": self.target_url,
                "output": "json",
                "fl": "timestamp,original,statuscode",
                "limit": 100
            }
            
            response = requests.get(self.cdx_api, params=params)
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:  # First row is header
                    for row in data[1:]:
                        if len(row) >= 3:
                            self.snapshots.append({
                                "url": f"https://web.archive.org/web/{row[0]}/{row[1]}",
                                "timestamp": row[0],
                                "status": row[2]
                            })
                            
        except Exception as e:
            print(f"Error getting snapshots: {str(e)}")

    def _extract_snapshot_params(self, snapshot: Dict) -> List[Dict]:
        """
        Extract parameters from a single snapshot
        """
        params = []
        
        try:
            response = requests.get(snapshot["url"])
            if response.status_code == 200:
                content = response.text
                
                # Extract URLs from the content
                urls = re.findall(r'href=[\'"]?([^\'" >]+)', content)
                urls.extend(re.findall(r'src=[\'"]?([^\'" >]+)', content))
                
                # Parse parameters from each URL
                for url in urls:
                    try:
                        parsed = urlparse(url)
                        if parsed.query:
                            query_params = parse_qs(parsed.query)
                            for param, values in query_params.items():
                                self.parameters.add(param)
                                params.append({
                                    "snapshot": snapshot["url"],
                                    "timestamp": snapshot["timestamp"],
                                    "url": url,
                                    "parameter": param,
                                    "values": values
                                })
                    except:
                        continue
                        
        except Exception as e:
            print(f"Error extracting parameters from snapshot {snapshot['url']}: {str(e)}")
            
        return params

    def _get_scan_details(self, results: Dict) -> List[Dict]:
        """
        Generate detailed scan information
        """
        details = []
        
        try:
            # Add summary information
            details.append({
                "total_snapshots": len(results["snapshots"]),
                "total_parameters": len(results["parameters"]),
                "unique_parameters": len(results["unique_params"])
            })
            
            # Add parameter statistics
            param_stats = {}
            for param in results["parameters"]:
                param_name = param["parameter"]
                if param_name not in param_stats:
                    param_stats[param_name] = 0
                param_stats[param_name] += 1
                
            details.append({
                "parameter_statistics": param_stats
            })
            
            # Add timeline information
            timeline = {}
            for param in results["parameters"]:
                timestamp = param["timestamp"][:8]  # YYYYMMDD
                if timestamp not in timeline:
                    timeline[timestamp] = 0
                timeline[timestamp] += 1
                
            details.append({
                "parameter_timeline": timeline
            })
            
        except Exception as e:
            print(f"Error generating scan details: {str(e)}")
            
        return details

    def analyze_parameter_usage(self) -> Dict[str, List[Dict]]:
        """
        Analyze how parameters are used across snapshots
        """
        results = {
            "parameter_usage": [],
            "common_patterns": [],
            "details": []
        }
        
        try:
            # Get parameters first
            param_results = self.extract_params()
            
            # Analyze parameter usage
            for param in param_results["unique_params"]:
                usage = self._analyze_single_parameter(param, param_results["parameters"])
                if usage:
                    results["parameter_usage"].append(usage)
                    
            # Find common patterns
            results["common_patterns"] = self._find_common_patterns(param_results["parameters"])
            
            # Add detailed information
            results["details"] = self._get_analysis_details(results)
            
        except Exception as e:
            print(f"Error analyzing parameter usage: {str(e)}")
            
        return results

    def _analyze_single_parameter(self, param: str, all_params: List[Dict]) -> Optional[Dict]:
        """
        Analyze usage of a single parameter
        """
        try:
            param_data = [p for p in all_params if p["parameter"] == param]
            if not param_data:
                return None
                
            # Analyze values
            values = set()
            for p in param_data:
                values.update(p["values"])
                
            # Analyze patterns in values
            patterns = self._analyze_value_patterns(list(values))
            
            return {
                "parameter": param,
                "total_occurrences": len(param_data),
                "unique_values": len(values),
                "value_patterns": patterns,
                "first_seen": min(p["timestamp"] for p in param_data),
                "last_seen": max(p["timestamp"] for p in param_data)
            }
            
        except Exception as e:
            print(f"Error analyzing parameter {param}: {str(e)}")
            return None

    def _analyze_value_patterns(self, values: List[str]) -> List[Dict]:
        """
        Analyze patterns in parameter values
        """
        patterns = []
        
        try:
            # Check for numeric patterns
            numeric_count = sum(1 for v in values if v.isdigit())
            if numeric_count > 0:
                patterns.append({
                    "type": "numeric",
                    "count": numeric_count,
                    "percentage": (numeric_count / len(values)) * 100
                })
                
            # Check for alphanumeric patterns
            alnum_count = sum(1 for v in values if v.isalnum())
            if alnum_count > 0:
                patterns.append({
                    "type": "alphanumeric",
                    "count": alnum_count,
                    "percentage": (alnum_count / len(values)) * 100
                })
                
            # Check for URL patterns
            url_count = sum(1 for v in values if v.startswith(("http://", "https://")))
            if url_count > 0:
                patterns.append({
                    "type": "url",
                    "count": url_count,
                    "percentage": (url_count / len(values)) * 100
                })
                
            # Check for email patterns
            email_count = sum(1 for v in values if "@" in v and "." in v)
            if email_count > 0:
                patterns.append({
                    "type": "email",
                    "count": email_count,
                    "percentage": (email_count / len(values)) * 100
                })
                
        except Exception as e:
            print(f"Error analyzing value patterns: {str(e)}")
            
        return patterns

    def _find_common_patterns(self, parameters: List[Dict]) -> List[Dict]:
        """
        Find common patterns across parameters
        """
        patterns = []
        
        try:
            # Group parameters by their values
            value_groups = {}
            for param in parameters:
                for value in param["values"]:
                    if value not in value_groups:
                        value_groups[value] = []
                    value_groups[value].append(param["parameter"])
                    
            # Find values used in multiple parameters
            for value, params in value_groups.items():
                if len(params) > 1:
                    patterns.append({
                        "value": value,
                        "parameters": params,
                        "count": len(params)
                    })
                    
        except Exception as e:
            print(f"Error finding common patterns: {str(e)}")
            
        return patterns

    def _get_analysis_details(self, results: Dict) -> List[Dict]:
        """
        Generate detailed analysis information
        """
        details = []
        
        try:
            # Add summary information
            details.append({
                "total_parameters_analyzed": len(results["parameter_usage"]),
                "total_common_patterns": len(results["common_patterns"])
            })
            
            # Add parameter usage statistics
            usage_stats = {}
            for usage in results["parameter_usage"]:
                param = usage["parameter"]
                usage_stats[param] = {
                    "occurrences": usage["total_occurrences"],
                    "unique_values": usage["unique_values"],
                    "patterns": len(usage["value_patterns"])
                }
                
            details.append({
                "parameter_usage_statistics": usage_stats
            })
            
            # Add pattern statistics
            pattern_stats = {}
            for pattern in results["common_patterns"]:
                pattern_type = pattern["value"][:20] + "..." if len(pattern["value"]) > 20 else pattern["value"]
                if pattern_type not in pattern_stats:
                    pattern_stats[pattern_type] = 0
                pattern_stats[pattern_type] += 1
                
            details.append({
                "pattern_statistics": pattern_stats
            })
            
        except Exception as e:
            print(f"Error generating analysis details: {str(e)}")
            
        return details 