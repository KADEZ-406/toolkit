import argparse
from typing import Dict, List
import json
from datetime import datetime
from modules.cve_scanner import CVEScanner
from modules.js_scanner import JSScanner
from modules.rate_limit_scanner import RateLimitScanner
from modules.sqli_scanner import SQLIScanner
from modules.xss_scanner import XSSScanner
from modules.lfi_scanner import LFIScanner
from modules.ssrf_scanner import SSRFScanner
from modules.cors_scanner import CORSScanner
from modules.redirect_scanner import RedirectScanner
from modules.subdomain_scanner import SubdomainScanner
from modules.headers_scanner import HeadersScanner
from modules.ssti_scanner import SSTIScanner
from modules.xxe_scanner import XXEScanner
from modules.command_injection_scanner import CommandInjectionScanner
from modules.upload_scanner import UploadScanner
from modules.websocket_fuzzer import WebSocketFuzzer
from modules.saml_analyzer import SAMLAnalyzer
from modules.oauth_scanner import OAuthScanner
from modules.graphql_schema_analyzer import GraphQLSchemaAnalyzer
from modules.cache_poisoning_scanner import CachePoisoningScanner
from modules.http_method_scanner import HTTPMethodScanner
from modules.host_header_scanner import HostHeaderScanner
from modules.wayback_scanner import WaybackScanner

def run_all_scans(target_url: str, output_file: str = None) -> Dict:
    """
    Run all available security scans on the target URL
    """
    results = {
        "target_url": target_url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scans": {}
    }
    
    # Initialize all scanners
    scanners = {
        "cve": CVEScanner(target_url),
        "js": JSScanner(target_url),
        "rate_limit": RateLimitScanner(target_url),
        "sqli": SQLIScanner(target_url),
        "xss": XSSScanner(target_url),
        "lfi": LFIScanner(target_url),
        "ssrf": SSRFScanner(target_url),
        "cors": CORSScanner(target_url),
        "redirect": RedirectScanner(target_url),
        "subdomain": SubdomainScanner(target_url),
        "headers": HeadersScanner(target_url),
        "ssti": SSTIScanner(target_url),
        "xxe": XXEScanner(target_url),
        "command_injection": CommandInjectionScanner(target_url),
        "upload": UploadScanner(target_url),
        "websocket": WebSocketFuzzer(target_url),
        "saml": SAMLAnalyzer(target_url),
        "oauth": OAuthScanner(target_url),
        "graphql": GraphQLSchemaAnalyzer(target_url),
        "cache_poisoning": CachePoisoningScanner(target_url),
        "http_method": HTTPMethodScanner(target_url),
        "host_header": HostHeaderScanner(target_url),
        "wayback": WaybackScanner(target_url)
    }
    
    # Run each scanner
    for name, scanner in scanners.items():
        try:
            print(f"Running {name} scan...")
            if hasattr(scanner, 'scan'):
                results["scans"][name] = scanner.scan()
            elif hasattr(scanner, 'scan_' + name):
                results["scans"][name] = getattr(scanner, 'scan_' + name)()
            else:
                print(f"Warning: No scan method found for {name}")
        except Exception as e:
            print(f"Error running {name} scan: {str(e)}")
            results["scans"][name] = {"error": str(e)}
    
    # Generate summary
    results["summary"] = generate_summary(results["scans"])
    
    # Save results if output file specified
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    return results

def generate_summary(scans: Dict) -> Dict:
    """
    Generate a summary of all scan results
    """
    summary = {
        "total_vulnerabilities": 0,
        "vulnerabilities_by_type": {},
        "risk_levels": {
            "High": 0,
            "Medium": 0,
            "Low": 0
        }
    }
    
    for scan_name, scan_results in scans.items():
        if isinstance(scan_results, dict) and "vulnerabilities" in scan_results:
            vulns = scan_results["vulnerabilities"]
            summary["total_vulnerabilities"] += len(vulns)
            
            # Count vulnerabilities by type
            for vuln in vulns:
                vuln_type = vuln.get("type", "Unknown")
                summary["vulnerabilities_by_type"][vuln_type] = summary["vulnerabilities_by_type"].get(vuln_type, 0) + 1
                
                # Count by risk level
                if "details" in vuln and "risk_level" in vuln["details"]:
                    risk_level = vuln["details"]["risk_level"]
                    summary["risk_levels"][risk_level] = summary["risk_levels"].get(risk_level, 0) + 1
    
    return summary

def main():
    parser = argparse.ArgumentParser(description='Web Security Scanner')
    parser.add_argument('target_url', help='Target URL to scan')
    parser.add_argument('--output', '-o', help='Output file for scan results')
    args = parser.parse_args()
    
    results = run_all_scans(args.target_url, args.output)
    
    # Print summary
    print("\nScan Summary:")
    print(f"Total Vulnerabilities: {results['summary']['total_vulnerabilities']}")
    print("\nVulnerabilities by Type:")
    for vuln_type, count in results['summary']['vulnerabilities_by_type'].items():
        print(f"  {vuln_type}: {count}")
    print("\nRisk Levels:")
    for risk_level, count in results['summary']['risk_levels'].items():
        print(f"  {risk_level}: {count}")

if __name__ == "__main__":
    main() 