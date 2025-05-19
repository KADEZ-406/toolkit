#!/usr/bin/env python3

import os
import sys
import pyfiglet
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    banner = pyfiglet.figlet_format("KADEZ-406", font="slant")
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "=" * 60)
    print(Fore.GREEN + " Automated Penetration Testing & Security Scanner Tool")
    print(Fore.GREEN + " Created by: KADEZ-406 Team")
    print(Fore.YELLOW + "=" * 60 + "\n")

def print_menu():
    menu_items = [
        "Single Scan SQLi",
        "Mass Scan SQLi",
        "WAF Detection",
        "Encode Text",
        "List Payload Bypass WAF",
        "String to Hex",
        "Hex to String",
        "Information Gathering (Recon)",
        "Find Real IP (Bypass Cloudflare)",
        "Search Port (Port Scanner)",
        "Analyze Web Technology",
        "Admin Page Finder",
        "Common Sensitive File Finder",
        "CMS Detector",
        "Clickjacking Checker",
        "Directory Listing Checker",
        "XSS Scanner",
        "Open Redirect Checker",
        "Subdomain Takeover Checker",
        "CORS Misconfiguration Checker",
        "SSRF Tester",
        "LFI/RFI Scanner",
        "SQLi Dork Generator",
        "Host Header Injection Checker",
        "HTTP Method Tester",
        "CVE Exploit Checker",
        "JavaScript File Scanner",
        "Wayback Machine Parameter Extractor",
        "Rate Limiting Checker",
        "JWT Token Scanner",
        "GraphQL Vulnerability Scanner",
        "API Security Scanner",
        "WebSocket Security Scanner",
        "DNS Zone Transfer Checker",
        "SSL/TLS Vulnerability Scanner",
        "File Upload Vulnerability Scanner",
        "Command Injection Scanner",
        "XML External Entity (XXE) Scanner",
        "Server-Side Template Injection (SSTI) Scanner",
        "HTTP Security Headers Scanner",
        "Subdomain Enumeration Scanner",
        "Web Cache Poisoning Scanner",
        "WebSocket Fuzzer",
        "GraphQL Schema Analyzer",
        "OAuth Security Scanner",
        "SAML Security Analyzer",
        "Run All Security Scans",
        "Exit"
    ]
    
    for i, item in enumerate(menu_items, 1):
        if i == len(menu_items):  # Exit option
            print(Fore.RED + f"[0] {item}")
        else:
            print(Fore.CYAN + f"[{i}] {item}")

def handle_menu_choice(choice):
    if choice == "1":
        from core.scanner import single_sqli_scan
        single_sqli_scan()
    elif choice == "2":
        from core.scanner import mass_sqli_scan
        mass_sqli_scan()
    elif choice == "3":
        from core.waf import detect_waf
        detect_waf()
    elif choice == "4":
        from core.encoder import encode_text
        encode_text()
    elif choice == "5":
        from core.payloads import list_waf_payloads
        list_waf_payloads()
    elif choice == "6":
        from core.convert import string_to_hex
        string_to_hex()
    elif choice == "7":
        from core.convert import hex_to_string
        hex_to_string()
    elif choice == "8":
        from core.recon import gather_info
        gather_info()
    elif choice == "9":
        from core.real_ip import find_real_ip
        find_real_ip()
    elif choice == "10":
        from core.scanner import port_scan
        port_scan()
    elif choice == "11":
        from core.tech_analyst import analyze_tech
        analyze_tech()
    elif choice == "12":
        from modules.admin_finder import find_admin_pages
        find_admin_pages()
    elif choice == "13":
        from modules.file_finder import find_sensitive_files
        find_sensitive_files()
    elif choice == "14":
        from modules.cms_detector import detect_cms
        detect_cms()
    elif choice == "15":
        from modules.clickjacking import check_clickjacking
        check_clickjacking()
    elif choice == "16":
        from modules.dir_listing import check_directory_listing
        check_directory_listing()
    elif choice == "17":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.xss_scanner import XSSScanner
        scanner = XSSScanner(target)
        scanner.check_xss()
    elif choice == "18":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.redirect_scanner import RedirectScanner
        scanner = RedirectScanner(target)
        scanner.check_open_redirect()
    elif choice == "19":
        target = input(f"{Fore.CYAN}Enter target domain: {Style.RESET_ALL}")
        from modules.subdomain_scanner import SubdomainScanner
        scanner = SubdomainScanner(target)
        scanner.check_subdomain_takeover()
    elif choice == "20":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.cors_scanner import CORSScanner
        scanner = CORSScanner(target)
        scanner.check_cors()
    elif choice == "21":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.ssrf_scanner import SSRFScanner
        scanner = SSRFScanner(target)
        scanner.check_ssrf()
    elif choice == "22":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.lfi_scanner import LFIScanner
        scanner = LFIScanner(target)
        scanner.check_lfi()
    elif choice == "23":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.sqli_scanner import SQLIScanner
        scanner = SQLIScanner(target)
        scanner.generate_dorks()
    elif choice == "24":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.host_header_scanner import HostHeaderScanner
        scanner = HostHeaderScanner(target)
        scanner.check_host_header()
    elif choice == "25":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.http_method_scanner import HTTPMethodScanner
        scanner = HTTPMethodScanner(target)
        scanner.check_http_methods()
    elif choice == "26":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.cve_scanner import CVEScanner
        scanner = CVEScanner(target)
        scanner.check_cve()
    elif choice == "27":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.js_scanner import JSScanner
        scanner = JSScanner(target)
        scanner.scan_js_files()
    elif choice == "28":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.wayback_scanner import WaybackScanner
        scanner = WaybackScanner(target)
        scanner.extract_params()
    elif choice == "29":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.rate_limit_scanner import RateLimitScanner
        scanner = RateLimitScanner(target)
        scanner.check_rate_limiting()
    elif choice == "30":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        jwt_token = input(f"{Fore.CYAN}Enter JWT token: {Style.RESET_ALL}")
        from modules.jwt_scanner import JWTScanner
        scanner = JWTScanner(target)
        scanner.scan_jwt(jwt_token)
    elif choice == "31":
        target = input(f"{Fore.CYAN}Enter GraphQL endpoint: {Style.RESET_ALL}")
        from modules.graphql_scanner import GraphQLScanner
        scanner = GraphQLScanner(target)
        scanner.scan_vulnerabilities()
    elif choice == "32":
        target = input(f"{Fore.CYAN}Enter API endpoint: {Style.RESET_ALL}")
        from modules.api_scanner import APIScanner
        scanner = APIScanner(target)
        scanner.scan_api_security()
    elif choice == "33":
        target = input(f"{Fore.CYAN}Enter WebSocket URL: {Style.RESET_ALL}")
        from modules.websocket_scanner import WebSocketScanner
        scanner = WebSocketScanner(target)
        scanner.scan_websocket_security()
    elif choice == "34":
        target = input(f"{Fore.CYAN}Enter domain name: {Style.RESET_ALL}")
        from modules.dns_scanner import DNSScanner
        scanner = DNSScanner(target)
        scanner.check_zone_transfer()
    elif choice == "35":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.ssl_scanner import SSLScanner
        scanner = SSLScanner(target)
        scanner.scan_ssl_vulnerabilities()
    elif choice == "36":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.upload_scanner import UploadScanner
        scanner = UploadScanner(target)
        scanner.scan_upload_vulnerabilities()
    elif choice == "37":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.command_injection_scanner import CommandInjectionScanner
        scanner = CommandInjectionScanner(target)
        scanner.scan_command_injection()
    elif choice == "38":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.xxe_scanner import XXEScanner
        scanner = XXEScanner(target)
        scanner.scan_xxe_vulnerabilities()
    elif choice == "39":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.ssti_scanner import SSTIScanner
        scanner = SSTIScanner(target)
        scanner.scan_ssti_vulnerabilities()
    elif choice == "40":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.headers_scanner import HeadersScanner
        scanner = HeadersScanner(target)
        scanner.scan_security_headers()
    elif choice == "41":
        target = input(f"{Fore.CYAN}Enter target domain: {Style.RESET_ALL}")
        from modules.subdomain_scanner import SubdomainScanner
        scanner = SubdomainScanner(target)
        scanner.scan_subdomains()
    elif choice == "42":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        from modules.cache_poisoning_scanner import CachePoisoningScanner
        scanner = CachePoisoningScanner(target)
        scanner.scan_cache_poisoning()
    elif choice == "43":
        target = input(f"{Fore.CYAN}Enter WebSocket URL: {Style.RESET_ALL}")
        from modules.websocket_fuzzer import WebSocketFuzzer
        fuzzer = WebSocketFuzzer(target)
        fuzzer.fuzz_websocket()
    elif choice == "44":
        target = input(f"{Fore.CYAN}Enter GraphQL endpoint: {Style.RESET_ALL}")
        from modules.graphql_schema_analyzer import GraphQLSchemaAnalyzer
        analyzer = GraphQLSchemaAnalyzer(target)
        analyzer.analyze_schema()
    elif choice == "45":
        target = input(f"{Fore.CYAN}Enter OAuth endpoint: {Style.RESET_ALL}")
        from modules.oauth_scanner import OAuthScanner
        scanner = OAuthScanner(target)
        scanner.scan_oauth()
    elif choice == "46":
        target = input(f"{Fore.CYAN}Enter SAML endpoint: {Style.RESET_ALL}")
        from modules.saml_analyzer import SAMLAnalyzer
        analyzer = SAMLAnalyzer(target)
        analyzer.analyze_saml()
    elif choice == "47":
        target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
        run_all_scans(target)
    elif choice == "0":
        print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
        exit(0)
    else:
        print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

def main():
    while True:
        print_banner()
        print_menu()
        choice = input(Fore.GREEN + "\nEnter your choice: " + Style.RESET_ALL)
        try:
            handle_menu_choice(choice)
            if choice != "47":
                input(Fore.YELLOW + "\nPress Enter to continue...")
        except KeyboardInterrupt:
            print(Fore.RED + "\n\nOperation cancelled by user.")
            input(Fore.YELLOW + "Press Enter to continue...")
        except Exception as e:
            print(Fore.RED + f"\nAn error occurred: {str(e)}")
            input(Fore.YELLOW + "Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nExiting KADEZ-406...")
        sys.exit(0)