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
    print(Fore.GREEN + " Automated Penetration Testing & SQL Injection Scanner Tool")
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
    elif choice == "0":
        print(Fore.YELLOW + "\nThank you for using KADEZ-406!")
        sys.exit(0)
    else:
        print(Fore.RED + "\nInvalid choice! Please try again.")

def main():
    while True:
        print_banner()
        print_menu()
        choice = input(Fore.GREEN + "\nEnter your choice: " + Style.RESET_ALL)
        try:
            handle_menu_choice(choice)
            if choice != "0":
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