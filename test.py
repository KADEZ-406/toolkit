#!/usr/bin/env python3

import sys
import os
from colorama import init, Fore, Style

# Initialize colorama
init()

def test_module(module_name, function_name):
    """Test if a module can be imported and its main function exists"""
    try:
        module = __import__(module_name, fromlist=[function_name])
        if hasattr(module, function_name):
            print(Fore.GREEN + f"[+] {module_name}.{function_name} - OK")
            return True
        else:
            print(Fore.RED + f"[!] {module_name}.{function_name} - Function not found")
            return False
    except ImportError as e:
        print(Fore.RED + f"[!] {module_name} - Import failed: {str(e)}")
        return False
    except Exception as e:
        print(Fore.RED + f"[!] {module_name} - Error: {str(e)}")
        return False

def check_directory(path):
    """Check if a directory exists"""
    if os.path.exists(path):
        print(Fore.GREEN + f"[+] Directory {path} - OK")
        return True
    else:
        print(Fore.RED + f"[!] Directory {path} - Not found")
        return False

def check_file(path):
    """Check if a file exists"""
    if os.path.exists(path):
        print(Fore.GREEN + f"[+] File {path} - OK")
        return True
    else:
        print(Fore.RED + f"[!] File {path} - Not found")
        return False

def main():
    print(Fore.CYAN + "\n=== KADEZ-406 Module Test ===\n")
    
    # Test core modules
    print(Fore.YELLOW + "\nTesting core modules:")
    core_tests = [
        ('core.scanner', 'single_sqli_scan'),
        ('core.scanner', 'mass_sqli_scan'),
        ('core.waf', 'detect_waf'),
        ('core.encoder', 'encode_text'),
        ('core.convert', 'string_to_hex'),
        ('core.convert', 'hex_to_string'),
        ('core.recon', 'gather_info'),
        ('core.real_ip', 'find_real_ip'),
        ('core.tech_analyst', 'analyze_tech')
    ]
    
    for module, function in core_tests:
        test_module(module, function)
    
    # Test additional modules
    print(Fore.YELLOW + "\nTesting additional modules:")
    module_tests = [
        ('modules.admin_finder', 'find_admin_pages'),
        ('modules.file_finder', 'find_sensitive_files'),
        ('modules.cms_detector', 'detect_cms'),
        ('modules.clickjacking', 'check_clickjacking'),
        ('modules.dir_listing', 'check_directory_listing')
    ]
    
    for module, function in module_tests:
        test_module(module, function)
    
    # Check directories
    print(Fore.YELLOW + "\nChecking directories:")
    directories = [
        'core',
        'modules',
        'data',
        'data/results'
    ]
    
    for directory in directories:
        check_directory(directory)
    
    # Check files
    print(Fore.YELLOW + "\nChecking files:")
    files = [
        'requirements.txt',
        'README.md',
        'data/admin.txt',
        'data/files.txt'
    ]
    
    for file in files:
        check_file(file)
    
    print(Fore.CYAN + "\n=== Test Complete ===\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"\nError during test: {str(e)}")
        sys.exit(1) 