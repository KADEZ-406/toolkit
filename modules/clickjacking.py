import requests
from colorama import Fore, Style
import os
import json

def check_clickjacking():
    print(Fore.CYAN + "\n=== Clickjacking Vulnerability Checker ===\n")
    
    url = input(Fore.GREEN + "Enter the target URL: " + Style.RESET_ALL)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    results = {
        'url': url,
        'vulnerable': False,
        'headers': {},
        'details': []
    }
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    print(Fore.YELLOW + "\n[*] Checking for clickjacking protection...")
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response_headers = response.headers
        
        # Store all headers for reference
        results['headers'] = dict(response_headers)
        
        # Check X-Frame-Options header
        x_frame_options = response_headers.get('X-Frame-Options', '').upper()
        
        if not x_frame_options:
            results['vulnerable'] = True
            results['details'].append("X-Frame-Options header is missing")
            print(Fore.RED + "\n[!] Vulnerable: X-Frame-Options header is missing")
            
            # Generate PoC HTML
            poc_html = generate_poc_html(url)
            
            # Save PoC
            if not os.path.exists("data/results"):
                os.makedirs("data/results")
            
            with open("data/results/clickjacking_poc.html", "w") as f:
                f.write(poc_html)
            
            print(Fore.YELLOW + "\n[*] A proof-of-concept HTML file has been generated:")
            print(Fore.WHITE + "    data/results/clickjacking_poc.html")
            
        else:
            # Check X-Frame-Options value
            if x_frame_options not in ['DENY', 'SAMEORIGIN']:
                results['vulnerable'] = True
                results['details'].append(f"Invalid X-Frame-Options value: {x_frame_options}")
                print(Fore.RED + f"\n[!] Vulnerable: Invalid X-Frame-Options value: {x_frame_options}")
            else:
                print(Fore.GREEN + f"\n[+] Protected: X-Frame-Options header is set to {x_frame_options}")
                results['details'].append(f"X-Frame-Options header is set to {x_frame_options}")
        
        # Check Content-Security-Policy header
        csp = response_headers.get('Content-Security-Policy', '')
        if 'frame-ancestors' in csp.lower():
            print(Fore.GREEN + "\n[+] Additional protection: Content-Security-Policy frame-ancestors directive is present")
            results['details'].append("CSP frame-ancestors directive is present")
        else:
            print(Fore.YELLOW + "\n[!] Note: No Content-Security-Policy frame-ancestors directive found")
            results['details'].append("No CSP frame-ancestors directive")
        
        # Save detailed results
        if not os.path.exists("data/results"):
            os.makedirs("data/results")
            
        output_file = f"data/results/clickjacking_results.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        
        print(Fore.GREEN + f"\n[+] Full results saved to {output_file}")
        
    except Exception as e:
        print(Fore.RED + f"\nError checking for clickjacking: {str(e)}")
        return None
    
    return results

def generate_poc_html(url):
    """Generate a proof-of-concept HTML file for clickjacking"""
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        .container {{
            position: relative;
            width: 100%;
            height: 100%;
            opacity: 0.8;
            z-index: 2;
        }}
        .clickjacking-overlay {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 1;
            background-color: #ffffff;
        }}
        .warning {{
            color: red;
            text-align: center;
            padding: 20px;
            font-family: Arial, sans-serif;
        }}
    </style>
</head>
<body>
    <div class="warning">
        <h2>Clickjacking Vulnerability Proof of Concept</h2>
        <p>This page demonstrates that {url} is vulnerable to clickjacking attacks.</p>
        <p>The website can be embedded in an iframe and overlaid with malicious content.</p>
    </div>
    <div class="container">
        <iframe src="{url}" width="100%" height="800px"></iframe>
    </div>
    <div class="clickjacking-overlay"></div>
</body>
</html>
""" 