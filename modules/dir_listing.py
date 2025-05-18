import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
import os
import json

# Common directories to check
COMMON_DIRS = [
    'images/',
    'img/',
    'uploads/',
    'upload/',
    'files/',
    'documents/',
    'docs/',
    'downloads/',
    'download/',
    'assets/',
    'media/',
    'static/',
    'css/',
    'js/',
    'scripts/',
    'includes/',
    'temp/',
    'tmp/',
    'cache/',
    'backup/',
    'backups/',
    'data/',
    'logs/',
    'test/',
    'tests/',
    'old/',
    'new/',
    'pub/',
    'public/',
    'private/',
    'admin/',
    'administrator/',
    'staff/',
    'common/',
    'shared/',
    'lib/',
    'libs/',
    'library/',
    'libraries/',
    'vendor/',
    'resources/'
]

def is_directory_listing(html_content):
    """Check if the page appears to be a directory listing"""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Common directory listing indicators
    indicators = [
        'Index of',
        'Directory listing',
        'Parent Directory',
        '[To Parent Directory]',
        '<title>Index of',
        'Directory: /',
        'Last modified</a>'
    ]
    
    # Check page title and content
    for indicator in indicators:
        if indicator.lower() in html_content.lower():
            return True
    
    # Check if page contains typical directory listing elements
    if soup.find_all('a', href='../'):  # Parent directory link
        return True
    
    # Check for table with typical directory listing columns
    tables = soup.find_all('table')
    for table in tables:
        headers = [th.text.strip().lower() for th in table.find_all('th')]
        if any(h in ['name', 'last modified', 'size'] for h in headers):
            return True
    
    return False

def check_directory_listing():
    print(Fore.CYAN + "\n=== Directory Listing Checker ===\n")
    
    url = input(Fore.GREEN + "Enter the target URL: " + Style.RESET_ALL)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove trailing slash if present
    url = url.rstrip('/')
    
    results = {
        'url': url,
        'vulnerable_dirs': [],
        'total_checked': len(COMMON_DIRS),
        'total_vulnerable': 0
    }
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    print(Fore.YELLOW + "\n[*] Checking for directory listing vulnerabilities...")
    print(Fore.YELLOW + f"[*] Testing {len(COMMON_DIRS)} common directories\n")
    
    try:
        for directory in COMMON_DIRS:
            test_url = f"{url}/{directory}"
            try:
                response = requests.get(test_url, headers=headers, timeout=5)
                
                if response.status_code == 200:
                    if is_directory_listing(response.text):
                        results['vulnerable_dirs'].append({
                            'url': test_url,
                            'status_code': response.status_code,
                            'content_length': len(response.content)
                        })
                        print(Fore.RED + f"[!] Vulnerable: {test_url}")
                        
            except requests.exceptions.RequestException:
                continue
        
        results['total_vulnerable'] = len(results['vulnerable_dirs'])
        
        # Save results
        if results['vulnerable_dirs']:
            if not os.path.exists("data/results"):
                os.makedirs("data/results")
                
            output_file = f"data/results/directory_listing.json"
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4)
            
            print(Fore.RED + f"\n[!] Found {results['total_vulnerable']} directories with listing enabled:")
            for dir_info in results['vulnerable_dirs']:
                print(Fore.WHITE + f"  - {dir_info['url']}")
            
            print(Fore.GREEN + f"\n[+] Results saved to {output_file}")
            
            # Generate HTML report with screenshots placeholder
            report_html = generate_report_html(results)
            report_file = "data/results/directory_listing_report.html"
            
            with open(report_file, "w") as f:
                f.write(report_html)
            
            print(Fore.GREEN + f"[+] HTML report saved to {report_file}")
            
        else:
            print(Fore.GREEN + "\n[+] No directory listing vulnerabilities found")
        
    except Exception as e:
        print(Fore.RED + f"\nError during directory listing check: {str(e)}")
        return None
    
    return results

def generate_report_html(results):
    """Generate an HTML report for directory listing findings"""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Directory Listing Vulnerability Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1, h2 {{
            color: #333;
        }}
        .vulnerable {{
            color: #d9534f;
        }}
        .directory {{
            margin: 10px 0;
            padding: 10px;
            background-color: #f9f9f9;
            border-left: 4px solid #d9534f;
        }}
        .stats {{
            margin: 20px 0;
            padding: 10px;
            background-color: #e9ecef;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Directory Listing Vulnerability Report</h1>
        <div class="stats">
            <h2>Scan Statistics</h2>
            <p>Target URL: {results['url']}</p>
            <p>Total Directories Checked: {results['total_checked']}</p>
            <p>Vulnerable Directories Found: {results['total_vulnerable']}</p>
        </div>
        
        <h2>Vulnerable Directories</h2>
        {''.join([f'<div class="directory"><p>URL: <a href="{dir_info["url"]}" target="_blank">{dir_info["url"]}</a></p><p>Status Code: {dir_info["status_code"]}</p><p>Content Length: {dir_info["content_length"]} bytes</p></div>' for dir_info in results['vulnerable_dirs']])}
    </div>
</body>
</html>
"""
    return html 