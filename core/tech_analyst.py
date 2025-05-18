import requests
from bs4 import BeautifulSoup
import json
from colorama import Fore, Style
import os
import re
from urllib3.exceptions import ConnectTimeoutError, ReadTimeoutError
from requests.exceptions import RequestException

# Technology fingerprints
TECH_FINGERPRINTS = {
    'WordPress': {
        'html': [
            '<link[^>]+wp-content',
            '<link[^>]+wp-includes',
            'wp-json',
        ],
        'headers': ['x-powered-by: php'],
        'cookies': ['wordpress_'],
        'meta': ['generator" content="WordPress']
    },
    'Joomla': {
        'html': [
            '/components/com_',
            '/media/jui/',
            '/media/system/js/core.js'
        ],
        'headers': ['x-content-encoded-by: Joomla'],
        'meta': ['generator" content="Joomla']
    },
    'Drupal': {
        'html': [
            'Drupal.settings',
            '/sites/all/themes/',
            '/sites/all/modules/'
        ],
        'headers': ['x-generator: Drupal'],
        'meta': ['generator" content="Drupal']
    },
    'Bootstrap': {
        'html': [
            'bootstrap.min.css',
            'bootstrap.min.js',
            'class="container"',
            'class="navbar"'
        ]
    },
    'jQuery': {
        'html': [
            'jquery.min.js',
            'jquery.js'
        ]
    },
    'React': {
        'html': [
            'react.js',
            'react.min.js',
            'react-dom',
            '_reactRootContainer'
        ]
    },
    'Vue.js': {
        'html': [
            'vue.js',
            'vue.min.js',
            'data-v-',
            '__vue__'
        ]
    },
    'Angular': {
        'html': [
            'ng-app',
            'ng-controller',
            'angular.js',
            'angular.min.js'
        ]
    },
    'PHP': {
        'headers': [
            'x-powered-by: php',
            'set-cookie: phpsessid'
        ]
    },
    'ASP.NET': {
        'headers': [
            'x-powered-by: asp.net',
            'x-aspnet-version'
        ],
        'cookies': [
            'asp.net_sessionid'
        ]
    },
    'nginx': {
        'headers': [
            'server: nginx'
        ]
    },
    'Apache': {
        'headers': [
            'server: apache'
        ]
    }
}

def analyze_tech():
    print(Fore.CYAN + "\n=== Web Technology Analyzer ===\n")
    
    url = input(Fore.GREEN + "Enter the target URL: " + Style.RESET_ALL)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    results = {
        'url': url,
        'technologies': {},
        'headers': {},
        'cookies': []
    }
    
    try:
        print(Fore.YELLOW + "\n[*] Analyzing website technologies...")
        
        # Make request with common browser headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Try HTTPS first, then fallback to HTTP if it fails
        try:
            if not url.startswith('https://'):
                https_url = url.replace('http://', 'https://')
            else:
                https_url = url
            response = requests.get(https_url, headers=headers, timeout=15, verify=False)
            url = https_url
        except (ConnectTimeoutError, ReadTimeoutError, RequestException):
            if url.startswith('https://'):
                http_url = url.replace('https://', 'http://')
            else:
                http_url = url
            try:
                response = requests.get(http_url, headers=headers, timeout=15)
                url = http_url
            except (ConnectTimeoutError, ReadTimeoutError) as e:
                print(Fore.RED + f"\nError: Connection timed out. The server is not responding.")
                print(Fore.YELLOW + "Suggestions:")
                print("1. Check if the URL is correct")
                print("2. Verify if the server is online")
                print("3. Try again later")
                return None
            except RequestException as e:
                print(Fore.RED + f"\nError: Unable to connect to the server.")
                print(Fore.YELLOW + f"Details: {str(e)}")
                return None
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Store response headers and cookies
        results['headers'] = dict(response.headers)
        results['cookies'] = [cookie.name for cookie in response.cookies]
        
        # Check each technology's fingerprints
        for tech, fingerprints in TECH_FINGERPRINTS.items():
            detected = False
            evidence = []
            
            try:
                # Check HTML patterns
                if 'html' in fingerprints:
                    html_str = str(soup)
                    for pattern in fingerprints['html']:
                        if re.search(pattern, html_str, re.I):
                            detected = True
                            evidence.append(f"HTML pattern: {pattern}")
                
                # Check headers
                if 'headers' in fingerprints:
                    headers_str = str(response.headers).lower()
                    for pattern in fingerprints['headers']:
                        if pattern.lower() in headers_str:
                            detected = True
                            evidence.append(f"Header: {pattern}")
                
                # Check cookies
                if 'cookies' in fingerprints:
                    for pattern in fingerprints['cookies']:
                        for cookie in response.cookies:
                            if pattern.lower() in cookie.name.lower():
                                detected = True
                                evidence.append(f"Cookie: {cookie.name}")
                
                # Check meta tags
                if 'meta' in fingerprints:
                    for pattern in fingerprints['meta']:
                        meta_tags = soup.find_all('meta')
                        for meta in meta_tags:
                            if pattern.lower() in str(meta).lower():
                                detected = True
                                evidence.append(f"Meta tag: {str(meta)}")
            
                if detected:
                    results['technologies'][tech] = evidence
                    
            except Exception as e:
                print(Fore.YELLOW + f"\nWarning: Error checking {tech} fingerprints: {str(e)}")
                continue
        
        # Save results
        try:
            if not os.path.exists("data/results"):
                os.makedirs("data/results")
                
            output_file = f"data/results/tech_analysis.json"
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4)
            
            # Print results
            print(Fore.CYAN + "\n=== Detected Technologies ===\n")
            
            if results['technologies']:
                for tech, evidence in results['technologies'].items():
                    print(Fore.GREEN + f"\n[+] {tech}")
                    for e in evidence:
                        print(Fore.WHITE + f"  - {e}")
            else:
                print(Fore.YELLOW + "No common technologies detected")
            
            print(Fore.GREEN + f"\n[+] Full results saved to {output_file}")
            
        except Exception as e:
            print(Fore.RED + f"\nError saving results: {str(e)}")
            
    except Exception as e:
        print(Fore.RED + f"\nUnexpected error: {str(e)}")
        print(Fore.YELLOW + "Please try again or report this issue")
        return None
    
    return results 