import requests
from bs4 import BeautifulSoup
import json
from colorama import Fore, Style
import os
import re

# CMS Detection Patterns
CMS_PATTERNS = {
    'WordPress': {
        'paths': [
            '/wp-admin/',
            '/wp-content/',
            '/wp-includes/',
            '/wp-login.php'
        ],
        'headers': [
            'x-powered-by: php',
            'set-cookie: wordpress'
        ],
        'meta': [
            'generator" content="WordPress'
        ],
        'html': [
            'wp-content',
            'wp-includes',
            'wp-json'
        ]
    },
    'Joomla': {
        'paths': [
            '/administrator/',
            '/components/',
            '/modules/',
            '/templates/',
            '/media/system/js/'
        ],
        'headers': [
            'x-content-encoded-by: Joomla'
        ],
        'meta': [
            'generator" content="Joomla'
        ],
        'html': [
            'joomla!',
            '/media/system/js/',
            '/media/jui/'
        ]
    },
    'Drupal': {
        'paths': [
            '/sites/all/',
            '/sites/default/',
            '/modules/',
            '/themes/'
        ],
        'headers': [
            'x-generator: Drupal',
            'x-drupal-cache'
        ],
        'meta': [
            'generator" content="Drupal'
        ],
        'html': [
            'drupal.settings',
            'sites/all',
            'sites/default'
        ]
    },
    'Magento': {
        'paths': [
            '/app/etc/local.xml',
            '/media/catalog/',
            '/skin/frontend/'
        ],
        'headers': [
            'x-magento-init'
        ],
        'html': [
            'Mage.Cookies.path',
            'skin/frontend',
            'media/catalog'
        ]
    },
    'PrestaShop': {
        'paths': [
            '/modules/',
            '/themes/',
            '/img/',
            '/admin/'
        ],
        'meta': [
            'generator" content="PrestaShop'
        ],
        'html': [
            'prestashop',
            'presta-',
            '/modules/prestashop'
        ]
    },
    'OpenCart': {
        'paths': [
            '/admin/',
            '/catalog/',
            '/system/'
        ],
        'html': [
            'opencart',
            'route=common',
            'route=product'
        ]
    },
    'Shopify': {
        'headers': [
            'x-shopify-stage',
            'x-shopify-shop'
        ],
        'html': [
            'shopify.com',
            'cdn.shopify.com',
            'shopify-buy'
        ]
    }
}

def detect_cms():
    print(Fore.CYAN + "\n=== CMS Detector ===\n")
    
    url = input(Fore.GREEN + "Enter the target URL: " + Style.RESET_ALL)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove trailing slash if present
    url = url.rstrip('/')
    
    results = {
        'url': url,
        'detected_cms': None,
        'confidence': 0,
        'evidence': []
    }
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    print(Fore.YELLOW + "\n[*] Analyzing website...")
    
    try:
        # Get main page
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check each CMS
        for cms_name, patterns in CMS_PATTERNS.items():
            matches = 0
            evidence = []
            
            # Check paths
            if 'paths' in patterns:
                for path in patterns['paths']:
                    try:
                        path_response = requests.get(f"{url}{path}", headers=headers, timeout=5)
                        if path_response.status_code == 200:
                            matches += 1
                            evidence.append(f"Path exists: {path}")
                    except:
                        continue
            
            # Check headers
            if 'headers' in patterns:
                headers_str = str(response.headers).lower()
                for pattern in patterns['headers']:
                    if pattern.lower() in headers_str:
                        matches += 2  # Headers are strong indicators
                        evidence.append(f"Header found: {pattern}")
            
            # Check meta tags
            if 'meta' in patterns:
                for pattern in patterns['meta']:
                    meta_tags = soup.find_all('meta')
                    for meta in meta_tags:
                        if pattern.lower() in str(meta).lower():
                            matches += 3  # Meta tags are very strong indicators
                            evidence.append(f"Meta tag found: {pattern}")
            
            # Check HTML content
            if 'html' in patterns:
                html_str = str(soup).lower()
                for pattern in patterns['html']:
                    if pattern.lower() in html_str:
                        matches += 1
                        evidence.append(f"HTML pattern found: {pattern}")
            
            # Update results if this CMS has the highest confidence
            confidence = (matches / (len(patterns.get('paths', [])) + 
                                  2 * len(patterns.get('headers', [])) + 
                                  3 * len(patterns.get('meta', [])) + 
                                  len(patterns.get('html', [])))) * 100
            
            if confidence > results['confidence']:
                results['detected_cms'] = cms_name
                results['confidence'] = confidence
                results['evidence'] = evidence
        
        # Save and display results
        if results['detected_cms']:
            print(Fore.GREEN + f"\n[+] Detected CMS: {results['detected_cms']}")
            print(Fore.GREEN + f"[+] Confidence: {results['confidence']:.2f}%")
            print(Fore.GREEN + "\nEvidence:")
            for e in results['evidence']:
                print(Fore.WHITE + f"  - {e}")
            
            # Save results
            if not os.path.exists("data/results"):
                os.makedirs("data/results")
                
            output_file = f"data/results/cms_detection.json"
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4)
            
            print(Fore.GREEN + f"\n[+] Results saved to {output_file}")
        else:
            print(Fore.YELLOW + "\n[-] No CMS detected or unknown CMS")
        
    except Exception as e:
        print(Fore.RED + f"\nError during CMS detection: {str(e)}")
        return None
    
    return results