import requests
from colorama import Fore, Style
from tqdm import tqdm
import os

# Common sensitive files and directories
SENSITIVE_FILES = [
    '.env',
    '.git/config',
    '.gitignore',
    'backup.sql',
    'backup.zip',
    'backup.tar.gz',
    'db.sql',
    'database.sql',
    'wp-config.php',
    'config.php',
    'configuration.php',
    'config.inc.php',
    'settings.php',
    'config.yml',
    'config.xml',
    '.htaccess',
    'web.config',
    'robots.txt',
    'sitemap.xml',
    'phpinfo.php',
    'info.php',
    'test.php',
    'admin/config.php',
    'includes/config.php',
    'conf/config.php',
    'db/db.php',
    'database/db.php',
    'log/access.log',
    'logs/access.log',
    'log/error.log',
    'logs/error.log',
    'backup/',
    'backups/',
    'dump/',
    'dumps/',
    'temp/',
    'tmp/',
    'upload/',
    'uploads/',
    'files/',
    'admin/backup/',
    'admin/backups/',
    'admin/db_backup/',
    'phpmyadmin/',
    'myadmin/',
    'sql/',
    'mysql/',
    'database/',
    'db/',
    'phpMyAdmin/',
    'composer.json',
    'package.json',
    'yarn.lock',
    'package-lock.json',
    'Dockerfile',
    'docker-compose.yml',
    'Jenkinsfile',
    '.travis.yml',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    'CONTRIBUTING.md'
]

def find_sensitive_files():
    print(Fore.CYAN + "\n=== Sensitive File Finder ===\n")
    
    url = input(Fore.GREEN + "Enter the target URL (e.g., example.com): " + Style.RESET_ALL)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove trailing slash if present
    url = url.rstrip('/')
    
    found_files = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    print(Fore.YELLOW + "\n[*] Starting sensitive file scan...")
    
    try:
        for file_path in tqdm(SENSITIVE_FILES, desc="Testing files"):
            test_url = f"{url}/{file_path}"
            try:
                response = requests.get(test_url, headers=headers, timeout=5, allow_redirects=True)
                
                # Check response status and content
                if response.status_code == 200:
                    content_length = len(response.content)
                    
                    # Skip if content is too small (likely 404 page)
                    if content_length < 10:
                        continue
                    
                    # Check if response is binary
                    is_binary = False
                    try:
                        response.content.decode('utf-8')
                    except UnicodeDecodeError:
                        is_binary = True
                    
                    found_files.append({
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_length': content_length,
                        'content_type': response.headers.get('content-type', 'unknown'),
                        'is_binary': is_binary
                    })
                    
                    print(Fore.GREEN + f"\n[+] Found: {test_url}")
                    print(Fore.GREEN + f"    Size: {content_length} bytes")
                    print(Fore.GREEN + f"    Type: {response.headers.get('content-type', 'unknown')}")
                
                # Check for interesting response codes
                elif response.status_code in [401, 403]:
                    found_files.append({
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('content-type', 'unknown'),
                        'is_binary': False
                    })
                    print(Fore.YELLOW + f"\n[!] Protected file found: {test_url} (Status: {response.status_code})")
                    
            except requests.exceptions.RequestException:
                continue
        
        # Save results
        if found_files:
            if not os.path.exists("data/results"):
                os.makedirs("data/results")
                
            output_file = f"data/results/sensitive_files.txt"
            with open(output_file, "w") as f:
                f.write(f"Sensitive File Scan Results for {url}\n")
                f.write("=" * 50 + "\n\n")
                for file in found_files:
                    f.write(f"URL: {file['url']}\n")
                    f.write(f"Status Code: {file['status_code']}\n")
                    f.write(f"Content Length: {file['content_length']} bytes\n")
                    f.write(f"Content Type: {file['content_type']}\n")
                    f.write(f"Is Binary: {file['is_binary']}\n")
                    f.write("-" * 30 + "\n")
            
            print(Fore.GREEN + f"\n[+] Found {len(found_files)} sensitive files")
            print(Fore.GREEN + f"[+] Results saved to {output_file}")
        else:
            print(Fore.RED + "\n[-] No sensitive files found")
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user")
    except Exception as e:
        print(Fore.RED + f"\nError during scan: {str(e)}")
    
    return found_files