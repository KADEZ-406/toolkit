import requests
from colorama import Fore, Style
from tqdm import tqdm
import os
import random
import time
from urllib.parse import urljoin
import re
from difflib import SequenceMatcher

# Common sensitive file patterns
SENSITIVE_FILES = [
    # Configuration files
    '.env', 'config.php', 'config.inc.php', 'configuration.php', 'settings.php',
    'config.yml', 'config.yaml', 'config.json', 'config.xml', 'config.ini',
    'wp-config.php', 'wp-config.bak', 'wp-config.old', 'wp-config.txt',
    'config.js', 'config.conf', 'database.yml', 'settings.ini', '.htconfig.php',
    
    # Backup files
    'backup.zip', 'backup.tar', 'backup.tar.gz', 'backup.tgz', 'backup.sql',
    'backup.old', 'backup.bak', 'backup.txt', 'backup-db.sql', 'db_backup.sql',
    'db.sql', 'database.sql', 'mysql.sql', 'dump.sql', 'data.sql',
    
    # Log files
    'error.log', 'error_log', 'debug.log', 'access.log', 'php_error.log',
    'server.log', 'mysql.log', 'mail.log', '.logs/', 'logs/', 'log.txt',
    
    # Version control
    '.git/HEAD', '.git/config', '.gitignore', '.git/index',
    '.svn/entries', '.svn/wc.db', '.hg/', 'CVS/Root', 'CVS/Entries',
    
    # IDE and development files
    '.vscode/launch.json', '.idea/workspace.xml', 'nbproject/private/',
    'Dockerfile', 'docker-compose.yml', 'Vagrantfile',
    
    # PHP files
    'phpinfo.php', 'info.php', 'test.php', 'php.ini', '.php_cs.cache',
    'composer.json', 'composer.lock', 'vendor/autoload.php',
    
    # Common CMS files
    'wp-config.php', 'wp-admin/', 'wp-includes/', 'wp-content/debug.log',
    'configuration.php', 'joomla.xml', 'drupal/', 'administrator/',
    'admin/', 'admin.php', 'admin.html', 'login.php',
    
    # Database files
    '.sqlite', '.db', '.mysql_history', '.psql_history', '.pgpass',
    'phpmyadmin/', 'adminer.php', 'adminer/', 'myadmin/',
    
    # Sensitive directories
    'backup/', 'backups/', 'bak/', 'old/', 'temp/', 'tmp/', 'admin/',
    'test/', 'dev/', 'development/', 'staging/', 'beta/', 'debug/',
    
    # Common sensitive extensions
    '.bak', '.old', '.backup', '.swp', '.save', '.copy', '~',
    '.tmp', '.temp', '.cfg', '.conf', '.config', '.ini', '.dist',
    
    # API and documentation
    'api/', 'api/v1/', 'api/v2/', 'swagger/', 'swagger.json', 'swagger.yaml',
    'docs/', 'documentation/', 'apidoc/', 'javadoc/', 'api-docs/',
    
    # Server configuration
    '.htaccess', '.htpasswd', 'web.config', 'robots.txt', 'crossdomain.xml',
    'sitemap.xml', '.well-known/', 'security.txt',
    
    # Common frameworks
    'laravel/.env', 'symfony/.env', 'codeigniter/application/config/database.php',
    'yii/config/db.php', 'fuel/app/config/development/',
    
    # JavaScript and frontend
    'package.json', 'package-lock.json', 'yarn.lock', 'bower.json',
    'webpack.config.js', 'gruntfile.js', 'gulpfile.js',
    
    # Python
    'requirements.txt', 'pip.log', 'pip.conf', '.pypirc', '.python-version',
    'venv/', 'virtualenv/', 'env/', '.env/', 'pythonenv/',
    
    # Ruby
    'Gemfile', 'Gemfile.lock', 'config/database.yml', 'config/secrets.yml',
    'config/master.key', 'config/credentials.yml.enc',
    
    # Java
    'WEB-INF/web.xml', 'META-INF/context.xml', 'application.properties',
    'application.yml', 'application-dev.properties',
]

# Bypass techniques for 403/401/406
BYPASS_HEADERS = [
    {
        'X-Original-URL': '../',
        'X-Rewrite-URL': '../'
    },
    {
        'X-Custom-IP-Authorization': 'localhost',
        'X-Forwarded-For': '127.0.0.1',
        'X-Forward-For': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1',
        'X-Originating-IP': '127.0.0.1',
        'X-Remote-Addr': '127.0.0.1',
        'X-Client-IP': '127.0.0.1'
    },
    {
        'X-Forwarded-Host': 'localhost',
        'X-Host': 'localhost'
    },
    {
        'Content-Length': '0',
        'X-Original-URL': '../'
    }
]

# Common User-Agents for bypassing restrictions
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
]

def detect_soft_404(session, base_url, original_headers):
    """Detect soft 404 patterns by requesting known non-existent pages"""
    random_paths = [
        f"this_page_definitely_does_not_exist_{random.randint(100000, 999999)}.html",
        f"definitely_not_found_{random.randint(100000, 999999)}.php",
        f"no_such_page_{random.randint(100000, 999999)}/",
    ]
    
    soft_404_patterns = []
    content_lengths = []
    page_titles = []
    
    for path in random_paths:
        try:
            url = urljoin(base_url, path)
            headers = original_headers.copy()
            headers['User-Agent'] = random.choice(USER_AGENTS)
            
            response = session.get(url, headers=headers, timeout=5, allow_redirects=True)
            
            if response.status_code == 200:
                # Store the content length
                content_lengths.append(len(response.content))
                
                # Store page title if exists
                title = extract_page_title(response.text)
                if title:
                    page_titles.append(title)
                
                # Store common 404 text patterns
                text = response.text.lower()
                patterns = [
                    "404", "not found", "page not found", "does not exist",
                    "could not be found", "no longer available", "not available",
                    "error", "no encontrada", "não encontrada", "не найдена"
                ]
                
                for pattern in patterns:
                    if pattern in text:
                        soft_404_patterns.append(pattern)
        
        except requests.exceptions.RequestException:
            continue
    
    return {
        'content_lengths': content_lengths,
        'page_titles': page_titles,
        'patterns': list(set(soft_404_patterns))
    }

def extract_page_title(html_content):
    """Extract page title from HTML content"""
    try:
        title_match = re.search('<title>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
    except:
        pass
    return None

def is_soft_404(response_text, response_length, soft_404_info):
    """Check if a response matches soft 404 patterns"""
    # Check content length similarity
    if soft_404_info['content_lengths']:
        avg_404_length = sum(soft_404_info['content_lengths']) / len(soft_404_info['content_lengths'])
        length_similarity = abs(response_length - avg_404_length) / max(response_length, avg_404_length)
        if length_similarity > 0.98:  # 98% similar in length
            return True
    
    # Check title similarity
    page_title = extract_page_title(response_text)
    if page_title and soft_404_info['page_titles']:
        for title_404 in soft_404_info['page_titles']:
            if SequenceMatcher(None, page_title, title_404).ratio() > 0.9:  # 90% similar title
                return True
    
    # Check for 404 patterns in content
    text = response_text.lower()
    for pattern in soft_404_info['patterns']:
        if pattern in text:
            return True
    
    return False

def try_path_with_bypass(session, base_url, path, original_headers, soft_404_info):
    """Try different bypass techniques for a given path"""
    results = []
    
    # Try different request methods
    methods = ['GET', 'HEAD', 'OPTIONS']
    
    for method in methods:
        # Try original request
        try:
            headers = original_headers.copy()
            headers['User-Agent'] = random.choice(USER_AGENTS)
            
            url = urljoin(base_url, path)
            response = session.request(
                method,
                url,
                headers=headers,
                timeout=5,
                allow_redirects=True
            )
            
            # Skip if it's a soft 404
            if response.status_code == 200:
                if method == 'GET' and is_soft_404(response.text, len(response.content), soft_404_info):
                    continue
            
            if response.status_code in [200, 302, 401, 403, 406]:
                results.append({
                    'url': url,
                    'method': method,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('Content-Type', ''),
                    'title': extract_page_title(response.text) if method == 'GET' else None
                })
        
        except requests.exceptions.RequestException:
            continue
        
        # Try bypass headers if we got 403/401/406
        if response.status_code in [401, 403, 406]:
            for bypass_header in BYPASS_HEADERS:
                try:
                    headers = original_headers.copy()
                    headers.update(bypass_header)
                    headers['User-Agent'] = random.choice(USER_AGENTS)
                    
                    response = session.request(
                        method,
                        url,
                        headers=headers,
                        timeout=5,
                        allow_redirects=True
                    )
                    
                    # Skip if it's a soft 404
                    if response.status_code == 200:
                        if method == 'GET' and is_soft_404(response.text, len(response.content), soft_404_info):
                            continue
                    
                    if response.status_code == 200:
                        results.append({
                            'url': url,
                            'method': method,
                            'status_code': response.status_code,
                            'content_length': len(response.content),
                            'content_type': response.headers.get('Content-Type', ''),
                            'title': extract_page_title(response.text) if method == 'GET' else None,
                            'bypass_headers': bypass_header
                        })
                        
                except requests.exceptions.RequestException:
                    continue
    
    return results

def find_sensitive_files():
    print(Fore.CYAN + "\n=== Enhanced Sensitive File Finder ===\n")
    
    url = input(Fore.GREEN + "Enter the target URL (e.g., example.com): " + Style.RESET_ALL)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove trailing slash if present
    url = url.rstrip('/')
    
    found_files = []
    base_headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': '*/*',  # Accept any content type
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache'
    }
    
    print(Fore.YELLOW + "\n[*] Detecting server's 404 response pattern...")
    with requests.Session() as session:
        soft_404_info = detect_soft_404(session, url, base_headers)
        if soft_404_info['patterns']:
            print(Fore.YELLOW + "[*] Detected soft 404 patterns: " + ", ".join(soft_404_info['patterns']))
    
    print(Fore.YELLOW + "\n[*] Starting enhanced sensitive file scan with bypass techniques...")
    
    try:
        with requests.Session() as session:
            for path in tqdm(SENSITIVE_FILES, desc="Testing files"):
                # Add small delay to avoid overwhelming the server
                time.sleep(0.1)
                
                results = try_path_with_bypass(session, url, path, base_headers, soft_404_info)
                
                for result in results:
                    found_files.append(result)
                    
                    if 'bypass_headers' in result:
                        print(Fore.GREEN + f"\n[+] Found with bypass: {result['url']}")
                        print(Fore.GREEN + f"    Method: {result['method']}")
                        print(Fore.GREEN + f"    Status: {result['status_code']}")
                        print(Fore.GREEN + f"    Content-Type: {result['content_type']}")
                        if result.get('title'):
                            print(Fore.GREEN + f"    Title: {result['title']}")
                        print(Fore.GREEN + f"    Bypass headers: {result['bypass_headers']}")
                    else:
                        status_color = Fore.GREEN if result['status_code'] == 200 else Fore.YELLOW
                        print(status_color + f"\n[+] Found: {result['url']}")
                        print(status_color + f"    Method: {result['method']}")
                        print(status_color + f"    Status: {result['status_code']}")
                        print(status_color + f"    Content-Type: {result['content_type']}")
                        if result.get('title'):
                            print(status_color + f"    Title: {result['title']}")
        
        # Save results
        if found_files:
            if not os.path.exists("data/results"):
                os.makedirs("data/results")
                
            output_file = f"data/results/sensitive_files.txt"
            with open(output_file, "w") as f:
                f.write(f"Enhanced Sensitive File Scan Results for {url}\n")
                f.write("=" * 50 + "\n\n")
                for file in found_files:
                    f.write(f"URL: {file['url']}\n")
                    f.write(f"Method: {file['method']}\n")
                    f.write(f"Status Code: {file['status_code']}\n")
                    f.write(f"Content Length: {file['content_length']}\n")
                    f.write(f"Content-Type: {file['content_type']}\n")
                    if file.get('title'):
                        f.write(f"Page Title: {file['title']}\n")
                    if file.get('bypass_headers'):
                        f.write(f"Bypass Headers: {file['bypass_headers']}\n")
                    f.write("-" * 30 + "\n")
            
            print(Fore.GREEN + f"\n[+] Found {len(found_files)} potential sensitive files")
            print(Fore.GREEN + f"[+] Results saved to {output_file}")
        else:
            print(Fore.RED + "\n[-] No sensitive files found")
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user")
    except Exception as e:
        print(Fore.RED + f"\nError during scan: {str(e)}")
    
    return found_files