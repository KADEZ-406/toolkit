import requests
from colorama import Fore, Style
from tqdm import tqdm
import os
import random
import time

# Common admin page paths with more variations
ADMIN_PATHS = [
    # Standard admin paths
    'admin/', 'administrator/', 'admin.php', 'admin.html', 'admin.asp', 'admin.aspx',
    'admincp/', 'admin/cp.php', 'admin/dashboard/', 'admin/admin.php', 'admin/login',
    'admin/login.php', 'admin/login.html', 'admin/index.php', 'admin/home',
    
    # WordPress specific
    'wp-admin/', 'wp-login.php', 'wp-login/', 'wordpress/wp-admin/', 'wp/wp-admin/',
    'blog/wp-admin/', 'wp-admin/admin-ajax.php',
    
    # Common CMS admin paths
    'administrator/index.php', 'administrator/login.php', 'cms/admin/', 'cms/administrator/',
    'system/admin/', 'system/administrator/', 'control/', 'control/login', 'cp/', 'cp/login',
    
    # Joomla specific
    'joomla/administrator/', 'administrator/', 'admin/index.php', 'administrator/index.php',
    'administrator/login.php', 'administrator/admin.php', 'joomla/admin/',
    
    # Drupal specific
    'user/login/', 'user/admin/', 'user/login.php', 'admin/user/login', 'drupal/admin/',
    
    # Laravel/PHP specific
    'laravel-admin/', 'laravel/admin/', 'admin/auth/login', 'auth/login', 'auth/admin',
    
    # Common variations
    'adminarea/', 'admin-area/', 'admin_area/', 'admin-login/', 'admin_login/',
    'login-admin/', 'login_admin/', 'admin123/', 'admin_123/', 'admin-123/',
    
    # Backend variations
    'backend/', 'backend/login', 'backend/admin', 'backend/dashboard', 'backend/cp',
    'admin/backend/', 'administrator/backend/', 'backoffice/', 'back-office/',
    
    # Panel variations
    'panel/', 'panel/login', 'panel/admin', 'panel/dashboard', 'control-panel/',
    'controlpanel/', 'admin-panel/', 'admin_panel/', 'adminpanel/', 'cpanel/',
    
    # Dashboard variations
    'dashboard/', 'dashboard/login', 'dashboard/admin', 'admin/dashboard/',
    'administrator/dashboard/', 'dash/', 'admin-dash/', 'admin_dash/',
    
    # Moderator/staff paths
    'moderator/', 'moderator/login', 'moderator/admin', 'staff/', 'staff/login',
    'staff/admin', 'staff-area/', 'staff_area/', 'staffcp/', 'staff-cp/',
    
    # Management paths
    'manage/', 'management/', 'manager/', 'mgr/', 'manage/login', 'management/login',
    'manager/login', 'manage/admin', 'management/admin', 'manager/admin',
    
    # Additional common paths
    'adm/', 'admin1/', 'admin2/', 'admin3/', 'admin4/', 'admin5/',
    'moderator/', 'webadmin/', 'adminarea/', 'bb-admin/', 'adminLogin/',
    'admin_area/', 'panel-administracion/', 'instadmin/', 'memberadmin/',
    'administratorlogin/', 'adm/', 'admin/account.php', 'admin/index.html',
    'admin/login.html', 'admin/admin.html', 'admin/home.html',
    
    # Common file names
    'administrator.php', 'administrator.html', 'administrator.jsp', 'administrator.asp',
    'administrator.aspx', 'admin.jsp', 'admin.cgi', 'admin.pl',
    
    # Secure/SSL variations
    'secure/', 'secure/admin/', 'secure/login/', 'secure/admin-login/',
    'ssl/', 'ssl/admin/', 'ssl/login/', 'ssl/admin-login/',
]

# Bypass techniques for 403/401/406
BYPASS_HEADERS = [
    {
        'X-Original-URL': 'admin/',
        'X-Rewrite-URL': 'admin/'
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
        'X-Original-URL': '../admin/'
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

def try_path_with_bypass(session, base_url, path, original_headers):
    """Try different bypass techniques for a given path"""
    results = []
    
    # Try different request methods
    methods = ['GET', 'POST', 'HEAD', 'OPTIONS']
    
    for method in methods:
        # Try original request
        try:
            headers = original_headers.copy()
            headers['User-Agent'] = random.choice(USER_AGENTS)
            
            response = session.request(
                method,
                f"{base_url}/{path}",
                headers=headers,
                timeout=5,
                allow_redirects=True
            )
            
            if response.status_code in [200, 302, 401, 403, 406]:
                results.append({
                    'url': f"{base_url}/{path}",
                    'method': method,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'title': get_page_title(response.text)
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
                        f"{base_url}/{path}",
                        headers=headers,
                        timeout=5,
                        allow_redirects=True
                    )
                    
                    if response.status_code == 200:
                        results.append({
                            'url': f"{base_url}/{path}",
                            'method': method,
                            'status_code': response.status_code,
                            'content_length': len(response.content),
                            'title': get_page_title(response.text),
                            'bypass_headers': bypass_header
                        })
                        
                except requests.exceptions.RequestException:
                    continue
    
    return results

def find_admin_pages():
    print(Fore.CYAN + "\n=== Enhanced Admin Page Finder ===\n")
    
    url = input(Fore.GREEN + "Enter the target URL (e.g., example.com): " + Style.RESET_ALL)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove trailing slash if present
    url = url.rstrip('/')
    
    found_pages = []
    base_headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    print(Fore.YELLOW + "\n[*] Starting enhanced admin page scan with bypass techniques...")
    
    try:
        with requests.Session() as session:
            for path in tqdm(ADMIN_PATHS, desc="Testing paths"):
                # Add small delay to avoid overwhelming the server
                time.sleep(0.1)
                
                results = try_path_with_bypass(session, url, path, base_headers)
                
                for result in results:
                    found_pages.append(result)
                    
                    if 'bypass_headers' in result:
                        print(Fore.GREEN + f"\n[+] Found with bypass: {result['url']}")
                        print(Fore.GREEN + f"    Method: {result['method']}")
                        print(Fore.GREEN + f"    Status: {result['status_code']}")
                        print(Fore.GREEN + f"    Bypass headers: {result['bypass_headers']}")
                    else:
                        status_color = Fore.GREEN if result['status_code'] == 200 else Fore.YELLOW
                        print(status_color + f"\n[+] Found: {result['url']}")
                        print(status_color + f"    Method: {result['method']}")
                        print(status_color + f"    Status: {result['status_code']}")
        
        # Save results
        if found_pages:
            if not os.path.exists("data/results"):
                os.makedirs("data/results")
                
            output_file = f"data/results/admin_pages.txt"
            with open(output_file, "w") as f:
                f.write(f"Enhanced Admin Page Scan Results for {url}\n")
                f.write("=" * 50 + "\n\n")
                for page in found_pages:
                    f.write(f"URL: {page['url']}\n")
                    f.write(f"Method: {page['method']}\n")
                    f.write(f"Status Code: {page['status_code']}\n")
                    f.write(f"Content Length: {page['content_length']}\n")
                    if page.get('title'):
                        f.write(f"Page Title: {page['title']}\n")
                    if page.get('bypass_headers'):
                        f.write(f"Bypass Headers: {page['bypass_headers']}\n")
                    f.write("-" * 30 + "\n")
            
            print(Fore.GREEN + f"\n[+] Found {len(found_pages)} potential admin pages")
            print(Fore.GREEN + f"[+] Results saved to {output_file}")
        else:
            print(Fore.RED + "\n[-] No admin pages found")
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user")
    except Exception as e:
        print(Fore.RED + f"\nError during scan: {str(e)}")
    
    return found_pages

def get_page_title(html_content):
    """Extract page title from HTML content"""
    try:
        start = html_content.find('<title>')
        end = html_content.find('</title>')
        if start != -1 and end != -1:
            return html_content[start + 7:end].strip()
    except:
        pass
    return None 