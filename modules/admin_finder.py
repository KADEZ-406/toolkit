import requests
from colorama import Fore, Style
from tqdm import tqdm
import os

# Common admin page paths
ADMIN_PATHS = [
    'admin/',
    'administrator/',
    'admin.php',
    'admin.html',
    'admin.asp',
    'admin.aspx',
    'admincp/',
    'admin/cp.php',
    'admin/dashboard/',
    'admin/admin.php',
    'admin/login',
    'admin/login.php',
    'admin/login.html',
    'admin/index.php',
    'admin/home',
    'wp-admin/',
    'wp-login.php',
    'panel/',
    'cpanel/',
    'dashboard/',
    'moderator/',
    'webadmin/',
    'adminarea/',
    'bb-admin/',
    'adminLogin/',
    'admin_area/',
    'panel-administracion/',
    'instadmin/',
    'memberadmin/',
    'administratorlogin/',
    'adm/',
    'login.php',
    'login.html',
    'login/',
    'administration/',
    'sysadmin/',
    'phpmyadmin/',
    'administrator/index.php',
    'administrator/login.php',
    'user.php',
    'user.html',
    'admin1.php',
    'admin1.html',
    'admin2.php',
    'admin2.html',
    'yonetim.php',
    'yonetim.html',
    'yonetici.php',
    'yonetici.html',
    'adm.php',
    'adm.html',
    'moderator.php',
    'moderator.html',
    'moderator/login.php',
    'moderator/login.html',
    'moderator/admin.php',
    'moderator/admin.html',
]

def find_admin_pages():
    print(Fore.CYAN + "\n=== Admin Page Finder ===\n")
    
    url = input(Fore.GREEN + "Enter the target URL (e.g., example.com): " + Style.RESET_ALL)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove trailing slash if present
    url = url.rstrip('/')
    
    found_pages = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    print(Fore.YELLOW + "\n[*] Starting admin page scan...")
    
    try:
        for path in tqdm(ADMIN_PATHS, desc="Testing paths"):
            test_url = f"{url}/{path}"
            try:
                response = requests.get(test_url, headers=headers, timeout=5, allow_redirects=True)
                
                # Check if page exists (200 OK) or redirects to login
                if response.status_code == 200:
                    found_pages.append({
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'title': get_page_title(response.text)
                    })
                    print(Fore.GREEN + f"\n[+] Found: {test_url} (Status: {response.status_code})")
                
                # Check for specific response codes that might indicate admin pages
                elif response.status_code in [302, 401, 403]:
                    found_pages.append({
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'title': get_page_title(response.text)
                    })
                    print(Fore.YELLOW + f"\n[!] Potential admin page: {test_url} (Status: {response.status_code})")
                    
            except requests.exceptions.RequestException:
                continue
        
        # Save results
        if found_pages:
            if not os.path.exists("data/results"):
                os.makedirs("data/results")
                
            output_file = f"data/results/admin_pages.txt"
            with open(output_file, "w") as f:
                f.write(f"Admin Page Scan Results for {url}\n")
                f.write("=" * 50 + "\n\n")
                for page in found_pages:
                    f.write(f"URL: {page['url']}\n")
                    f.write(f"Status Code: {page['status_code']}\n")
                    f.write(f"Content Length: {page['content_length']}\n")
                    if page['title']:
                        f.write(f"Page Title: {page['title']}\n")
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