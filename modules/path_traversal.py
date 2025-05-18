import requests
import os
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

class PathTraversal:
    def __init__(self):
        self.payloads = []
        self.target_files = []
        self.load_payloads()
        self.results = []
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def load_payloads(self):
        """Load path traversal payloads from wordlist"""
        wordlist_path = os.path.join('data', 'traversal.txt')
        try:
            with open(wordlist_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.payloads.append(line)
        except Exception as e:
            print(f"Error loading payloads: {str(e)}")
            return False
        return True

    def test_payload(self, url, payload):
        """Test a single path traversal payload"""
        try:
            # Parse the URL and identify potential parameters
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Test in URL path
            if base_url.endswith('/'):
                base_url = base_url[:-1]
            path_url = f"{base_url}/{payload}"
            
            try:
                resp = self.session.get(path_url, allow_redirects=False, timeout=10)
                if self.check_success(resp):
                    self.results.append({
                        'url': path_url,
                        'payload': payload,
                        'status': resp.status_code,
                        'length': len(resp.content),
                        'type': 'URL Path'
                    })
            except requests.RequestException:
                pass  # Silently handle connection errors for invalid paths

            # Test in parameters if they exist
            if parsed.query:
                params = {}
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = payload
                        param_url = base_url + '?' + '&'.join(f"{k}={v}" for k, v in params.items())
                        try:
                            resp = self.session.get(param_url, allow_redirects=False, timeout=10)
                            if self.check_success(resp):
                                self.results.append({
                                    'url': param_url,
                                    'payload': payload,
                                    'status': resp.status_code,
                                    'length': len(resp.content),
                                    'type': f'Parameter ({key})'
                                })
                        except requests.RequestException:
                            pass  # Silently handle connection errors for invalid paths
                        params[key] = value  # Reset parameter value

        except Exception as e:
            pass  # Silently handle any other errors

    def check_success(self, response):
        """Check if the path traversal attempt was successful"""
        if response.status_code in [200, 206]:
            content = response.content.lower()
            # Check for common file content indicators
            indicators = [
                b'root:', b'[boot loader]', b'[operating systems]',
                b'<?php', b'#!/bin', b'mysql', b'password',
                b'pwd', b'root:', b'daemon:', b'mail:',
                b'ftp:', b'http:', b'uucp:', b'operator:',
                b'nobody:', b'registry', b'[ntfs]', b'[paths]'
            ]
            return any(i in content for i in indicators)
        return False

    def scan(self, url, max_threads=10):
        """Main scanning function"""
        print(f"[*] Starting path traversal scan on {url}")
        print(f"[*] Loaded {len(self.payloads)} traversal payloads")
        
        print(f"[*] Testing {len(self.payloads)} payload combinations")
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            list(tqdm(executor.map(lambda p: self.test_payload(url, p), self.payloads),
                     total=len(self.payloads),
                     desc="Testing payloads"))

        # Save results
        if self.results:
            output_dir = "data/results"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            domain = urlparse(url).netloc
            output_file = os.path.join(output_dir, f"traversal_{domain}.txt")
            
            with open(output_file, 'w') as f:
                f.write(f"Path Traversal Scan Results for {url}\n")
                f.write("=" * 60 + "\n\n")
                for result in self.results:
                    f.write(f"Found: {result['type']}\n")
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Payload: {result['payload']}\n")
                    f.write(f"Status: {result['status']}\n")
                    f.write(f"Response Length: {result['length']}\n")
                    f.write("-" * 60 + "\n")
            
            print(f"\n[+] Found {len(self.results)} potential path traversal vulnerabilities")
            print(f"[+] Results saved to {output_file}")
        else:
            print("\n[-] No path traversal vulnerabilities found")

        return self.results

def scan_path_traversal(url):
    """Function to be called from main script"""
    scanner = PathTraversal()
    return scanner.scan(url) 