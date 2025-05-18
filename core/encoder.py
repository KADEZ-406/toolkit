import base64
import hashlib
import urllib.parse
from colorama import Fore, Style
import os

def encode_text():
    print(Fore.CYAN + "\n=== Text Encoder Tool ===\n")
    
    text = input(Fore.GREEN + "Enter text to encode: " + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\nEncoding results:")
    
    # Base64
    base64_encoded = base64.b64encode(text.encode()).decode()
    print(Fore.GREEN + "\n[+] Base64:")
    print(Fore.WHITE + base64_encoded)
    
    # URL Encode
    url_encoded = urllib.parse.quote_plus(text)
    print(Fore.GREEN + "\n[+] URL Encoded:")
    print(Fore.WHITE + url_encoded)
    
    # Double URL Encode
    double_url_encoded = urllib.parse.quote_plus(url_encoded)
    print(Fore.GREEN + "\n[+] Double URL Encoded:")
    print(Fore.WHITE + double_url_encoded)
    
    # MD5
    md5_hash = hashlib.md5(text.encode()).hexdigest()
    print(Fore.GREEN + "\n[+] MD5 Hash:")
    print(Fore.WHITE + md5_hash)
    
    # SHA-1
    sha1_hash = hashlib.sha1(text.encode()).hexdigest()
    print(Fore.GREEN + "\n[+] SHA-1 Hash:")
    print(Fore.WHITE + sha1_hash)
    
    # SHA-256
    sha256_hash = hashlib.sha256(text.encode()).hexdigest()
    print(Fore.GREEN + "\n[+] SHA-256 Hash:")
    print(Fore.WHITE + sha256_hash)
    
    # Save results
    if not os.path.exists("data/results"):
        os.makedirs("data/results")
        
    result = {
        "original_text": text,
        "base64": base64_encoded,
        "url_encoded": url_encoded,
        "double_url_encoded": double_url_encoded,
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash
    }
    
    with open("data/results/encoded_text.txt", "a") as f:
        f.write("\n=== Encoding Results ===\n")
        for key, value in result.items():
            f.write(f"{key}: {value}\n")
        f.write("=" * 30 + "\n")
    
    print(Fore.GREEN + "\n[+] Results saved to data/results/encoded_text.txt") 