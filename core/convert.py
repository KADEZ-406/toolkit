from colorama import Fore, Style
import os

def string_to_hex():
    print(Fore.CYAN + "\n=== String to Hex Converter ===\n")
    
    text = input(Fore.GREEN + "Enter text to convert to hex: " + Style.RESET_ALL)
    
    try:
        # Convert to hex with different formats
        hex_space = ' '.join([hex(ord(c))[2:].zfill(2) for c in text])
        hex_no_space = ''.join([hex(ord(c))[2:].zfill(2) for c in text])
        hex_0x = ''.join(['0x' + hex(ord(c))[2:].zfill(2) for c in text])
        hex_percent = ''.join(['%' + hex(ord(c))[2:].zfill(2) for c in text])
        
        print(Fore.YELLOW + "\nHex conversion results:")
        print(Fore.GREEN + "\n[+] Hex (space-separated):")
        print(Fore.WHITE + hex_space)
        print(Fore.GREEN + "\n[+] Hex (no spaces):")
        print(Fore.WHITE + hex_no_space)
        print(Fore.GREEN + "\n[+] Hex (0x format):")
        print(Fore.WHITE + hex_0x)
        print(Fore.GREEN + "\n[+] Hex (percent format):")
        print(Fore.WHITE + hex_percent)
        
        # Save results
        if not os.path.exists("data/results"):
            os.makedirs("data/results")
            
        with open("data/results/hex_conversions.txt", "a") as f:
            f.write("\n=== String to Hex Conversion ===\n")
            f.write(f"Original text: {text}\n")
            f.write(f"Hex (space): {hex_space}\n")
            f.write(f"Hex (no space): {hex_no_space}\n")
            f.write(f"Hex (0x): {hex_0x}\n")
            f.write(f"Hex (percent): {hex_percent}\n")
            f.write("=" * 30 + "\n")
        
        print(Fore.GREEN + "\n[+] Results saved to data/results/hex_conversions.txt")
        
    except Exception as e:
        print(Fore.RED + f"\nError: {str(e)}")

def hex_to_string():
    print(Fore.CYAN + "\n=== Hex to String Converter ===\n")
    
    hex_text = input(Fore.GREEN + "Enter hex string (space-separated or continuous): " + Style.RESET_ALL)
    
    try:
        # Remove spaces and 0x if present
        hex_text = hex_text.replace(" ", "").replace("0x", "").replace("%", "")
        
        # Convert hex to string
        text = bytes.fromhex(hex_text).decode('utf-8')
        
        print(Fore.YELLOW + "\nDecoded string:")
        print(Fore.WHITE + text)
        
        # Save results
        if not os.path.exists("data/results"):
            os.makedirs("data/results")
            
        with open("data/results/hex_conversions.txt", "a") as f:
            f.write("\n=== Hex to String Conversion ===\n")
            f.write(f"Original hex: {hex_text}\n")
            f.write(f"Decoded text: {text}\n")
            f.write("=" * 30 + "\n")
        
        print(Fore.GREEN + "\n[+] Results saved to data/results/hex_conversions.txt")
        
    except Exception as e:
        print(Fore.RED + f"\nError: Invalid hex string or {str(e)}") 