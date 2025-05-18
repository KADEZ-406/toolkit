# KADEZ-406 Penetration Testing Tool

KADEZ-406 is a comprehensive command-line penetration testing tool that combines multiple security testing capabilities into a single, powerful CLI interface. It provides various scanners, tools, and security checks to help security professionals and penetration testers assess web applications efficiently from the terminal.

![KADEZ-406 Logo](static/img/logo.png) *(Add your logo image)*

## 🚀 Features

### Scanners
- SQL Injection Scanner (Single URL and Mass Scanning)
- Port Scanner
- WAF (Web Application Firewall) Detector

### Tools
- Text Encoder (Various encoding formats)
- Hex Converter (String to Hex and vice versa)
- Real IP Finder
- Technology Stack Analyzer

### Finders & Checkers
- Admin Page Finder
- Sensitive File Finder
- CMS Detector
- Clickjacking Vulnerability Checker
- Directory Listing Checker

## 📋 Requirements

```
Python 3.8+
pip (Python package installer)
```

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/KADEZ-406/kadez-406.git
cd kadez-406
```

2. Create and activate a virtual environment (recommended):
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. Install required dependencies:
```bash
pip install -r requirements.txt
```

4. Configure your environment:
- Create necessary directories:
  ```bash
  mkdir -p data/results
  ```

## 🚀 Usage

Run the main script:
```bash
python kadez.py
```

### Available Commands

1. SQL Injection Scanner:
```bash
# Single URL scan
python kadez.py sqli -u <target_url>

# Mass scan from file
python kadez.py sqli -f urls.txt
```

2. Port Scanner:
```bash
python kadez.py portscan -t <target_host> [-p <port_range>]
```

3. WAF Detection:
```bash
python kadez.py waf -u <target_url>
```

4. Text Encoding:
```bash
python kadez.py encode -t <text> [-m <method>]
# Methods: base64, url, md5, sha256
```

5. Hex Conversion:
```bash
# String to Hex
python kadez.py hex -s "string"

# Hex to String
python kadez.py hex -x "68657864656320"
```

6. Admin Finder:
```bash
python kadez.py admin -u <target_url>
```

7. File Finder:
```bash
python kadez.py files -u <target_url>
```

8. CMS Detection:
```bash
python kadez.py cms -u <target_url>
```

9. Security Checks:
```bash
# Clickjacking Test
python kadez.py click -u <target_url>

# Directory Listing Check
python kadez.py dirlist -u <target_url>
```

### Output Files

All scan results are saved in the `data/results/` directory:
- `vuln_urls.txt` - SQL injection vulnerabilities
- `waf_detection.json` - WAF analysis results
- `domain_recon.json` - Information gathering results
- `admin_pages.txt` - Found admin pages
- `sensitive_files.txt` - Found sensitive files
- `tech_analysis.json` - Detected technologies

## 📁 Project Structure

```
kadez-406/
├── kadez.py              # Main CLI application
├── requirements.txt      # Python dependencies
├── core/                 # Core functionality modules
│   ├── scanner.py
│   ├── waf.py
│   ├── encoder.py
│   ├── convert.py
│   ├── recon.py
│   ├── real_ip.py
│   └── tech_analyst.py
├── modules/              # Additional feature modules
│   ├── admin_finder.py
│   ├── file_finder.py
│   ├── cms_detector.py
│   ├── clickjacking.py
│   └── dir_listing.py
└── data/                # Data storage
    └── results/         # Scan results storage
```

## 🛡️ Security Considerations

- This tool is for educational and authorized testing purposes only
- Always obtain proper authorization before testing any target
- Some features may require API keys (e.g., Shodan)
- Store sensitive API keys in environment variables
- Regular updates are recommended for security patches

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Uses various open-source security tools and libraries
- Community contributions and feedback

## ⚠️ Disclaimer

This tool is for educational purposes and authorized testing only. Users are responsible for obtaining proper authorization before testing any target systems. The developers are not responsible for any misuse or damage caused by this tool.

## 📧 Contact

Your Name - [@KADEZ-406](https://twitter.com/KADEZ-406)
Project Link: [https://github.com/KADEZ-406/kadez-406](https://github.com/KADEZ-406/kadez-406) 