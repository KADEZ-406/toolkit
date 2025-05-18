# KADEZ-406 Penetration Testing Tool

KADEZ-406 is a comprehensive command-line penetration testing tool that combines multiple security testing capabilities into a single, powerful CLI interface. It provides various scanners, tools, and security checks to help security professionals and penetration testers assess web applications efficiently from the terminal.

## 🚀 Features

### Scanners
- SQL Injection Scanner (Single URL and Mass Scanning)
- Port Scanner
- WAF (Web Application Firewall) Detector
- Enhanced Recon Module with Nmap and Amass Integration

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
Nmap
Amass
```

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/KADEZ-406/toolkit.git
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

4. Install system dependencies:
```bash
# Debian/Ubuntu
sudo apt-get install nmap amass

# Windows (with Chocolatey)
choco install nmap amass
```

5. Configure your environment:
- Create necessary directories:
  ```bash
  mkdir -p data/results
  ```

## 🚀 Usage

Run the main script:
```bash
python kadez.py
```

### Output Files

All scan results are saved in the `data/results/` directory:
- `vuln_urls.txt` - SQL injection vulnerabilities
- `waf_detection.json` - WAF analysis results
- `domain_recon.json` - Information gathering results
- `admin_pages.txt` - Found admin pages
- `sensitive_files.txt` - Found sensitive files
- `tech_analysis.json` - Detected technologies
- `nmap_[domain].txt` - Nmap scan results
- `amass_[domain].txt` - Amass enumeration results

## 🛡️ Security Considerations

- This tool is for educational and authorized testing purposes only
- Always obtain proper authorization before testing any target
- Some features may require API keys (e.g., Shodan)
- Store sensitive API keys in environment variables

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Uses various open-source security tools and libraries
- Community contributions and feedback

## ⚠️ Disclaimer

This tool is for educational purposes and authorized testing only. Users are responsible for obtaining proper authorization before testing any target systems. The developers are not responsible for any misuse or damage caused by this tool.

## 📧 Contact

Project Link: [https://github.com/KADEZ-406/toolkit](https://github.com/KADEZ-406/toolkit)
