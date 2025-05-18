# KADEZ-406 Penetration Testing Tool

KADEZ-406 is a comprehensive penetration testing tool designed for security professionals and ethical hackers. It provides various modules for reconnaissance and vulnerability assessment.

## Features

- **Information Gathering**
  - WHOIS lookup
  - DNS enumeration
  - Subdomain discovery
  - Port scanning with Nmap integration
  - Web technology detection
  - GeoIP information

- **Web Application Testing**
  - Directory listing detection
  - File discovery
  - CMS detection
  - Clickjacking vulnerability testing
  - Admin panel finder

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/KADEZ-406.git
cd KADEZ-406
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the main tool:
```bash
python kadez.py
```

## Project Structure

```
KADEZ-406/
├── core/               # Core functionality
│   ├── __init__.py
│   └── recon.py       # Reconnaissance module
├── modules/           # Testing modules
│   ├── __init__.py
│   ├── admin_finder.py
│   ├── clickjacking.py
│   ├── cms_detector.py
│   ├── dir_listing.py
│   └── file_finder.py
├── data/             # Data directory
│   ├── admin.txt     # Admin panel wordlist
│   ├── files.txt     # File discovery wordlist
│   └── results/      # Scan results directory
├── wordlists/        # Additional wordlists
├── requirements.txt  # Python dependencies
└── kadez.py         # Main application
```

## Requirements

- Python 3.8+
- See requirements.txt for Python package dependencies

## Dependencies

The tool requires the following main packages:
- colorama
- pyfiglet
- requests
- python-whois
- dnspython
- beautifulsoup4
- shodan
- python-nmap
- tqdm
- cryptography
- Flask
- Flask-WTF
- Werkzeug

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational purposes and ethical penetration testing only. Users are responsible for obtaining proper authorization before testing any systems they don't own or have explicit permission to test.

## 📧 Contact

Project Link: [https://github.com/KADEZ-406/toolkit](https://github.com/KADEZ-406/toolkit)
