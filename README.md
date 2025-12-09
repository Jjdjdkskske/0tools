OSINT Multitool

**OSINT Multitool** is a Python 3 command-line tool focused on **legal and passive OSINT** (Open Source Intelligence), with a special emphasis on **Discord-related lookups** and general reconnaissance.

> ⚠️ This project is for **educational and legal purposes only**.  
> Do NOT use it for harassment, invasion of privacy, or illegal activities.

---

## Features

### Discord OSINT (Public & Passive)
- Discord ID → account creation date (Snowflake decoding)
- Discord avatar URL generator
- Discord invite lookup (public info only)
- Discord username format validation
- Message / User / Server ID timestamp decoding

### General OSINT
- IP geolocation lookup (GeoIP)
- Reverse DNS lookup
- DNS A record lookup
- MX record lookup
- WHOIS domain lookup
- SSL certificate information
- HTTP headers inspection
- robots.txt retrieval
- Domain parsing (subdomain, domain, TLD)
- Image EXIF metadata extraction (local files)
- Email format validation + MX check
- Webpage title & meta description extraction

---

## Requirements

- **Python 3.8+**

### Python dependencies
Install dependencies using `pip`:

```bash
pip install requests dnspython python-whois Pillow beautifulsoup4 colorama tldextract

> On Linux, python-whois may require the system package:



sudo apt install whois


---

Installation

1. Clone or download this repository


2. Install the required Python libraries


3. Run the script using Python 3



python osint_multitool.py


---

Usage

Run the script

Select a module from the menu

Provide the requested input (Discord ID, IP, domain, etc.)

Results are displayed directly in the terminal


The tool is designed to be simple, fast, and terminal-friendly.


---

Legal Disclaimer

This tool does not perform hacking, does not bypass security, and does not interact with private or protected systems.

You are fully responsible for how you use this tool. Only use it on:

Data you own

Publicly available information

Systems you have explicit permission to analyze



---

Compatibility

✅ Windows

✅ Linux

✅ macOS

✅ Android (Pydroid 3)



---

Author

dev by brzx_xx


---

License

This project is released for educational purposes. You are free to modify it, but reselling or malicious usage is strictly discouraged.
