# XSS Pro Scanner v1.0

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)

A professional-grade tool for detecting **Reflected**, **Stored**, and **DOM-based XSS** vulnerabilities with support for bypassing rate limits and identifying site blocking behavior.

---

## ✨ Features

- 🔍 Detects:
  - Reflected XSS (via URL injection)
  - Stored XSS (via POST payloads)
  - DOM-based XSS (via fragment injection)
- 🛡 WAF & Rate-limit detection
- 🌐 JavaScript-rendered XSS detection with Playwright
- 🎯 Payload customization (`FUZZ` injection placeholder)
- 🚨 Clean alerts with color-coded CLI output
- 💡 Ready to extend with resolvers, wordlists, and proxy support

---

## 📦 Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/xss-pro-scanner.git
cd xss-pro-scanner
```
2. Install dependencies
```
pip install -r requirements.txt
python3 -m playwright install
3. Run the scanner
python3 main.py
```

🧪 Usage
When you run the tool, you'll be prompted to enter:

A target URL (use FUZZ as the injection point)

The scan type:

1 – Reflected XSS

2 – Stored XSS (with custom POST data)

3 – DOM-based XSS

Example: Reflected XSS

Enter target URL (use FUZZ to inject): https://example.com/search?q=FUZZ
Enter choice: 1
Example: Stored XSS

Enter target URL: https://example.com/comment
Enter POST data: name=FUZZ&message=FUZZ
Enter choice: 2
Example: DOM-based XSS

Enter target URL: https://example.com/page
Enter choice: 3
📁 Folder Structure

xss-pro-scanner/
├── core/
│   ├── reflected.py
│   ├── stored.py
│   ├── dom.py
│   └── utils.py
├── scanners/
│   ├── http_scanner.py
│   └── browser_scanner.py
├── payloads/
│   └── wordlist.txt
├── output/
│   └── reports/
├── main.py
├── config.yaml
└── README.md
🧠 Customization
Payloads
Edit or extend payloads in payloads/wordlist.txt or modify the list in main.py.

Rate-Limit Bypass
Coming soon:

Proxy rotation

Random user agents

Header spoofing

Retry logic

🚧 Roadmap (v1.1+)
 Add automatic crawling for input discovery

 Export HTML/Markdown reports

 Proxy and Tor support

 Input auto-resolvers for form detection

 CLI flags for headless automation


