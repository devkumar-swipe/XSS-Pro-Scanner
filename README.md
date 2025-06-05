# 🛡️ XSS Pro Scanner 2050 — Elite Edition

**AI-Powered Next-Gen XSS Detection Framework**  
Built by [Dev Kumar](https://github.com/devkumar-swipe) for elite bug bounty hunting and automated web app security analysis.

![Banner](https://img.shields.io/badge/XSS-Scanner-green?style=for-the-badge)
![Version](https://img.shields.io/badge/version-2050.2--Elite-blue?style=for-the-badge)
![OS](https://img.shields.io/badge/Linux-Kali%2FDebian%20Recommended-critical?style=for-the-badge)

---

## 📌 Features

- 🔍 Reflected, Stored, and DOM-based XSS Detection
- 🧠 Smart FUZZ Payload Injection (query/path/fragment/header-aware)
- 🌐 Full browser support using Playwright (headless Chromium)
- 🕸️ Auto Proxy Rotation with HTTP/SOCKS5 + Verification
- ⚙️ Concurrent Scanning with `--threads` option
- 📂 Multi-URL scanning via `--list urls.txt`
- ♻️ Resume scans from logs with `--continue`
- 📊 Report output in JSON, HTML, or Terminal

---

## 🐧 OS Compatibility

> ✅ **Recommended OS:** Kali Linux, Parrot OS, Debian-based Linux  
> ⚠️ MacOS or Windows (WSL) may partially work but are unsupported for Playwright browser injection.

---

## ⚙️ Installation

### 1. Clone the repo

```bash
https://github.com/devkumar-swipe/XSS-Pro-Scanner.git
cd xss-pro-scanner
```
## 2. Install dependencies
```bash
sudo apt update
sudo apt install python3 python3-pip libwebkit2gtk-4.0-dev -y
pip3 install -r requirements.txt
playwright install
```

## Usage
🔹 Basic Scan (Single URL)
```bash
python3 xsschamp.py "https://target.com/search?q=FUZZ" --mode active --type reflected
```
🔹 Scan from List
```bash
python3 xsschamp.py --list urls.txt --type all --threads 20 --output final_report.html
```
🔹 Resume Scan (After Interruption)
```bash
python3 xsschamp.py --continue scan_log.json --output resumed_report.json
```

## CLI Options
Flag	Description
-  --list	(File with URLs to scan)
-  --mode	(active, passive, or dom)
-  --type	(reflected, stored, all)
-  --post	(POST body with FUZZ marker)
-  --payloads	(Custom payload file)
-  --proxy	(Proxy list file (e.g., socks5.txt))
-  --protocol	(http, socks4, socks5, or auto)
-  --threads	(Number of concurrent requests)
-  --continue	(Resume from previous scan log)
-  --output	(Save report to file)
-  --format	(Output format: console, json, or html)


## Output Formats
report.json: Structured output

report.html: Visual summary (clickable)

console: Color-rich CLI output

## 📚 Requirements
See requirements.txt for pinned versions.
```bash
httpx
aiohttp
playwright
rich
argcomplete
loguru
beautifulsoup4
lxml
PySocks
```
## Install with:

```bash
pip3 install -r requirements.txt
playwright install
```

## 🤝 Contributing
PRs welcome!
Open an issue to propose features or report bugs.

## 🧠 Author
AwesomeVed
Cybersecurity Student • Bug Bounty Hunter
devkumarmahto204@outlook.com


