# 🛡️ XSS Cyber Champ Pro 2050 — Elite Edition

**AI-Powered Next-Gen XSS Detection Framework**  
Built by [AwesomeVed](https://github.com/devkumar-swipe) for elite bug bounty hunting and automated web app security analysis.

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
git clone https://github.com/awesomeved/cyber-champ-xss.git
cd cyber-champ-xss
