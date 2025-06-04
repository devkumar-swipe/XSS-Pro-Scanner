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
