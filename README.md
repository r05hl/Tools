# 🔍 Web Reconnaissance & Vulnerability Scanner

A Python-based web reconnaissance and vulnerability scanner designed for ethical hackers, bug bounty hunters, and penetration testers. This tool collects information about a target domain and identifies 
potential security flaws such as exposed endpoints, API keys, misconfigurations, and basic vulnerabilities.

---

## 🚀 Features

- **🕵️ Information Gathering**
  - Extracts email addresses and subdomains
  - Parses `robots.txt` for disallowed/sensitive paths
  - Lists all linked JavaScript files

- **🛡️ Vulnerability Scanning**
  - Detects SQL Injection points via error pattern matching
  - Basic XSS detection through reflected input payloads
  - Checks for CORS misconfiguration via response headers

- **📁 Sensitive File Detection**
  - Looks for exposed files like `.env`, `.git/HEAD`, `backup.zip`, `db.sql`, etc.

- **🔐 API Key & Token Finder**
  - Scans JavaScript for hardcoded API keys (AWS, Google, Stripe, JWT, etc.)

- **🔐 Admin Panel Discovery**
  - Checks for common login and admin paths (`/admin`, `/login`, etc.)

- **🛠️ Hidden Path Fuzzing**
  - Attempts to access commonly sensitive directories (`/debug`, `/test`, `/config`, etc.)

---

## 📦 Requirements

- Python 3.6+
- `requests`
- `beautifulsoup4`
- `colorama`

