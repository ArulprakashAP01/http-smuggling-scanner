# Arul HTTP Smuggling Hunter 🚀

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A **professional CLI tool** to detect **HTTP Request Smuggling (HRS) vulnerabilities**, including:  

**CL.TE, TE.CL, TE.TE, obfuscated TE headers, mixed-case TE, double chunks, and incomplete chunks**.  

Designed for **penetration testers, bug bounty hunters, and security researchers**, this tool helps identify anomalies and possible smuggling behavior in HTTP request processing.

---

## ✨ Features

- 🔍 **Automated HRS Detection** – Detects multiple types of HTTP Request Smuggling vulnerabilities.  
- 📡 **Payload Techniques Supported**:
  - `CL.TE` (Content-Length + Transfer-Encoding)
  - `TE.CL` (Transfer-Encoding + Content-Length)
  - `TE.TE` (Duplicate Transfer-Encoding headers)
  - Obfuscated TE headers (space, tab, mixed case)
  - Double Chunk & Incomplete Chunk payloads
- 📑 **Repeater-style Logging** – Side-by-side request/response output for analysis.  
- ⚡ **Baseline Response Comparison** – Detect anomalies in:
  - Status codes
  - Headers
  - Body content
  - Response timing
- 🌀 **CURL Integration** – Option to send raw HTTP requests via `curl` or use Python `requests` library.  
- 🕵️ **Endpoint Discovery**:
  - Crawls internal links and forms
  - Brute-forces **common admin/API endpoints**
- 📊 **Professional CLI Output** – Colorful terminal output with clear scan summary.  
- 🎭 **ASCII Banner & Researcher Credits** – Eye-catching startup banner.

---

## 📸 Demo (CLI Preview)
<img width="957" height="416" alt="image" src="https://github.com/user-attachments/assets/f3c47fed-664d-436f-84d5-89e5a92c35f5" />


---

## 🛠 Installation

```bash
git clone https://github.com/ArulprakashAP01/http-smuggling-scanner.git
cd http-smuggling-scanner
pip install -r requirements.txt
