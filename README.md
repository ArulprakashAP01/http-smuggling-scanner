# Arul HTTP Smuggling Hunter 🚀

A **professional CLI tool** to scan for **HTTP Request Smuggling (HRS) vulnerabilities** such as **CL.TE, TE.CL, TE.TE, obfuscated TE headers, mixed-case TE, double chunks, and incomplete chunks**.  

This tool is designed for **penetration testers, bug bounty hunters, and security researchers** to help identify anomalies and possible smuggling behavior in HTTP request processing.

---

## ✨ Features
- 🔍 Automated detection of **HTTP Request Smuggling vulnerabilities**
- 📡 Supports **multiple payload techniques**:
  - CL.TE (Content-Length + Transfer-Encoding)
  - TE.CL (Transfer-Encoding + Content-Length)
  - TE.TE (duplicate TE headers)
  - Obfuscated TE headers (space, tab, mixed case)
  - Double Chunk & Incomplete Chunk payloads
- 📑 **Repeater-style request/response logging**
- ⚡ Baseline response comparison with timing & anomaly detection
- 🌀 **CURL integration** (raw requests) or Python `requests` library
- 🕵️ Endpoint Discovery:
  - Crawls links and forms
  - Brute-forces **common admin/API endpoints**
- 📊 Colorful CLI with professional **scan summary report**
- 🎭 ASCII Banner + researcher credits

---

## 📸 Demo (CLI Preview)

