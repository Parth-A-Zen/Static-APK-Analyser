# 🔍 Static APK Security Analyzer  
### OWASP Mobile Top 10 (2024) Focused — v5.1 Enhanced

A modular Android APK static analysis engine designed to detect security vulnerabilities aligned with the **OWASP Mobile Top 10 (2024)**.

Built with precision-focused rule execution, scope filtering, confidence scoring, and structured reporting.

---

## 🚀 Overview

This tool performs static security analysis on Android APK files and generates structured vulnerability reports in **HTML** and **JSON** formats.

It focuses on:

- Reducing false positives
- Structured rule-based detection
- Context-aware vulnerability analysis
- Source–sink taint correlation
- Parallel execution support

---

## 🧠 Core Capabilities

- 📦 APK parsing & structured scope filtering
- 🔎 32 modular security rules
- 🔗 Source–sink taint analysis
- 🧩 Cross-rule correlation
- 🧹 Semantic deduplication
- 📊 Confidence-based filtering
- 🏷 OWASP category mapping
- ⚡ Parallel rule execution
- 📄 HTML + JSON reporting

---

## 🛡 Vulnerability Coverage

### Categories Implemented

- Binary Protection & Environment Detection
- Network Communication
- Component Exposure
- Privacy Controls
- Credential & Secret Storage
- Cryptographic Issues
- Input Validation (WebView, SQL, Path)
- Data Storage
- Dynamic Code Loading

---

## ⚙ Engine Highlights (v3.1)

- Adaptive confidence thresholds per OWASP category
- Context-aware secret detection
- Exported component security analysis
- Manifest risk flag detection
- Structured API categorization
- Multi-threaded execution support
- Semantic duplicate removal

---

## 📦 Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/Static-APK-Analyser.git
cd Static-APK-Analyser
```
2️⃣ Create Virtual Environment
```bash
python -m venv .venv
```

Activate:

Windows
```bash
.venv\Scripts\activate
```

Linux / macOS
```bash
source .venv/bin/activate
```
3️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```
▶ Usage
Basic Analysis
```bash
python analyse.py app.apk
```
JSON Report Only
```bash
python analyse.py app.apk --format json
```
Save Reports to Custom Directory
```bash
python analyse.py app.apk --output ./reports
```
Enable Parallel Execution
```bash
python analyse.py app.apk --parallel --workers 8
```
Run Specific Categories
```bash
python analyse.py app.apk --categories "Network Communication"
```
Exclude Specific Rule
```bash
python analyse.py app.apk --exclude MISSING_OBFUSCATION
```
Disable Advanced Features (Basic Mode)
```bash
python analyse.py app.apk --no-taint-analysis --no-correlation
```
List All Rules
```bash
python analyse.py --list-rules
```

🏗 Architecture Overview
```
APK Loader
   ↓
Scope Filter (v2.3)
   ↓
Rule Engine (v3.1)
   ↓
Correlation & Deduplication
   ↓
Report Generator (HTML + JSON)
```

🧪 Tested Against

- OWASP GoatDroid (owasp.sat.agoat)
- Custom vulnerable APK samples

Features:

- Static analysis techniques

- Secure rule engine architecture

- OWASP-aligned vulnerability detection

- Intelligent filtering to reduce noise

- Professional reporting structure

⚠ Limitations:

- Static analysis only (no runtime behavior monitoring)

- Complex business logic vulnerabilities may require dynamic testing

- False positives minimized but not fully eliminated

👥 Team

Team Name: CryptoKnights

Hackathon: KrackHack3.0
