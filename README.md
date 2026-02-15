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

## How to run the web interface locally:

📦 Step 1: Clone or Download the Repository
Option A: Clone with Git
powershell

git clone https://github.com/Parth-A-Zen/Static-APK-Analyser.git
cd Static-APK-Analyser

Option B: Download ZIP

    Go to github.com/Parth-A-Zen/Static-APK-Analyser

    Click "Code" → "Download ZIP"

    Extract the ZIP file

    Open PowerShell/Terminal in the extracted folder

🔧 Step 2: Set Up Virtual Environment
Windows (PowerShell)
powershell

### Create virtual environment
python -m venv venv

### Activate virtual environment
.\venv\Scripts\Activate.ps1

### If you get an execution policy error, run:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

macOS / Linux
bash

### Create virtual environment
python3 -m venv venv

### Activate virtual environment
source venv/bin/activate

📥 Step 3: Install Dependencies
powershell

### Make sure you're in the project root (where requirements.txt is)
pip install -r requirements.txt

Contents of requirements.txt:
txt

androguard>=3.4.0
cryptography>=41.0.0
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
python-multipart>=0.0.6

### Run 'run.py'
```bash
python run.py
```
### 🌐 Step 6: Use the Web App

    Open your browser and go to: http://127.0.0.1:8000

    You'll see the CyberKnights APK Analyzer interface

    Upload an APK file (drag & drop or click to browse)

    Click "Analyze APK"

    Wait for the analysis to complete (30-60 seconds)

    View the results:

        Risk score and level

        Detected permissions

        All findings by severity

        OWASP category summary

    Download reports:

        Click "Download JSON" for raw data

        Click "Download HTML" for formatted report

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

### 🛑 Step 7: Stop the Server

Press Ctrl + C in the terminal to stop the server.

⚠ Limitations:

- Static analysis only (no runtime behavior monitoring)

- Complex business logic vulnerabilities may require dynamic testing

- False positives minimized but not fully eliminated

👥 Team

Team Name: CryptoKnights

Hackathon: KrackHack3.0
