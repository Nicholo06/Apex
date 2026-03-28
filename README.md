# APex: AI-Powered APK Explorer and Exfiltrator

**APex** is an *AI-powered* advanced Android security orchestration suite and a robust wrapper for the Frida framework. It is designed to bridge the gap between static analysis and dynamic instrumentation. By integrating Large Language Models (LLMs) directly into the reverse-engineering workflow, APex automates the discovery and bypassing of complex security controls like SSL pinning and root detection.

---

## Project Goals

The goal of **APex** is to reduce the manual effort required during mobile application penetration tests by:
* Automating the Boring Stuff: Fast-track APK decompilation, secret sniffing, and permission auditing.
* Bridging RE Gaps with AI: Use AI to interpret obfuscated Smali logic and generate functional Frida hooks.
* Centralizing Exfiltration: Provide a one-click solution for dumping sensitive app data (databases, native libs, configurations).
* Interactive Workflow: A menu-driven CLI for rapid mobile security auditing.
* Frida Integration: Acting as a streamlined wrapper for the Frida framework to simplify dynamic analysis.

---

## Key Features

### 1. Intelligent Static Analysis (SAST)
* AI-Powered Scanning: Leverages LLMs to identify and analyze complex security logic.
* Automated Decompilation: Uses pyapktool to decompile APKs for immediate inspection.
* Logic Extraction: Automatically hunts for SSL pinning and root detection patterns in Smali files.
* Vulnerability Detection: Scans for manifest misconfigurations, hardcoded secrets, and insecure code patterns.

### 2. Dynamic Instrumentation (DAST)
* Frida Wrapper: Provides a high-level interface for the Frida framework, managing spawning, attachment, and script injection.
* BYOS Logic: Dedicated directory for custom scripts with auto-detection and selection.
* Real-time Logging: Streams output from Frida scripts directly to the console.

### 3. AI-Assisted Bypass Engine
* Surgical Hooking: Extracts relevant Smali code for failed security checks.
* LLM Integration: Connects to Gemini, Claude, or OpenAI to generate custom JS hooks tailored specifically to the application.

### 4. Data Exfiltration Suite
* ADB Dumper: Automatically pulls SQLite databases, shared preferences, and native libraries from the device storage.

---

## Getting Started

### Prerequisites
- Python 3.10+
- Java (JRE/JDK) in your system PATH (required for APK decompilation).
- ADB in your system PATH.
- A rooted Android device or emulator with frida-server running.

### Installation

1. Clone and Enter Folder:
   ```bash
   git clone https://github.com/your-username/APex.git
   cd APex
   ```

2. Setup Environment:
   ```bash
   pip install -r requirements.txt
   cp .env.example .env # Add your AI API Key here
   ```

---

## Usage Guide

To start the tool, run:
```bash
python apex.py
```

### 1. Scan APK
Select Option 1 and provide the path to your APK. APex will decompile it and generate a comprehensive security report covering manifest misconfigurations, hardcoded secrets, and insecure code patterns.

### 2. Inject Frida Script
Select Option 2 to inject a script into a running app. APex will list installed 3rd-party packages and available scripts for selection. It then launches the app using the Frida framework wrapper.

### 3. Generate AI Hook
Select Option 3 if you encounter a security check that standard scripts cannot bypass. Provide the path to a text file containing the Smali code, and APex will use AI to generate a surgical Frida hook.

### 4. Exfiltrate Data
Select Option 4 to dump internal app data. APex pulls databases and native libraries from the device and saves them to the local downloads folder.

---

## Contributing
Contributions are welcome. Please feel free to submit a Pull Request.

---

## Disclaimer
**APex** is intended for authorized security auditing and educational purposes only. Unauthorized access to computer systems is illegal. The author is not responsible for any misuse of this tool.
