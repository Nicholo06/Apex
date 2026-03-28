# APex: AI-Powered APK Explorer & Exfiltrator

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg?logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/AI-Gemini-blue.svg?logo=google-gemini&logoColor=white" alt="Gemini">
  <img src="https://img.shields.io/badge/AI-Claude-orange.svg?logo=anthropic&logoColor=white" alt="Claude">
  <img src="https://img.shields.io/badge/AI-OpenAI-black.svg?logo=openai&logoColor=white" alt="OpenAI">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

**APex** is an advanced Android security orchestration suite designed to bridge the gap between static analysis and dynamic instrumentation. By integrating Large Language Models (LLMs) directly into the reverse-engineering workflow, APex automates the discovery and bypassing of complex security controls like SSL pinning and root detection.

---

## 📖 Table of Contents
- [🎯 Project Goals](#-project-goals)
- [✨ Key Features](#-key-features)
- [🚀 Getting Started](#-getting-started)
- [📖 Usage Guide](#-usage-guide)
- [🤝 Contributing](#-contributing)
- [⚖️ Disclaimer](#-disclaimer)

---

## 🎯 Project Goals

The goal of APex is to reduce the manual effort required during mobile application penetration tests by:
*   **Automating the "Boring" Stuff:** Fast-track APK decompilation, secret sniffing, and permission auditing.
*   **Bridging RE Gaps with AI:** Use AI to interpret obfuscated Smali logic and generate functional Frida hooks.
*   **Centralizing Exfiltration:** Provide a one-click solution for dumping sensitive app data (databases, native libs, configurations).
*   **Interactive Workflow:** A menu-driven CLI for rapid mobile security auditing.

---

## Key Features

### 1. Intelligent Static Analysis (SAST)
*   **Automated Decompilation:** Leverages `pyapktool` to crack open APKs instantly.
*   **Logic Extraction:** Automatically hunts for SSL pinning and root detection patterns in Smali files.

### 2. Dynamic Instrumentation (DAST)
*   **Frida Orchestrator:** Attach to processes and inject JS hooks on the fly.
*   **BYOS Logic:** Dedicated `/frida-scripts` directory with auto-detection for custom scripts.

### 3. AI-Assisted Bypass Engine
*   **Surgical Hooking:** Extracts relevant Smali code for failed security checks.
*   **LLM Integration:** Connects to Gemini/Claude/OpenAI to generate custom JS hooks tailored specifically to the app.

### 4. Data Exfiltration Suite
*   **ADB Dumper:** Automatically pulls SQLite `.db` files, `shared_prefs`, and `.so` files from `/data/data/[pkg]/`.

---

## 🚀 Getting Started


### Prerequisites
- Python 3.10+
- **Java (JRE/JDK)** in your system PATH (required for APK decompilation).
- **ADB** in your system PATH.
- A **rooted** Android device or emulator with `frida-server` running.

### Installation

1. **Clone & Enter Folder:**
   ```bash
   git clone https://github.com/your-username/apex-toolkit.git
   cd apex-toolkit
   ```

2. **Setup Environment:**
   ```bash
   pip install -r requirements.txt
   cp .env.example .env # Add your Google API Key here
   ```

---

## Usage Guide

APex is an interactive, menu-driven CLI. To start the tool, run:
```bash
python apex.py
```

### 1. Scan APK
Select **Option 1** and provide the path to your APK. APex will decompile it and display a JSON summary of security-related code blocks found in the Smali files.

### 2. Inject Frida Script
Select **Option 2** to inject a script into a running app. APex will ask for the package name (e.g., `com.example.app`) and the name of the script from your `frida-scripts/` folder.

### 3. Generate AI Hook
Select **Option 3** if you encounter a security check that standard scripts can't bypass. Provide the path to a text file containing the Smali code, and APex will use AI to generate a surgical Frida hook.

### 4. Exfiltrate Data
Select **Option 4** to dump internal app data. APex pulls databases and native libraries from the device and saves them to the local `./downloads/` folder.

---

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

---

## Disclaimer
APex is intended for **authorized security auditing and educational purposes only**. Unauthorized access to computer systems is illegal. The author is not responsible for any misuse of this tool.
