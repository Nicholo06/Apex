# APex: AI-Powered APK Explorer & Exfiltrator

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg?logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/AI-Gemini-blue.svg?logo=google-gemini&logoColor=white" alt="Gemini">
  <img src="https://img.shields.io/badge/AI-Claude-orange.svg?logo=anthropic&logoColor=white" alt="Claude">
  <img src="https://img.shields.io/badge/AI-OpenAI-black.svg?logo=openai&logoColor=white" alt="OpenAI">
  <img src="https://img.shields.io/badge/FastAPI-009688.svg?logo=fastapi&logoColor=white" alt="FastAPI">
</p>

**APex** is an advanced Android security orchestration suite designed to bridge the gap between static analysis and dynamic instrumentation. By integrating Large Language Models (LLMs) directly into the reverse-engineering workflow, APex automates the discovery and bypassing of complex security controls like SSL pinning and root detection.

---

## Table of Contents
- [Project Goals](#-project-goals)
- [Key Features](#-key-features)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#-usage)
- [Contributing](#-contributing)
- [Disclaimer](#-disclaimer)
- [License](#-license)

---

## Project Goals
The goal of APex is to reduce the manual effort required during mobile application penetration tests by:
*   **Automating the "Boring" Stuff:** Fast-track APK decompilation, secret sniffing, and permission auditing.
*   **Bridging RE Gaps with AI:** Use AI to interpret obfuscated Smali logic and generate functional Frida hooks.
*   **Centralizing Exfiltration:** Provide a one-click solution for dumping sensitive app data (databases, native libs, configurations).
*   **Flexible Orchestration:** Offer a "Bring Your Own Script" (BYOS) environment for seasoned pentesters.

---

## Key Features

### 1. Intelligent Static Analysis (SAST)
*   **Automated Decompilation:** Leverages `apktool` to crack open APKs instantly.
*   **Secret Sniffer:** Regex-based scanning for API keys, Firebase URLs, hardcoded credentials, and RSA keys.
*   **Manifest Auditor:** Identifies dangerous permissions and exported components (Intent Redirection, Provider leakage).

### 2. Dynamic Instrumentation (DAST)
*   **Frida Orchestrator:** Attach to processes and inject JS hooks on the fly.
*   **BYOS Logic:** Dedicated `/frida-scripts` directory with auto-detection for custom scripts.

### 3. AI-Assisted Bypass Engine
*   **Surgical Hooking:** Extracts relevant Smali code for failed security checks.
*   **LLM Integration:** Connects to Gemini/Claude to generate custom JS hooks tailored to specific app implementations.

### 4. Data Exfiltration Suite
*   **Database Dumper:** Automatically pulls SQLite `.db` files from `/data/data/[pkg]/`.
*   **Native Library Extraction:** Pulls `.so` files for offline binary analysis (Ghidra/IDA).
*   **Config Grabber:** Extracts `shared_prefs` and other XML configurations.

---

## Tech Stack
| Category | Tools/Frameworks |
| :--- | :--- |
| **Backend** | Python 3.10+, FastAPI |
| **Analysis** | Scapy, Frida-Tools, Apktool |
| **AI** | Google Generative AI (Gemini API) |
| **Frontend** | JavaScript (ES6+), Tailwind CSS |
| **Database** | SQLite |

---

## Getting Started

### Prerequisites
- Python 3.10+
- **ADB** (Android Debug Bridge) in your system PATH.
- A **rooted** Android device or emulator with `frida-server` running.
- (Optional) API Key for Gemini or Claude.

### Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/apex-toolkit.git
   cd apex-toolkit
   ```

2. **Add Your Scripts:**
   Place your existing Frida scripts in the `frida-scripts/` directory.

3. **Setup Environment:**
   ```bash
   pip install -r requirements.txt
   cp .env.example .env # Add your API keys here
   ```

4. **Run APex:**
   ```bash
   python backend/main.py
   ```

---

## Usage
1.  **Upload:** Drag an APK into the APex Dashboard.
2.  **Analyze:** Run the Static Scan to find hardcoded secrets.
3.  **Inject:** Select a script from your `/frida-scripts` library and click **Inject**.
4.  **AI Bypass:** If traffic is blocked, use "Generate AI Hook" to analyze Smali and create a custom bypass.
5.  **Exfiltrate:** Use the "Dump Data" button to pull internal files to your local `/downloads` folder.

---

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

---

## Disclaimer
APex is intended for **authorized security auditing and educational purposes only**. Unauthorized access to computer systems is illegal. The author is not responsible for any misuse of this tool.

---


