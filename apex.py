#!/usr/bin/env python3
import argparse
import sys
import json
import os
import shutil
import subprocess
from backend.core.scanner import APKScanner
from backend.core.dynamic import FridaOrchestrator
from backend.core.dumper import ADBDumper
from backend.ai.provider import AIProviderFactory
from backend.config import config

# Global indentation
INDENT = "    "

BANNER = r"""
    /   |  / __ \___  _  __
   / /| | / /_/ / _ \| |/_/
  / ___ |/ ____/  __/>  <  
 /_/  |_/_/    \___/_/|_|  
"""

def print_header():
    print()
    # Print the banner which already has built-in spacing, plus our indent
    for line in BANNER.split('\n'):
        if line.strip():
            print(INDENT + line)
    print()

def c_input(prompt_text="", newline=True):
    """Displays an indented prompt and returns user input"""
    if prompt_text:
        if newline:
            print(INDENT + f"{prompt_text}")
            return input(INDENT + "> ").strip()
        else:
            return input(INDENT + f"{prompt_text} > ").strip()
    return input(INDENT + "> ").strip()

def interactive_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_header()
        
        print(INDENT + "[ MAIN MENU ]")
        print()

        menu_items = [
            "1. Scan APK (Static Analysis)",
            "2. Inject Frida Script (Dynamic)",
            "3. Generate AI Bypass Hook",
            "4. Exfiltrate App Data (ADB)",
            "5. List Local Scripts",
            "6. Select/Change Device",
            "0. Exit"
        ]
        
        for item in menu_items:
            print(INDENT + item)
            
        print("\n" + INDENT + "-" * 20)
        
        choice = c_input("Select an option")

        print()

        if choice == '1':
            path = c_input("Enter APK path")
            if os.path.exists(path):
                scanner = APKScanner(path)
                if scanner.decompile():
                    findings = scanner.find_security_logic()
                    print("\n" + INDENT + "[+] Findings:")
                    # Indent JSON output
                    formatted_json = json.dumps(findings, indent=4)
                    for line in formatted_json.split('\n'):
                        print(INDENT + line)
                else: print(INDENT + "[-] Decompilation failed.")
            else: print(INDENT + "[-] File not found.")

        elif choice == '2':
            pkg = c_input("Enter Package Name")
            script = c_input("Enter Script Name")
            orch = FridaOrchestrator(pkg)
            if orch.attach_and_inject(script): print(INDENT + "[+] Injection Success!")
            else: print(INDENT + "[-] Injection Failed.")

        elif choice == '3':
            file_path = c_input("Enter path to Smali snippet file")
            if os.path.exists(file_path):
                with open(file_path, 'r') as f: code = f.read()
                cat = c_input("Category (default: ssl_pinning)") or "ssl_pinning"
                try:
                    provider = AIProviderFactory.get_provider()
                    hook = provider.generate_hook(code, cat)
                    out = os.path.join(config.FRIDA_SCRIPTS_PATH, "ai_generated.js")
                    if not os.path.exists(config.FRIDA_SCRIPTS_PATH):
                        os.makedirs(config.FRIDA_SCRIPTS_PATH)
                    with open(out, "w") as f: f.write(hook)
                    print(f"\n{INDENT}[+] Saved to {out}")
                    print(INDENT + "-" * 20)
                    for line in hook.split('\n'): print(INDENT + line)
                    print(INDENT + "-" * 20)
                except Exception as e: print(INDENT + f"[-] AI Error: {e}")
            else: print(INDENT + "[-] File not found.")

        elif choice == '4':
            pkg = c_input("Enter Package Name")
            dumper = ADBDumper(pkg)
            results = dumper.pull_data()
            print("\n" + INDENT + "[+] Exfiltration Results:")
            for r in results:
                status = "V" if r['status'] == 'pulled' else "X"
                print(INDENT + f"  {status} {r['target']}")

        elif choice == '5':
            scripts = FridaOrchestrator(None).list_scripts()
            print("\n" + INDENT + "[+] Script Library:\n")
            if not scripts: print(INDENT + "(No scripts found in frida-scripts/)")
            for s in scripts:
                print(INDENT + f"  - {s}")

        elif choice == '6':
            print(INDENT + "[*] Feature coming soon: Select/Change ADB Device")

        elif choice == '0':
            print(INDENT + "Exiting APex...")
            break
        
        print()
        c_input("Press Enter to return to menu", newline=False)

def main():
    parser = argparse.ArgumentParser(description="🛡️  APex CLI", add_help=False)
    parser.add_argument('-h', '--help', action='help')
    subparsers = parser.add_subparsers(dest="command")
    
    subparsers.add_parser("scan").add_argument("apk_path")
    subparsers.add_parser("inject").add_argument("package_name")
    subparsers.add_parser("list-scripts")
    subparsers.add_parser("exfiltrate").add_argument("package_name")
    subparsers.add_parser("generate-hook").add_argument("smali_file")

    if len(sys.argv) == 1:
        interactive_menu()
        return

    args = parser.parse_args()
    if args.command == "scan":
        scanner = APKScanner(args.apk_path)
        if scanner.decompile(): print(json.dumps(scanner.find_security_logic(), indent=2))
    elif args.command == "list-scripts":
        for s in FridaOrchestrator(None).list_scripts(): print(f"  - {s}")
    elif args.command == "inject":
        FridaOrchestrator(args.package_name).attach_and_inject(args.script_name)

if __name__ == "__main__":
    main()
