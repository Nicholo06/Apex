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
from backend.core.utils import AndroidUtils
from backend.ai.provider import AIProviderFactory
from backend.config import config

# --- UI Styling ---
def clr(text, color_code=None):
    return text

def strip_ansi(text):
    return text

def get_indent(text_len=20):
    width = shutil.get_terminal_size().columns
    # Use a fixed indentation that feels "centered" as a block but is left-aligned
    # 1/4 of terminal width is a good balance
    return max(0, (width - 60) // 2)

def left_print(text, color_code=None):
    indent = get_indent()
    print(" " * indent + text)

def centered_print(text, color_code=None):
    width = shutil.get_terminal_size().columns
    padding = (width - len(text)) // 2
    if padding < 0: padding = 0
    print(" " * padding + text)

BANNER = r"""
   ___    ____           
  /   |  / __ \___  _  __
 / /| | / /_/ / _ \| |/_/
/ ___ |/ ____/  __/>  <  
/_/  |_/_/    \___/_/|_|
"""

def print_header():
    width = shutil.get_terminal_size().columns
    lines = BANNER.strip("\n").split("\n")
    # Find the longest line to center the whole block
    max_len = max(len(line) for line in lines)
    indent = (width - max_len) // 2
    if indent < 0: indent = 0
    
    for line in lines:
        print(" " * indent + line)
    print("\n")

def left_input(prompt_text, color=None):
    indent = get_indent()
    return input(" " * indent + prompt_text).strip()

def check_dependencies():
    """Check if Java is installed since pyapktool needs it"""
    try:
        subprocess.run(["java", "-version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    except FileNotFoundError:
        left_print("[!] Warning: Java (JRE) not found. APK scanning will fail.")

def select_device():
    devices = AndroidUtils.list_devices()
    if not devices:
        left_print("[-] No USB devices found via Frida.")
        return None
    
    if len(devices) == 1:
        return devices[0]
    
    left_print("\n[ SELECT DEVICE ]")
    for i, d in enumerate(devices):
        left_print(f"{i+1}. {d.name} ({d.id})")
    
    choice = left_input("Select device number (default 1): ")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(devices): return devices[idx]
    except: pass
    return devices[0]

def select_package(device_id=None):
    query = left_input("Search package (enter to list all): ")
    if query:
        packages = AndroidUtils.search_packages(query, device_id)
    else:
        packages = AndroidUtils.list_packages(device_id)
    
    if not packages:
        left_print("[-] No packages found.")
        return left_input("Enter package name manually: ")

    left_print("\n[ SELECT PACKAGE ]")
    display_limit = 10
    for i, p in enumerate(packages[:display_limit]):
        left_print(f"{i+1}. {p}")
    
    if len(packages) > display_limit:
        left_print(f"... and {len(packages) - display_limit} more.")

    choice = left_input("Select number or enter manual name: ")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(packages): return packages[idx]
    except: pass
    return choice if choice else None

def interactive_menu():
    check_dependencies()
    current_device = None
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_header()
        
        if current_device:
            left_print(f"Connected Device: {current_device.name} ({current_device.id})")
            left_print("-" * 20)

        left_print("[ MAIN MENU ]")
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
            left_print(item)
            
        print("")
        left_print("-" * 20)
        
        choice = left_input("Select an option > ")

        if choice == '1':
            path = left_input("Enter APK path: ")
            if os.path.exists(path):
                scanner = APKScanner(path)
                if scanner.decompile():
                    findings = scanner.find_security_logic()
                    left_print("\n[+] Findings:")
                    if not findings:
                        left_print("No specific security patterns found.")
                    else:
                        print(json.dumps(findings, indent=2))
                else: left_print("[-] Decompilation failed.")
            else: left_print("[-] File not found.")

        elif choice == '2':
            if not current_device: current_device = select_device()
            if not current_device:
                left_input("Press Enter to continue...")
                continue
            
            ok, msg = AndroidUtils.verify_frida_environment(current_device)
            if not ok:
                left_print(f"[-] {msg}")
                if not AndroidUtils.is_rooted(current_device.id):
                    left_print("[!] Device appears to be UNROOTED (Jailed). Frida standard attachment may fail.")
                left_input("Press Enter to continue anyway...")

            pkg = select_package(current_device.id)
            if not pkg: continue
            
            script = left_input("Enter Script Name: ")
            orch = FridaOrchestrator(pkg, device=current_device)
            if orch.attach_and_inject(script): left_print("[+] Injection Success!")
            else: left_print("[-] Injection Failed.")

        elif choice == '3':
            file_path = left_input("Enter path to Smali snippet file: ")
            if os.path.exists(file_path):
                with open(file_path, 'r') as f: code = f.read()
                cat = left_input("Category (default: ssl_pinning): ") or "ssl_pinning"
                try:
                    provider = AIProviderFactory.get_provider()
                    hook = provider.generate_hook(code, cat)
                    out = os.path.join(config.FRIDA_SCRIPTS_PATH, "ai_generated.js")
                    if not os.path.exists(config.FRIDA_SCRIPTS_PATH):
                        os.makedirs(config.FRIDA_SCRIPTS_PATH)
                    with open(out, "w") as f: f.write(hook)
                    left_print(f"\n[+] Saved to {out}\n")
                    print(hook)
                except Exception as e: left_print(f"[-] AI Error: {e}")
            else: left_print("[-] File not found.")

        elif choice == '4':
            if not current_device: current_device = select_device()
            if not current_device:
                left_input("Press Enter to continue...")
                continue
            
            pkg = select_package(current_device.id)
            if not pkg: continue
            
            dumper = ADBDumper(pkg, device_id=current_device.id)
            results = dumper.pull_data()
            left_print("\n[+] Exfiltration Results:")
            for r in results:
                status = "DONE" if r['status'] == 'pulled' else "FAIL"
                left_print(f"  {status} {r['target']}")

        elif choice == '5':
            scripts = FridaOrchestrator(None).list_scripts()
            left_print("\n[+] Script Library:")
            if not scripts: left_print("(No scripts found in frida-scripts/)")
            for s in scripts: left_print(f"  - {s}")

        elif choice == '6':
            current_device = select_device()

        elif choice == '0':
            left_print("Exiting APex...")
            break
        
        left_input("Press Enter to return to menu...")

def main():
    parser = argparse.ArgumentParser(description="🛡️  APex CLI", add_help=False)
    parser.add_argument('-h', '--help', action='help')
    subparsers = parser.add_subparsers(dest="command")
    
    scan_p = subparsers.add_parser("scan")
    scan_p.add_argument("apk_path")
    
    inject_p = subparsers.add_parser("inject")
    inject_p.add_argument("package_name")
    inject_p.add_argument("script_name")
    
    hook_p = subparsers.add_parser("generate-hook")
    hook_p.add_argument("smali_file")
    
    exfil_p = subparsers.add_parser("exfiltrate")
    exfil_p.add_argument("package_name")
    
    subparsers.add_parser("list-scripts")

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
    elif args.command == "exfiltrate":
        ADBDumper(args.package_name).pull_data()

if __name__ == "__main__":
    main()
