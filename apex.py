#!/usr/bin/env python3
import argparse
import sys
import json
import os
import shutil
import subprocess
import threading
import time
from backend.core.scanner import APKScanner
from backend.core.dynamic import FridaOrchestrator
from backend.core.dumper import ADBDumper
from backend.core.explorer import LootExplorer
from backend.core.templates import HookTemplates
from backend.config import config
from backend.core.utils import list_adb_devices, list_installed_packages

# Global indentation
INDENT = "    "

BANNER = r"""
    /   |  / __ \___  _  __
   / /| | / /_/ / _ \| |/_/
  / ___ |/ ____/  __/>  <  
 /_/  |_/_/    \___/_/|_|  
"""

def print_header(current_session=None):
    print()
    for line in BANNER.split('\n'):
        if line.strip():
            print(INDENT + line)
    print()
    status = "CONNECTED" if config.ACTIVE_DEVICE_ID else "NOT CONNECTED"
    dev_id = config.ACTIVE_DEVICE_ID if config.ACTIVE_DEVICE_ID else "None"
    print(INDENT + f"[ STATUS: {status} | DEVICE: {dev_id} ]")
    if current_session:
        print(INDENT + f"[ ACTIVE SESSION: {current_session} ]")
    print()

def c_input(prompt_text="", newline=True, indicator="> "):
    if prompt_text:
        if newline:
            print(INDENT + f"{prompt_text}")
            return input(INDENT + indicator).strip()
        else: return input(INDENT + f"{prompt_text} {indicator}").strip()
    return input(INDENT + indicator).strip()

def print_progress_bar(current, total, prefix="Analyzing APK"):
    width = 40
    percent = float(current) * 100 / total
    filled = int(width * current // total)
    bar = "█" * filled + "-" * (width - filled)
    sys.stdout.write(f"\r{INDENT}{prefix}: |{bar}| {percent:.1f}%")
    sys.stdout.flush()
    if current == total: print()

def run_task_with_loading(task_func, prefix="Decompiling APK"):
    done = False
    result = [None]
    def target():
        nonlocal done
        try: result[0] = task_func()
        except Exception as e: result[0] = e
        done = True
    thread = threading.Thread(target=target)
    thread.start()
    current = 0
    while not done:
        if current < 95: current += 1
        print_progress_bar(current, 100, prefix=prefix)
        time.sleep(0.1)
    if isinstance(result[0], Exception):
        print_progress_bar(0, 100, prefix=prefix)
        return result[0]
    print_progress_bar(100, 100, prefix=prefix)
    return result[0]

def print_report(data):
    print("\n" + INDENT + "=" * 60)
    print(INDENT + "MOBILE SECURITY SCAN REPORT")
    print(INDENT + "=" * 60 + "\n")
    m = data["Manifest Risks"]
    print(INDENT + "[ MANIFEST CONFIGURATION ]")
    print(INDENT + f"  - Debuggable:      {'[!!] YES' if m['debuggable'] else 'No'}")
    print(INDENT + f"  - Allow Backup:    {'[!] YES' if m['allow_backup'] else 'No'}")
    print(INDENT + f"  - Cleartext HTTP:  {'[!] YES' if m['cleartext_traffic'] else 'No'}")
    if m["permissions"]: print(INDENT + "  - Sensitive Perms: " + ", ".join(m["permissions"]))
    if m["exported_components"]:
        print(INDENT + "  - Exported Components:")
        for comp in m["exported_components"][:5]: print(INDENT + f"    * {comp}")
    print()
    if data.get("Sensitive Assets"):
        print(INDENT + "[ SENSITIVE FILES IN ASSETS ]")
        for asset in data["Sensitive Assets"]: print(INDENT + f"  - [!] {asset}")
        print()
    print(INDENT + "[ CODE-LEVEL FINDINGS ]")
    findings_found = False
    for category, findings in data["Code Findings"].items():
        if findings:
            findings_found = True
            print(INDENT + f"  > {category}:")
            grouped = {}
            for f in findings:
                if f["type"] not in grouped: grouped[f["type"]] = []
                grouped[f["type"]].append(f)
            for ftype, instances in grouped.items():
                print(INDENT + f"    - {ftype} ({len(instances)} instances)")
                for inst in instances[:2]:
                    print(INDENT + f"      @ {inst['file']}")
                    if inst['matches']:
                        val = inst['matches'][0][:50] + "..." if len(inst['matches'][0]) > 50 else inst['matches'][0]
                        print(INDENT + f"        Match: {val}")
    if not findings_found: print(INDENT + "  - No critical code vulnerabilities detected.")
    print("\n" + INDENT + "=" * 60)

def select_package():
    if not config.ACTIVE_DEVICE_ID: return None
    packages = list_installed_packages(config.ACTIVE_DEVICE_ID)
    if not packages: return None
    print(INDENT + "[ SELECT PACKAGE ]")
    for i, pkg in enumerate(packages): print(INDENT + f"{i+1}. {pkg}")
    print()
    sel = c_input("Enter number")
    try: return packages[int(sel)-1]
    except: return None

def select_previous_session():
    if not os.path.exists(config.TEMP_DECOMPILED_PATH): return None
    prev_scans = [d for d in os.listdir(config.TEMP_DECOMPILED_PATH) if os.path.isdir(os.path.join(config.TEMP_DECOMPILED_PATH, d))]
    if not prev_scans: return None
    print(INDENT + "[ SELECT PREVIOUS SESSION ]")
    for i, s in enumerate(prev_scans): print(INDENT + f"{i+1}. {s}")
    print()
    s_sel = c_input("Enter number")
    try: return prev_scans[int(s_sel)-1]
    except: return None

def explore_loot_workflow(package_name):
    explorer = LootExplorer(config.DOWNLOADS_PATH)
    files = explorer.list_files(package_name)
    if not files:
        print(INDENT + "[-] No files found in this session.")
        return
    print(f"\n{INDENT}[ FILES IN {package_name} ]")
    for i, f in enumerate(files): print(INDENT + f"{i+1}. {f}")
    print()
    f_sel = c_input("Select file number to view")
    try:
        file_rel_path = files[int(f_sel)-1]
        if file_rel_path.endswith(".db"):
            db_data = explorer.explore_db(package_name, file_rel_path)
            for table, content in db_data.get("tables", {}).items():
                print(f"\n{INDENT}--- TABLE: {table} ---")
                print(INDENT + " | ".join(content["columns"]))
                for row in content["rows"]: print(INDENT + " | ".join(map(str, row)))
        else:
            print(f"\n{INDENT}--- FILE CONTENT ---")
            print(explorer.view_xml(package_name, file_rel_path))
    except: print(INDENT + "[-] Invalid selection.")

def interactive_menu():
    devices = list_adb_devices()
    if devices: config.ACTIVE_DEVICE_ID = devices[0]["id"]
    current_session = None # Directory name of decompiled app
    active_pkg = None      # Actual package name for ADB/Frida

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_header(current_session)
        print(INDENT + "[ MAIN MENU ]")
        
        if not current_session:
            print(INDENT + "1. Scan New APK")
            print(INDENT + "2. Load Previous Session")
            print(INDENT + "3. Select/Change Device")
            print(INDENT + "0. Exit")
        else:
            print(INDENT + "1. View/Rescan Security Report")
            print(INDENT + "2. Inject Frida Script (Dynamic)")
            print(INDENT + "3. Exfiltrate & Explore Loot")
            print(INDENT + "4. Hook Template Generator")
            print(INDENT + "5. Switch App / New Scan")
            print(INDENT + "6. Select/Change Device")
            print(INDENT + "0. Exit")

        print("\n" + INDENT + "-" * 20)
        choice = c_input("Select an option")
        print()

        # Logic for NO SESSION
        if not current_session:
            if choice == '1':
                path = c_input("Enter APK path")
                if os.path.exists(path):
                    scanner = APKScanner(apk_path=path)
                    if run_task_with_loading(scanner.decompile, prefix="Decompiling APK"):
                        current_session = os.path.basename(scanner.output_dir)
                        print_report(scanner.find_security_logic(progress_callback=print_progress_bar))
                        c_input("Press Enter to continue", newline=False, indicator="")
                else: print(INDENT + "[-] File not found.")
            elif choice == '2':
                dir_name = select_previous_session()
                if dir_name:
                    current_session = dir_name
            elif choice == '3':
                devices = list_adb_devices()
                if devices:
                    print(INDENT + "[ SELECT DEVICE ]")
                    for i, dev in enumerate(devices): print(INDENT + f"{i+1}. {dev['id']} ({dev['status']})")
                    print()
                    sel = c_input("Enter number")
                    try: config.ACTIVE_DEVICE_ID = devices[int(sel)-1]["id"]
                    except: pass
            elif choice == '0': break

        # Logic for ACTIVE SESSION
        else:
            if choice == '1':
                scanner = APKScanner(existing_dir=os.path.join(config.TEMP_DECOMPILED_PATH, current_session))
                report = scanner.load_cached_report()
                if report:
                    print(INDENT + "[*] Loading cached report...")
                    print_report(report)
                else:
                    print(INDENT + "[*] Running scan...")
                    print_report(scanner.find_security_logic(progress_callback=print_progress_bar))
                c_input("Press Enter to continue", newline=False, indicator="")
            
            elif choice == '2': # Inject
                # Try to resolve package name from session folder if not set
                if not active_pkg: active_pkg = select_package()
                if active_pkg:
                    orch = FridaOrchestrator(active_pkg)
                    scripts = orch.list_scripts()
                    print(INDENT + f"[ TARGET: {active_pkg} ]")
                    print(INDENT + "[ SELECT SCRIPT ]")
                    for i, s in enumerate(scripts): print(INDENT + f"{i+1}. {s}")
                    print()
                    s_sel = c_input("Enter number")
                    try: orch.attach_and_inject(scripts[int(s_sel)-1])
                    except: pass

            elif choice == '3': # Exfiltrate
                if not active_pkg: active_pkg = select_package()
                if active_pkg:
                    dumper = ADBDumper(active_pkg)
                    print(f"{INDENT}[*] Pulling data from {active_pkg}...")
                    results = dumper.pull_data()
                    print("\n" + INDENT + "[+] Exfiltration Results:")
                    for r in results:
                        status = "V" if r['status'] == 'pulled' else "X"
                        print(f"{INDENT}  {status} {r['target']}")
                    print(f"\n{INDENT}[*] Entering Loot Explorer...")
                    explore_loot_workflow(active_pkg)
                    c_input("Press Enter to continue", newline=False, indicator="")

            elif choice == '4': # Templates
                templates = HookTemplates()
                list_t = templates.list_templates()
                print(INDENT + "[ SELECT HOOK TEMPLATE ]")
                for i, t in enumerate(list_t): print(INDENT + f"{i+1}. {t}")
                print()
                t_sel = c_input("Enter number")
                try:
                    name = list_t[int(t_sel)-1]
                    code = templates.generate_hook(name)
                    fname = name.lower().replace(" ", "_").replace("(", "").replace(")", "") + ".js"
                    path = templates.save_hook(code, fname)
                    print(f"\n{INDENT}[+] Template generated and saved to: {path}\n{INDENT}" + "-" * 20)
                    for line in code.split('\n'): print(INDENT + line)
                    print(INDENT + "-" * 20)
                except: pass
                c_input("Press Enter to continue", newline=False, indicator="")

            elif choice == '5':
                current_session = None
                active_pkg = None
            
            elif choice == '6':
                devices = list_adb_devices()
                if devices:
                    print(INDENT + "[ SELECT DEVICE ]")
                    for i, dev in enumerate(devices): print(INDENT + f"{i+1}. {dev['id']} ({dev['status']})")
                    print()
                    sel = c_input("Enter number")
                    try: config.ACTIVE_DEVICE_ID = devices[int(sel)-1]["id"]
                    except: pass
            elif choice == '0': break

def main():
    parser = argparse.ArgumentParser(description="🛡️  APex CLI", add_help=False)
    parser.add_argument('-h', '--help', action='help')
    subparsers = parser.add_subparsers(dest="command")
    if len(sys.argv) == 1: interactive_menu()
    else:
        # Command line arg support here...
        pass

if __name__ == "__main__": main()
