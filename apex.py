import argparse
import sys
import json
import os
import shutil
from backend.core.scanner import APKScanner
from backend.core.dynamic import FridaOrchestrator
from backend.core.dumper import ADBDumper
from backend.ai.provider import AIProviderFactory
from backend.config import config

# --- UI Enhancements ---

BANNER = r"""
      ___           ___           ___           ___     
     /\  \         /\  \         /\  \         /\  \    
    /::\  \       /::\  \       /::\  \        \:\  \   
   /:/\:\  \     /:/\:\  \     /:/\:\  \        \:\  \  
  /::\~\:\  \   /::\~\:\  \   /::\~\:\  \       /::\  \ 
 /:/\:\ \:\__\ /:/\:\ \:\__\ /:/\:\ \:\__\     /:/\:\__\
 \/__\:\/:/  / \/__\:\/:/  / \:\~\:\ \/__/    /:/  \/__/
      \::/  /       \::/  /   \:\ \:\__\     /:/  /     
      /:/  /        /:/  /     \:\ \/__/     \/__/      
     /:/  /        /:/  /       \:\__\                  
     \/__/         \/__/         \/__/                  
                                                        
          AI-Powered APK Explorer & Exfiltrator
"""

def get_centered(text, width):
    lines = text.split('\n')
    return "\n".join(line.center(width) for line in lines)

def print_banner():
    width = shutil.get_terminal_size().columns
    # Cyan/Blue-ish color for the banner
    print("\033[96m" + get_centered(BANNER, width) + "\033[0m")
    print("-" * width)

def main():
    # Only show banner if no arguments or help is requested
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        print_banner()

    parser = argparse.ArgumentParser(
        description="🛡️  APex CLI: Security Orchestration for Android",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False # We handle help manually for better styling
    )
    
    # Re-adding help for subcommands
    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit')
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 1. Scan
    scan_parser = subparsers.add_parser("scan", help="Decompile and scan an APK for security logic (SAST)")
    scan_parser.add_argument("apk_path", help="Path to the APK file to analyze")

    # 2. List Scripts
    subparsers.add_parser("list-scripts", help="List available Frida scripts")

    # 3. Inject
    inject_parser = subparsers.add_parser("inject", help="Inject a Frida script into a running app (DAST)")
    inject_parser.add_argument("package_name", help="Target app package name")
    inject_parser.add_argument("script_name", help="Name of the script to inject")

    # 4. Generate AI Hook
    hook_parser = subparsers.add_parser("generate-hook", help="Ask AI to generate a custom Frida bypass hook")
    hook_parser.add_argument("smali_file", help="Path to a text file containing the target Smali code")
    hook_parser.add_argument("--category", default="ssl_pinning", help="Bypass category")

    # 5. Exfiltrate
    exfil_parser = subparsers.add_parser("exfiltrate", help="Pull sensitive data from the device")
    exfil_parser.add_argument("package_name", help="Target app package name")

    # Center the help options if no command provided
    if len(sys.argv) == 1:
        width = shutil.get_terminal_size().columns
        print("\n" + "\033[93m[ AVAILABLE COMMANDS ]\033[0m".center(width))
        commands_list = [
            "scan            : Decompile and find security logic",
            "list-scripts    : View your Frida script library",
            "inject          : Attach and bypass security checks",
            "generate-hook   : Use LLM to create surgical hooks",
            "exfiltrate      : Dump databases and native libs"
        ]
        for cmd in commands_list:
            print(cmd.center(width))
        print("\n" + "Run 'python apex.py [command] --help' for details.".center(width) + "\n")
        sys.exit(0)

    args = parser.parse_args()

    # --- Command Execution ---

    if args.command == "scan":
        if not os.path.exists(args.apk_path):
            print(f"\033[91m[-] Error: File not found at {args.apk_path}\033[0m")
            sys.exit(1)
            
        print(f"\033[94m[*] Starting APex Scanner on {args.apk_path}...\033[0m")
        scanner = APKScanner(args.apk_path)
        
        if scanner.decompile():
            print("\033[92m[*] Decompilation successful. Hunting for security logic...\033[0m")
            findings = scanner.find_security_logic()
            print(f"\n\033[92m[+] Scan Complete! Found {len(findings)} points of interest:\033[0m\n")
            print(json.dumps(findings, indent=2))
        else:
            print("\033[91m[-] Decompilation failed. Ensure Java is installed and working.\033[0m")
            sys.exit(1)

    elif args.command == "list-scripts":
        orchestrator = FridaOrchestrator(None)
        scripts = orchestrator.list_scripts()
        print("\n\033[92m[+] Available Frida Scripts:\033[0m")
        if not scripts:
            print("  (No scripts found in frida-scripts/)")
        for s in scripts:
            print(f"  - {s}")
        print()

    elif args.command == "inject":
        print(f"\033[94m[*] Attaching to {args.package_name} and injecting {args.script_name}...\033[0m")
        orchestrator = FridaOrchestrator(args.package_name)
        if orchestrator.attach_and_inject(args.script_name):
            print(f"\033[92m[+] Successfully injected {args.script_name}!\033[0m")
        else:
            print(f"\033[91m[-] Failed to inject script. Is frida-server running and the app open?\033[0m")
            sys.exit(1)

    elif args.command == "generate-hook":
        if not os.path.exists(args.smali_file):
            print(f"\033[91m[-] Error: Smali text file not found at {args.smali_file}\033[0m")
            sys.exit(1)
            
        with open(args.smali_file, 'r') as f:
            smali_code = f.read()
            
        print(f"\033[94m[*] Analyzing Smali code with AI ({config.AI_PROVIDER})...\033[0m")
        try:
            provider = AIProviderFactory.get_provider()
            hook = provider.generate_hook(smali_code, args.category)
            
            if not os.path.exists(config.FRIDA_SCRIPTS_PATH):
                os.makedirs(config.FRIDA_SCRIPTS_PATH)
                
            out_path = os.path.join(config.FRIDA_SCRIPTS_PATH, "ai_generated.js")
            with open(out_path, "w") as f:
                f.write(hook)
                
            print(f"\033[92m[+] Success! Hook generated and saved to: {out_path}\033[0m\n")
            print("\033[93m--- Generated Hook ---\033[0m")
            print(hook)
            print("\033[93m----------------------\033[0m")
        except Exception as e:
            print(f"\033[91m[-] AI Generation failed: {e}\033[0m")

    elif args.command == "exfiltrate":
        print(f"\033[94m[*] Initiating ADB data exfiltration for {args.package_name}...\033[0m")
        dumper = ADBDumper(args.package_name)
        results = dumper.pull_data()
        
        print("\n\033[92m[+] Exfiltration Results:\033[0m")
        for r in results:
            status = "✅" if r['status'] == 'pulled' else "❌"
            print(f"  {status} {r['target']} -> {r.get('status')}")
        print(f"\n[*] Check the './downloads/{args.package_name}' directory for your loot.")

if __name__ == "__main__":
    main()
