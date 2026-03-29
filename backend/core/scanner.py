import os
import re
import subprocess
import sys
import json
import xml.etree.ElementTree as ET
from backend.config import config

class APKScanner:
    def __init__(self, apk_path=None, existing_dir=None):
        self.apk_path = apk_path
        if existing_dir:
            self.output_dir = os.path.normpath(existing_dir)
        elif apk_path:
            self.output_dir = os.path.normpath(os.path.join(config.TEMP_DECOMPILED_PATH, os.path.basename(apk_path).replace(".apk", "")))
        
        self.manifest_path = os.path.join(self.output_dir, "AndroidManifest.xml")
        self.report_cache_path = os.path.join(self.output_dir, "apex_report.json")
        self.apktool_jar = os.path.join("pyapktool_tools", "apktool.jar")

    def decompile(self):
        """Decompiles the APK using the managed apktool.jar directly"""
        if not self.apk_path: return False
        if not os.path.exists(config.TEMP_DECOMPILED_PATH): os.makedirs(config.TEMP_DECOMPILED_PATH)
        if not os.path.exists(self.apktool_jar):
            try:
                import pyapktool.pyapktool as pat
                pat.Apktool("pyapktool_tools").get()
            except ImportError: return False

        try:
            cmd = ["java", "-jar", self.apktool_jar, "d", self.apk_path, "-o", self.output_dir, "-f"]
            subprocess.run(cmd, check=True, shell=True, capture_output=True)
            return True
        except subprocess.CalledProcessError: return False

    def load_cached_report(self):
        """Returns the previously saved report if it exists"""
        if os.path.exists(self.report_cache_path):
            try:
                with open(self.report_cache_path, 'r') as f:
                    return json.load(f)
            except: return None
        return None

    def save_report(self, report):
        """Saves the report to the local directory for fast loading"""
        try:
            with open(self.report_cache_path, 'w') as f:
                json.dump(report, f, indent=4)
        except: pass

    def find_manifest_risks(self):
        """Parses AndroidManifest.xml for misconfigurations"""
        risks = {"permissions": [], "exported_components": [], "debuggable": False, "allow_backup": True, "cleartext_traffic": False}
        if not os.path.exists(self.manifest_path): return risks
        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()
            application = root.find('application')
            if application is not None:
                risks["debuggable"] = application.get('{http://schemas.android.com/apk/res/android}debuggable') == "true"
                risks["allow_backup"] = application.get('{http://schemas.android.com/apk/res/android}allowBackup') != "false"
                risks["cleartext_traffic"] = application.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic') == "true"
                for tag in ['activity', 'service', 'receiver', 'provider']:
                    for comp in application.findall(tag):
                        if comp.get('{http://schemas.android.com/apk/res/android}exported') == "true":
                            risks["exported_components"].append(f"{tag.capitalize()}: {comp.get('{http://schemas.android.com/apk/res/android}name')}")
            dangerous_perms = ["READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "CAMERA", "ACCESS_FINE_LOCATION", "RECORD_AUDIO"]
            for perm in root.findall('uses-permission'):
                name = perm.get('{http://schemas.android.com/apk/res/android}name', "").split('.')[-1]
                if name in dangerous_perms: risks["permissions"].append(name)
        except: pass
        return risks

    def get_security_context(self):
        """Surgically extracts relevant Smali methods for AI analysis"""
        context_patterns = [r"X509TrustManager", r"checkServerTrusted", r"CertificatePinner", r"Superuser\.apk", r"root-checker", r"which su"]
        aggregated_code = ""
        found_methods = 0
        char_limit = 15000 
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if file.endswith(".smali"):
                    try:
                        with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for pat in context_patterns:
                                matches = re.finditer(pat, content, re.IGNORECASE)
                                for match in matches:
                                    start = max(0, content.rfind('.method', 0, match.start()))
                                    end = content.find('.end method', match.end()) + 11
                                    if start != -1 and end != -1:
                                        method_code = content[start:end]
                                        if method_code not in aggregated_code:
                                            block = f"\n--- FILE: {os.path.relpath(os.path.join(root, file), self.output_dir)} ---\n{method_code}\n"
                                            if len(aggregated_code) + len(block) < char_limit:
                                                aggregated_code += block
                                                found_methods += 1
                                            else: return aggregated_code 
                                    if found_methods >= 5: return aggregated_code
                    except: pass
        return aggregated_code

    def find_security_logic(self, progress_callback=None):
        """Comprehensive scan for vulnerabilities and secrets"""
        patterns = {
            "Secrets & API Keys": {
                "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
                "AWS Access Key": r"AKIA[0-9A-Z]{16}",
                "Firebase URL": r"https://.*\.firebaseio\.com",
                "Generic Secret": r"(?i)(api_key|secret_key|auth_token|db_password|access_token)\s*[:=]\s*['\"]([^'\"]+)['\"]"
            },
            "Network & API Endpoints": {
                "HTTP Endpoint": r"http://[a-zA-Z0-9\./_-]+",
                "Internal IP": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
            },
            "Security Protections": {
                "SSL Pinning Logic": r"X509TrustManager|checkServerTrusted|CertificatePinner",
                "Root Detection": r"Superuser\.apk|root-checker|which su|test-keys"
            }
        }
        
        report = {"Manifest Risks": self.find_manifest_risks(), "Code Findings": {}, "Sensitive Assets": []}
        high_risk_names = [".env", "credentials", "secret", "password", "google-services", "client_secret", "auth_config"]
        high_risk_exts = [".jks", ".keystore", ".p12", ".pem", ".cert", ".pkcs12"]
        noise_dirs = ["res/anim", "res/color", "res/layout", "res/drawable", "res/values", "res/mipmap", "res/animator"]
        noise_prefixes = ["abc_", "mtrl_", "design_", "androidx_", "notification_", "messenger_"]

        all_scan_files = []
        for root, dirs, files in os.walk(self.output_dir):
            rel_dir = os.path.relpath(root, self.output_dir).replace("\\", "/")
            if any(rel_dir.startswith(nd) for nd in noise_dirs): continue
            for file in files:
                file_lower = file.lower()
                rel_path = os.path.join(rel_dir, file)
                if any(file_lower.startswith(np) for np in noise_prefixes): continue
                is_sensitive = any(hr in file_lower for hr in high_risk_names) or any(file_lower.endswith(ext) for ext in high_risk_exts)
                if is_sensitive:
                    report["Sensitive Assets"].append(rel_path)
                    all_scan_files.append(os.path.join(root, file))
                elif file.endswith(".smali") or file.endswith(".json") or file.endswith(".xml") or file.endswith(".env"):
                    all_scan_files.append(os.path.join(root, file))

        total_files = len(all_scan_files)
        for idx, file_path in enumerate(all_scan_files):
            if progress_callback: progress_callback(idx + 1, total_files)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for category, sub_patterns in patterns.items():
                        if category not in report["Code Findings"]: report["Code Findings"][category] = []
                        for name, regex in sub_patterns.items():
                            matches = re.findall(regex, content)
                            if matches:
                                clean_matches = list(set([str(m[1]) if isinstance(m, tuple) else str(m) for m in matches]))
                                report["Code Findings"][category].append({"type": name, "file": os.path.relpath(file_path, self.output_dir), "matches": clean_matches[:5]})
            except: pass
        
        # Cache for next time
        self.save_report(report)
        return report
