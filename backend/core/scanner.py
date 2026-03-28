import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from backend.config import config

class APKScanner:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.output_dir = os.path.normpath(os.path.join(config.TEMP_DECOMPILED_PATH, os.path.basename(apk_path).replace(".apk", "")))
        self.manifest_path = os.path.join(self.output_dir, "AndroidManifest.xml")
        self.apktool_jar = os.path.join("pyapktool_tools", "apktool.jar")

    def decompile(self):
        """Decompiles the APK using the managed apktool.jar directly for maximum reliability"""
        print(f"[*] Decompiling {self.apk_path}...")
        
        if not os.path.exists(config.TEMP_DECOMPILED_PATH):
            os.makedirs(config.TEMP_DECOMPILED_PATH)

        # 1. Ensure the tools are downloaded via pyapktool first (if not already there)
        try:
            import pyapktool.pyapktool as pat
            # This ensures apktool.jar exists in pyapktool_tools/
            apktool_obj = pat.Apktool("pyapktool_tools")
            apktool_obj.get()
        except ImportError:
            print("[-] Error: pyapktool package not found.")
            return False

        # 2. Run the jar directly to support -o and -f flags properly
        if not os.path.exists(self.apktool_jar):
            print(f"[-] Error: {self.apktool_jar} not found.")
            return False

        try:
            # Command: java -jar apktool.jar d <apk> -o <out> -f
            cmd = ["java", "-jar", self.apktool_jar, "d", self.apk_path, "-o", self.output_dir, "-f"]
            subprocess.run(cmd, check=True, shell=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Decompilation failed: {e.stderr.decode(errors='ignore')}")
            return False

    def find_manifest_risks(self):
        """Parses AndroidManifest.xml for dangerous permissions and exported components"""
        risks = {"permissions": [], "exported_components": [], "debuggable": False}
        if not os.path.exists(self.manifest_path):
            return risks

        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()
            
            # Check if debuggable
            application = root.find('application')
            if application is not None:
                debuggable = application.get('{http://schemas.android.com/apk/res/android}debuggable')
                if debuggable == "true":
                    risks["debuggable"] = True

            # Check for dangerous permissions
            dangerous_perms = [
                "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                "android.permission.READ_CONTACTS", "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO"
            ]
            for perm in root.findall('uses-permission'):
                name = perm.get('{http://schemas.android.com/apk/res/android}name')
                if name in dangerous_perms:
                    risks["permissions"].append(name)

            # Check for exported components
            for tag in ['activity', 'service', 'receiver', 'provider']:
                for comp in application.findall(tag):
                    exported = comp.get('{http://schemas.android.com/apk/res/android}exported')
                    name = comp.get('{http://schemas.android.com/apk/res/android}name')
                    if exported == "true":
                        risks["exported_components"].append({"type": tag, "name": name})
        except Exception as e:
            print(f"[-] Error parsing manifest: {e}")
        
        return risks

    def find_security_logic(self):
        """Comprehensive scan for security logic, secrets, and insecure patterns"""
        patterns = {
            "ssl_pinning": [
                r"X509TrustManager", r"checkServerTrusted", r"CertificatePinner", r"OkHttpClient"
            ],
            "root_detection": [
                r"/system/app/Superuser.apk", r"root-checker", r"which su", r"test-keys", r"bin/su"
            ],
            "hardcoded_secrets": [
                r"AIza[0-9A-Za-z-_]{35}", 
                r"AKIA[0-9A-Z]{16}",       
                r"https://.*\.firebaseio\.com",
                r"-----BEGIN RSA PRIVATE KEY-----"
            ],
            "insecure_webview": [
                r"setJavaScriptEnabled\(1\)", r"setAllowFileAccess\(1\)"
            ]
        }
        
        results = {"manifest_risks": self.find_manifest_risks(), "smali_findings": []}
        if not os.path.exists(self.output_dir):
            return results

        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if file.endswith(".smali"):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for category, regex_list in patterns.items():
                            for regex in regex_list:
                                if re.search(regex, content, re.IGNORECASE):
                                    match = re.search(regex, content, re.IGNORECASE)
                                    start = max(0, content.rfind('.method', 0, match.start()))
                                    end = content.find('.end method', match.end()) + 11
                                    if start != -1 and end != -1:
                                        results["smali_findings"].append({
                                            "file": os.path.relpath(file_path, self.output_dir),
                                            "category": category,
                                            "code": content[start:end]
                                        })
        return results
