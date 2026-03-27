import subprocess
import frida

class AndroidUtils:
    @staticmethod
    def list_devices():
        """Lists connected Android devices via Frida"""
        try:
            return [d for d in frida.enumerate_devices() if d.type == 'usb']
        except Exception as e:
            print(f"Error listing devices: {e}")
            return []

    @staticmethod
    def list_packages(device_id=None):
        """Lists installed packages on a specific device using adb"""
        cmd = ["adb"]
        if device_id:
            cmd.extend(["-s", device_id])
        cmd.extend(["shell", "pm", "list", "packages", "-3"]) # Only 3rd party apps by default
        
        try:
            output = subprocess.check_output(cmd).decode("utf-8")
            packages = [line.split(":")[1].strip() for line in output.splitlines() if line.startswith("package:")]
            return sorted(packages)
        except subprocess.CalledProcessError as e:
            print(f"Error listing packages: {e}")
            return []

    @staticmethod
    def is_rooted(device_id=None):
        """Checks if the device has root access via adb"""
        cmd = ["adb"]
        if device_id:
            cmd.extend(["-s", device_id])
        cmd.extend(["shell", "which", "su"])
        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            return True
        except:
            return False

    @staticmethod
    def verify_frida_environment(device):
        """Verifies if frida-server is running and accessible on the device"""
        try:
            device.enumerate_processes()
            return True, "Frida server is running and accessible."
        except Exception as e:
            if "unable to find process" in str(e).lower() or "connection refused" in str(e).lower():
                return False, "Frida server is not running or not reachable. Ensure frida-server is started as root on the device."
            return False, f"Frida error: {e}"

    @staticmethod
    def search_packages(query, device_id=None):
        """Filters installed packages based on a query"""
        packages = AndroidUtils.list_packages(device_id)
        return [p for p in packages if query.lower() in p.lower()]
