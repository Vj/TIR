import subprocess
from typing import List, Optional

class ADBBridge:
    def __init__(self, adb_path: str = "adb"):
        self.adb = adb_path

    def run_cmd(self, args: List[str]) -> str:
        cmd = [self.adb] + args
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return res.stdout.strip()

    def get_connected_devices(self) -> List[str]:
        output = self.run_cmd(["devices"])
        lines = output.splitlines()[1:]
        devices = [line.split()[0] for line in lines if "\tdevice" in line]
        return devices

    def pull_sandbox_file(self, device_id: str, package_name: str, target_rel_path: str, local_dest: str):
        # Utilizes run-as for non-rooted debug builds or direct su fallback
        cmd = f"run-as {package_name} cat {target_rel_path}"
        content = self.run_cmd(["-s", device_id, "shell", cmd])
        with open(local_dest, "w", encoding="utf-8") as f:
            f.write(content)

    def capture_screenshot(self, device_id: str, local_save_path: str):
        self.run_cmd(["-s", device_id, "shell", "screencap", "-p", "/data/local/tmp/tir_screen.png"])
        self.run_cmd(["-s", device_id, "pull", "/data/local/tmp/tir_screen.png", local_save_path])
        self.run_cmd(["-s", device_id, "shell", "rm", "/data/local/tmp/tir_screen.png"])