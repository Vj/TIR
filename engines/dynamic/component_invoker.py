# engines/dynamic/component_invoker.py
import subprocess
from typing import List, Dict, Any
from core.models import Finding, Severity, CheckStatus
from engines.dynamic.adb_client import ADBBridge

class ComponentInvocationEngine:
    def __init__(self, package_name: str, device_id: str = None):
        self.package_name = package_name
        self.device_id = device_id
        self.adb = ADBBridge()

    def test_exported_activity_access(self, activity_name: str) -> Finding:
        """
        Attempts to launch an exported activity via ADB and evaluates whether 
        unauthorized access to the interface is permitted.
        """
        component = f"{self.package_name}/{activity_name}"
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(["shell", "am", "start", "-n", component])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Check current focused window to determine if the screen displayed
            focus_cmd = ["adb"]
            if self.device_id:
                focus_cmd.extend(["-s", self.device_id])
            focus_cmd.extend(["shell", "dumpsys", "window"])
            focus_res = subprocess.run(focus_cmd, capture_output=True, text=True, timeout=5)

            is_focused = activity_name in focus_res.stdout

            if is_focused:
                return Finding(
                    check_id="AND-PLAT-08",
                    title=f"Exported Activity Open to Unauthorized Launch: {activity_name}",
                    category="MASVS-PLATFORM",
                    tab_index=6,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    description=f"Activity '{activity_name}' was invoked externally and retained foreground focus without authorization checks.",
                    evidence=f"Invocation command: {' '.join(cmd)}\nCurrent focus output:\n{res.stdout.strip()}",
                    remediation="Set android:exported='false' in AndroidManifest.xml or enforce a custom signature permission."
                )
            else:
                return Finding(
                    check_id="AND-PLAT-08",
                    title=f"Exported Activity Invocation Guarded: {activity_name}",
                    category="MASVS-PLATFORM",
                    tab_index=6,
                    severity=Severity.INFO,
                    status=CheckStatus.PASS,
                    description=f"Activity '{activity_name}' did not retain foreground focus upon unauthenticated invocation.",
                    evidence=f"am start result: {res.stdout.strip()}",
                    remediation=None
                )
        except Exception as e:
            return Finding(
                check_id="AND-PLAT-08",
                title=f"Activity Invocation Error: {activity_name}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.LOW,
                status=CheckStatus.NEEDS_REVIEW,
                description=f"Encountered error while testing component launch: {str(e)}",
                evidence=str(e),
                remediation=None
            )