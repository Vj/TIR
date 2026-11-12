# engines/dynamic/runtime_behavior_engine.py
import time
import subprocess
from typing import List, Set
from core.models import Finding, Severity, CheckStatus

class RuntimeBehaviorEngine:
    def __init__(self, package_name: str, device_id: str = None):
        self.package_name = package_name
        self.device_id = device_id

    def _adb_exec(self, cmd_args: List[str]) -> str:
        base = ["adb"]
        if self.device_id:
            base.extend(["-s", self.device_id])
        base.extend(cmd_args)
        try:
            res = subprocess.run(base, capture_output=True, text=True, timeout=12)
            return res.stdout.strip()
        except Exception as e:
            return f"ERROR: {str(e)}"

    def discover_exported_activities(self) -> List[str]:
        """Queries dumpsys package to discover all exported activities for the target package."""
        raw_dump = self._adb_exec(["shell", "dumpsys", "package", self.package_name])
        activities: Set[str] = set()

        # Parse Activity Resolver Table in dumpsys output
        capture = False
        for line in raw_dump.splitlines():
            clean = line.strip()
            if "Activity Resolver Table:" in clean:
                capture = True
                continue
            if capture and ("Receiver Resolver Table:" in clean or "Service Resolver Table:" in clean):
                break
            if capture and f"{self.package_name}/" in clean:
                parts = clean.split()
                for token in parts:
                    if f"{self.package_name}/" in token:
                        act = token.split(f"{self.package_name}/")[-1].replace("filter", "").strip()
                        if act and not act.startswith("."):
                            activities.add(act)
                        elif act.startswith("."):
                            activities.add(f"{self.package_name}{act}")

        return sorted(list(activities))

    def audit_dyn_030_screenshot_protection(self, test_activity: str) -> Finding:
        """Tests window capture protection (FLAG_SECURE) on an activity."""
        component = test_activity if "/" in test_activity else f"{self.package_name}/{test_activity}"
        
        # Launch target component
        self._adb_exec(["shell", "am", "start", "-n", component])
        time.sleep(1.2)

        tmp_png = f"/data/local/tmp/tir_snap_{int(time.time())}.png"
        capture_result = self._adb_exec(["shell", "screencap", "-p", tmp_png])
        check_file = self._adb_exec(["shell", "ls", "-l", tmp_png])
        self._adb_exec(["shell", "rm", "-f", tmp_png])

        if "Status 1" in capture_result or "Permission denied" in capture_result or "failed" in capture_result.lower():
            return Finding(
                check_id="DYN-030",
                title=f"Screenshot Protection Enforced: {test_activity.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                description=f"Activity '{test_activity}' enforces FLAG_SECURE. Screen captures and recent app preview caching are blocked by the OS.",
                evidence="screencap returned protected window denial.",
                remediation=None
            )
        else:
            return Finding(
                check_id="DYN-030",
                title=f"Missing Screen Capture Protection: {test_activity.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                description=f"Activity '{test_activity}' does not set FLAG_SECURE. Sensitive UI fields remain exposed to background screenshot captures and task switchers.",
                evidence=f"Screen snapshot captured via screencap: {check_file.strip()}",
                remediation="Add getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) in onCreate()."
            )

    def audit_dyn_029_clipboard_leakage(self) -> Finding:
        """Inspects system clipboard for sensitive data remnants."""
        clip_data = self._adb_exec(["shell", "cmd", "clipboard", "get"])
        sensitive_keywords = ["token", "password", "bearer", "api_key", "secret", "cvv", "key"]
        matched = [k for k in sensitive_keywords if k in clip_data.lower()]

        if matched:
            return Finding(
                check_id="DYN-029",
                title="Sensitive Data Found in System Clipboard",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description=f"Potential credentials or sensitive tokens ({', '.join(matched)}) found in clipboard buffer.",
                evidence=f"Matched fragment in clipboard buffer: {clip_data[:60]}...",
                remediation="Clear clipboard data or tag ClipData with ClipDescription.EXTRA_IS_SENSITIVE when handling sensitive inputs."
            )
        return Finding(
            check_id="DYN-029",
            title="Clipboard Buffer Clean",
            category="MASVS-STORAGE",
            tab_index=2,
            severity=Severity.INFO,
            status=CheckStatus.PASS,
            description="No plaintext authentication tokens or credentials detected in the system clipboard.",
            evidence="Clipboard buffer empty or free of targeted keywords.",
            remediation=None
        )