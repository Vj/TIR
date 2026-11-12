# engines/dynamic/intent_fuzzer_engine.py
import subprocess
import time
from typing import List, Dict, Any
from core.models import Finding, Severity, CheckStatus
from engines.dynamic.adb_client import ADBBridge

class IntentFuzzerEngine:
    def __init__(self, package_name: str, device_id: str = None):
        self.package_name = package_name
        self.device_id = device_id
        self.adb = ADBBridge()

    def _adb_exec(self, shell_cmd: str) -> str:
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(["shell", shell_cmd])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
            return res.stdout.strip()
        except Exception as e:
            return f"ERROR: {str(e)}"

    def test_component_injection(self, component_name: str, component_type: str = "activity") -> List[Finding]:
        """
        Fuzzes exported components with null, boundary, and unexpected Intent extra types
        to detect unhandled runtime exceptions or authorization bypasses (DYN-031, DYN-032).
        """
        findings: List[Finding] = []
        full_target = f"{self.package_name}/{component_name}"

        # 1. Test Baseline Invocation without extras
        if component_type == "activity":
            cmd = f"am start -n {full_target}"
        elif component_type == "service":
            cmd = f"am startservice -n {full_target}"
        else:
            cmd = f"am broadcast -a {full_target}"

        out_baseline = self._adb_exec(cmd)
        
        # Check if process crashed immediately
        if "FATAL EXCEPTION" in out_baseline or "has died" in out_baseline:
            findings.append(Finding(
                check_id="DYN-032",
                title=f"Unhandled Null Intent Crash: {component_name}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                description=f"Exported {component_type} '{component_name}' crashed upon receiving a standard intent without extras.",
                evidence=f"Invocation: {cmd}\nOutput:\n{out_baseline[:300]}",
                remediation="Add null-safety checks when accessing getIntent() and intent.getExtras() in the component lifecycle."
            ))

        # 2. Test Boundary & Malformed Parameter Injection
        fuzz_params = [
            "--es url 'javascript:alert(1)'",
            "--es file '../../../../data/data/com.target/shared_prefs/creds.xml'",
            "--ez is_admin true --ei role_id 0",
            "--es payload '\\x00\\xFF\\xFE\\xFD'",
        ]

        for param in fuzz_params:
            fuzz_cmd = f"{cmd} {param}"
            out_fuzz = self._adb_exec(fuzz_cmd)

            if "SecurityException" in out_fuzz and "Permission Denial" in out_fuzz:
                # Proper authorization boundary enforced by permission
                continue

            if "NullPointerException" in out_fuzz or "ClassCastException" in out_fuzz or "FATAL" in out_fuzz:
                findings.append(Finding(
                    check_id="DYN-032",
                    title=f"Intent Parameter Deserialization / Type Casting Flaw: {component_name}",
                    category="MASVS-PLATFORM",
                    tab_index=6,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    description=f"Component crashed or threw unhandled cast exceptions when processing unexpected intent extra types.",
                    evidence=f"Fuzz Command: {fuzz_cmd}\nExecution Output:\n{out_fuzz[:300]}",
                    remediation="Wrap intent extra parsing in try-catch blocks and sanitize inputs against type boundaries."
                ))
                break

        return findings