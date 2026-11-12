# engines/dynamic/component_audit_engine.py
import subprocess
import time
from typing import List, Dict, Any, Set
from core.models import Finding, Severity, CheckStatus

class ComponentAuditEngine:
    def __init__(self, package_name: str, device_id: str = None):
        self.package_name = package_name
        self.device_id = device_id

    def _adb_exec(self, cmd_args: List[str]) -> str:
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(cmd_args)
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            return res.stdout.strip()
        except Exception as e:
            return f"ERROR: {str(e)}"

    def discover_components(self) -> Dict[str, List[str]]:
        """Parses dumpsys package to catalog exported activities, receivers, and services."""
        raw_dump = self._adb_exec(["shell", "dumpsys", "package", self.package_name])
        components = {
            "activities": set(),
            "services": set(),
            "receivers": set()
        }

        current_section = None
        for line in raw_dump.splitlines():
            clean = line.strip()
            if "Activity Resolver Table:" in clean:
                current_section = "activities"
                continue
            elif "Receiver Resolver Table:" in clean:
                current_section = "receivers"
                continue
            elif "Service Resolver Table:" in clean:
                current_section = "services"
                continue
            elif "ContentProvider Authorities:" in clean or "Key Set Manager:" in clean:
                current_section = None

            if current_section and f"{self.package_name}/" in clean:
                for token in clean.split():
                    if f"{self.package_name}/" in token:
                        comp = token.split(f"{self.package_name}/")[-1].replace("filter", "").strip()
                        if comp:
                            clean_name = comp if comp.startswith(self.package_name) else f"{self.package_name}.{comp.lstrip('.')}"
                            components[current_section].add(clean_name)

        return {k: sorted(list(v)) for k, v in components.items()}

    def audit_exported_components(self) -> List[Finding]:
        """Runs launch and fuzz tests on all discovered exported components."""
        findings: List[Finding] = []
        catalog = self.discover_components()

        # 1. Audit Exported Activities
        for act in catalog["activities"]:
            findings.extend(self._test_activity_lifecycle(act))

        # 2. Audit Exported Broadcast Receivers
        for rec in catalog["receivers"]:
            findings.extend(self._test_receiver_resilience(rec))

        return findings

    def _test_activity_lifecycle(self, activity_name: str) -> List[Finding]:
        results: List[Finding] = []
        full_target = f"{self.package_name}/{activity_name}"

        # Baseline start: evaluate whether component requires permissions or crashes on null extras
        cmd_start = ["shell", "am", "start", "-n", full_target]
        start_out = self._adb_exec(cmd_start)

        if "SecurityException" in start_out or "Permission Denial" in start_out:
            results.append(Finding(
                check_id="DYN-031",
                title=f"Exported Activity Enforces Permission Guard: {activity_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                description=f"Activity '{activity_name}' rejected unprivileged invocation with a security exception.",
                evidence=start_out[:250],
                remediation=None
            ))
            return results

        if "FATAL EXCEPTION" in start_out or "has died" in start_out:
            results.append(Finding(
                check_id="DYN-032",
                title=f"Activity Crashed on Null Intent Extras: {activity_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description=f"Activity '{activity_name}' encountered an unhandled exception when invoked without required parameters.",
                evidence=f"Command: am start -n {full_target}\nOutput:\n{start_out[:300]}",
                remediation="Validate intent data with null checks before dereferencing parameters in onCreate()."
            ))

        # Boundary parameter fuzzing: test unexpected types (e.g. type confusion or boundary values)
        fuzz_cmd = [
            "shell", "am", "start", "-n", full_target,
            "--es", "extra_str", "test",
            "--ei", "extra_int", "2147483647",
            "--ez", "extra_bool", "true"
        ]
        fuzz_out = self._adb_exec(fuzz_cmd)

        if "ClassCastException" in fuzz_out or "NullPointerException" in fuzz_out:
            results.append(Finding(
                check_id="DYN-032",
                title=f"Parameter Type Casting Flaw: {activity_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                description=f"Activity '{activity_name}' failed to safely parse intent extras of varying data types.",
                evidence=f"Output:\n{fuzz_out[:300]}",
                remediation="Ensure intent extras are retrieved with fallback defaults and type-safe wrappers."
            ))

        return results

    def _test_receiver_resilience(self, receiver_name: str) -> List[Finding]:
        results: List[Finding] = []
        full_target = f"{self.package_name}/{receiver_name}"

        # Send empty directed broadcast
        bcast_cmd = ["shell", "am", "broadcast", "-n", full_target]
        bcast_out = self._adb_exec(bcast_cmd)

        if "SecurityException" in bcast_out:
            results.append(Finding(
                check_id="DYN-031",
                title=f"Broadcast Receiver Enforces Calling Permission: {receiver_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                description=f"Receiver '{receiver_name}' rejects broadcasts from unauthorized callers.",
                evidence=bcast_out[:250],
                remediation=None
            ))
        elif "FATAL" in bcast_out:
            results.append(Finding(
                check_id="DYN-032",
                title=f"Broadcast Receiver Crashed on Malformed Intent: {receiver_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description=f"Receiver '{receiver_name}' crashed during onReceive() execution.",
                evidence=bcast_out[:300],
                remediation="Wrap onReceive() handling logic in exception handlers to prevent denial-of-service."
            ))

        return results