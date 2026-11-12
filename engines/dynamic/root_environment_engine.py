# engines/dynamic/root_environment_engine.py
import subprocess
from typing import List, Dict, Any
from core.models import Finding, Severity, CheckStatus
from engines.dynamic.adb_client import ADBBridge

class RootEnvironmentEngine:
    def __init__(self, package_name: str, device_id: str = None):
        self.package_name = package_name
        self.device_id = device_id
        self.adb = ADBBridge()

    def _adb_exec(self, shell_cmd: str) -> str:
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(["shell", shell_cmd])
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.stdout.strip()

    def audit_environment(self) -> List[Finding]:
        findings = []
        findings.extend(self._audit_rot_020_file_permissions())
        findings.extend(self._audit_rot_024_system_properties())
        findings.extend(self._audit_rot_025_debug_interfaces())
        return findings

    def _audit_rot_020_file_permissions(self) -> List[Finding]:
        """ROT-020: Check if app sandbox files are world-readable or world-writable."""
        findings = []
        target_dir = f"/data/data/{self.package_name}"
        ls_output = self._adb_exec(f"ls -la {target_dir}")

        world_accessible_entries = []
        for line in ls_output.splitlines():
            # Check for other read (r) or write (w) flags in Unix permissions: e.g., drwxrwxrwx
            parts = line.split()
            if len(parts) >= 9:
                perms = parts[0]
                filename = parts[-1]
                if perms[7] == 'r' or perms[8] == 'w':
                    world_accessible_entries.append(f"{filename} ({perms})")

        if world_accessible_entries:
            findings.append(Finding(
                check_id="ROT-020",
                title="Insecure Sandbox File Permissions Detected",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description="Private files within the internal application sandbox are configured with world-readable or world-writable permissions.",
                evidence=f"Directory: {target_dir}\nAffected items:\n" + "\n".join(f"- {e}" for e in world_accessible_entries),
                remediation="Ensure files are created with MODE_PRIVATE. Never use deprecated MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE."
            ))
        else:
            findings.append(Finding(
                check_id="ROT-020",
                title="Sandbox File Permission Isolation Confirmed",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                description="Application sandbox files strictly enforce private user UID/GID ownership.",
                evidence=f"All files under {target_dir} restrict access to application UID.",
                remediation=None
            ))
        return findings

    def _audit_rot_024_system_properties(self) -> List[Finding]:
        """ROT-024: Validate Android system properties (ro.debuggable, ro.secure)."""
        findings = []
        ro_debuggable = self._adb_exec("getprop ro.debuggable")
        ro_secure = self._adb_exec("getprop ro.secure")

        insecure_props = []
        if ro_debuggable == "1":
            insecure_props.append("ro.debuggable=1 (Device kernel allows global debugging)")
        if ro_secure == "0":
            insecure_props.append("ro.secure=0 (Device operating with disabled root restrictions)")

        if insecure_props:
            findings.append(Finding(
                check_id="ROT-024",
                title="Device Operating Under Insecure Global System Properties",
                category="MASVS-RESILIENCE",
                tab_index=8,
                severity=Severity.MEDIUM,
                status=CheckStatus.NEEDS_REVIEW,
                description="The test execution device runs on a development or rooted build.",
                evidence="\n".join(insecure_props),
                remediation="Ensure client releases disable sensitive operations when running under custom rooted build properties."
            ))
        return findings

    def _audit_rot_025_debug_interfaces(self) -> List[Finding]:
        """ROT-025: Verify JDWP (Java Debug Wire Protocol) and debug port exposure."""
        findings = []
        jdwp_pids = self._adb_exec("jdwp").splitlines()
        
        # Get PID of current package
        pid_output = self._adb_exec(f"pidof {self.package_name}")
        app_pid = pid_output.strip()

        if app_pid and app_pid in jdwp_pids:
            findings.append(Finding(
                check_id="ROT-025",
                title="Live JDWP Debugging Port Exposed on Runtime Process",
                category="MASVS-RESILIENCE",
                tab_index=8,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description=f"Process PID {app_pid} exposes an active JDWP debugging listener, enabling arbitrary runtime memory inspection and code injection via jdb.",
                evidence=f"Package: {self.package_name} | PID: {app_pid} found in active adb jdwp table.",
                remediation="Set android:debuggable='false' in release builds and ensure debuggers are detached."
            ))
        return findings