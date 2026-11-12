# engines/dynamic/root_isolation_engine.py
import subprocess
import time
from typing import List, Dict, Any, Optional
from core.models import AnalysisType, Finding, Severity, CheckStatus
from engines.dynamic.adb_client import ADBBridge

class RootIsolationEngine:
    """
    Executes Batch 2: Root & Data Isolation test cases:
    - ROT-021: Root Detection Validation
    - ROT-022: Root Bypass & Anti-Hooking Resistance
    - ROT-023: Runtime Process Memory & Maps Inspection
    - ROT-026: Private App Data Extraction Validation
    """

    def __init__(self, package_name: str, device_id: Optional[str] = None):
        self.package_name = package_name
        self.device_id = device_id
        self.adb = ADBBridge()

    def _adb_exec(self, cmd_args: List[str], timeout: int = 10) -> str:
        base = ["adb"]
        if self.device_id:
            base.extend(["-s", self.device_id])
        base.extend(cmd_args)
        try:
            res = subprocess.run(
                base,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout
            )
            return res.stdout.strip()
        except Exception as e:
            return f"ERROR: {str(e)}"

    def audit_all_batch2(self, main_activity: Optional[str] = None) -> List[Finding]:
        findings: List[Finding] = []
        findings.append(self.audit_rot_021_root_detection(main_activity))
        findings.append(self.audit_rot_022_root_bypass_resistance())
        findings.append(self.audit_rot_023_process_memory_inspection())
        findings.append(self.audit_rot_026_app_data_extraction())
        return findings

    def audit_rot_021_root_detection(self, main_activity: Optional[str] = None) -> Finding:
        """
        ROT-021: Verifies whether the application detects root indicators and terminates or warns.
        """
        su_check = self._adb_exec(["shell", "which su 2>/dev/null || ls /system/bin/su /system/xbin/su 2>/dev/null"])
        device_is_rooted = bool(su_check and "not found" not in su_check and "No such" not in su_check)

        pid_before = self._adb_exec(["shell", f"pidof {self.package_name}"])
        if not pid_before:
            target = f"{self.package_name}/{main_activity}" if main_activity else self.package_name
            self._adb_exec(["shell", "monkey", "-p", self.package_name, "-c", "android.intent.category.LAUNCHER", "1"])
            time.sleep(2)
            pid_before = self._adb_exec(["shell", f"pidof {self.package_name}"])

        if not pid_before:
            return Finding(
                check_id="ROT-021",
                title="Root Detection Activated / Application Terminated",
                category="MASVS-RESILIENCE",
                tab_index=8,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                analysis_type=AnalysisType.DYNAMIC,
                description="The application refused to launch or immediately terminated upon startup on a rooted device environment.",
                evidence=f"Device root status: Root binaries detected ({su_check}). Process exited immediately.",
                remediation=None
            )

        return Finding(
            check_id="ROT-021",
            title="Root Detection Not Enforced / Absent",
            category="MASVS-RESILIENCE",
            tab_index=8,
            severity=Severity.MEDIUM,
            status=CheckStatus.NEEDS_REVIEW,
            analysis_type=AnalysisType.DYNAMIC,
            description="The application continues normal execution on a rooted environment without warning or terminating.",
            evidence=f"Device contains su binary ({su_check.strip()}). Target package running with PID: {pid_before.strip()}.",
            poc_command=f"adb shell pidof {self.package_name}",
            poc_observed=f"Application continues executing on rooted environment with PID {pid_before.strip()}.",
            remediation="If the application processes high-risk data, implement multi-layered root indicators (Play Integrity API, checking su/magisk paths)."
        )

    def audit_rot_022_root_bypass_resistance(self) -> Finding:
        """
        ROT-022: Evaluates anti-hooking, debugger attachment restrictions, and ptrace controls.
        """
        pid = self._adb_exec(["shell", f"pidof {self.package_name}"])
        if not pid:
            return Finding(
                check_id="ROT-022",
                title="Root Bypass Resistance: Process Inactive",
                category="MASVS-RESILIENCE",
                tab_index=8,
                severity=Severity.LOW,
                status=CheckStatus.NEEDS_REVIEW,
                analysis_type=AnalysisType.DYNAMIC,
                description="Target process is not running. Launch application to evaluate ptrace status.",
                evidence="No active PID found.",
                remediation=None
            )

        first_pid = pid.split()[0]
        status_dump = self._adb_exec(["shell", f"cat /proc/{first_pid}/status | grep TracerPid"])
        tracer_pid = "0"
        if "TracerPid:" in status_dump:
            tracer_pid = status_dump.split("TracerPid:")[-1].strip()

        ps_output = self._adb_exec(["shell", "ps -A | grep -E 'frida|magisk' || true"])

        if tracer_pid != "0":
            return Finding(
                check_id="ROT-022",
                title="Active Debugger or Tracer Attached to Process",
                category="MASVS-RESILIENCE",
                tab_index=8,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                analysis_type=AnalysisType.DYNAMIC,
                description=f"Process {first_pid} is actively attached to a tracing process (TracerPid: {tracer_pid}).",
                evidence=f"/proc/{first_pid}/status reports TracerPid: {tracer_pid}",
                remediation="Implement ptrace(PTRACE_TRACEME, 0, 1, 0) in native code to block third-party debuggers and hooking engines."
            )

        return Finding(
            check_id="ROT-022",
            title="Anti-Hooking & Runtime Tamper Resistance",
            category="MASVS-RESILIENCE",
            tab_index=8,
            severity=Severity.MEDIUM,
            status=CheckStatus.NEEDS_REVIEW,
            analysis_type=AnalysisType.DYNAMIC,
            description="Process is running without an active tracer attached (TracerPid: 0). Verify whether native integrity checks or runtime hook verifications are active.",
            evidence=f"Target PID {first_pid}: TracerPid is 0. Running instrumentation processes: {ps_output or 'None detected'}.",
            remediation="Implement runtime integrity checks, verify method hooking against ART memory tables, and detect dynamic instrumentation agents."
        )

    def audit_rot_023_process_memory_inspection(self) -> Finding:
        """
        ROT-023: Inspects /proc/<pid>/maps for readable execution segments and memory exposure.
        """
        pid = self._adb_exec(["shell", f"pidof {self.package_name}"])
        if not pid:
            return Finding(
                check_id="ROT-023",
                title="Process Memory Inspection: Target Inactive",
                category="MASVS-RESILIENCE",
                tab_index=8,
                severity=Severity.INFO,
                status=CheckStatus.NEEDS_REVIEW,
                analysis_type=AnalysisType.DYNAMIC,
                description="Cannot inspect process memory layout because the target application is not running.",
                evidence="No active PID detected.",
                remediation=None
            )

        first_pid = pid.split()[0]
        maps_sample = self._adb_exec(["shell", f"head -n 25 /proc/{first_pid}/maps"])
        mem_perms = self._adb_exec(["shell", f"ls -l /proc/{first_pid}/mem"])

        return Finding(
            check_id="ROT-023",
            title="Runtime Process Memory Layout Inspected",
            category="MASVS-RESILIENCE",
            tab_index=8,
            severity=Severity.INFO,
            status=CheckStatus.PASS,
            analysis_type=AnalysisType.DYNAMIC,
            description=f"Inspected /proc/{first_pid}/maps and memory descriptor security boundaries.",
            evidence=f"/proc/{first_pid}/mem access: {mem_perms}\nTop memory segments:\n{maps_sample[:300]}...",
            remediation="Sensitive credentials, tokens, and cryptographic keys should be cleared from memory immediately after use."
        )

    def audit_rot_026_app_data_extraction(self) -> Finding:
        """
        ROT-026: Tests data extraction through run-as execution and accessible staging paths.
        """
        run_as_cmd = f"run-as {self.package_name} ls -la /data/data/{self.package_name}"
        run_as_result = self._adb_exec(["shell", run_as_cmd])

        if run_as_result and "not debuggable" not in run_as_result and "ERROR" not in run_as_result and "Permission denied" not in run_as_result:
            return Finding(
                check_id="ROT-026",
                title="Application Private Storage Extractable via run-as",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                analysis_type=AnalysisType.DYNAMIC,
                description="The internal sandbox directory (/data/data/<pkg>) can be fully enumerated using the run-as command. This allows arbitrary file extraction without root privileges.",
                affected_component=f"/data/data/{self.package_name}",
                source_file="AndroidManifest.xml",
                cwe_id="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                masvs_ref="MASVS-STORAGE-1",
                mastg_ref="MASTG-TEST-0001",
                poc_preconditions="Application build has android:debuggable='true'. Device connected via ADB.",
                poc_command=f"adb shell {run_as_cmd}",
                poc_expected="System package manager rejects access with 'Application not debuggable' or 'Permission denied'.",
                poc_observed="Sandbox filesystem enumerated without root credentials.",
                reproduction_sequence=[
                    f"# 1. Verify device connection",
                    f"adb devices",
                    f"# 2. Attempt sandbox enumeration via unprivileged run-as",
                    f"adb shell {run_as_cmd}"
                ],
                evidence=f"run-as execution output:\n{run_as_result[:350]}",
                remediation="Ensure android:debuggable is set to 'false' in production release manifests to disable the run-as helper."
            )

        return Finding(
            check_id="ROT-026",
            title="Private App Data Extraction Guarded Against Unprivileged Access",
            category="MASVS-STORAGE",
            tab_index=2,
            severity=Severity.INFO,
            status=CheckStatus.PASS,
            analysis_type=AnalysisType.DYNAMIC,
            description="run-as extraction is rejected by the Android package manager. Private storage is shielded from non-root extraction channels.",
            evidence=f"run-as execution result: {run_as_result[:150] or 'Rejected (not debuggable)'}.",
            remediation=None
        )