"""Run bundled, read-only Android shell checks through ADB."""

from pathlib import Path
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from core.models import CheckStatus, Finding, Severity


class ShellTestEngine:
    """Execute allow-listed shell scripts and translate their output into findings."""

    PACKAGE_PATTERN = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
    SCRIPT_DIR = Path(__file__).resolve().parents[2] / "scripts" / "dynamic"
    CHECKS = {
        "process_integrity.sh": "DYN-SHELL-001",
        "debuggable_state.sh": "DYN-SHELL-002",
    }

    def __init__(
        self,
        package_name: str,
        device_id: Optional[str] = None,
        adb_path: str = "adb",
        timeout: int = 15,
    ):
        self.package_name = package_name
        self.device_id = device_id
        self.adb_path = adb_path
        self.timeout = timeout

    def _run_script(self, filename: str) -> Tuple[Dict[str, str], Optional[str]]:
        if not self.PACKAGE_PATTERN.fullmatch(self.package_name):
            return {}, "Package name must be a fully qualified Android identifier."

        # Script names come only from CHECKS; arbitrary shell input is never accepted.
        if filename not in self.CHECKS:
            return {}, "Unknown shell check."

        script_path = self.SCRIPT_DIR / filename
        try:
            script = script_path.read_text(encoding="utf-8")
        except OSError as exc:
            return {}, f"Could not load bundled script: {exc}"

        command = [self.adb_path]
        if self.device_id:
            command.extend(["-s", self.device_id])
        command.extend(["shell", "sh", "-s", "--", self.package_name])

        try:
            result = subprocess.run(
                command,
                input=script,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {}, f"ADB shell check could not complete: {exc}"

        values = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()

        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
            return values, detail[:500]
        if "ERROR" in values:
            return values, values["ERROR"]
        return values, None

    def audit_all(self) -> List[Finding]:
        findings: List[Finding] = []
        for filename, check_id in self.CHECKS.items():
            values, error = self._run_script(filename)
            if error:
                findings.append(Finding(
                    check_id=check_id,
                    title=f"Runtime shell check needs review: {filename.removesuffix('.sh')}",
                    category="Dynamic Runtime Analysis",
                    tab_index=8,
                    severity=Severity.INFO,
                    status=CheckStatus.NEEDS_REVIEW,
                    description="The read-only device shell check could not establish a reliable result.",
                    evidence=error,
                    remediation="Confirm the package is installed and running, the selected ADB device is authorized, and Android shell access is available.",
                ))
                continue

            state = values.get("STATE", "")
            if state == "NOT_RUNNING":
                findings.append(Finding(
                    check_id=check_id,
                    title=f"Runtime shell check skipped: {filename.removesuffix('.sh')}",
                    category="Dynamic Runtime Analysis",
                    tab_index=8,
                    severity=Severity.INFO,
                    status=CheckStatus.NEEDS_REVIEW,
                    description="The target application was not running when the check executed.",
                    evidence="Start the target app, then repeat the dynamic audit to collect process-level evidence.",
                    remediation=None,
                ))
                continue

            if check_id == "DYN-SHELL-001":
                tracer_pid = values.get("TRACER_PID", "")
                if tracer_pid.isdigit() and int(tracer_pid) > 0:
                    findings.append(Finding(
                        check_id=check_id,
                        title="Target Process Is Being Traced",
                        category="MASVS-RESILIENCE",
                        tab_index=8,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description="The Android process status reports a non-zero TracerPid during the live audit.",
                        evidence=f"Package: {self.package_name}\nPID: {values.get('PID', 'unknown')}\nTracerPid: {tracer_pid}",
                        remediation="For production builds, detect unexpected debuggers where appropriate and investigate the attached tracing process.",
                    ))
                else:
                    findings.append(Finding(
                        check_id=check_id,
                        title="No Active Process Tracer Detected",
                        category="MASVS-RESILIENCE",
                        tab_index=8,
                        severity=Severity.INFO,
                        status=CheckStatus.PASS,
                        description="The running target process reports TracerPid 0.",
                        evidence=f"Package: {self.package_name}\nPID: {values.get('PID', 'unknown')}\nTracerPid: {tracer_pid or 'unavailable'}",
                        remediation=None,
                    ))

            elif check_id == "DYN-SHELL-002":
                debuggable = values.get("DEBUGGABLE", "UNKNOWN").upper()
                is_debuggable = debuggable in {"TRUE", "YES", "1"}
                findings.append(Finding(
                    check_id=check_id,
                    title="Runtime Package Debuggable Flag",
                    category="MASVS-CODE",
                    tab_index=7,
                    severity=Severity.HIGH if is_debuggable else Severity.INFO,
                    status=CheckStatus.FAIL if is_debuggable else CheckStatus.PASS,
                    description=(
                        "The installed package flags include DEBUGGABLE."
                        if is_debuggable
                        else "The installed package does not report the DEBUGGABLE flag."
                    ),
                    evidence=f"Package: {self.package_name}\nDEBUGGABLE={debuggable}",
                    remediation="Ensure release variants set android:debuggable to false." if is_debuggable else None,
                ))

        return findings
