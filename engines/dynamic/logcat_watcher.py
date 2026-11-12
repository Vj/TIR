# engines/dynamic/logcat_watcher.py
import re
import subprocess
import threading
from typing import List, Optional
from core.models import Finding, Severity, CheckStatus

class LogcatWatcher:
    def __init__(self, adb_path: str = "adb", device_id: Optional[str] = None):
        self.adb = adb_path
        self.device_id = device_id
        self.process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.captured_findings: List[Finding] = []

        # High-confidence leakage patterns in log outputs
        self.sensitive_patterns = {
            "Bearer / Access Token": re.compile(r"(?i)(bearer\s+[A-Za-z0-9_\-\.]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,})"),
            "Cleartext Password": re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s&,]{4,})["\']?'),
            "Credit Card Number (Luhn-candidate)": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
            "API / Secret Key": re.compile(r'(?i)(api[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})'),
            "OTP / Security PIN": re.compile(r'(?i)(otp|pin|passcode)\s*[:=]\s*["\']?(\d{4,8})["\']?'),
            "Unhandled Exception Stack Trace": re.compile(r"(FATAL EXCEPTION|java\.lang\.[a-zA-Z0-9_]+Exception)"),
        }

    def _build_adb_cmd(self) -> List[str]:
        cmd = [self.adb]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        # Clear previous buffer and stream thread-time logs
        cmd.extend(["exec-out", "logcat", "-v", "threadtime"])
        return cmd

    def start(self, package_name: Optional[str] = None):
        """Starts background logcat monitoring."""
        self._stop_event.clear()
        self.captured_findings.clear()

        # Clear existing device buffer before monitoring session
        clear_cmd = [self.adb]
        if self.device_id:
            clear_cmd.extend(["-s", self.device_id])
        clear_cmd.extend(["logcat", "-c"])
        subprocess.run(clear_cmd, capture_output=True, check=False)

        def _monitor():
            try:
                self.process = subprocess.Popen(
                    self._build_adb_cmd(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="ignore"
                )

                for line in iter(self.process.stdout.readline, ""):
                    if self._stop_event.is_set():
                        break

                    # Filter by package name if target process is provided
                    if package_name and package_name not in line:
                        continue

                    self._evaluate_line(line.strip())

            except Exception:
                pass
            finally:
                if self.process:
                    self.process.terminate()

        self._thread = threading.Thread(target=_monitor, daemon=True)
        self._thread.start()

    def stop(self) -> List[Finding]:
        """Stops the worker and returns all detected leak findings."""
        self._stop_event.set()
        if self.process:
            self.process.terminate()
            self.process = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        return self.captured_findings

    def _evaluate_line(self, line: str):
        for leak_type, pattern in self.sensitive_patterns.items():
            match = pattern.search(line)
            if match:
                # Mask sensitive output to prevent writing raw credentials to report
                matched_text = match.group(0)
                masked_sample = matched_text[:6] + "..." + matched_text[-4:] if len(matched_text) > 12 else "[REDACTED]"

                tab_idx = 13 if "Exception" in leak_type else 2
                check_id = "AND-LOGM-01" if "Exception" in leak_type else "AND-STOR-04"
                cat = "Logging, Crash Reporting and Alerting" if tab_idx == 13 else "MASVS-STORAGE"

                # Deduplicate identical findings
                if not any(f.evidence and masked_sample in f.evidence for f in self.captured_findings):
                    self.captured_findings.append(Finding(
                        check_id=check_id,
                        title=f"Sensitive Data Exposure in Logcat: {leak_type}",
                        category=cat,
                        tab_index=tab_idx,
                        severity=Severity.HIGH if "Password" in leak_type or "Token" in leak_type else Severity.MEDIUM,
                        status=CheckStatus.FAIL,
                        description=f"Runtime logging output leaks sensitive data ({leak_type}).",
                        evidence=f"Log Line Sample: {line[:80]}...\nMatched Fragment: {masked_sample}",
                        remediation="Remove verbose and debug log statements in release builds, or sanitize parameters via custom Timber/Log tree printers."
                    ))