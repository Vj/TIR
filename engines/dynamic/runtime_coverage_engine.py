"""Opt-in bounded UI exploration and metadata-only app sandbox diffing."""
import hashlib
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from core.models import AnalysisType, CheckStatus, Confidence, Finding, Severity


PACKAGE_PATTERN = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
BOUNDS_PATTERN = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")
DO_NOT_TAP = ("delete", "remove", "purchase", "pay", "submit", "send", "transfer",
              "buy", "order", "revoke", "share", "upload", "logout", "confirm")


class RuntimeCoverageEngine:
    """Explore safe, labeled UI controls with strict action/time bounds."""

    def __init__(self, package_name: str, device_id: Optional[str] = None,
                 adb_path: str = "adb", timeout: int = 15):
        if not PACKAGE_PATTERN.fullmatch(package_name):
            raise ValueError("Invalid Android package name")
        self.package_name = package_name
        self.device_id = device_id
        self.adb_path = adb_path
        self.timeout = timeout

    def _adb(self, args: List[str], timeout: Optional[int] = None) -> str:
        command = [self.adb_path]
        if self.device_id:
            command.extend(["-s", self.device_id])
        command.extend(["shell"] + args)
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", errors="replace",
                                timeout=timeout or self.timeout, check=False)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout or "ADB command failed")[:300])
        return result.stdout.strip()

    def _snapshot(self) -> Dict[str, str]:
        # run-as is available only for debuggable/test builds; never read file content.
        output = self._adb([
            "run-as", self.package_name, "sh", "-c",
            "find files shared_prefs databases cache no_backup -type f -exec sha256sum {} \\; 2>/dev/null"
        ])
        rows = {}
        for line in output.splitlines():
            match = re.match(r"^([0-9a-fA-F]{64})\s+(.+)$", line.strip())
            if match:
                rows[match.group(2)] = match.group(1).lower()
        return rows

    @staticmethod
    def _ui_controls(xml_text: str) -> Tuple[str, List[Tuple[int, int]]]:
        root = ET.fromstring(xml_text)
        digest = hashlib.sha256(xml_text.encode("utf-8", errors="replace")).hexdigest()
        controls = []
        for node in root.iter("node"):
            if node.attrib.get("clickable") != "true":
                continue
            label = " ".join((node.attrib.get("text", "") + " " +
                              node.attrib.get("content-desc", "")).lower().split())
            if not label or any(word in label for word in DO_NOT_TAP):
                continue
            bounds = BOUNDS_PATTERN.fullmatch(node.attrib.get("bounds", ""))
            if not bounds:
                continue
            x1, y1, x2, y2 = map(int, bounds.groups())
            controls.append(((x1 + x2) // 2, (y1 + y2) // 2))
        return digest, controls

    def explore(self, max_actions: int = 12) -> List[Finding]:
        if not 1 <= max_actions <= 40:
            raise ValueError("max_actions must be between 1 and 40")
        findings: List[Finding] = []
        before = after = {}
        states, tapped = set(), set()
        actions = 0
        coverage_error = None

        try:
            before = self._snapshot()
        except Exception as exc:
            coverage_error = f"Pre-exploration app sandbox snapshot unavailable: {exc}"

        try:
            self._adb(["monkey", "-p", self.package_name, "1"])
            time.sleep(1)
            while actions < max_actions:
                remote = "/data/local/tmp/tir_ui_state.xml"
                self._adb(["uiautomator", "dump", remote])
                xml_text = self._adb(["cat", remote])
                self._adb(["rm", "-f", remote])
                state_id, controls = self._ui_controls(xml_text)
                states.add(state_id)
                candidate = next((point for point in controls
                                  if (state_id, point) not in tapped), None)
                if candidate is None:
                    break
                tapped.add((state_id, candidate))
                self._adb(["input", "tap", str(candidate[0]), str(candidate[1])])
                actions += 1
                time.sleep(0.4)
            try:
                after = self._snapshot()
            except Exception as exc:
                coverage_error = (coverage_error + "; " if coverage_error else "") + f"Post-exploration snapshot unavailable: {exc}"
        except Exception as exc:
            coverage_error = (coverage_error + "; " if coverage_error else "") + f"UI exploration stopped: {exc}"

        changed = []
        for path in sorted(set(before) | set(after)):
            old, new = before.get(path), after.get(path)
            if old != new:
                changed.append(f"{path}: {'created' if old is None else 'deleted' if new is None else 'modified'}")
        coverage = {"ui_states": len(states), "actions": actions, "max_actions": max_actions,
                    "device": self.device_id, "app_sandbox_files_before": len(before),
                    "app_sandbox_files_after": len(after)}

        findings.append(Finding(
            check_id="TIR-UI-COVERAGE",
            title="Bounded UI exploration coverage",
            category="Dynamic Runtime Analysis",
            tab_index=8,
            severity=Severity.INFO,
            status=CheckStatus.NEEDS_REVIEW if coverage_error else CheckStatus.PASS,
            analysis_type=AnalysisType.DYNAMIC,
            confidence=Confidence.MEDIUM if states else Confidence.LOW,
            description="TIR explored labeled, non-destructive UI controls without submitting forms or entering data.",
            evidence=f"Distinct UI states: {len(states)}; taps: {actions}/{max_actions}." +
                     (f"\nCoverage limitation: {coverage_error}" if coverage_error else ""),
            remediation="Review unexplored authenticated or deep-link flows manually; provide a test account and explicit workflow when needed.",
            coverage=coverage,
        ))
        findings.append(Finding(
            check_id="TIR-RUNTIME-FILESYSTEM",
            title="Runtime app sandbox file changes",
            category="MASVS-STORAGE",
            tab_index=2,
            severity=Severity.INFO,
            status=CheckStatus.NEEDS_REVIEW if coverage_error or not before and not after else CheckStatus.PASS,
            analysis_type=AnalysisType.DYNAMIC,
            confidence=Confidence.MEDIUM if before or after else Confidence.LOW,
            description="File names and SHA-256 digests were compared before and after UI exploration; file contents are not collected.",
            evidence="\n".join(changed[:100]) if changed else "No file changes detected in accessible app-private directories.",
            remediation="Inspect changed artifacts for sensitive plaintext. A file change alone does not establish a storage weakness.",
            coverage={**coverage, "changed_file_count": len(changed)},
        ))
        return findings
