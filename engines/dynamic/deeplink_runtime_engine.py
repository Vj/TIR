"""Trigger explicitly supplied, manifest-seeded deep links on the test device."""
import re
import shlex
import subprocess
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from core.models import AnalysisType, CheckStatus, Confidence, Finding, Severity


SAFE_URI = re.compile(r"^[A-Za-z0-9:/?#[\]@!$&'()*+,;=._%~-]{1,2048}$")


class DeepLinkRuntimeEngine:
    def __init__(self, package_name: str, device_id: Optional[str] = None, adb_path: str = "adb"):
        self.package_name = package_name
        self.device_id = device_id
        self.adb_path = adb_path

    def invoke(self, uri: str, targets: List[Dict[str, Any]]) -> Finding:
        if not isinstance(uri, str) or not SAFE_URI.fullmatch(uri) or any(ch in uri for ch in ('"', "\\", "`", "\n", "\r")):
            return self._finding(uri, False, "URI contains unsupported characters and was not sent to ADB.")
        parsed = urlsplit(uri)
        scheme, host = parsed.scheme.lower(), (parsed.hostname or "").lower()
        allowed = False
        for target in targets if isinstance(targets, list) else []:
            if not isinstance(target, dict) or target.get("exported") is not True:
                continue
            declared_scheme = target.get("scheme")
            declared_hosts = target.get("hosts", [])
            if not isinstance(declared_scheme, str) or not isinstance(declared_hosts, list):
                continue
            safe_hosts = [item.lower() for item in declared_hosts if isinstance(item, str)]
            if declared_scheme.lower() == scheme and (not safe_hosts or host in safe_hosts):
                allowed = True
                break
        if not allowed:
            return self._finding(uri, False, "URI scheme/host is not present in the exported static target allow-list.")

        command = [self.adb_path]
        if self.device_id:
            command.extend(["-s", self.device_id])
        command.extend(["shell", f"am start -a android.intent.action.VIEW -d {shlex.quote(uri)} -p {shlex.quote(self.package_name)}"])
        try:
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=15, check=False)
            sent = result.returncode == 0
            output = f"ADB exit code: {result.returncode}; " + ("launch accepted" if sent else "launch rejected")
        except (OSError, subprocess.TimeoutExpired):
            output, sent = "ADB invocation failed or timed out.", False
        return self._finding(uri, sent, output)

    @staticmethod
    def _finding(target: str, sent: bool, detail: str) -> Finding:
        try:
            parsed = urlsplit(target)
            safe_target = f"{parsed.scheme}://{parsed.hostname}" if parsed.hostname else f"{parsed.scheme}:"
        except ValueError:
            safe_target = "[invalid URI]"
        return Finding(
            check_id="TIR-DEEPLINK-RUNTIME",
            title="Manifest-seeded deep-link invocation",
            category="MASVS-PLATFORM",
            tab_index=6,
            severity=Severity.INFO,
            status=CheckStatus.NEEDS_REVIEW,
            analysis_type=AnalysisType.DYNAMIC,
            confidence=Confidence.LOW,
            confidence_score=0.35,
            description="TIR attempted an analyst-supplied URI only when its scheme and host matched an explicitly exported static target. Invocation success alone does not prove an input-validation weakness.",
            evidence=f"Target: {safe_target}\nInvocation sent: {sent}\nADB result: {detail}",
            remediation="Verify handler validation, caller assumptions, and downstream use of URI data.",
            coverage={"probe": "analyst-supplied manifest-seeded URI"},
        )
