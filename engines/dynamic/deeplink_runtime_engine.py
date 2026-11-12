"""Trigger explicitly supplied, manifest-seeded deep links on the test device."""
import re
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
        if not SAFE_URI.fullmatch(uri) or any(c in uri for c in ('"', "\\", "`", "\n", "\r")):
            return self._finding(uri, False, "URI contains unsupported characters and was not sent to ADB.")
        parsed = urlsplit(uri)
        scheme, host = parsed.scheme.lower(), (parsed.hostname or "").lower()
        allowed = any(
            target.get("scheme", "").lower() == scheme
            and (not target.get("hosts") or host in [item.lower() for item in target.get("hosts", [])])
            and target.get("exported") is True
            for target in targets
        )
        if not allowed:
            return self._finding(uri, False, "URI scheme/host is not present in the exported static target allow-list.")

        command = [self.adb_path]
        if self.device_id:
            command.extend(["-s", self.device_id])
        command.extend(["shell", "am", "start", "-a", "android.intent.action.VIEW",
                        "-d", uri, "-p", self.package_name])
        try:
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=15, check=False)
            output = (result.stdout or result.stderr or "").strip()
            sent = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired) as exc:
            output, sent = str(exc), False
        # Retain only scheme/host in evidence; query and path may contain secrets.
        safe_target = f"{scheme}://{host}" if host else scheme + ":"
        return self._finding(safe_target, sent, output[:300] or "ADB returned no output.")

    @staticmethod
    def _finding(target: str, sent: bool, detail: str) -> Finding:
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
            evidence=f"Target: {target}\nInvocation sent: {sent}\nADB result: {detail}",
            remediation="Verify handler validation, caller assumptions, and downstream use of URI data.",
            coverage={"probe": "analyst-supplied manifest-seeded URI"},
        )
