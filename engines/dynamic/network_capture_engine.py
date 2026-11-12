"""Interpret metadata-only mitmproxy flow exports without retaining secrets."""
import json
import os
import re
from typing import Dict, List, Optional

from core.models import AnalysisType, CheckStatus, Confidence, Finding, Severity


HOST_PATTERN = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9.-]+$")


class NetworkCaptureEngine:
    def __init__(self, flow_path: str, device_id: Optional[str] = None, max_bytes: int = 10_000_000):
        self.flow_path = flow_path
        self.device_id = device_id
        self.max_bytes = max_bytes

    def audit(self) -> List[Finding]:
        try:
            if os.path.getsize(self.flow_path) > self.max_bytes:
                raise ValueError(f"Flow export exceeds {self.max_bytes} bytes")
            records = []
            with open(self.flow_path, "r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, 1):
                    if line_number > 100000:
                        raise ValueError("Flow export exceeds 100,000 records")
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        continue
                    scheme, host = str(row.get("scheme", "")).lower(), str(row.get("host", "")).lower()
                    if scheme not in {"http", "https"} or not HOST_PATTERN.fullmatch(host):
                        continue
                    records.append({
                        "scheme": scheme,
                        "host": host,
                        "status": row.get("status_code"),
                        "tls_version": row.get("tls_version"),
                        "proxy_response_observed": bool(row.get("proxy_response_observed")),
                    })
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return [Finding(
                check_id="TIR-NETWORK-CAPTURE",
                title="Network capture needs review",
                category="MASVS-NETWORK",
                tab_index=5,
                severity=Severity.INFO,
                status=CheckStatus.NEEDS_REVIEW,
                analysis_type=AnalysisType.DYNAMIC,
                confidence=Confidence.LOW,
                confidence_score=0.2,
                description="TIR could not parse the optional metadata-only mitmproxy export.",
                evidence=str(exc)[:300],
                remediation="Export JSONL using scripts/dynamic/mitm_export.py and rerun the dynamic scan.",
                coverage={"device": self.device_id, "flow_file": os.path.basename(self.flow_path)},
            )]

        if not records:
            return [Finding(
                check_id="TIR-NETWORK-CAPTURE",
                title="No network flows observed",
                category="MASVS-NETWORK",
                tab_index=5,
                severity=Severity.INFO,
                status=CheckStatus.NEEDS_REVIEW,
                analysis_type=AnalysisType.DYNAMIC,
                confidence=Confidence.LOW,
                confidence_score=0.2,
                description="No valid request/response records were present. This does not establish that the app made no network requests.",
                evidence="Capture may not have been active during app use, or traffic may not have traversed the configured proxy.",
                remediation="Repeat a controlled workflow while the test device is configured to use the analyst-managed proxy.",
                coverage={"device": self.device_id, "flow_count": 0},
            )]

        cleartext: Dict[str, int] = {}
        proxied_tls: Dict[str, int] = {}
        for row in records:
            if row["scheme"] == "http":
                cleartext[row["host"]] = cleartext.get(row["host"], 0) + 1
            elif row["proxy_response_observed"]:
                proxied_tls[row["host"]] = proxied_tls.get(row["host"], 0) + 1

        findings = []
        if cleartext:
            findings.append(Finding(
                check_id="TIR-NETWORK-CLEARTEXT",
                title="Cleartext HTTP traffic observed in proxy capture",
                category="MASVS-NETWORK",
                tab_index=5,
                severity=Severity.HIGH,
                status=CheckStatus.NEEDS_REVIEW,
                analysis_type=AnalysisType.DYNAMIC,
                confidence=Confidence.MEDIUM,
                confidence_score=0.65,
                description="HTTP requests were present in the capture. Confirm they belong to the target app and assess whether the payload contains sensitive data.",
                evidence="\n".join(f"http://{host} ({count} response(s))" for host, count in sorted(cleartext.items())),
                remediation="Use HTTPS for sensitive traffic and disable cleartext traffic unless a documented endpoint requires it.",
                coverage={"device": self.device_id, "flow_count": len(records)},
            ))
        if proxied_tls:
            findings.append(Finding(
                check_id="TIR-NETWORK-INTERCEPTED-TLS",
                title="HTTPS responses observed through configured proxy",
                category="MASVS-NETWORK",
                tab_index=5,
                severity=Severity.INFO,
                status=CheckStatus.NEEDS_REVIEW,
                analysis_type=AnalysisType.DYNAMIC,
                confidence=Confidence.LOW,
                confidence_score=0.4,
                description="The proxy returned HTTPS responses for these hosts. This shows the captured connection accepted the test proxy certificate; confirm app attribution and compare with the app's pinning policy.",
                evidence="\n".join(f"https://{host} ({count} response(s))" for host, count in sorted(proxied_tls.items())),
                remediation="If the app is expected to pin certificates, verify that proxy interception fails for the relevant endpoints on a controlled test device.",
                coverage={"device": self.device_id, "flow_count": len(records)},
            ))
        return findings
