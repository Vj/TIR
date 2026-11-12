# engines/static/rules/deeplink_analyzer.py
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Set
from core.models import Finding, Severity, CheckStatus

class DeepLinkSecurityAnalyzer:
    """Audits manifest scheme definitions and traces intent parameter consumption into dangerous sinks."""

    @classmethod
    def audit_manifest_and_bytecode(cls, manifest_xml: str, dex_files_content: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        handled_activities: Set[str] = set()

        # Step 1: Extract deep link entry activities from AndroidManifest.xml
        try:
            root = ET.fromstring(manifest_xml)
            for activity in root.findall(".//activity"):
                act_name = activity.attrib.get("{http://schemas.android.com/apk/res/android}name", "")
                for intent_filter in activity.findall("intent-filter"):
                    for data in intent_filter.findall("data"):
                        scheme = data.attrib.get("{http://schemas.android.com/apk/res/android}scheme", "")
                        host = data.attrib.get("{http://schemas.android.com/apk/res/android}host", "")

                        if scheme:
                            clean_act = act_name.split(".")[-1]
                            handled_activities.add(clean_act)

                            # Identify wildcard or overly broad scheme filters
                            if host == "*" or not host:
                                findings.append(Finding(
                                    check_id="STA-025",
                                    title=f"Wildcard / Unrestricted Deep-Link Host: {scheme}://",
                                    category="MASVS-PLATFORM",
                                    tab_index=6,
                                    severity=Severity.MEDIUM,
                                    status=CheckStatus.FAIL,
                                    description=(
                                        f"Activity '{act_name}' registers scheme '{scheme}://' without restricting target hosts. "
                                        "Any arbitrary host passed via this scheme will route to this activity."
                                    ),
                                    evidence=f"Manifest declaration: <data android:scheme=\"{scheme}\" /> (Host is missing or wildcard)",
                                    remediation="Explicitly declare target hosts using <data android:host=\"app.example.com\" />."
                                ))
        except Exception:
            pass

        # Step 2: Bytecode Sink Trace
        # Verify if intent parameters flow into WebView or File operations
        for dex_name, dex_data in dex_files_content.items():
            # Check for Intent.getData() -> getQueryParameter() -> loadUrl()
            if "getQueryParameter" in dex_data and "loadUrl" in dex_data:
                # Heuristic: Check if class handles intent data and forwards to WebView
                if re.search(r"getQueryParameter\(.*?\).*?loadUrl\(", dex_data, re.DOTALL):
                    findings.append(Finding(
                        check_id="STA-025",
                        title="Deep-Link Parameter Fed Directly into WebView (Open Redirect / XSS)",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description=(
                            "The application retrieves URL parameters from incoming deep-link intents "
                            "and loads them directly into a WebView without domain whitelisting."
                        ),
                        evidence=f"Identified in {dex_name}: Intent query parameters flow toward loadUrl() sink.",
                        remediation="Strictly validate that retrieved URLs belong to authorized internal domains (HTTPS scheme and exact host match)."
                    ))

            # Check for Intent.parseUri(..., URI_INTENT_SCHEME) without safety flags
            if "parseUri" in dex_data:
                if "CATEGORY_BROWSABLE" not in dex_data:
                    findings.append(Finding(
                        check_id="STA-025",
                        title="Unsafe Intent.parseUri() Construction (Intent Redirection Risk)",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description=(
                            "Intent.parseUri is used to instantiate intents from string URIs. If not sanitized with "
                            "Intent.URI_ANDROID_APP_SCHEME and stripped of selector intents, this enables arbitrary component launches."
                        ),
                        evidence=f"Call to Intent.parseUri detected in {dex_name}.",
                        remediation="Filter out internal component selectors and enforce Intent.CATEGORY_BROWSABLE before invoking startActivity()."
                    ))

        return findings