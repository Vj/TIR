# engines/static/rules/sdk_analyzer.py
import re
from typing import List, Dict, Any
from core.models import Finding, Severity, CheckStatus

class SDKVulnerabilityAnalyzer:
    """Detects known vulnerable, deprecated, or high-risk third-party libraries and frameworks."""

    # Curated registry of problematic SDK namespaces and historical risks
    KNOWN_SDK_RISKS = [
        {
            "id": "SDK-CORDOVA",
            "name": "Apache Cordova (Legacy)",
            "signature": "Lorg/apache/cordova/CordovaActivity;",
            "severity": Severity.MEDIUM,
            "description": "Legacy Apache Cordova framework detected. Older embedded Cordova webviews are prone to cross-origin bridge bypasses.",
            "remediation": "Migrate hybrid web components to modern Capacitor or ensure Cordova Android engine is updated to version 10.x+."
        },
        {
            "id": "SDK-LEGACY-HTTP",
            "name": "Apache HttpClient (org.apache.http)",
            "signature": "Lorg/apache/http/client/HttpClient;",
            "severity": Severity.MEDIUM,
            "description": "Deprecated Apache HTTP client detected. Deprecated since Android 6.0 and unmaintained; lacks modern TLS 1.3 cipher suite negotiation.",
            "remediation": "Migrate network communications to OkHttp 4.x or standard HttpURLConnection."
        },
        {
            "id": "SDK-DEBUG-STETHO",
            "name": "Facebook Stetho Debugging Bridge",
            "signature": "Lcom/facebook/stetho/Stetho;",
            "severity": Severity.HIGH,
            "description": "Stetho debugging tool is bundled in the build. It exposes Chrome DevTools inspection hooks for SQLite, network, and view hierarchies.",
            "remediation": "Ensure Stetho is strictly linked via debugImplementation in build.gradle and omitted from release APKs."
        },
        {
            "id": "SDK-LEAKCANARY",
            "name": "Square LeakCanary (In Release)",
            "signature": "Lleakcanary/LeakCanary;",
            "severity": Severity.MEDIUM,
            "description": "LeakCanary memory analysis tool detected in compiled application. Retains memory dump services that leak state.",
            "remediation": "Ensure LeakCanary is declared under debugImplementation in build.gradle."
        },
        {
            "id": "SDK-OLD-OKHTTP",
            "name": "OkHttp 2.x / Deprecated TLS Defaults",
            "signature": "Lcom/squareup/okhttp/OkHttpClient;",
            "severity": Severity.MEDIUM,
            "description": "Legacy OkHttp 2.x namespace detected (com.squareup.okhttp instead of okhttp3). Prone to connection fallback weaknesses.",
            "remediation": "Upgrade dependency to modern com.squareup.okhttp3:okhttp:4.x."
        }
    ]

    @classmethod
    def audit_sdks(cls, dex_content_combined: str) -> List[Finding]:
        findings: List[Finding] = []

        for sdk in cls.KNOWN_SDK_RISKS:
            if sdk["signature"] in dex_content_combined:
                findings.append(Finding(
                    check_id="STA-032",
                    title=f"Third-Party SDK Risk: {sdk['name']}",
                    category="Supply Chain & Third-Party SDKs",
                    tab_index=12,
                    severity=sdk["severity"],
                    status=CheckStatus.FAIL if sdk["severity"] == Severity.HIGH else CheckStatus.NEEDS_REVIEW,
                    description=sdk["description"],
                    evidence=f"Matched namespace signature: {sdk['signature']}",
                    remediation=sdk["remediation"]
                ))

        return findings