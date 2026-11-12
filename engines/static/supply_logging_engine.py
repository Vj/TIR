import re
import zipfile
from typing import List, Dict, Set
from core.models import Finding, Severity, CheckStatus

class SupplyChainLoggingEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def audit_tab11_api(self) -> List[Finding]:
        findings = []
        url_regex = re.compile(r'https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&\'()*+,;=%]+')
        shadow_keywords = ["/debug/", "/internal/", "/test/", "/staging/"]
        
        extracted_urls: Set[str] = set()
        suspicious_endpoints: List[str] = []
        query_token_leaks: List[str] = []

        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]
            for dex in dex_files:
                text = z.read(dex).decode("latin-1", errors="ignore")
                matches = url_regex.findall(text)
                for u in matches:
                    extracted_urls.add(u)
                    if any(k in u.lower() for k in shadow_keywords):
                        suspicious_endpoints.append(u)
                    if re.search(r"[?&](token|access_token|auth|bearer)=", u, re.IGNORECASE):
                        query_token_leaks.append(u)

        if query_token_leaks:
            findings.append(Finding(
                check_id="AND-API-01",
                title="API Authentication Tokens in Query Strings",
                category="Backend API and Server-side Testing",
                tab_index=11,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description="Hardcoded endpoints or query parameters passing tokens directly in URLs.",
                evidence="\n".join(query_token_leaks[:5]),
                remediation="Pass authentication credentials using the Authorization: Bearer header."
            ))

        if suspicious_endpoints:
            findings.append(Finding(
                check_id="AND-API-05",
                title="Shadow or Debug Endpoints Exposed in Bytecode",
                category="Backend API and Server-side Testing",
                tab_index=11,
                severity=Severity.LOW,
                status=CheckStatus.NEEDS_REVIEW,
                description="Debug, test, or internal endpoints detected in production DEX code.",
                evidence="\n".join(suspicious_endpoints[:5]),
                remediation="Remove staging/internal API references before releasing production builds."
            ))

        return findings

    def audit_tab12_supply_chain(self) -> List[Finding]:
        findings = []
        known_sdks = {
            "okhttp3": "Square OkHttp",
            "retrofit2": "Square Retrofit",
            "com.google.gson": "Google Gson",
            "com.squareup.picasso": "Picasso",
            "com.bumptech.glide": "Glide",
            "io.reactivex": "RxJava",
            "com.amazonaws": "AWS Mobile SDK",
            "com.facebook.android": "Facebook SDK"
        }

        detected_sdks: Set[str] = set()

        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]
            for dex in dex_files:
                content = z.read(dex)
                for pkg, name in known_sdks.items():
                    if pkg.replace(".", "/").encode() in content:
                        detected_sdks.add(name)

        if detected_sdks:
            findings.append(Finding(
                check_id="AND-SCSI-01",
                title="Third-Party Library SBOM Inventory",
                category="Supply Chain and Third-party SDK Testing",
                tab_index=12,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                description=f"Identified {len(detected_sdks)} third-party libraries in the application bundle.",
                evidence="Bundled Components:\n" + "\n".join(f"- {s}" for s in sorted(detected_sdks))
            ))

        return findings

    def audit_tab13_logging(self) -> List[Finding]:
        findings = []
        debug_log_calls = 0

        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]
            for dex in dex_files:
                content = z.read(dex)
                debug_log_calls += content.count(b"Landroid/util/Log;->d(")
                debug_log_calls += content.count(b"Landroid/util/Log;->v(")

        if debug_log_calls > 0:
            findings.append(Finding(
                check_id="AND-LOGM-03",
                title=f"Verbose/Debug Logging Active in Release ({debug_log_calls} calls)",
                category="Logging, Crash Reporting and Alerting",
                tab_index=13,
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                description="Bytecode contains unstripped android.util.Log debug/verbose calls.",
                evidence=f"Detected {debug_log_calls} occurrences of Log.d or Log.v in DEX bytecode.",
                remediation="Configure ProGuard/R8 to strip logging calls in release builds (-assumenosideeffects class android.util.Log { ... })."
            ))
        else:
            findings.append(Finding(
                check_id="AND-LOGM-03",
                title="Debug Logging Stripped from Bytecode",
                category="Logging, Crash Reporting and Alerting",
                tab_index=13,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                description="No active Log.d or Log.v invocations detected.",
                evidence="Zero references found in DEX classes."
            ))

        return findings