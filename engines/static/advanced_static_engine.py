# engines/static/advanced_static_engine.py
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

from core.models import Finding, Severity, CheckStatus
from engines.static.rules.sqli_heuristic import SQLiHeuristicAnalyzer
from engines.static.rules.deeplink_analyzer import DeepLinkSecurityAnalyzer
from engines.static.rules.sdk_analyzer import SDKVulnerabilityAnalyzer
from engines.static.rules.batch1_static_engine import Batch1StaticEngine


class AdvancedStaticEngine:
    def __init__(self, apk_path: str, manifest_xml: str, declared_permissions: List[str] = None):
        self.apk_path = apk_path
        self.manifest_xml = manifest_xml
        self.declared_permissions = declared_permissions or []

    def execute_all_additional_static(self) -> List[Finding]:
        """
        Executes all refined static rules (STA-021 through STA-035).
        Preloads DEX bytecode into memory once for all analyzers.
        """
        findings: List[Finding] = []

        # 1. Load all classes*.dex files once
        dex_files_data: Dict[str, str] = {}
        with zipfile.ZipFile(self.apk_path, "r") as z:
            for fname in z.namelist():
                if fname.startswith("classes") and fname.endswith(".dex"):
                    dex_files_data[fname] = z.read(fname).decode("latin-1", errors="ignore")

        combined_dex = "".join(dex_files_data.values())

        # 2. Refined SQL Injection Heuristics (STA-033)
        for dex_name, dex_content in dex_files_data.items():
            findings.extend(SQLiHeuristicAnalyzer.analyze_dex_code(dex_name, dex_content))
        findings.extend(DeepLinkSecurityAnalyzer.audit_manifest_and_bytecode(self.manifest_xml, dex_files_data))
        findings.extend(SDKVulnerabilityAnalyzer.audit_sdks(combined_dex))

        # 3. Batch 1 Static Engine (STA-021, STA-022, STA-024, STA-029, STA-030, STA-031, STA-035)
        batch1 = Batch1StaticEngine(self.apk_path, self.manifest_xml, self.declared_permissions)
        findings.extend(batch1.audit_all(dex_files_data, combined_dex))

        # 3. Refined Deep-Link Scheme & Sink Analysis (STA-025)
        findings.extend(
            DeepLinkSecurityAnalyzer.audit_manifest_and_bytecode(
                self.manifest_xml, dex_files_data
            )
        )

        # 4. Third-Party SDK & Supply-Chain Signatures (STA-032)
        findings.extend(SDKVulnerabilityAnalyzer.audit_sdks(combined_dex))

        # 5. Standard in-engine checks (STA-023, STA-026, STA-034)
        findings.extend(self._check_sta_023_weak_random(dex_files_data))
        findings.extend(self._check_sta_026_cert_validation(dex_files_data))
        findings.extend(self._check_sta_034_sensitive_resources())

        return findings

    def _check_sta_023_weak_random(self, dex_files_data: Dict[str, str]) -> List[Finding]:
        """STA-023: Weak PRNG Usage (java.util.Random vs SecureRandom)."""
        findings: List[Finding] = []
        for dex_name, data in dex_files_data.items():
            if "Ljava/util/Random;" in data and any(
                k in data for k in ["token", "key", "iv", "nonce", "salt"]
            ):
                findings.append(Finding(
                    check_id="STA-023",
                    title="Potentially Predictable Pseudo-Random Number Generator",
                    category="MASVS-CRYPTO",
                    tab_index=3,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    description=(
                        "java.util.Random was detected in proximity to security-critical tokens or keys. "
                        "This PRNG is non-cryptographic, linear congruential, and predictable."
                    ),
                    evidence=f"Invocation Ljava/util/Random; in {dex_name}",
                    remediation="Replace all security and cryptographic randomization calls with java.security.SecureRandom."
                ))
        return findings

    def _check_sta_026_cert_validation(self, dex_files_data: Dict[str, str]) -> List[Finding]:
        """STA-026: Insecure X509TrustManager or HostnameVerifier overrides."""
        findings: List[Finding] = []
        for dex_name, data in dex_files_data.items():
            if "ALLOW_ALL_HOSTNAME_VERIFIER" in data or "NullHostnameVerifier" in data:
                findings.append(Finding(
                    check_id="STA-026",
                    title="Insecure HostnameVerifier Detected (Allow All)",
                    category="MASVS-NETWORK",
                    tab_index=5,
                    severity=Severity.CRITICAL,
                    status=CheckStatus.FAIL,
                    description="The application uses an overly permissive HostnameVerifier, disabling host identity checks on TLS certificates.",
                    evidence=f"Flagged HostnameVerifier pattern in {dex_name}",
                    remediation="Enforce standard HostnameVerifier matching against the validated certificate SAN/CN."
                ))
        return findings

    def _check_sta_034_sensitive_resources(self) -> List[Finding]:
        """STA-034: Cleartext secrets in strings.xml and res/values."""
        findings: List[Finding] = []
        patterns = {
            "Google API / Client Key": r"AIza[0-9A-Za-z-_]{35}",
            "Generic Password/Secret Field": r'(?i)<string name="[^"]*(password|secret|apikey|token)[^"]*">([^<]+)</string>'
        }
        with zipfile.ZipFile(self.apk_path, "r") as z:
            for xml_file in [f for f in z.namelist() if f.startswith("res/values") and f.endswith(".xml")]:
                try:
                    content = z.read(xml_file).decode("utf-8", errors="ignore")
                except Exception:
                    continue

                for name, pat in patterns.items():
                    matches = re.findall(pat, content)
                    if matches:
                        findings.append(Finding(
                            check_id="STA-034",
                            title=f"Sensitive Value Embedded in Resources: {name}",
                            category="MASVS-STORAGE",
                            tab_index=2,
                            severity=Severity.MEDIUM,
                            status=CheckStatus.NEEDS_REVIEW,
                            description=f"Resource file '{xml_file}' contains strings indicative of embedded credentials.",
                            evidence=f"File: {xml_file}\nMatched key types: {name}",
                            remediation="Move secrets out of resource strings; retrieve them dynamically from backend services or inject them securely at runtime."
                        ))
        return findings