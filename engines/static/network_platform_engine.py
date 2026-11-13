import re
import zipfile
import xml.etree.ElementTree as ET
from typing import List
from lxml import etree
from core.models import Finding, Severity, CheckStatus, Any

class NetworkPlatformEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def audit_tab05_network(self) -> List[Finding]:
        findings = []
        
        with zipfile.ZipFile(self.apk_path, "r") as z:
            # 1. Check network_security_config.xml
            config_files = [f for f in z.namelist() if "network_security_config" in f.lower() and f.endswith(".xml")]
            
            if not config_files:
                findings.append(Finding(
                    check_id="AND-NETW-01",
                    title="Missing Dedicated Network Security Configuration",
                    category="MASVS-NETWORK",
                    tab_index=5,
                    severity=Severity.LOW,
                    status=CheckStatus.NEEDS_REVIEW,
                    description="No network_security_config.xml found in APK. Default Android 9+ rules apply.",
                    evidence="No configuration file detected in resources.",
                    remediation="Explicitly declare res/xml/network_security_config.xml disabling cleartext."
                ))
            else:
                for cfg in config_files:
                    raw_xml = z.read(cfg).decode("latin-1", errors="ignore")
                    if 'cleartextTrafficPermitted="true"' in raw_xml:
                        findings.append(Finding(
                            check_id="AND-NETW-01",
                            title="Cleartext Traffic Permitted in Network Config",
                            category="MASVS-NETWORK",
                            tab_index=5,
                            severity=Severity.HIGH,
                            status=CheckStatus.FAIL,
                            description="Network security config explicitly permits cleartext HTTP traffic.",
                            evidence=f"Found in {cfg}",
                            remediation="Set cleartextTrafficPermitted='false' across all domain configs."
                        ))
                    
                    if "<pin-set" in raw_xml:
                        findings.append(Finding(
                            check_id="AND-NETW-03",
                            title="Certificate Pinning Declared in Network Security Config",
                            category="MASVS-NETWORK",
                            tab_index=5,
                            severity=Severity.INFO,
                            status=CheckStatus.PASS,
                            description="Application configures native pin-set for certificate pinning.",
                            evidence=f"Pin-set detected in {cfg}"
                        ))

            # 2. Insecure TrustManager / HostnameVerifier Bytecode Scan
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]
            empty_trust_manager = False
            for dex in dex_files:
                text = z.read(dex).decode("latin-1", errors="ignore")
                if "X509TrustManager" in text and "checkServerTrusted" in text:
                    # Generic heuristic for all-trusting managers
                    if "ALLOW_ALL_HOSTNAME_VERIFIER" in text or "TrustAllCerts" in text:
                        empty_trust_manager = True

            if empty_trust_manager:
                findings.append(Finding(
                    check_id="AND-NETW-02",
                    title="Insecure TrustManager / HostnameVerifier Implemented",
                    category="MASVS-NETWORK",
                    tab_index=5,
                    severity=Severity.CRITICAL,
                    status=CheckStatus.FAIL,
                    description="Custom implementation disables SSL/TLS certificate validation.",
                    evidence="References to TrustAllCerts or permissive HostnameVerifier found in DEX bytecode.",
                    remediation="Rely on standard system CA trust stores without implementing empty checkServerTrusted methods."
                ))

        return findings

    def audit_tab06_platform(self, manifest_input: Any) -> List[Finding]:
        findings = []

        # 1. WebView Security Checks in Bytecode
        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]
            for dex in dex_files:
                text = z.read(dex).decode("latin-1", errors="ignore")
                
                if "setJavaScriptEnabled" in text:
                    findings.append(Finding(
                        check_id="AND-PLAT-03",
                        title="WebView JavaScript Execution Enabled",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.LOW,
                        status=CheckStatus.NEEDS_REVIEW,
                        description="setJavaScriptEnabled(true) detected. Audit to ensure WebView loads trusted content only.",
                        evidence=f"Found in {dex}",
                        remediation="Disable JavaScript unless required, and enforce strict URL whitelisting."
                    ))

                if "addJavascriptInterface" in text:
                    findings.append(Finding(
                        check_id="AND-PLAT-03",
                        title="Native JavaScript Interface Exposed",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.MEDIUM,
                        status=CheckStatus.NEEDS_REVIEW,
                        description="addJavascriptInterface exposes native methods to JavaScript within WebViews.",
                        evidence=f"addJavascriptInterface call found in {dex}",
                        remediation="Ensure all exposed methods use @JavascriptInterface and validate calling origins."
                    ))

                if "setAllowUniversalAccessFromFileURLs" in text or "setAllowFileAccessFromFileURLs" in text:
                    findings.append(Finding(
                        check_id="AND-PLAT-03",
                        title="Insecure File Access Permitted in WebView",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description="File scheme access permissions enabled in WebView, allowing local file harvesting.",
                        evidence=f"Permissive file flags found in {dex}",
                        remediation="Disable setAllowFileAccess(false) and universal file access APIs."
                    ))

        # 2. Content Provider Inspection in Manifest
        if isinstance(manifest_input, str):
            root = ET.fromstring(manifest_input)
        elif hasattr(manifest_input, "tag"):
            raw = etree.tostring(manifest_input, encoding="utf-8")
            root = ET.fromstring(raw)
        else:
            root = None

        if root is not None:
            application = root.find("application")
            if application is not None:
                for provider in application.findall("provider"):
                    name = provider.attrib.get("{http://schemas.android.com/apk/res/android}name", "UnknownProvider")
                    exported = provider.attrib.get("{http://schemas.android.com/apk/res/android}exported", "false").lower() == "true"
                    read_perm = provider.attrib.get("{http://schemas.android.com/apk/res/android}readPermission")
                    write_perm = provider.attrib.get("{http://schemas.android.com/apk/res/android}writePermission")

                    if exported and not (read_perm or write_perm):
                        findings.append(Finding(
                            check_id="AND-PLAT-04",
                            title=f"Exported Content Provider Unprotected: {name}",
                            category="MASVS-PLATFORM",
                            tab_index=6,
                            severity=Severity.HIGH,
                            status=CheckStatus.FAIL,
                            description=f"Provider '{name}' is exported without readPermission or writePermission attributes.",
                            evidence="android:exported='true' with no access permissions defined.",
                            remediation="Set android:exported='false' or guard the component with signature-level permissions."
                        ))

        return findings
    '''def audit_tab06_platform(self, manifest_xml: str) -> List[Finding]:
        findings = []

        # 1. WebView Security Checks in Bytecode
        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]
            for dex in dex_files:
                text = z.read(dex).decode("latin-1", errors="ignore")
                
                if "setJavaScriptEnabled" in text:
                    findings.append(Finding(
                        check_id="AND-PLAT-03",
                        title="WebView JavaScript Execution Enabled",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.LOW,
                        status=CheckStatus.NEEDS_REVIEW,
                        description="setJavaScriptEnabled(true) detected. Audit to ensure WebView loads trusted content only.",
                        evidence=f"Found in {dex}",
                        remediation="Disable JavaScript unless required, and enforce strict URL whitelisting."
                    ))

                if "addJavascriptInterface" in text:
                    findings.append(Finding(
                        check_id="AND-PLAT-03",
                        title="Native JavaScript Interface Exposed",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.MEDIUM,
                        status=CheckStatus.NEEDS_REVIEW,
                        description="addJavascriptInterface exposes native methods to JavaScript within WebViews.",
                        evidence=f"addJavascriptInterface call found in {dex}",
                        remediation="Ensure all exposed methods use @JavascriptInterface and validate calling origins."
                    ))

                if "setAllowUniversalAccessFromFileURLs" in text or "setAllowFileAccessFromFileURLs" in text:
                    findings.append(Finding(
                        check_id="AND-PLAT-03",
                        title="Insecure File Access Permitted in WebView",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description="File scheme access permissions enabled in WebView, allowing local file harvesting.",
                        evidence=f"Permissive file flags found in {dex}",
                        remediation="Disable setAllowFileAccess(false) and universal file access APIs."
                    ))

        # 2. Content Provider Inspection in Manifest
        root = ET.fromstring(manifest_xml)
        application = root.find("application")
        if application is not None:
            for provider in application.findall("provider"):
                name = provider.attrib.get("{http://schemas.android.com/apk/res/android}name", "UnknownProvider")
                exported = provider.attrib.get("{http://schemas.android.com/apk/res/android}exported", "false").lower() == "true"
                read_perm = provider.attrib.get("{http://schemas.android.com/apk/res/android}readPermission")
                write_perm = provider.attrib.get("{http://schemas.android.com/apk/res/android}writePermission")

                if exported and not (read_perm or write_perm):
                    findings.append(Finding(
                        check_id="AND-PLAT-04",
                        title=f"Exported Content Provider Unprotected: {name}",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description=f"Provider '{name}' is exported without readPermission or writePermission attributes.",
                        evidence=f"android:exported='true' with no access permissions defined.",
                        remediation="Set android:exported='false' or guard the component with signature-level permissions."
                    ))

        return findings'''