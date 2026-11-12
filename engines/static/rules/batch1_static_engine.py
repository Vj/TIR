# engines/static/rules/batch1_static_engine.py
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Dict, Set, Any
from core.models import AnalysisType, Finding, Severity, CheckStatus

class Batch1StaticEngine:
    """Implements STA-021, STA-022, STA-024, STA-029, STA-030, STA-031, and STA-035."""

    def __init__(self, apk_path: str, manifest_xml: str, declared_permissions: List[str]):
        self.apk_path = apk_path
        self.manifest_xml = manifest_xml
        self.declared_permissions = declared_permissions

    def audit_all(self, dex_files_data: Dict[str, str], combined_dex: str) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._audit_sta_021_api_keys(dex_files_data))
        findings.extend(self._audit_sta_022_hardcoded_crypto_keys(dex_files_data))
        findings.extend(self._audit_sta_024_webview_configurations(dex_files_data))
        findings.extend(self._audit_sta_029_unsafe_native_functions())
        findings.extend(self._audit_sta_030_backup_data_exposure())
        findings.extend(self._audit_sta_031_insecure_auth(combined_dex))
        findings.extend(self._audit_sta_035_permission_misuse(combined_dex))
        return findings

    def _audit_sta_021_api_keys(self, dex_files_data: Dict[str, str]) -> List[Finding]:
        """STA-021: Scans DEX strings for multi-provider API keys, secrets, and bearer tokens."""
        findings: List[Finding] = []
        key_patterns = {
            "AWS Client Secret / Key": r"(?i)aws[_\-]?(?:secret|key|access)[\s\"':=]+([A-Za-z0-9/+=]{40})",
            "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24,34}",
            "GitHub Personal Access Token": r"gh[pous]_[A-Za-z0-9_]{36,255}",
            "Generic Bearer Token": r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})",
            "JWT Token": r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        }

        matched_keys: Set[str] = set()
        for dex_name, content in dex_files_data.items():
            for key_type, pattern in key_patterns.items():
                for match in re.finditer(pattern, content):
                    token = match.group(0)
                    if token not in matched_keys:
                        matched_keys.add(token)
                        snippet = token[:10] + "..." + token[-4:] if len(token) > 16 else token[:6] + "..."
                        findings.append(Finding(
                            check_id="STA-021",
                            title=f"Hardcoded Credential Discovered: {key_type}",
                            category="Information Gathering and Static Setup",
                            tab_index=1,
                            severity=Severity.HIGH,
                            status=CheckStatus.FAIL,
                            description=f"DEX bytecode contains embedded credential patterns indicative of {key_type}.",
                            evidence=f"File: {dex_name}\nRedacted Token Match: {snippet}",
                            remediation="Store secrets externally in secure vaults or load dynamically from authenticated backends."
                        ))
        return findings

    def _audit_sta_022_hardcoded_crypto_keys(self, dex_files_data: Dict[str, str]) -> List[Finding]:
        """STA-022: Identifies static SecretKeySpec and IvParameterSpec initializations."""
        findings: List[Finding] = []
        for dex_name, content in dex_files_data.items():
            # Check for SecretKeySpec initialized from static string bytes
            if "Ljavax/crypto/spec/SecretKeySpec;" in content:
                # Look for literal string definitions immediately passed to getBytes() or SecretKeySpec
                if re.search(r'const-string [vp]\d+,\s*"[^"]{8,32}"\s*.*?SecretKeySpec', content, re.DOTALL):
                    findings.append(Finding(
                        check_id="STA-022",
                        title="Hardcoded Symmetric Cryptographic Key in Bytecode",
                        category="MASVS-CRYPTO",
                        tab_index=3,
                        severity=Severity.CRITICAL,
                        status=CheckStatus.FAIL,
                        description="Bytecode contains static string literals passed into SecretKeySpec, enabling key extraction.",
                        evidence=f"Static SecretKeySpec initialization detected in {dex_name}.",
                        remediation="Derive encryption keys using the Android KeyStore provider or PBKDF2/Argon2 with salted credentials."
                    ))

            # Check for static IVParameterSpec (e.g., all zeros or static array)
            if "Ljavax/crypto/spec/IvParameterSpec;" in content:
                if re.search(r'new-array [vp]\d+,\s*[vp]\d+,\s*\[B.*?IvParameterSpec', content, re.DOTALL):
                    findings.append(Finding(
                        check_id="STA-022",
                        title="Static / Predictable Initialization Vector (IV)",
                        category="MASVS-CRYPTO",
                        tab_index=3,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description="IvParameterSpec is instantiated without random generation, allowing replay and pattern leakage.",
                        evidence=f"Non-random IvParameterSpec instantiation pattern in {dex_name}.",
                        remediation="Generate IVs dynamically using java.security.SecureRandom for every encryption operation."
                    ))
        return findings

    def _audit_sta_024_webview_configurations(self, dex_files_data: Dict[str, str]) -> List[Finding]:
        """STA-024: Insecure WebView Settings and JavaScript Interfaces."""
        findings: List[Finding] = []
        for dex_name, content in dex_files_data.items():
            if "Landroid/webkit/WebView;" in content or "Landroid/webkit/WebSettings;" in content:
                # 1. addJavascriptInterface
                if "addJavascriptInterface" in content:
                    findings.append(Finding(
                        check_id="STA-024",
                        title="WebView JavaScript Interface Bridge Exposed",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.HIGH,
                        status=CheckStatus.NEEDS_REVIEW,
                        description="addJavascriptInterface() exposes native Java/Kotlin methods to the JavaScript context.",
                        evidence=f"Call to addJavascriptInterface identified in {dex_name}.",
                        remediation="Annotate all exposed methods with @JavascriptInterface and enforce strict origin checks on loaded URLs."
                    ))

                # 2. setAllowFileAccess / setAllowUniversalAccessFromFileURLs
                if "setAllowUniversalAccessFromFileURLs" in content or "setAllowFileAccessFromFileURLs" in content:
                    findings.append(Finding(
                        check_id="STA-024",
                        title="Universal File Access Enabled in WebView",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description="setAllowUniversalAccessFromFileURLs is enabled, allowing file:// schemes to access arbitrary origin data.",
                        evidence=f"Flagged file URL access settings in {dex_name}.",
                        remediation="Explicitly disable setAllowFileAccess(false) and setAllowUniversalAccessFromFileURLs(false)."
                    ))
        return findings

    def _audit_sta_029_unsafe_native_functions(self) -> List[Finding]:
        """STA-029: Scans application .so files for dangerous C memory functions lacking fortified variants,
        aggregating detections across all architectures into a single finding per library."""
        findings: List[Finding] = []
        dangerous_fns = [b"strcpy", b"strcat", b"sprintf", b"vsprintf", b"gets"]
        fortified_fns = [b"__strcpy_chk", b"__strcat_chk", b"__sprintf_chk", b"__vsprintf_chk"]

        # Track results per shared object library: {lib_name: {"archs": set(), "functions": set()}}
        vulnerable_libs: Dict[str, Dict[str, set]] = {}

        with zipfile.ZipFile(self.apk_path, "r") as z:
            so_files = [f for f in z.namelist() if f.startswith("lib/") and f.endswith(".so")]
            for so in so_files:
                # Exclude runtime/engine libraries
                if any(x in so for x in ["libflutter.so", "libhermes.so", "libmonosgen"]):
                    continue

                parts = so.split("/")
                if len(parts) < 3:
                    continue

                arch = parts[1]
                lib_name = parts[-1]

                elf_data = z.read(so)
                found_danger = [fn.decode() for fn in dangerous_fns if fn in elf_data]
                has_fortification = any(fn in elf_data for fn in fortified_fns)

                if found_danger and not has_fortification:
                    if lib_name not in vulnerable_libs:
                        vulnerable_libs[lib_name] = {"archs": set(), "functions": set()}
                    vulnerable_libs[lib_name]["archs"].add(arch)
                    vulnerable_libs[lib_name]["functions"].update(found_danger)

        for lib_name, data in vulnerable_libs.items():
            arch_list = sorted(list(data["archs"]))
            fn_list = sorted(list(data["functions"]))
            findings.append(Finding(
                check_id="STA-029",
                title=f"Unsafe Native Memory Functions: {lib_name}",
                category="MASVS-CODE",
                tab_index=7,
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                description=(
                    f"Shared library '{lib_name}' imports unbounded memory manipulation functions "
                    f"({', '.join(fn_list)}) without compiler buffer overflow checks (FORTIFY_SOURCE) "
                    f"across {len(arch_list)} architecture(s)."
                ),
                evidence=(
                    f"Library: {lib_name}\n"
                    f"Unbounded functions: {fn_list}\n"
                    f"Fortified symbols: 0\n"
                    f"Affected architectures ({len(arch_list)}): {', '.join(arch_list)}"
                ),
                remediation="Compile with -D_FORTIFY_SOURCE=2 and replace unbounded string operations with snprintf/strncpy."
            ))

        return findings

 
    def _audit_sta_030_backup_data_exposure(self) -> List[Finding]:
        """
        STA-030: Deep inspection of backup XML rules.
        Defers baseline allowBackup checks to AND-STOR-05 to prevent duplicate reporting.
        """
        findings: List[Finding] = []
        ns = {"android": "http://schemas.android.com/apk/res/android"}

        # 1. Resolve manifest root element safely
        manifest_root = None
        if hasattr(self, "manifest_xml") and self.manifest_xml:
            try:
                manifest_root = ET.fromstring(self.manifest_xml)
            except Exception:
                manifest_root = None
        elif hasattr(self, "_parsed_manifest") and self._parsed_manifest is not None:
            manifest_root = self._parsed_manifest

        if manifest_root is None:
            return findings

        # 2. Extract application element safely
        app_elem = manifest_root.find("application")
        if app_elem is None:
            return findings

        full_backup_content = app_elem.attrib.get(f"{{{ns['android']}}}fullBackupContent")
        data_extraction_rules = app_elem.attrib.get(f"{{{ns['android']}}}dataExtractionRules")

        # If no explicit custom backup rule files are referenced, skip deep inspection
        if not full_backup_content and not data_extraction_rules:
            return findings

        # 3. Check explicit XML backup resource rules for sensitive directory inclusions
        with zipfile.ZipFile(self.apk_path, "r") as z:
            for name in z.namelist():
                if name.startswith("res/xml/") and name.endswith(".xml"):
                    try:
                        content = z.read(name).decode("utf-8", errors="ignore")
                        if "<include" in content and any(d in content for d in ["sharedpref", "database"]):
                            findings.append(Finding(
                                check_id="STA-030",
                                title=f"Sensitive Storage Domain Included in Backup Rules: {name.split('/')[-1]}",
                                category="MASVS-STORAGE",
                                tab_index=2,
                                severity=Severity.HIGH,
                                status=CheckStatus.FAIL,
                                analysis_type=AnalysisType.STATIC,
                                description=(
                                    f"Custom backup rule resource '{name}' includes private database "
                                    "or SharedPreferences directories in device or cloud backup scopes."
                                ),
                                affected_component=name,
                                source_file=name,
                                cwe_id="CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory",
                                masvs_ref="MASVS-STORAGE-2",
                                mastg_ref="MASTG-TEST-0005",
                                evidence=f"Resource: {name}\nContent snippet:\n{content[:250]}",
                                remediation="Add <exclude domain='database' .../> and <exclude domain='sharedpref' .../> directives."
                            ))
                    except Exception:
                        continue

        return findings

    
    def _audit_sta_031_insecure_auth(self, combined_dex: str) -> List[Finding]:
        """STA-031: Evaluates biometric implementation patterns (CryptoObject binding)."""
        findings: List[Finding] = []
        if "BiometricPrompt" in combined_dex or "FingerprintManager" in combined_dex:
            # Check if authenticate is called with CryptoObject parameter
            has_crypto_binding = "Landroidx/biometric/BiometricPrompt$CryptoObject;" in combined_dex or \
                                 "Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;" in combined_dex

            if not has_crypto_binding:
                findings.append(Finding(
                    check_id="STA-031",
                    title="Biometric Authentication Implemented Without CryptoObject Binding",
                    category="MASVS-AUTH",
                    tab_index=4,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    description="BiometricPrompt authentication relies on software-only UI callbacks without binding to a KeyStore CryptoObject.",
                    evidence="BiometricPrompt found in bytecode, but references to BiometricPrompt.CryptoObject are absent.",
                    remediation="Pass a KeyStore-backed Cipher inside BiometricPrompt.CryptoObject during biometric authentication."
                ))
            else:
                findings.append(Finding(
                    check_id="STA-031",
                    title="Cryptographically Bound Biometric Authentication Confirmed",
                    category="MASVS-AUTH",
                    tab_index=4,
                    severity=Severity.INFO,
                    status=CheckStatus.PASS,
                    description="Biometric authentication integrates KeyStore CryptoObject verification.",
                    evidence="BiometricPrompt.CryptoObject binding verified in bytecode.",
                    remediation=None
                ))
        return findings

    def _audit_sta_035_permission_misuse(self, combined_dex: str) -> List[Finding]:
        """STA-035: Cross-references declared dangerous permissions against bytecode callsites."""
        findings: List[Finding] = []
        # Mapping dangerous permissions to required API signatures in DEX
        permission_api_map = {
            "android.permission.CAMERA": ["Landroid/hardware/Camera;", "Landroid/hardware/camera2/"],
            "android.permission.RECORD_AUDIO": ["Landroid/media/AudioRecord;", "Landroid/media/MediaRecorder;"],
            "android.permission.ACCESS_FINE_LOCATION": ["Landroid/location/LocationManager;", "com/google/android/gms/location"],
            "android.permission.READ_CONTACTS": ["content://com.android.contacts", "ContactsContract"]
        }

        unused_declared: List[str] = []
        for perm, signatures in permission_api_map.items():
            if perm in self.declared_permissions:
                if not any(sig in combined_dex for sig in signatures):
                    unused_declared.append(perm)

        if unused_declared:
            findings.append(Finding(
                check_id="STA-035",
                title=f"Potential Over-Privileged Permissions Declared ({len(unused_declared)})",
                category="MASVS-PRIVACY",
                tab_index=9,
                severity=Severity.LOW,
                status=CheckStatus.NEEDS_REVIEW,
                description="Application declares dangerous permissions whose core Android API callsites were not detected in compiled bytecode.",
                evidence="Declared permissions lacking clear bytecode callsites:\n" + "\n".join(f"- {p}" for p in unused_declared),
                remediation="Remove unused permission requests to adhere to the principle of least privilege."
            ))

        return findings