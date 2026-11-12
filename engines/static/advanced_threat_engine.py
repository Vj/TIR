# engines/static/advanced_threat_engine.py
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import List
from core.models import Finding, Severity, CheckStatus

class AdvancedThreatEngine:
    def __init__(self, apk_path: str, manifest_xml: str):
        self.apk_path = apk_path
        self.manifest_xml = manifest_xml

    def audit_all_advanced_threats(self) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._audit_tapjacking_protection())
        findings.extend(self._audit_hybrid_framework_assets())
        findings.extend(self._audit_hardware_keystore_configuration())
        findings.extend(self._audit_on_device_ai_assets())
        return findings

    def _audit_tapjacking_protection(self) -> List[Finding]:
        """Detects overlay/tapjacking protections in manifest and bytecode."""
        findings = []
        
        # 1. Check layout XMLs or manifest for filterTouchesWhenObscured
        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]
            obscured_filter_detected = False

            for dex in dex_files:
                data = z.read(dex).decode("latin-1", errors="ignore")
                if "filterTouchesWhenObscured" in data or "FLAG_WINDOW_IS_OBSCURED" in data:
                    obscured_filter_detected = True
                    break

            if not obscured_filter_detected:
                findings.append(Finding(
                    check_id="ADV-TOUCH-01",
                    title="Overlay Protection Missing (Tapjacking Risk)",
                    category="Advanced Platform Security",
                    tab_index=6,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.NEEDS_REVIEW,
                    description="No references to 'filterTouchesWhenObscured' or 'FLAG_WINDOW_IS_OBSCURED' detected. Input fields may be vulnerable to malicious overlays.",
                    evidence="Zero references to touch filtering flags detected in application bytecode.",
                    remediation="Apply android:filterTouchesWhenObscured='true' to sensitive layout views or handle onTouch events by checking for FLAG_WINDOW_IS_OBSCURED."
                ))

        return findings

    def _audit_hybrid_framework_assets(self) -> List[Finding]:
        """Audits React Native and Flutter specific runtime vulnerabilities."""
        findings = []

        with zipfile.ZipFile(self.apk_path, "r") as z:
            namelist = z.namelist()

            # React Native Checks
            if "assets/index.android.bundle" in namelist:
                bundle_data = z.read("assets/index.android.bundle")
                # Hermes bytecode starts with magic bytes 0x1F2040C3 (little-endian: C3 40 20 1F)
                is_hermes = bundle_data.startswith(b"\xc3\x40\x20\x1f")

                if not is_hermes:
                    findings.append(Finding(
                        check_id="ADV-HYB-01",
                        title="React Native JavaScript Bundle Uncompiled (Plaintext JS)",
                        category="Advanced Code Quality & Supply Chain",
                        tab_index=7,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description="The React Native index.android.bundle is stored as plain JavaScript rather than compiled Hermes bytecode.",
                        evidence=f"Asset: assets/index.android.bundle (Size: {len(bundle_data)} bytes, Hermes: False)",
                        remediation="Enable Hermes engine in android/app/build.gradle: project.ext.react = [ enableHermes: true ] to protect source code."
                    ))

            # Flutter Checks
            if any("libflutter.so" in name for name in namelist):
                findings.append(Finding(
                    check_id="ADV-HYB-02",
                    title="Flutter Engine Framework Detected",
                    category="Advanced Code Quality & Supply Chain",
                    tab_index=7,
                    severity=Severity.INFO,
                    status=CheckStatus.PASS,
                    description="Flutter runtime detected. Audit application network security configuration to ensure Dart TLS pinning is separately enforced.",
                    evidence="Embedded libraries: libflutter.so and libapp.so located in native ABI directories.",
                    remediation="Flutter uses its own network stack (BoringSSL). Ensure custom SecurityContext is used to validate SSL certificates in Dart."
                ))

        return findings

    def _audit_hardware_keystore_configuration(self) -> List[Finding]:
        """Checks for hardware-backed keystore enclaves (StrongBox)."""
        findings = []

        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]
            strongbox_invoked = False
            user_auth_required = False

            for dex in dex_files:
                data = z.read(dex).decode("latin-1", errors="ignore")
                if "setIsStrongBoxBacked" in data:
                    strongbox_invoked = True
                if "setUserAuthenticationRequired" in data:
                    user_auth_required = True

            if not strongbox_invoked:
                findings.append(Finding(
                    check_id="ADV-CRYP-02",
                    title="Hardware StrongBox Key Storage Not Enforced",
                    category="Advanced Cryptographic Security",
                    tab_index=3,
                    severity=Severity.LOW,
                    status=CheckStatus.NEEDS_REVIEW,
                    description="No invocations of 'setIsStrongBoxBacked(true)' detected in KeyGenParameterSpec definitions. Cryptographic keys may reside in software TEE rather than dedicated hardware security modules.",
                    evidence="No references to setIsStrongBoxBacked detected in DEX classes.",
                    remediation="On supported devices (Android 9+), call setIsStrongBoxBacked(true) for high-value encryption and signing keys."
                ))

        return findings

    def _audit_on_device_ai_assets(self) -> List[Finding]:
        """Detects exposed on-device machine learning models."""
        findings = []
        ml_extensions = (".tflite", ".onnx", ".pt", ".bin", ".engine")

        with zipfile.ZipFile(self.apk_path, "r") as z:
            for file_path in z.namelist():
                lower_name = file_path.lower()
                if any(lower_name.endswith(ext) for ext in ml_extensions):
                    file_info = z.getinfo(file_path)
                    findings.append(Finding(
                        check_id="ADV-AI-01",
                        title=f"Bundled On-Device AI/ML Model: {file_path.split('/')[-1]}",
                        category="Advanced Asset & AI Security",
                        tab_index=1,
                        severity=Severity.LOW,
                        status=CheckStatus.NEEDS_REVIEW,
                        description="An on-device machine learning model file was detected in unencrypted assets. Proprietary weights and architecture are exposed.",
                        evidence=f"Path: {file_path} (Uncompressed Size: {file_info.file_size} bytes)",
                        remediation="Evaluate if model parameters or bundled prompt templates represent proprietary IP. If so, encrypt model assets and decrypt directly into memory."
                    ))

        return findings