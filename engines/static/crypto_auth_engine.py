# engines/static/crypto_auth_engine.py
import re
import zipfile
from typing import List, Dict, Any, Set
from core.models import Finding, Severity, CheckStatus

class CryptoAuthEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def audit_tab03_crypto(self) -> List[Finding]:
        findings = []

        # Strict regex matching Cipher.getInstance("...") invocation sequences in DEX/Smali
        cipher_invocation_regex = re.compile(
            r'const-string\s+[vp]\d+,\s*"([^"]*(?:DES|DESede|RC4|Blowfish|AES/ECB)[^"]*)"\s*'
            r'(?:[^\n]+\n){1,6}\s*'
            r'invoke-static\s*\{[^}]+\},\s*Ljavax/crypto/Cipher;->getInstance',
            re.IGNORECASE
        )

        # Standalone transformation regex with strict token boundaries
        strict_algo_pattern = re.compile(
            r'"\b(DES|DESede|RC4|Blowfish)(?:/(?:CBC|ECB|CFB|OFB|CTR)/(?:PKCS5Padding|PKCS7Padding|NoPadding))?"',
            re.IGNORECASE
        )

        # Standard third-party library namespaces to exclude from first-party crypto alerts
        ignored_namespaces = (
            "com/google/android/gms",
            "com/google/android/material",
            "androidx/",
            "android/support/",
            "okhttp3/",
            "org/apache/http/"
        )

        seen_matches: Set[str] = set()

        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]

            for dex in dex_files:
                data = z.read(dex).decode("latin-1", errors="ignore")

                # Strategy 1: Targeted Cipher.getInstance(...) calls
                for match in cipher_invocation_regex.finditer(data):
                    algo = match.group(1).strip()
                    pos = match.start()

                    # Resolve closest enclosing class path
                    preceding = data[max(0, pos - 2500):pos]
                    class_matches = re.findall(r'L([a-zA-Z0-9_\$]+(?:/[a-zA-Z0-9_\$]+)+);', preceding)
                    raw_class = class_matches[-1] if class_matches else "UnknownClass"

                    # Skip third-party SDK false positives
                    if any(raw_class.startswith(ns) for ns in ignored_namespaces):
                        continue

                    class_path = raw_class.replace("/", ".")
                    location_key = f"{class_path}:{algo.upper()}"
                    if location_key in seen_matches:
                        continue
                    seen_matches.add(location_key)

                    snippet = match.group(0)[:200]
                    findings.append(Finding(
                        check_id="AND-CRYP-01",
                        title=f"Insecure Cipher Instantiated: {algo.upper()}",
                        category="MASVS-CRYPTO",
                        tab_index=3,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description=f"Weak or obsolete cipher transformation '{algo.upper()}' instantiated via Cipher.getInstance().",
                        evidence=f"File: {dex}\nClass Path: {class_path}\nCall Sequence:\n{snippet}",
                        remediation="Replace with AES/GCM/NoPadding or use AndroidKeyStore implementations."
                    ))

                # Strategy 2: Explicit weak algorithm literals in code
                for match in strict_algo_pattern.finditer(data):
                    algo_literal = match.group(1).upper()
                    full_literal = match.group(0).strip('"')
                    pos = match.start()

                    preceding = data[max(0, pos - 2500):pos]
                    class_matches = re.findall(r'L([a-zA-Z0-9_\$]+(?:/[a-zA-Z0-9_\$]+)+);', preceding)
                    raw_class = class_matches[-1] if class_matches else "UnknownClass"

                    if any(raw_class.startswith(ns) for ns in ignored_namespaces):
                        continue

                    class_path = raw_class.replace("/", ".")
                    location_key = f"{class_path}:{full_literal.upper()}"
                    if location_key in seen_matches:
                        continue
                    seen_matches.add(location_key)

                    findings.append(Finding(
                        check_id="AND-CRYP-01",
                        title=f"Insecure Cipher Literal: {full_literal.upper()}",
                        category="MASVS-CRYPTO",
                        tab_index=3,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description=f"Weak cipher algorithm literal '{full_literal.upper()}' identified in bytecode string pool.",
                        evidence=f"File: {dex}\nClass Path: {class_path}\nMatched Literal: \"{full_literal}\"",
                        remediation="Migrate to AES-256-GCM or ChaCha20-Poly1305."
                    ))

        return findings

    def audit_tab04_auth(self) -> List[Finding]:
        findings = []

        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]

            has_biometric_prompt = False
            has_crypto_object = False

            for dex in dex_files:
                content = z.read(dex).decode("latin-1", errors="ignore")

                if "androidx/biometric/BiometricPrompt" in content or "android/hardware/biometrics/BiometricPrompt" in content:
                    has_biometric_prompt = True
                    if "BiometricPrompt$CryptoObject" in content or "authenticate([BL" in content:
                        has_crypto_object = True

            # AND-AUTH-03: Biometric Crypto Validation
            if has_biometric_prompt and not has_crypto_object:
                findings.append(Finding(
                    check_id="AND-AUTH-03",
                    title="Biometric Authentication Lacks CryptoObject Binding",
                    category="MASVS-AUTH",
                    tab_index=4,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    description="BiometricPrompt is implemented without passing a CryptoObject. Authentication operates as a bypassable client-side boolean check.",
                    evidence="BiometricPrompt detected without CryptoObject parameter binding.",
                    remediation="Pass a Cipher initialized with an AndroidKeyStore key into BiometricPrompt.authenticate(PromptInfo, CryptoObject)."
                ))
            elif has_biometric_prompt and has_crypto_object:
                findings.append(Finding(
                    check_id="AND-AUTH-03",
                    title="Cryptographically Bound Biometric Authentication",
                    category="MASVS-AUTH",
                    tab_index=4,
                    severity=Severity.INFO,
                    status=CheckStatus.PASS,
                    description="BiometricPrompt correctly utilizes CryptoObject key gating.",
                    evidence="CryptoObject signature found alongside BiometricPrompt."
                ))

        return findings

    def _check_and_cryp_01_insecure_ciphers(self, dex_files_data: Dict[str, str]) -> List[Finding]:
        """
        AND-CRYP-01: Detects broken or obsolete cryptographic algorithms (DES, 3DES/DESede, RC4, Blowfish)
        ensuring literals match actual Cipher transformations rather than benign UI variable substrings.
        """
        findings: List[Finding] = []

        cipher_invocation_pattern = re.compile(
            r'const-string\s+[vp]\d+,\s*"([^"]*(?:DES|DESede|RC4|Blowfish|AES/ECB)[^"]*)"\s*'
            r'(?:[^\n]+\n){1,6}\s*'
            r'invoke-static\s*\{[^}]+\},\s*Ljavax/crypto/Cipher;->getInstance',
            re.IGNORECASE
        )

        strict_algo_pattern = re.compile(
            r'"\b(DES|DESede|RC4|Blowfish)(?:/(?:CBC|ECB|CFB|OFB|CTR)/(?:PKCS5Padding|PKCS7Padding|NoPadding))?"',
            re.IGNORECASE
        )

        seen_matches = set()

        for dex_name, dex_content in dex_files_data.items():
            for match in cipher_invocation_pattern.finditer(dex_content):
                algo_str = match.group(1).strip()
                if algo_str not in seen_matches:
                    seen_matches.add(algo_str)
                    snippet = match.group(0)[:250]
                    findings.append(Finding(
                        check_id="AND-CRYP-01",
                        title=f"Insecure Cipher Instantiated: {algo_str}",
                        category="MASVS-CRYPTO",
                        tab_index=3,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description=(
                            f"The application requests an obsolete or weak cryptographic cipher transformation "
                            f"('{algo_str}') via Cipher.getInstance()."
                        ),
                        evidence=f"File: {dex_name}\nOpcode Call Sequence:\n{snippet}",
                        remediation="Replace with AES/GCM/NoPadding using AndroidKeyStore-backed secret keys."
                    ))

            for match in strict_algo_pattern.finditer(dex_content):
                full_literal = match.group(0).strip('"')
                if full_literal not in seen_matches:
                    seen_matches.add(full_literal)
                    findings.append(Finding(
                        check_id="AND-CRYP-01",
                        title=f"Insecure Cipher Algorithm Literal: {full_literal}",
                        category="MASVS-CRYPTO",
                        tab_index=3,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description=(
                            f"Identified explicit broken cipher algorithm specification ('{full_literal}') "
                            f"in DEX string pool."
                        ),
                        evidence=f"File: {dex_name}\nMatched string literal: \"{full_literal}\"",
                        remediation="Eliminate DES/RC4/Blowfish references and migrate to authenticated encryption (AES-256-GCM)."
                    ))

        return findings


class EnhancedCryptoEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def audit_cryptographic_operations(self) -> List[Finding]:
        findings = []

        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]

            for dex in dex_files:
                data = z.read(dex).decode("latin-1", errors="ignore")

                # 1. Cipher Transformation Inspection (with word boundaries)
                for match in re.finditer(r'"\b([A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+)\b"', data):
                    transformation = match.group(1).upper()
                    if any(weak in transformation for weak in ["DES", "DESEDE", "RC4", "BLOWFISH"]):
                        findings.append(Finding(
                            check_id="AND-CRYP-01",
                            title=f"Insecure Cipher Algorithm Invoked: {transformation}",
                            category="MASVS-CRYPTO",
                            tab_index=3,
                            severity=Severity.HIGH,
                            status=CheckStatus.FAIL,
                            description=f"Weak cryptographic algorithm '{transformation}' explicitly instantiated in bytecode.",
                            evidence=f"File: {dex}\nMatched Transformation: {transformation}",
                            remediation="Migrate to authenticated modern ciphers: AES/GCM/NoPadding or ChaCha20-Poly1305."
                        ))
                    elif "ECB" in transformation:
                        findings.append(Finding(
                            check_id="AND-CRYP-01",
                            title=f"Insecure Cipher Mode (ECB): {transformation}",
                            category="MASVS-CRYPTO",
                            tab_index=3,
                            severity=Severity.HIGH,
                            status=CheckStatus.FAIL,
                            description="Electronic Codebook (ECB) mode detected. ECB does not provide semantic security and exposes pattern data.",
                            evidence=f"File: {dex}\nTransformation: {transformation}",
                            remediation="Use authenticated streaming modes such as GCM with random 12-byte initialization vectors."
                        ))

                # 2. Check for Hardware AndroidKeyStore Usage
                if "AndroidKeyStore" not in data and "KeyStore" in data:
                    findings.append(Finding(
                        check_id="AND-CRYP-02",
                        title="KeyStore Initialized Without AndroidKeyStore Provider",
                        category="MASVS-CRYPTO",
                        tab_index=3,
                        severity=Severity.MEDIUM,
                        status=CheckStatus.NEEDS_REVIEW,
                        description="KeyStore references identified, but AndroidKeyStore provider string was not found. Keys may be software-bound.",
                        evidence=f"Bytecode scan in {dex} lacks 'AndroidKeyStore' provider identifier.",
                        remediation="Initialize KeyStore using KeyStore.getInstance('AndroidKeyStore') to enforce hardware isolation."
                    ))

        return findings