"""APK-level checks for modern Android storage, native code, intents and SBOM hints.

Checks emit reviewable static evidence; strings and API references alone never prove
that sensitive data is stored or that a code path is exploitable.
"""
import hashlib
import re
import struct
import zipfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Tuple

from core.models import CheckStatus, Confidence, Finding, Severity


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
SECRET_PATTERNS = {
    "AWS access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "Google API key": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "token-like assignment": re.compile(rb"(?i)(?:api[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*[A-Za-z0-9_./+=-]{16,}"),
}
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_DYNAMIC = 2
PF_X = 1
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB


class ModernAndroidAnalysisEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    @staticmethod
    def _safe_strings(data: bytes) -> str:
        return data.decode("latin-1", errors="ignore")

    @staticmethod
    def _elf_summary(data: bytes) -> Dict[str, Any]:
        result = {"valid": False, "class": None, "endian": None,
                  "exec_stack": None, "relro": False, "bind_now": False,
                  "stack_canary": b"__stack_chk_fail" in data,
                  "debug_symbols": any(x in data for x in (b".debug_info", b".debug_line", b".symtab"))}
        if len(data) < 52 or data[:4] != b"\x7fELF":
            return result
        elf_class, encoding = data[4], data[5]
        endian = "<" if encoding == 1 else ">" if encoding == 2 else None
        if endian is None or elf_class not in (1, 2):
            return result
        result.update(valid=True, **{"class": 32 if elf_class == 1 else 64,
                                     "endian": "little" if endian == "<" else "big"})
        try:
            if elf_class == 1:
                header = struct.unpack_from(endian + "16sHHIIIIIHHHHHH", data, 0)
                phoff, phentsize, phnum = header[5], header[9], header[10]
                phfmt, phmin = endian + "IIIIIIII", 32
            else:
                header = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data, 0)
                phoff, phentsize, phnum = header[5], header[9], header[10]
                phfmt, phmin = endian + "IIQQQQQQ", 56
            if phentsize < phmin or phnum > 4096 or phoff + phentsize * phnum > len(data):
                result["valid"] = False
                return result
            dynamic_regions = []
            for index in range(phnum):
                values = struct.unpack_from(phfmt, data, phoff + index * phentsize)
                if elf_class == 1:
                    p_type, p_offset, _, _, p_filesz, _, p_flags, _ = values
                else:
                    p_type, p_flags, p_offset, _, _, p_filesz, _, _ = values
                if p_type == PT_GNU_STACK:
                    result["exec_stack"] = bool(p_flags & PF_X)
                elif p_type == PT_GNU_RELRO:
                    result["relro"] = True
                elif p_type == PT_DYNAMIC:
                    dynamic_regions.append((p_offset, p_filesz))
            entry_size = 8 if elf_class == 1 else 16
            for offset, size in dynamic_regions:
                stop = min(offset + size, len(data))
                for cursor in range(offset, stop - entry_size + 1, entry_size):
                    tag, value = struct.unpack_from(endian + ("iI" if elf_class == 1 else "qQ"), data, cursor)
                    if tag == 0:
                        break
                    if tag == DT_BIND_NOW or (tag == DT_FLAGS and value & 0x8) or (tag == DT_FLAGS_1 and value & 0x1):
                        result["bind_now"] = True
            result["relro_level"] = "full" if result["relro"] and result["bind_now"] else "partial" if result["relro"] else "none"
        except (struct.error, IndexError, OverflowError):
            result["valid"] = False
        return result

    def audit(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        targets: Dict[str, Any] = {
            "schema_version": 1,
            "package_name": None,
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
            "deep_links": [],
            "runtime_hooks": {"trust_manager_classes": [], "crypto_methods": []},
            "sbom": [],
        }
        try:
            with zipfile.ZipFile(self.apk_path, "r") as apk:
                names = apk.namelist()
                dex_names = sorted(n for n in names if re.fullmatch(r"classes(?:\d+)?\.dex", n))
                dex_text = {name: self._safe_strings(apk.read(name)) for name in dex_names}
                all_dex = "\n".join(dex_text.values())

                package = ""
                try:
                    import pyaxmlparser
                    decoded = pyaxmlparser.APK(self.apk_path).get_android_manifest_xml()
                    if hasattr(decoded, "getroottree"):
                        manifest = ET.fromstring(ET.tostring(decoded))
                    else:
                        manifest = ET.fromstring(decoded)
                    package = manifest.attrib.get("package", "")
                    targets["package_name"] = package
                    findings.extend(self._audit_manifest(manifest, targets))
                except Exception as exc:
                    findings.append(Finding(
                        check_id="TIR-DEEPLINK",
                        title="Manifest analysis needs review",
                        category="MASVS-PLATFORM",
                        tab_index=6,
                        severity=Severity.INFO,
                        status=CheckStatus.NEEDS_REVIEW,
                        confidence=Confidence.LOW,
                        description="TIR could not decode the APK manifest for structured component and App Link analysis.",
                        evidence=str(exc)[:300],
                        remediation="Confirm the APK manifest is readable and rerun the static scan.",
                    ))

                findings.extend(self._audit_storage(all_dex, names))
                findings.extend(self._audit_pending_intents(all_dex, dex_names))
                native_findings, native_hashes = self._audit_native(apk, names)
                findings.extend(native_findings)
                targets["sbom"].extend(native_hashes)

                for marker, name in (
                    ("Lokhttp3/", "OkHttp"),
                    ("Lretrofit2/", "Retrofit"),
                    ("Lcom/google/gson/", "Gson"),
                    ("Lcom/squareup/moshi/", "Moshi"),
                    ("Lio/realm/", "Realm"),
                    ("Landroidx/room/", "AndroidX Room"),
                    ("Landroidx/datastore/", "AndroidX DataStore"),
                    ("Lcom/facebook/", "Facebook SDK"),
                ):
                    if marker in all_dex:
                        targets["sbom"].append({"name": name, "version": None, "source": "DEX package fingerprint"})
                if targets["sbom"]:
                    targets["sbom"] = sorted(targets["sbom"], key=lambda row: (row.get("name", ""), row.get("sha256", "")))
                    findings.append(Finding(
                        check_id="TIR-DEPENDENCY-SBOM",
                        title="Bundled dependency and native library inventory",
                        category="Supply Chain and Third-party SDK Testing",
                        tab_index=12,
                        severity=Severity.INFO,
                        status=CheckStatus.NEEDS_REVIEW,
                        confidence=Confidence.LOW,
                        description="Package and binary fingerprints are inventory hints; exact versions and known-vulnerability status require a verified SBOM or dependency metadata.",
                        evidence="\n".join(f"{row.get('name')} | version={row.get('version') or 'unknown'} | sha256={row.get('sha256', 'n/a')}" for row in targets["sbom"][:100]),
                        remediation="Correlate an authoritative CycloneDX/SPDX SBOM with a current vulnerability database before assigning vulnerability status.",
                    ))
        except (OSError, zipfile.BadZipFile) as exc:
            findings.append(Finding(
                check_id="TIR-NATIVE-HARDENING",
                title="APK archive could not be analyzed",
                category="MASVS-CODE",
                tab_index=7,
                severity=Severity.INFO,
                status=CheckStatus.NEEDS_REVIEW,
                confidence=Confidence.LOW,
                description="Modern Android static checks could not read the target APK as a ZIP archive.",
                evidence=str(exc)[:300],
                remediation="Provide a valid APK file and rerun the scan.",
            ))
        return findings, targets

    def _audit_manifest(self, root: ET.Element, targets: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for element in root.findall(f".//application/{tag}"):
                name = element.attrib.get(ANDROID_NS + "name", "")
                exported = element.attrib.get(ANDROID_NS + "exported")
                has_filter = bool(element.findall("intent-filter"))
                is_exported = exported == "true" or (exported is None and has_filter)
                if name and is_exported:
                    bucket = {"activity": "activities", "activity-alias": "activities",
                              "service": "services", "receiver": "receivers",
                              "provider": "providers"}[tag]
                    targets["components"][bucket].append({
                        "name": name, "type": tag, "permission": element.attrib.get(ANDROID_NS + "permission"),
                        "authority": element.attrib.get(ANDROID_NS + "authorities", ""),
                        "read_permission": element.attrib.get(ANDROID_NS + "readPermission"),
                        "exported": True,
                    })
                for intent_filter in element.findall("intent-filter"):
                    auto_verify = intent_filter.attrib.get(ANDROID_NS + "autoVerify") == "true"
                    schemes, hosts = set(), set()
                    for data in intent_filter.findall("data"):
                        if data.attrib.get(ANDROID_NS + "scheme"):
                            schemes.add(data.attrib[ANDROID_NS + "scheme"])
                        if data.attrib.get(ANDROID_NS + "host"):
                            hosts.add(data.attrib[ANDROID_NS + "host"])
                    for scheme in sorted(schemes):
                        entry = {"component": name, "scheme": scheme, "hosts": sorted(hosts),
                                 "auto_verify": auto_verify, "exported": is_exported}
                        targets["deep_links"].append(entry)
                        https_link = scheme.lower() == "https"
                        if https_link and hosts and not auto_verify:
                            findings.append(Finding(
                                check_id="TIR-DEEPLINK",
                                title=f"Web App Link is not marked for domain verification: {name}",
                                category="MASVS-PLATFORM",
                                tab_index=6,
                                severity=Severity.LOW,
                                status=CheckStatus.NEEDS_REVIEW,
                                confidence=Confidence.MEDIUM,
                                affected_component=name,
                                description="An HTTPS intent filter declares a host but does not set android:autoVerify=true.",
                                evidence=f"scheme=https; hosts={', '.join(sorted(hosts))}; exported={is_exported}",
                                remediation="Verify the domain association and set android:autoVerify=true when this filter is intended to be a verified App Link.",
                            ))
                        elif not https_link and is_exported and not hosts:
                            findings.append(Finding(
                                check_id="TIR-DEEPLINK",
                                title=f"Exported custom scheme has no host restriction: {name}",
                                category="MASVS-PLATFORM",
                                tab_index=6,
                                severity=Severity.MEDIUM,
                                status=CheckStatus.NEEDS_REVIEW,
                                confidence=Confidence.MEDIUM,
                                affected_component=name,
                                description="Any installed app may be able to invoke this exported custom URL scheme; validate all incoming URI fields at runtime.",
                                evidence=f"scheme={scheme}; component={name}; exported={is_exported}",
                                remediation="Prefer verified HTTPS App Links or validate scheme, host, path, and caller-sensitive data before processing.",
                            ))
        return findings

    def _audit_storage(self, dex_text: str, archive_names: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        datastore_refs = [name for name in ("androidx/datastore/preferences", "androidx/datastore/core", "DataStoreFactory", "PreferencesDataStore") if name in dex_text]
        if datastore_refs:
            findings.append(Finding(
                check_id="TIR-STORE-DATASTORE",
                title="Jetpack DataStore references need data-sensitivity review",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.INFO,
                status=CheckStatus.NEEDS_REVIEW,
                confidence=Confidence.LOW,
                description="The APK references Jetpack DataStore. DataStore does not encrypt values by default; inspect the stored data and Serializer/AeadSerializer configuration.",
                evidence="Detected references: " + ", ".join(sorted(set(datastore_refs))),
                remediation="Classify persisted values and protect sensitive data with an authenticated encryption layer and a securely managed key.",
            ))
        encrypted_refs = [name for name in ("EncryptedSharedPreferences", "MasterKey", "AndroidKeysetManager", "EncryptedFile") if name in dex_text]
        if encrypted_refs:
            findings.append(Finding(
                check_id="TIR-STORE-SHAREDPREFS",
                title="Jetpack Security Crypto storage references need configuration review",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.INFO,
                status=CheckStatus.NEEDS_REVIEW,
                confidence=Confidence.LOW,
                description="Encrypted storage API references were found, but a reference alone cannot establish correct keyset, key rotation, or migration behavior.",
                evidence="Detected references: " + ", ".join(sorted(set(encrypted_refs))),
                remediation="Review keyset storage, Android Keystore protection, failure handling, backup behavior, and migration plans.",
            ))
        if not datastore_refs and not encrypted_refs:
            return findings
        return findings

    def _audit_pending_intents(self, dex_text: str, dex_names: List[str]) -> List[Finding]:
        if "Landroid/app/PendingIntent;->get" not in dex_text and "PendingIntent" not in dex_text:
            return []
        has_immutable = "FLAG_IMMUTABLE" in dex_text or "67108864" in dex_text
        has_mutable = "FLAG_MUTABLE" in dex_text or "33554432" in dex_text
        return [Finding(
            check_id="TIR-PENDINGINTENT",
            title="PendingIntent creation requires call-site review",
            category="MASVS-PLATFORM",
            tab_index=6,
            severity=Severity.MEDIUM if has_mutable or not has_immutable else Severity.INFO,
            status=CheckStatus.NEEDS_REVIEW,
            confidence=Confidence.LOW,
            description="DEX references PendingIntent creation. Whole-DEX flag presence is insufficient to prove each call site is safe; inspect mutability and whether the wrapped Intent is explicit.",
            evidence=f"DEX files: {', '.join(dex_names)}; FLAG_IMMUTABLE reference={has_immutable}; FLAG_MUTABLE reference={has_mutable}",
            remediation="Use FLAG_IMMUTABLE with an explicit base Intent unless a documented use case requires narrowly scoped mutability.",
        )]

    def _audit_native(self, apk: zipfile.ZipFile, names: List[str]) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        libraries = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
        findings: List[Finding] = []
        inventory: List[Dict[str, Any]] = []
        for name in libraries:
            data = apk.read(name)
            summary = self._elf_summary(data)
            digest = hashlib.sha256(data).hexdigest()
            inventory.append({"name": name, "version": None, "source": "ELF path", "sha256": digest})
            if not summary["valid"]:
                findings.append(Finding(
                    check_id="TIR-NATIVE-HARDENING",
                    title=f"Unrecognized or malformed ELF library: {name}",
                    category="MASVS-CODE",
                    tab_index=7,
                    severity=Severity.INFO,
                    status=CheckStatus.NEEDS_REVIEW,
                    confidence=Confidence.LOW,
                    source_file=name,
                    description="TIR could not safely parse this native library's ELF program headers.",
                    evidence=f"ELF validation failed; sha256={digest}",
                    remediation="Inspect the binary with an updated ELF parser.",
                ))
                continue
            details = (
                f"ELF{summary['class']} {summary['endian']}; stack canary={summary['stack_canary']}; "
                f"NX={summary['exec_stack'] is False}; RELRO={summary['relro_level']}; "
                f"debug symbols={summary['debug_symbols']}; sha256={digest}"
            )
            missing = []
            if summary["exec_stack"] is True:
                missing.append("executable GNU_STACK")
            if not summary["stack_canary"]:
                missing.append("stack canary reference absent")
            if summary["exec_stack"] is None:
                missing.append("GNU_STACK segment absent")
            if summary["relro_level"] != "full":
                missing.append(f"RELRO is {summary['relro_level']}")
            findings.append(Finding(
                check_id="TIR-NATIVE-HARDENING",
                title=f"Native library hardening review: {name}",
                category="MASVS-CODE",
                tab_index=7,
                severity=Severity.HIGH if summary["exec_stack"] is True else Severity.INFO,
                status=CheckStatus.FAIL if summary["exec_stack"] is True else CheckStatus.NEEDS_REVIEW if missing else CheckStatus.PASS,
                confidence=Confidence.HIGH if summary["exec_stack"] is True else Confidence.MEDIUM,
                source_file=name,
                description="Native ELF hardening indicators were inspected. Missing indicators require review against toolchain and platform context.",
                evidence=details + ("; review: " + ", ".join(missing) if missing else ""),
                remediation="Rebuild with non-executable stack, stack protection, full RELRO, and production-appropriate debug-symbol handling.",
                metadata={"elf": summary},
            ))
            secret_hits = []
            for label, pattern in SECRET_PATTERNS.items():
                for match in pattern.findall(data):
                    value = match if isinstance(match, bytes) else match[0]
                    secret_hits.append(f"{label}: {value[:10].decode('latin-1', errors='replace')}…")
            if secret_hits:
                findings.append(Finding(
                    check_id="TIR-NATIVE-SECRETS",
                    title=f"Potential hardcoded secret in native library: {name}",
                    category="Information Gathering and Static Setup",
                    tab_index=1,
                    severity=Severity.HIGH,
                    status=CheckStatus.NEEDS_REVIEW,
                    confidence=Confidence.MEDIUM,
                    source_file=name,
                    description="A high-signal secret pattern matched bytes in a native library; validate whether it is active and sensitive.",
                    evidence="\n".join(secret_hits[:10]) + f"\nsha256={digest}",
                    remediation="Remove embedded credentials and rotate any exposed secret.",
                ))
        return findings, inventory
