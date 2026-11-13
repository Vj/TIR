"""Static indicators for RBI DPSC, NPCI UPI, and SEBI mobile controls.

These bytecode and manifest scans are triage signals, not proof of control efficacy or
legal compliance. Dynamic loading, native control flow, reflection, and server behavior
can invalidate conclusions drawn from string/API presence or absence.
"""
import re
import zipfile
from typing import Dict, List

from core.models import AnalysisType, CheckStatus, Confidence, Finding, Severity

REMOTE_PACKAGES = ("com.anydesk.anydeskandroid", "com.teamviewer.teamviewer.market.mobile",
                   "com.carriez.flutter_hbb", "com.teamviewer.host.market")


class IndianRegulatoryStaticEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def audit(self) -> List[Finding]:
        dex: Dict[str, str] = {}
        native: Dict[str, bytes] = {}
        manifest = None
        with zipfile.ZipFile(self.apk_path, "r") as apk:
            names = apk.namelist()
            for name in names:
                if re.fullmatch(r"classes(?:\d+)?\.dex", name):
                    dex[name] = apk.read(name).decode("latin-1", errors="ignore")
                elif name.startswith("lib/") and name.endswith(".so"):
                    native[name] = apk.read(name)
            if "AndroidManifest.xml" in names:
                try:
                    import pyaxmlparser
                    decoded = pyaxmlparser.APK(self.apk_path).get_android_manifest_xml()
                    manifest = decoded.decode("utf-8", errors="ignore") if isinstance(decoded, bytes) else str(decoded)
                except Exception:
                    manifest = None
        all_dex = "\n".join(dex.values())
        manifest_text = manifest or ""
        manifest_permissions = set(re.findall(r'(?:uses-permission[^>]*android:name=|android:name=)["\']([^"\']+)', manifest_text))
        results = []

        results.append(self._finding("STA-REG-01", "Device and SIM binding indicators",
            ["getSimSerialNumber", "getSubscriberId", "SubscriptionManager", "SmsManager",
             "setAttestationChallenge", "ANDROID_ID", "KeyGenParameterSpec"],
            dex, manifest_text, "Review whether device, SIM, hardware, and service identity are combined and server-verified. API presence alone does not prove binding."))
        results.append(self._finding("STA-REG-02", "Remote access and screen sharing indicators",
            [*REMOTE_PACKAGES, "DisplayManager$DisplayListener", "registerDisplayListener", "MediaProjection", "createScreenCaptureIntent"],
            dex, manifest_text, "Review remote-access package checks, screen capture and virtual-display detection, and whether access is restricted."))
        call_state = ["TelephonyCallback", "PhoneStateListener", "CALL_STATE_OFFHOOK", "CALL_STATE_RINGING"]
        phone_perm = "android.permission.READ_PHONE_STATE" in manifest_permissions
        results.append(self._finding("STA-REG-03", "Active voice call control indicators",
            call_state + (["android.permission.READ_PHONE_STATE"] if phone_perm else []), dex, manifest_text,
            "Confirm user warning or transaction restriction during an active call; static markers do not establish runtime response."))
        results.append(self._finding("STA-REG-04", "Developer options, ADB, and installer integrity indicators",
            ["ADB_ENABLED", "adb_enabled", "DEVELOPMENT_SETTINGS_ENABLED", "development_settings_enabled", "getInstallSourceInfo", "getInstallerPackageName"],
            dex, manifest_text, "Review whether developer/ADB state and installer integrity affect sensitive flows with documented false-positive handling."))
        results.append(self._finding("STA-REG-05", "OTP retrieval and sender validation indicators",
            ["SmsRetrieverClient", "SmsCodeRetriever", "SmsRetriever", "SMS_RETRIEVED_ACTION", "SmsManager", "Pattern.compile"],
            dex, manifest_text, "OTP API use is not itself a weakness. Review consent, SMS Retriever hash binding, sender/origin validation, OTP lifetime, and replay controls."))
        integrity_markers = ["StringFog", "StringEncryption", "getSigningInfo", "GET_SIGNING_CERTIFICATES",
                             "getPackageInfo", "CRC32", "MessageDigest", "verify"]
        results.append(self._finding("STA-REG-06", "Obfuscation and runtime integrity indicators",
            integrity_markers, dex, manifest_text,
            "Review obfuscation/encrypted string handling, runtime signature or checksum verification, and native symbol/debug stripping. Markers do not prove tamper response."))
        native_names = sorted(native)
        native_summary = []
        for name, data in native.items():
            if name.endswith(("libapp.so", "libflutter.so")):
                url_hits = sorted(set(re.findall(rb"https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?", data)))[:10]
                marker_hits = [m.decode("ascii") for m in (b"sha256/", b"CertificatePinner", b"pin-set", b"TrustManager") if m in data]
                native_summary.append(f"{name}: URL candidates={len(url_hits)}, TLS markers={','.join(marker_hits) or 'none'}, .symtab={'present' if b'.symtab' in data else 'absent'}, .debug_info={'present' if b'.debug_info' in data else 'absent'}")
                if url_hits:
                    native_summary.append("endpoint hosts: " + ", ".join(sorted({url.decode("ascii", errors="ignore")[:160] for url in url_hits})))
        if native_summary:
            ix = next(i for i, item in enumerate(results) if item.check_id == "STA-REG-06")
            item = results[ix]
            results[ix] = item.model_copy(update={"evidence": (item.evidence or "") + "\nFlutter/native review: " + "; ".join(native_summary),
                "coverage": {**item.coverage, "native_libraries": native_names}})
        return results

    @staticmethod
    def _finding(rule_id, title, markers, dex, manifest, remediation):
        combined = "\n".join([manifest, *dex.values()])
        hits = sorted(set(marker for marker in markers if marker in combined))
        source_files = [name for name, content in dex.items() if any(marker in content for marker in hits)]
        evidence = ("Potential indicators: " + ", ".join(hits[:30]) if hits else
                    "No recognized static markers found. Absence is inconclusive because of obfuscation, reflection, native code, and dynamic loading.")
        return Finding(check_id=rule_id, title=title, category="Regulatory Mobile Controls", tab_index=8,
            severity=Severity.INFO, status=CheckStatus.NEEDS_REVIEW, analysis_type=AnalysisType.STATIC,
            confidence=Confidence.LOW, confidence_score=0.35,
            description="Static heuristic evidence for manual control verification; not a compliance determination.",
            evidence=evidence + ("\nDEX sources: " + ", ".join(source_files[:20]) if source_files else ""),
            remediation=remediation, source_file=", ".join(source_files[:10]) or None,
            metadata={"matched_markers": hits, "marker_scan_completed": True},
            coverage={"dex_files": len(dex), "manifest_decoded": bool(manifest)})
