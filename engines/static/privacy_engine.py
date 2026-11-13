import zipfile
import re
from typing import List, Dict, Set
from core.models import Finding, Severity, CheckStatus

class PrivacyEngine:
    def __init__(self, apk_path: str, permissions: List[str], target_sdk=None):
        self.apk_path = apk_path
        self.permissions = set(permissions)
        try:
            self.target_sdk = int(target_sdk) if target_sdk is not None else None
        except (TypeError, ValueError):
            self.target_sdk = None

    def audit_tab09_privacy(self) -> List[Finding]:
        findings = []

        # Known Tracking & Analytics Package Signatures
        known_trackers = {
            "com.adjust.sdk": "Adjust Analytics",
            "com.appsflyer": "AppsFlyer Attribution",
            "com.google.firebase.analytics": "Google Firebase Analytics",
            "com.facebook.appevents": "Facebook App Events",
            "com.flurry": "Flurry Analytics",
            "com.mixpanel.android": "Mixpanel",
            "io.branch.referral": "Branch Metrics"
        }

        # 1. AND-PRIV-01: Sensitive Permissions Audit
        sensitive_perms = {
            "android.permission.ACCESS_FINE_LOCATION": "Precise GPS Location",
            "android.permission.ACCESS_BACKGROUND_LOCATION": "Continuous Background Location",
            "android.permission.READ_CONTACTS": "User Address Book",
            "android.permission.READ_SMS": "SMS Messages / OTPs",
            "android.permission.RECORD_AUDIO": "Device Microphone",
            "android.permission.CAMERA": "Device Camera",
            "android.permission.READ_PHONE_STATE": "Telephony State & Device Identifiers"
        }

        declared_sensitive = [
            f"{perm} ({desc})"
            for perm, desc in sensitive_perms.items()
            if perm in self.permissions
        ]

        if declared_sensitive:
            findings.append(Finding(
                check_id="AND-PRIV-01",
                title="Privacy-Sensitive Permissions Requested",
                category="MASVS-PRIVACY",
                tab_index=9,
                severity=Severity.LOW,
                status=CheckStatus.NEEDS_REVIEW,
                description="Application declares access to high-impact privacy permissions. Verify data minimization compliance.",
                evidence="Declared permissions:\n" + "\n".join(f"- {p}" for p in declared_sensitive),
                remediation="Remove unnecessary permissions and use modern storage/media pickers that avoid broad access."
            ))

        # 2. AND-PRIV-02 & AND-PRIV-03: SDK Detection & AAID Audit in DEX
        found_trackers: Set[str] = set()
        has_aaid_api = False
        has_hardware_identifiers = False

        hardware_id_patterns = [
            b"Landroid/telephony/TelephonyManager;->getDeviceId",
            b"Landroid/telephony/TelephonyManager;->getImei",
            b"Landroid/net/wifi/WifiInfo;->getMacAddress"
        ]

        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]

            for dex in dex_files:
                data = z.read(dex)

                # Match known tracker namespaces
                for pkg_prefix, name in known_trackers.items():
                    if pkg_prefix.replace(".", "/").encode() in data:
                        found_trackers.add(name)

                # AAID API usage
                if b"AdvertisingIdClient" in data:
                    has_aaid_api = True

                # Hardware identifier calls
                for pat in hardware_id_patterns:
                    if pat in data:
                        has_hardware_identifiers = True

        if found_trackers:
            findings.append(Finding(
                check_id="AND-PRIV-02",
                title=f"Third-Party Trackers Identified ({len(found_trackers)})",
                category="MASVS-PRIVACY",
                tab_index=9,
                severity=Severity.INFO,
                status=CheckStatus.NEEDS_REVIEW,
                description="Third-party tracking and telemetry SDKs detected in application bytecode.",
                evidence="Identified SDKs:\n" + "\n".join(f"- {t}" for t in found_trackers),
                remediation="Ensure all third-party tracker data sharing is explicitly covered under your privacy policy."
            ))

        # AND-PRIV-03: AAID vs Hardware Identifiers
        if has_hardware_identifiers:
            findings.append(Finding(
                check_id="AND-PRIV-03",
                title="Non-Resettable Hardware Identifiers Accessed",
                category="MASVS-PRIVACY",
                tab_index=9,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description="TelephonyManager/WifiInfo calls detected that access permanent hardware IDs (IMEI/MAC).",
                evidence="Bytecode contains invocations of getDeviceId, getImei, or getMacAddress.",
                remediation="Use the resettable Google Advertising ID (AAID) or app-set GUIDs instead of permanent device serials."
            ))
        elif has_aaid_api:
            has_ad_perm = "com.google.android.gms.permission.AD_ID" in self.permissions
            # AD_ID is required for apps targeting API 33+, not older targets.
            permission_required = self.target_sdk is None or self.target_sdk >= 33
            if not has_ad_perm and not permission_required:
                return findings
            findings.append(Finding(
                check_id="AND-PRIV-03",
                title="Advertising Identifier (AAID) In Use",
                category="MASVS-PRIVACY",
                tab_index=9,
                severity=Severity.INFO if has_ad_perm else Severity.LOW,
                status=CheckStatus.PASS if has_ad_perm else CheckStatus.NEEDS_REVIEW,
                description="Application uses AdvertisingIdClient with appropriate permission declaration." if has_ad_perm else "Application calls AdvertisingIdClient but is missing the AD_ID permission declaration.",
                evidence=f"AD_ID permission declared: {has_ad_perm}"
            ))

        # 3. AND-PRIV-04: Location Polling Audit
        if "android.permission.ACCESS_BACKGROUND_LOCATION" in self.permissions:
            findings.append(Finding(
                check_id="AND-PRIV-04",
                title="Continuous Background Location Requested",
                category="MASVS-PRIVACY",
                tab_index=9,
                severity=Severity.MEDIUM,
                status=CheckStatus.NEEDS_REVIEW,
                description="ACCESS_BACKGROUND_LOCATION is declared. Google Play requires justification for continuous background tracking.",
                evidence="android.permission.ACCESS_BACKGROUND_LOCATION found in manifest.",
                remediation="Limit location access to foreground operations using foreground services with while-in-use types."
            ))

        return findings