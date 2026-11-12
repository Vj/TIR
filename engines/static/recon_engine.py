# engines/static/recon_engine.py
import re
import zipfile
from typing import Dict, List, Any
from lxml import etree
from pyaxmlparser import APK

class ReconEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk = APK(apk_path)
        
    def get_manifest_string(self) -> str:
        """Retrieves AndroidManifest.xml as a decoded string."""
        raw_manifest = self.apk.get_android_manifest_xml()
        if isinstance(raw_manifest, (str, bytes)):
            return raw_manifest if isinstance(raw_manifest, str) else raw_manifest.decode("utf-8", errors="ignore")
        try:
            return etree.tostring(raw_manifest, encoding="utf-8").decode("utf-8", errors="ignore")
        except Exception:
            return str(raw_manifest)

    def execute_recon_01(self) -> Dict[str, Any]:
        """AND-RECON-01: App Identity and Signature Verification."""
        return {
            "package_name": self.apk.package,
            "version_name": self.apk.version_name,
            "version_code": self.apk.version_code,
            "min_sdk": self.apk.get_min_sdk_version(),
            "target_sdk": self.apk.get_target_sdk_version(),
            "is_signed": self.apk.is_signed(),
            "is_v1_signed": self.apk.is_signed_v1(),
            "is_v2_signed": self.apk.is_signed_v2(),
            "is_v3_signed": self.apk.is_signed_v3(),
        }

    def execute_recon_02(self) -> Dict[str, Any]:
        """AND-RECON-02: Manifest Security Flags & Permissions."""
        manifest_str = self.get_manifest_string()
        
        debuggable = bool(re.search(r'android:debuggable=["\']true["\']', manifest_str, re.IGNORECASE))
        allow_backup = not bool(re.search(r'android:allowBackup=["\']false["\']', manifest_str, re.IGNORECASE))
        
        return {
            "debuggable": debuggable,
            "allow_backup": allow_backup,
            "permissions": self.apk.get_permissions(),
            "activities": self.apk.get_activities(),
            "services": self.apk.get_services(),
            "receivers": self.apk.get_receivers(),
            "providers": self.apk.get_providers(),
        }

    def execute_recon_03(self) -> List[Dict[str, Any]]:
        """AND-RECON-03: URL Schemes and App Links."""
        manifest_str = self.get_manifest_string()
        scheme_matches = re.findall(r'<data\s+[^>]*android:scheme=["\']([^"\']+)["\']', manifest_str)
        host_matches = re.findall(r'<data\s+[^>]*android:host=["\']([^"\']+)["\']', manifest_str)
        
        return [
            {"scheme": s, "host": host_matches[i] if i < len(host_matches) else "*"}
            for i, s in enumerate(set(scheme_matches))
        ]

    def execute_recon_04(self) -> List[Dict[str, str]]:
        """AND-RECON-04: Hardcoded Secrets Scanner."""
        findings = []
        patterns = {
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Generic Bearer Token": r"Bearer\s+[A-Za-z0-9_\-\.]{20,}",
            "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
            "Standard Internal URL": r"https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        }
        
        with zipfile.ZipFile(self.apk_path, "r") as z:
            for filename in z.namelist():
                if filename.endswith(".dex") or filename.startswith("res/"):
                    content = z.read(filename).decode("latin-1", errors="ignore")
                    for secret_type, regex in patterns.items():
                        matches = set(re.findall(regex, content))
                        for match in matches:
                            findings.append({
                                "file": filename,
                                "type": secret_type,
                                "match": match[:30] + "..." if len(match) > 30 else match
                            })
        return findings