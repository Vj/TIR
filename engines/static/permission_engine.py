# engines/static/permission_engine.py
import xml.etree.ElementTree as ET
from typing import List, Dict, Any


class PermissionAnalyzer:
    """Analyzes declared Android permissions and maps them to OWASP MASVS risk classifications."""

    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_CONTACTS": {
            "level": "Dangerous (Runtime)",
            "risk": "Grants access to address book and contact details, posing user data privacy risks.",
            "rec": "Ensure permission is requested with in-context justification and strictly guarded."
        },
        "android.permission.WRITE_CONTACTS": {
            "level": "Dangerous (Runtime)",
            "risk": "Allows modification or deletion of user contacts.",
            "rec": "Remove if contact modification is not core to app functionality."
        },
        "android.permission.ACCESS_FINE_LOCATION": {
            "level": "Dangerous (Runtime)",
            "risk": "Provides continuous, high-precision GPS coordinates.",
            "rec": "Consider downgrading to ACCESS_COARSE_LOCATION if precise meter-level accuracy is unnecessary."
        },
        "android.permission.ACCESS_COARSE_LOCATION": {
            "level": "Dangerous (Runtime)",
            "risk": "Provides approximate network-based location.",
            "rec": "Request only when foreground location access is actively required."
        },
        "android.permission.RECORD_AUDIO": {
            "level": "Dangerous (Runtime)",
            "risk": "Enables microphone access to capture ambient audio.",
            "rec": "Enforce explicit user prompts before opening microphone channels."
        },
        "android.permission.CAMERA": {
            "level": "Dangerous (Runtime)",
            "risk": "Enables camera sensor capture.",
            "rec": "Enforce runtime permission requests and clear indicator states."
        },
        "android.permission.READ_EXTERNAL_STORAGE": {
            "level": "Dangerous / Legacy",
            "risk": "Allows global read access to shared external storage directories.",
            "rec": "Migrate to Scoped Storage (MediaStore API or Storage Access Framework)."
        },
        "android.permission.WRITE_EXTERNAL_STORAGE": {
            "level": "Dangerous / Legacy",
            "risk": "Allows modification or writing of files across shared storage.",
            "rec": "Target Android 10+ (API 29+) Scoped Storage and deprecate broad write access."
        },
        "android.permission.SEND_SMS": {
            "level": "Dangerous (Runtime)",
            "risk": "Allows sending SMS messages, which could result in unintended toll charges or data leakage.",
            "rec": "Verify SMS transmission is strictly necessary and protected from automated injection."
        },
        "android.permission.READ_SMS": {
            "level": "Dangerous (Runtime)",
            "risk": "Enables reading incoming and stored SMS messages (e.g., OTPs, 2FA codes).",
            "rec": "Use SMS Retriever API or User Consent API instead of requesting broad READ_SMS."
        },
    }

    def __init__(self, manifest_xml: str):
        self.manifest_xml = manifest_xml

    def analyze_permissions(self) -> List[Dict[str, Any]]:
        results = []
        if not self.manifest_xml:
            return results

        try:
            root = ET.fromstring(self.manifest_xml)
            for elem in root.findall(".//uses-permission"):
                name = elem.attrib.get("{http://schemas.android.com/apk/res/android}name", "")
                if not name:
                    continue

                info = self.DANGEROUS_PERMISSIONS.get(name)
                if info:
                    results.append({
                        "name": name,
                        "protection_level": info["level"],
                        "category": "Sensitive / Dangerous",
                        "risk_analysis": info["risk"],
                        "recommendation": info["rec"],
                    })
                else:
                    results.append({
                        "name": name,
                        "protection_level": "Normal (Install-time)",
                        "category": "Standard",
                        "risk_analysis": "Standard system permission requested at install time.",
                        "recommendation": "Maintain least-privilege principles.",
                    })
        except Exception:
            pass

        return sorted(results, key=lambda x: (x["category"] != "Sensitive / Dangerous", x["name"]))