import zipfile
import xml.etree.ElementTree as ET
from pyaxmlparser import APK

class ManifestEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk_obj = APK(apk_path)

    def get_metadata(self) -> dict:
        return {
            "package": self.apk_obj.package,
            "version_name": self.apk_obj.version_name,
            "version_code": self.apk_obj.version_code,
            "min_sdk": self.apk_obj.get_min_sdk_version(),
            "target_sdk": self.apk_obj.get_target_sdk_version(),
            "permissions": self.apk_obj.get_permissions(),
        }

    def inspect_security_flags(self) -> dict:
        xml_str = self.apk_obj.get_android_manifest_xml()
        root = ET.fromstring(xml_str)
        application = root.find("application")
        
        flags = {
            "debuggable": False,
            "allowBackup": True,  # Android default if omitted
            "networkSecurityConfig": None,
        }
        
        if application is not None:
            # Check android:debuggable
            flags["debuggable"] = application.attrib.get(
                "{http://schemas.android.com/apk/res/android}debuggable", "false"
            ).lower() == "true"
            
            # Check android:allowBackup
            flags["allowBackup"] = application.attrib.get(
                "{http://schemas.android.com/apk/res/android}allowBackup", "true"
            ).lower() == "true"
            
            # Check network security config
            flags["networkSecurityConfig"] = application.attrib.get(
                "{http://schemas.android.com/apk/res/android}networkSecurityConfig"
            )
            
        return flags