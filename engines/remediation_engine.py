# engines/remediation_engine.py
import re
from typing import Dict, Optional

class RemediationEngine:
    """Generates defensive patches and configuration fixes for identified findings."""

    @staticmethod
    def generate_patch(check_id: str, context: Optional[str] = None) -> Dict[str, str]:
        """Returns targeted file path and unified diff string based on check ID."""

        patches = {
            "AND-RECON-02": {
                "file": "AndroidManifest.xml",
                "diff": """--- AndroidManifest.xml
+++ AndroidManifest.xml
@@ -10,3 +10,3 @@
     <application
-        android:debuggable="true"
+        android:debuggable="false"
         android:allowBackup="false"
"""
            },
            "AND-STOR-05": {
                "file": "res/xml/data_extraction_rules.xml",
                "diff": """--- /dev/null
+++ res/xml/data_extraction_rules.xml
@@ -0,0 +1,9 @@
+<?xml version="1.0" encoding="utf-8"?>
+<data-extraction-rules>
+    <cloud-backup>
+        <exclude domain="database" />
+        <exclude domain="sharedpref" />
+    </cloud-backup>
+    <device-transfer>
+        <exclude domain="database" />
+        <exclude domain="sharedpref" />
+    </device-transfer>
+</data-extraction-rules>
"""
            },
            "AND-CRYP-01": {
                "file": "CryptoHelper.kt",
                "diff": """--- InsecureCrypto.kt
+++ SecureCrypto.kt
@@ -1,5 +1,8 @@
-val cipher = Cipher.getInstance("DES")
-cipher.init(Cipher.ENCRYPT_MODE, secretKey)
+// Migrated to AES-GCM with authenticated encryption
+val cipher = Cipher.getInstance("AES/GCM/NoPadding")
+val spec = GCMParameterSpec(128, initializationVector)
+cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
"""
            },
            "AND-PLAT-08": {
                "file": "AndroidManifest.xml",
                "diff": """--- AndroidManifest.xml
+++ AndroidManifest.xml
@@ -20,2 +20,3 @@
         <activity
             android:name=".TargetActivity"
-            android:exported="true">
+            android:exported="false">
"""
            },
            "AND-CODE-07": {
                "file": "app/build.gradle",
                "diff": """--- app/build.gradle
+++ app/build.gradle
@@ -25,4 +25,4 @@
         release {
-            minifyEnabled false
-            shrinkResources false
+            minifyEnabled true
+            shrinkResources true
             proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
         }
"""
            }
        }

        return patches.get(
            check_id,
            {
                "file": "N/A",
                "diff": "# No automated patch template available. Consult MASVS remediation guide."
            }
        )