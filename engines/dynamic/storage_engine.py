import re
from typing import List, Dict, Any
from core.models import Finding, Severity, CheckStatus

class StorageEngine:
    def __init__(self, adb_bridge, package_name: str, device_id: str):
        self.adb = adb_bridge
        self.pkg = package_name
        self.dev = device_id

    def execute_stor_01(self) -> List[Finding]:
        """AND-STOR-01: Plaintext data in SharedPreferences."""
        findings = []
        # Query shared preferences directory via app sandbox
        cmd = f"run-as {self.pkg} ls /data/data/{self.pkg}/shared_prefs/"
        files = self.adb.run_cmd(["-s", self.dev, "shell", cmd]).splitlines()

        sensitive_regex = re.compile(r"(password|token|secret|key|bearer|auth|ssn)", re.IGNORECASE)

        for pref_file in files:
            pref_file = pref_file.strip()
            if not pref_file.endswith(".xml"):
                continue

            read_cmd = f"run-as {self.pkg} cat /data/data/{self.pkg}/shared_prefs/{pref_file}"
            content = self.adb.run_cmd(["-s", self.dev, "shell", read_cmd])

            for line in content.splitlines():
                if sensitive_regex.search(line) and not re.search(r"EncryptedSharedPreferences", content):
                    findings.append(Finding(
                        check_id="AND-STOR-01",
                        title=f"Sensitive Plaintext Key in {pref_file}",
                        category="MASVS-STORAGE",
                        tab_index=2,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description="Plaintext credential/token pattern detected in SharedPreferences XML.",
                        evidence=line.strip(),
                        remediation="Use androidx.security.crypto.EncryptedSharedPreferences."
                    ))
        return findings

    def execute_stor_02(self) -> List[Finding]:
        """AND-STOR-02: SQLite / Room Unencrypted Storage Check."""
        findings = []
        cmd = f"run-as {self.pkg} ls /data/data/{self.pkg}/databases/"
        db_files = self.adb.run_cmd(["-s", self.dev, "shell", cmd]).splitlines()

        for db_file in db_files:
            db_file = db_file.strip()
            if db_file.endswith((".db", ".sqlite")):
                header_cmd = f"run-as {self.pkg} head -c 16 /data/data/{self.pkg}/databases/{db_file}"
                header = self.adb.run_cmd(["-s", self.dev, "shell", header_cmd])
                
                # Standard SQLite header string
                if "SQLite format 3" in header:
                    findings.append(Finding(
                        check_id="AND-STOR-02",
                        title=f"Unencrypted Database: {db_file}",
                        category="MASVS-STORAGE",
                        tab_index=2,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description=f"Database file '{db_file}' is a standard unencrypted SQLite file.",
                        evidence=f"Header: {header}",
                        remediation="Encrypt local database files using SQLCipher or Android Room encryption wrappers."
                    ))
        return findings

    def execute_stor_08(self, apk_manifest_xml: str) -> Finding:
        """AND-STOR-08: Screen Caching via FLAG_SECURE Check."""
        # AST string search check
        has_flag_secure = "FLAG_SECURE" in apk_manifest_xml or "setFlags(8192" in apk_manifest_xml

        if not has_flag_secure:
            return Finding(
                check_id="AND-STOR-08",
                title="Application Window Does Not Set FLAG_SECURE",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.LOW,
                status=CheckStatus.NEEDS_REVIEW,
                description="FLAG_SECURE was not detected in bytecode or configurations. Application switcher snapshots may cache sensitive screens.",
                evidence="No FLAG_SECURE usage found across primary activities.",
                remediation="Add window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) in activities handling sensitive data."
            )
        return Finding(
            check_id="AND-STOR-08",
            title="Application Restricts Screen Caching",
            category="MASVS-STORAGE",
            tab_index=2,
            severity=Severity.INFO,
            status=CheckStatus.PASS,
            description="FLAG_SECURE reference detected.",
            remediation=None
        )