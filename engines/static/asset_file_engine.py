# engines/static/asset_file_engine.py
import re
import zipfile
from typing import List, Dict, Any
from core.models import Finding, Severity, CheckStatus

class AssetFileEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

        # Sensitive file extensions that should never be bundled in production
        self.dangerous_extensions = {
            ".jks": ("Java Keystore file", Severity.CRITICAL),
            ".keystore": ("Android Keystore file", Severity.CRITICAL),
            ".p12": ("PKCS#12 Certificate / Private Key store", Severity.CRITICAL),
            ".pfx": ("PKCS#12 Certificate / Private Key store", Severity.CRITICAL),
            ".pem": ("PEM encoded certificate or private key", Severity.HIGH),
            ".key": ("Raw Private Key file", Severity.CRITICAL),
            ".sql": ("Raw SQLite / SQL database dump", Severity.HIGH),
            ".sqlite": ("Embedded SQLite database file", Severity.MEDIUM),
            ".db": ("Embedded database file", Severity.MEDIUM),
            ".env": ("Environment configuration file", Severity.HIGH),
            ".conf": ("Raw configuration file", Severity.LOW),
            ".bak": ("Backup artifact file", Severity.MEDIUM),
            ".swp": ("Vim swap/backup file", Severity.LOW),
            ".log": ("Bundled runtime or build log file", Severity.LOW),
        }

        # Regex patterns targeting secrets inside bundled text/config files
        self.secret_patterns = {
            "Embedded Private Key": re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
            "JWT / Bearer Token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"),
            "AWS Access Key": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
            "Google Cloud API Key": re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
            "Basic Auth / Password in URL": re.compile(r"https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\.-]+"),
            "Hardcoded Generic Secret": re.compile(r'(?i)(api[_-]?key|client[_-]?secret|auth[_-]?token|password)\s*[:=]\s*["\']([^"\']{6,})["\']')
        }

    def audit_assets_and_resources(self) -> List[Finding]:
        findings: List[Finding] = []
        scannable_text_exts = (".json", ".xml", ".properties", ".txt", ".env", ".yaml", ".yml", ".conf", ".js")

        with zipfile.ZipFile(self.apk_path, "r") as z:
            namelist = z.namelist()

            for filename in namelist:
                lower_name = filename.lower()

                # Ignore DEX files, standard compiled images/fonts, and standard Android layout resources
                if lower_name.endswith((".dex", ".png", ".jpg", ".webp", ".gif", ".ttf", ".otf")):
                    continue

                # 1. Check for Dangerous File Extensions (Tab 07 - Build Hygiene)
                for ext, (desc, severity) in self.dangerous_extensions.items():
                    if lower_name.endswith(ext):
                        findings.append(Finding(
                            check_id="AND-CODE-06",
                            title=f"Bundled Sensitive File Detected: {filename.split('/')[-1]}",
                            category="MASVS-CODE",
                            tab_index=7,
                            severity=severity,
                            status=CheckStatus.FAIL,
                            description=f"The APK bundle contains an artifact of type '{desc}' at path '{filename}'.",
                            evidence=f"File: {filename}\nType: {desc}",
                            remediation="Remove build artifacts, private keys, keystores, and SQL files from the assets/ and res/ directories before releasing production builds."
                        ))

                # 2. Deep-scan text/data assets for embedded secrets (Tab 01 - Recon & Secrets)
                if lower_name.startswith("assets/") or lower_name.startswith("res/raw/") or lower_name.endswith(scannable_text_exts):
                    try:
                        content = z.read(filename).decode("utf-8", errors="ignore")
                    except Exception:
                        continue

                    for secret_name, regex in self.secret_patterns.items():
                        matches = regex.findall(content)
                        if matches:
                            # Truncate evidence string to avoid dumping full credentials into report
                            first_match = matches[0]
                            if isinstance(first_match, tuple):
                                match_sample = f"{first_match[0]}={first_match[1][:6]}..."
                            else:
                                match_sample = str(first_match)[:25] + "..."

                            findings.append(Finding(
                                check_id="AND-RECON-04",
                                title=f"High-Entropy Secret in Asset: {filename.split('/')[-1]}",
                                category="Information Gathering and Static Setup",
                                tab_index=1,
                                severity=Severity.HIGH,
                                status=CheckStatus.FAIL,
                                description=f"Found potential secret pattern '{secret_name}' inside bundled asset file.",
                                evidence=f"Asset: {filename}\nPattern: {secret_name}\nSnippet: {match_sample}",
                                remediation="Do not embed production keys or configuration secrets in assets. Retrieve credentials dynamically at runtime using secure key management."
                            ))

        return findings