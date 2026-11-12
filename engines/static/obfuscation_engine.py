# engines/static/obfuscation_engine.py
import re
import zipfile
from typing import List, Set
from core.models import Finding, Severity, CheckStatus

class ObfuscationEngine:
    def __init__(self, apk_path: str, package_name: str):
        self.apk_path = apk_path
        self.package_name = package_name.replace(".", "/")

    def audit_code_obfuscation(self) -> List[Finding]:
        findings: List[Finding] = []

        total_app_classes = 0
        minified_classes = 0
        has_sourcefile_tags = False

        class_regex = re.compile(rf"L{re.escape(self.package_name)}/([a-zA-Z0-9_\$]+);")

        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]

            for dex in dex_files:
                data = z.read(dex)

                # Check for SourceFile debug metadata
                if b"SourceFile" in data:
                    has_sourcefile_tags = True

                # Extract classes belonging specifically to the application's package namespace
                text_content = data.decode("latin-1", errors="ignore")
                matches = class_regex.findall(text_content)

                unique_classes: Set[str] = set(matches)
                for class_name in unique_classes:
                    total_app_classes += 1
                    # Single- or double-character names typically represent ProGuard/R8 renaming (e.g., a, b, c1)
                    if len(class_name.split("$")[-1]) <= 2:
                        minified_classes += 1

        if total_app_classes > 0:
            obfuscation_ratio = (minified_classes / total_app_classes) * 100

            if obfuscation_ratio < 30.0:
                findings.append(Finding(
                    check_id="AND-CODE-07",
                    title="Code Obfuscation Not Detected (ProGuard / R8 Disabled)",
                    category="MASVS-CODE",
                    tab_index=7,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.FAIL,
                    description=(
                        f"Only {minified_classes} of {total_app_classes} application classes ({obfuscation_ratio:.1f}%) "
                        "appear minified. Original class and method names remain easily readable in bytecode."
                    ),
                    evidence=f"Analyzed {total_app_classes} classes in package '{self.package_name}'. Obfuscation score: {obfuscation_ratio:.1f}%",
                    remediation="Enable minifyEnabled true and shrinkResources true in the release buildType within build.gradle."
                ))
            else:
                findings.append(Finding(
                    check_id="AND-CODE-07",
                    title=f"Code Obfuscation Confirmed ({obfuscation_ratio:.1f}% Minification)",
                    category="MASVS-CODE",
                    tab_index=7,
                    severity=Severity.INFO,
                    status=CheckStatus.PASS,
                    description="Application classes are minified and obfuscated with ProGuard or R8.",
                    evidence=f"{minified_classes} of {total_app_classes} classes use shortened names.",
                    remediation=None
                ))

        if has_sourcefile_tags:
            findings.append(Finding(
                check_id="AND-CODE-08",
                title="Debugging Info & SourceFile Identifiers Retained",
                category="MASVS-CODE",
                tab_index=7,
                severity=Severity.LOW,
                status=CheckStatus.NEEDS_REVIEW,
                description="SourceFile attributes were detected in DEX data. Original Java/Kotlin file names may leak in stack traces.",
                evidence="SourceFile debugging tags identified in classes.dex.",
                remediation="Add '-renamesourcefileattribute SourceFile' and '-keepattributes !SourceFile,!LineNumberTable' to proguard-rules.pro."
            ))

        return findings