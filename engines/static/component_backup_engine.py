# engines/static/component_backup_engine.py
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from core.models import AnalysisType, Finding, Severity, CheckStatus


class ComponentBackupEngine:
    def __init__(self, apk_path: str, manifest_xml: str):
        self.apk_path = apk_path
        self.manifest_xml = manifest_xml
        self.ns = {"android": "http://schemas.android.com/apk/res/android"}
        self._parsed_manifest = self._parse_manifest_tree()

    def _parse_manifest_tree(self):
        try:
            return ET.fromstring(self.manifest_xml)
        except Exception:
            return None

    def audit_exported_components(self) -> List[Finding]:
        """Audits Activities, Services, and Broadcast Receivers for exposure gaps (Tabs 01 & 06)."""
        findings: List[Finding] = []
        if self._parsed_manifest is None:
            return findings

        # Extract package identifier from root manifest element
        pkg_name = self._parsed_manifest.attrib.get("package", "")

        app_elem = self._parsed_manifest.find("application")
        if app_elem is None:
            return findings

        component_tags = {
            "activity": ("Activity", 6),
            "service": ("Service", 6),
            "receiver": ("Broadcast Receiver", 6)
        }

        for tag, (comp_type, tab_idx) in component_tags.items():
            for elem in app_elem.findall(tag):
                name = elem.attrib.get(f"{{{self.ns['android']}}}name", "Unknown")
                permission = elem.attrib.get(f"{{{self.ns['android']}}}permission")
                intent_filters = elem.findall("intent-filter")

                # Android default behavior: exported=true if intent-filters exist and not explicitly set
                raw_exported = elem.attrib.get(f"{{{self.ns['android']}}}exported")
                if raw_exported is not None:
                    is_exported = raw_exported.lower() == "true"
                else:
                    is_exported = len(intent_filters) > 0

                # Flag exported components lacking protective permissions
                if is_exported and not permission:
                    # Ignore the launcher activity since it must be exported
                    is_launcher = False
                    for ifilter in intent_filters:
                        for action in ifilter.findall("action"):
                            action_name = action.attrib.get(f"{{{self.ns['android']}}}name", "")
                            if action_name == "android.intent.action.MAIN":
                                is_launcher = True

                    if not is_launcher:
                        target_comp = f"{pkg_name}/{name}" if pkg_name else name
                        findings.append(Finding(
                            check_id="AND-PLAT-08",
                            title=f"Exported Unprotected {comp_type}: {name.split('.')[-1]}",
                            category="MASVS-PLATFORM",
                            tab_index=tab_idx,
                            severity=Severity.HIGH if comp_type != "Broadcast Receiver" else Severity.MEDIUM,
                            status=CheckStatus.FAIL,
                            analysis_type=AnalysisType.STATIC,
                            description=f"{comp_type} '{name}' is exported to other applications without permission restrictions.",
                            affected_component=target_comp,
                            source_file="AndroidManifest.xml",
                            cwe_id="CWE-926: Improper Export of Android Application Components",
                            masvs_ref="MASVS-PLATFORM-1",
                            mastg_ref="MASTG-TEST-0029",
                            evidence=(
                                f"Component: {name}\n"
                                f"Type: {comp_type}\n"
                                f"Explicitly Exported: {raw_exported}\n"
                                f"Effective Exported: {is_exported}\n"
                                f"Intent Filters Count: {len(intent_filters)}"
                            ),
                            remediation="Set android:exported='false' if external access is unnecessary, or define android:permission with protectionLevel='signature'."
                        ))

        return findings
    '''
    def audit_exported_components(self) -> List[Finding]:
        """Audits Activities, Services, and Broadcast Receivers for exposure gaps (Tabs 01 & 06)."""
        findings: List[Finding] = []
        if self._parsed_manifest is None:
            return findings

        app_elem = self._parsed_manifest.find("application")
        if app_elem is None:
            return findings

        component_tags = {
            "activity": ("Activity", 6),
            "service": ("Service", 6),
            "receiver": ("Broadcast Receiver", 6)
        }
        pkg_name = "<pkg>"
        if self._parsed_manifest is not None:
            pkg_name = self._parsed_manifest.attrib.get("package", "<pkg>")
        
        for tag, (comp_type, tab_idx) in component_tags.items():
            for elem in app_elem.findall(tag):
                name = elem.attrib.get(f"{{{self.ns['android']}}}name", "Unknown")
                permission = elem.attrib.get(f"{{{self.ns['android']}}}permission")
                intent_filters = elem.findall("intent-filter")

                # Android default behavior: exported=true if intent-filters exist and not explicitly set
                raw_exported = elem.attrib.get(f"{{{self.ns['android']}}}exported")
                if raw_exported is not None:
                    is_exported = raw_exported.lower() == "true"
                else:
                    is_exported = len(intent_filters) > 0

                # Flag exported components lacking protective permissions
                if is_exported and not permission:
                    # Ignore the launcher activity since it must be exported
                    is_launcher = False
                    for ifilter in intent_filters:
                        for action in ifilter.findall("action"):
                            action_name = action.attrib.get(f"{{{self.ns['android']}}}name", "")
                            if action_name == "android.intent.action.MAIN":
                                is_launcher = True

                    if not is_launcher:
                        full_comp = name if "." in name else f"{pkg_name}.{name}"
                        poc_cmd = f"adb shell am start -n {self.metadata.get('package_name', '<pkg>')}/{name}"
                        findings.append(Finding(
                            check_id="AND-PLAT-08",
                            title=f"Exported Unprotected {comp_type}: {name.split('.')[-1]}",
                            category="MASVS-PLATFORM",
                            tab_index=tab_idx,
                            severity=Severity.HIGH if comp_type != "Broadcast Receiver" else Severity.MEDIUM,
                            status=CheckStatus.FAIL,
                            description=f"{comp_type} '{name}' is exported to other applications without permission restrictions.",
                            affected_component=full_comp,
                            source_file="AndroidManifest.xml",
                            cwe_id="CWE-926: Improper Export of Android Application Components",
                            masvs_ref="MASVS-PLATFORM-1",
                            mastg_ref="MASTG-TEST-0029",
                            poc_preconditions="Device or emulator running with USB debugging enabled. Target app installed.",
                            poc_command=poc_cmd,
                            poc_expected="System rejects invocation with SecurityException or redirects to authentication gate.",
                            poc_observed="Component launches directly in the foreground, bypassing intent origin validation.",
                            reproduction_sequence=[
                                f"# Verify package is installed",
                                f"adb shell pm list packages | grep {pkg_name}",
                                f"# Invoke exported component",
                                poc_cmd
                            ],
                            evidence=(
                                f"Component: {name}\n"
                                f"Type: {comp_type}\n"
                                f"Explicitly Exported: {raw_exported}\n"
                                f"Effective Exported: {is_exported}\n"
                                f"Intent Filters Count: {len(intent_filters)}"
                            ),
                            remediation="Set android:exported='false' if external access is unnecessary, or define android:permission with protectionLevel='signature'."
                        ))

        return findings
'''
    def audit_backup_configurations(self) -> List[Finding]:
        """Deep-scans backup_rules.xml and fullBackupContent definitions (Tab 02)."""
        findings: List[Finding] = []
        if self._parsed_manifest is None:
            return findings

        app_elem = self._parsed_manifest.find("application")
        if app_elem is None:
            return findings

        allow_backup = app_elem.attrib.get(f"{{{self.ns['android']}}}allowBackup", "true").lower() == "true"
        full_backup_content = app_elem.attrib.get(f"{{{self.ns['android']}}}fullBackupContent")
        data_extraction_rules = app_elem.attrib.get(f"{{{self.ns['android']}}}dataExtractionRules")

        if not allow_backup:
            findings.append(Finding(
                check_id="AND-STOR-05",
                title="Android Backup Disabled",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                description="android:allowBackup is explicitly set to false, preventing unauthorized ADB and cloud backups.",
                affected_component="<application>",
                source_file="AndroidManifest.xml",
                cwe_id="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                masvs_ref="MASVS-STORAGE-2",
                mastg_ref="MASTG-TEST-0005",
                evidence="android:allowBackup='false'",
                remediation=None
            ))
            return findings

        # allowBackup is true: audit backup filter declarations
        with zipfile.ZipFile(self.apk_path, "r") as z:
            xml_files = [f for f in z.namelist() if f.startswith("res/xml/") and f.endswith(".xml")]

            rules_checked = False
            for xml_file in xml_files:
                # Target common backup config naming
                if "backup" in xml_file.lower():
                    rules_checked = True
                    try:
                        content = z.read(xml_file).decode("utf-8", errors="ignore")
                        # Check if sensitive subpaths are explicitly included
                        if re.search(r'<include[^>]+domain=["\'](sharedpref|database)["\']', content):
                            findings.append(Finding(
                                check_id="AND-STOR-05",
                                title="Backup Rules Include Sensitive Storage Domains",
                                category="MASVS-STORAGE",
                                tab_index=2,
                                severity=Severity.HIGH,
                                status=CheckStatus.FAIL,
                                description=f"Backup configuration '{xml_file}' includes databases or shared preferences in cloud/device backups.",
                                affected_component=xml_file,
                                source_file=xml_file,
                                cwe_id="CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory",
                                masvs_ref="MASVS-STORAGE-2",
                                mastg_ref="MASTG-TEST-0005",
                                evidence=f"File: {xml_file}\nMatched rule entries:\n" + "\n".join(re.findall(r'<include[^>]+>', content)),
                                remediation="Add <exclude domain='database' .../> and <exclude domain='sharedpref' .../> rules, or store sensitive items using EncryptedSharedPreferences."
                            ))
                    except Exception:
                        continue

            if not rules_checked and (full_backup_content is None and data_extraction_rules is None):
                findings.append(Finding(
                    check_id="AND-STOR-05",
                    title="Full Backup Permitted Without Exclusion Rules",
                    category="MASVS-STORAGE",
                    tab_index=2,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.FAIL,
                    description="android:allowBackup is enabled with no fullBackupContent or dataExtractionRules specified. All sandbox files will be backed up by default.",
                    affected_component="<application>",
                    source_file="AndroidManifest.xml",
                    cwe_id="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                    masvs_ref="MASVS-STORAGE-2",
                    mastg_ref="MASTG-TEST-0005",
                    evidence="android:allowBackup='true' with no exclusion filter configured.",
                    remediation="Set android:allowBackup='false' or define a data_extraction_rules.xml resource excluding private application storage."
                ))

        return findings