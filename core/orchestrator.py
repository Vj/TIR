# core/orchestrator.py
import os
import json
import datetime
from typing import List, Dict, Any
from jinja2 import Environment, FileSystemLoader

from core.models import Finding, CheckStatus, Severity, AuditSession
from core.standards import enrich_findings
from engines.static.recon_engine import ReconEngine
from engines.static.crypto_auth_engine import CryptoAuthEngine
from engines.static.network_platform_engine import NetworkPlatformEngine
from engines.static.code_resilience_engine import CodeResilienceEngine
from engines.static.privacy_engine import PrivacyEngine
from engines.static.supply_logging_engine import SupplyChainLoggingEngine
from engines.static.asset_file_engine import AssetFileEngine
from engines.static.component_backup_engine import ComponentBackupEngine
from engines.static.network_advanced_engine import AdvancedNetworkEngine
from engines.static.obfuscation_engine import ObfuscationEngine
from engines.static.advanced_threat_engine import AdvancedThreatEngine
from engines.static.advanced_static_engine import AdvancedStaticEngine

# New extractors
from engines.static.metadata_extractor import APKMetadataExtractor
from engines.static.permission_engine import PermissionAnalyzer
from engines.static.modern_android_engine import ModernAndroidAnalysisEngine


class TIROrchestrator:
    def __init__(self, apk_path: str, template_dir: str = None):
        self.apk_path = apk_path
        
        # Resolve absolute template path relative to project root
        if template_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.template_dir = os.path.join(base_dir, "reporting", "templates")
        else:
            self.template_dir = template_dir

        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        
        # Initialize native static engines
        self.recon = ReconEngine(apk_path)
        self.metadata = self.recon.execute_recon_01()
        self.manifest_flags = self.recon.execute_recon_02()
        manifest_str = self.recon.get_manifest_string()
        
        self.crypto_auth = CryptoAuthEngine(apk_path)
        self.net_plat = NetworkPlatformEngine(apk_path)
        self.code_resil = CodeResilienceEngine(apk_path)
        self.privacy = PrivacyEngine(apk_path, self.metadata.get("permissions", []), self.metadata.get("target_sdk"))
        self.supply_logs = SupplyChainLoggingEngine(apk_path)
        self.asset_scanner = AssetFileEngine(apk_path)
        self.component_backup = ComponentBackupEngine(apk_path, manifest_str)
        self.adv_net_scanner = AdvancedNetworkEngine(apk_path)
        self.obfuscation_scanner = ObfuscationEngine(apk_path, self.metadata.get("package_name", ""))
        self.advanced_threats = AdvancedThreatEngine(apk_path, manifest_str)
        self.advanced_static = AdvancedStaticEngine(
            apk_path, 
            manifest_str, 
            declared_permissions=self.metadata.get("permissions", [])
        )

        # Extended metadata & permission extractors
        self.meta_extractor = APKMetadataExtractor(apk_path)
        self.perm_analyzer = PermissionAnalyzer(manifest_str)
        self.modern_android = ModernAndroidAnalysisEngine(apk_path)
        self.dynamic_targets: Dict[str, Any] = {}

    @staticmethod
    def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
        """Deduplicates findings based on Check ID, title, and target location snippet."""
        unique: Dict[tuple, Finding] = {}
        for f in findings:
            bridge_match = "addjavascriptinterface" in (f.evidence or "").lower() or "javascript interface" in f.title.lower()
            key = ("webview-bridge",) if bridge_match else (f.check_id, f.title.strip(), (f.evidence[:80] if f.evidence else ""))
            if key not in unique or (bridge_match and f.check_id == "STA-024"):
                unique[key] = f
        return list(unique.values())

    def execute_all_automated(self) -> List[Finding]:
        """Runs the standalone automated static analysis pipeline across all 13 tabs."""
        findings: List[Finding] = []

        # ==========================================
        # Tab 01: Setup, Recon & Permissions
        # ==========================================
        if self.manifest_flags.get("debuggable"):
            findings.append(Finding(
                check_id="AND-RECON-02",
                title="Application is Marked Debuggable",
                category="Information Gathering and Static Setup",
                tab_index=1,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description="android:debuggable is set to true in AndroidManifest.xml.",
                evidence="android:debuggable='true'",
                remediation="Set android:debuggable='false' in release builds."
            ))
            
        for sec in self.recon.execute_recon_04():
            findings.append(Finding(
                check_id="AND-RECON-04",
                title=f"Hardcoded Secret Found: {sec['type']}",
                category="Information Gathering and Static Setup",
                tab_index=1,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description=f"Potential embedded secret pattern identified in {sec['file']}.",
                evidence=sec['match'],
                remediation="Store secrets externally or fetch dynamically via authenticated APIs."
            ))

        permissions = self.metadata.get("permissions", [])
        if permissions:
            findings.append(Finding(
                check_id="STA-035",
                title=f"Declared Application Permissions Inventory ({len(permissions)} Found)",
                category="Information Gathering and Static Setup",
                tab_index=1,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                description="Inventory of all permissions declared in AndroidManifest.xml.",
                evidence="\n".join(f"- {p}" for p in permissions),
                remediation=None
            ))

        # ==========================================
        # Asset, Resources & Sensitive File Checks
        # ==========================================
        findings.extend(self.asset_scanner.audit_assets_and_resources())

        # ==========================================
        # Tab 02: Storage & Backup Rules
        # ==========================================
        findings.extend(self.component_backup.audit_backup_configurations())

        # ==========================================
        # Tab 03 & 04: Cryptography & Authentication
        # ==========================================
        findings.extend(self.crypto_auth.audit_tab03_crypto())
        findings.extend(self.crypto_auth.audit_tab04_auth())

        # ==========================================
        # Tab 05 & 06: Network & Platform Components
        # ==========================================
        findings.extend(self.net_plat.audit_tab05_network())
        findings.extend(self.adv_net_scanner.audit_network_security_xml())
        manifest_str = self.recon.get_manifest_string()
        findings.extend(self.net_plat.audit_tab06_platform(manifest_str))
        findings.extend(self.component_backup.audit_exported_components())

        # ==========================================
        # Tab 07 & 08: Code Quality & Binary Resilience
        # ==========================================
        findings.extend(self.code_resil.audit_tab07_code())
        findings.extend(self.code_resil.audit_tab08_resilience())
        findings.extend(self.obfuscation_scanner.audit_code_obfuscation())

        # ==========================================
        # Tab 09: Privacy & Sensitive Permissions
        # ==========================================
        findings.extend(self.privacy.audit_tab09_privacy())

        dangerous_perms = [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS"
        ]
        active_dangerous = [p for p in permissions if p in dangerous_perms]
        if active_dangerous:
            findings.append(Finding(
                check_id="AND-PRIV-01",
                title=f"Dangerous Android Permissions Declared ({len(active_dangerous)})",
                category="MASVS-PRIVACY",
                tab_index=9,
                severity=Severity.MEDIUM,
                status=CheckStatus.NEEDS_REVIEW,
                description="The application declares runtime permissions that grant access to sensitive hardware or user data.",
                evidence="Dangerous permissions requested:\n" + "\n".join(f"- {p}" for p in active_dangerous),
                remediation="Apply the principle of least privilege. Remove unneeded permissions and rely on system pickers."
            ))

        # ==========================================
        # Tab 11, 12, 13: Backend, Supply Chain & Logging
        # ==========================================
        findings.extend(self.supply_logs.audit_tab11_api())
        findings.extend(self.supply_logs.audit_tab12_supply_chain())
        findings.extend(self.supply_logs.audit_tab13_logging())

        # ==========================================
        # Extended Emerging Threats & Static Cases
        # ==========================================
        findings.extend(self.advanced_threats.audit_all_advanced_threats())
        findings.extend(self.advanced_static.execute_all_additional_static())

        # Modern APK checks produce both findings and static-to-dynamic targets.
        modern_findings, self.dynamic_targets = self.modern_android.audit()
        findings.extend(modern_findings)

        # Attach versioned OWASP mappings where the rule catalog has an exact entry.
        findings = enrich_findings(findings)

        # Filter duplicates before returning.
        return self.deduplicate_findings(findings)

    def write_dynamic_targets(self, output_path: str) -> str:
        """Write the static-to-dynamic handoff as a versioned JSON artifact."""
        output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as stream:
            json.dump(self.dynamic_targets, stream, indent=2, sort_keys=True)
            stream.write("\n")
        return output_path

    def generate_pdf_report(self, session: AuditSession, output_pdf_path: str):
        """Populates APK metadata, certificate info, permissions, and renders to PDF/HTML."""
        template = self.env.get_template("report_base.html")

        # 1. Deduplicate session findings
        session.findings = self.deduplicate_findings(session.findings)

        # 2. Extract and attach application metadata & certificate details
        meta_info = self.meta_extractor.extract_metadata()
        cert_info = meta_info.get("certificate", {})

        session.file_size = meta_info.get("file_size_human")
        session.sha256 = meta_info.get("sha256")
        session.target_sdk = str(self.metadata.get("target_sdk", "N/A"))
        session.min_sdk = str(self.metadata.get("min_sdk", "N/A"))
        session.version_code = str(self.metadata.get("version_code", "1"))
        session.cert_status = cert_info.get("status", "Unverified")
        session.cert_fingerprint = cert_info.get("fingerprint_sha256", "N/A")
        session.cert_issuer = cert_info.get("issuer", "N/A")

        # 3. Extract and attach permissions inventory
        session.permissions = self.perm_analyzer.analyze_permissions()

        # 4. Compute accurate severity metrics across all active findings
        counts = {"Total": len(session.findings),"Fail": 0,"Needs_Review": 0,"Pass": 0,"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in session.findings:
            if f.status == CheckStatus.FAIL:
                counts["Fail"] += 1
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
            elif f.status == CheckStatus.NEEDS_REVIEW:
                counts["Needs_Review"] += 1
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
            elif f.status == CheckStatus.PASS:
                counts["Pass"] += 1
  

        # Compute Prioritized Remediation Roadmap
        roadmap = {
            "immediate": [f for f in session.findings if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.status in (CheckStatus.FAIL, CheckStatus.NEEDS_REVIEW)],
            "short_term": [f for f in session.findings if f.status == CheckStatus.FAIL and f.severity == Severity.MEDIUM],
            "scheduled": [f for f in session.findings if f.status == CheckStatus.NEEDS_REVIEW or f.severity == Severity.LOW]
        }

        html_content = template.render(
            session=session,
            counts=counts,
            roadmap=roadmap,
            tool_version="TIR Auditor v2.4-enterprise",
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        

        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(output_pdf_path)
            print(f"[+] PDF report generated successfully: {output_pdf_path}")
        except (ImportError, OSError) as err:
            html_path = output_pdf_path.rsplit(".", 1)[0] + ".html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"[!] WeasyPrint native GTK library not found ({err}).")
            print(f"[+] Generated standalone HTML audit report instead: {html_path}")