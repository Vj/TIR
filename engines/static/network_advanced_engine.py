# engines/static/network_advanced_engine.py
import re
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List
from core.models import Finding, Severity, CheckStatus

class AdvancedNetworkEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def audit_network_security_xml(self) -> List[Finding]:
        findings: List[Finding] = []

        with zipfile.ZipFile(self.apk_path, "r") as z:
            config_files = [f for f in z.namelist() if "network_security_config" in f.lower() and f.endswith(".xml")]

            for cfg_path in config_files:
                try:
                    raw_xml = z.read(cfg_path).decode("utf-8", errors="ignore")
                    root = ET.fromstring(raw_xml)
                except Exception:
                    continue

                # 1. Check for User-Installed Trust Anchors (<certificates src="user" />)
                for trust_anchors in root.iter("trust-anchors"):
                    for cert in trust_anchors.findall("certificates"):
                        src = cert.attrib.get("src", "").lower()
                        if src == "user":
                            findings.append(Finding(
                                check_id="AND-NETW-06",
                                title="User-Installed CA Certificates Trusted in Network Config",
                                category="MASVS-NETWORK",
                                tab_index=5,
                                severity=Severity.HIGH,
                                status=CheckStatus.FAIL,
                                description=(
                                    "The network security configuration explicitly trusts user-installed CA certificates. "
                                    "This enables HTTPS interception on production builds without requiring root privileges."
                                ),
                                evidence=f"File: {cfg_path}\nConfiguration: <certificates src=\"user\" />",
                                remediation="Restrict <certificates src=\"user\" /> to <debug-overrides> so it is only active during debug testing."
                            ))

                # 2. Check for Domain-Specific Cleartext Traffic
                for domain_config in root.iter("domain-config"):
                    cleartext_allowed = domain_config.attrib.get("cleartextTrafficPermitted", "").lower() == "true"
                    if cleartext_allowed:
                        domains = [d.text.strip() for d in domain_config.findall("domain") if d.text]
                        findings.append(Finding(
                            check_id="AND-NETW-01",
                            title=f"Domain Whitelisted for Cleartext HTTP Traffic ({len(domains)} Domains)",
                            category="MASVS-NETWORK",
                            tab_index=5,
                            severity=Severity.HIGH,
                            status=CheckStatus.FAIL,
                            description="Cleartext HTTP communication is explicitly allowed for specific domains.",
                            evidence=f"File: {cfg_path}\nDomains:\n" + "\n".join(f"- {d}" for d in domains),
                            remediation="Migrate all target endpoints to HTTPS and remove cleartextTrafficPermitted attributes."
                        ))

                # 3. Check Certificate Pinning Expiration
                for pin_set in root.iter("pin-set"):
                    expiration_str = pin_set.attrib.get("expiration")
                    if expiration_str:
                        try:
                            exp_date = datetime.strptime(expiration_str, "%Y-%m-%d")
                            if exp_date < datetime.now():
                                findings.append(Finding(
                                    check_id="AND-NETW-03",
                                    title="Expired Certificate Pinning Configuration",
                                    category="MASVS-NETWORK",
                                    tab_index=5,
                                    severity=Severity.MEDIUM,
                                    status=CheckStatus.FAIL,
                                    description=f"Certificate pin-set expired on {expiration_str}. The app falls back to standard CA trust.",
                                    evidence=f"File: {cfg_path}\nExpiration Attribute: {expiration_str}",
                                    remediation="Update certificate pins and specify future expiration dates matching certificate renewal cycles."
                                ))
                        except ValueError:
                            pass
                    else:
                        findings.append(Finding(
                            check_id="AND-NETW-03",
                            title="Certificate Pinning Lacks Expiration Date",
                            category="MASVS-NETWORK",
                            tab_index=5,
                            severity=Severity.LOW,
                            status=CheckStatus.NEEDS_REVIEW,
                            description="The pin-set does not declare an expiration date. An unexpected certificate revocation may break connectivity.",
                            evidence=f"File: {cfg_path}\nPin set detected without 'expiration' attribute.",
                            remediation="Include an expiration='YYYY-MM-DD' attribute on <pin-set> to provide a fallback window during renewals."
                        ))

        return findings