"""Read-only, opt-in runtime checks for regulatory mobile-control evidence.

Only the emulator call simulation actively changes state, and it is isolated to an
emulator serial and always requests call cancellation in a finally block.
"""
import re
import subprocess
import time
from typing import List, Optional

from core.models import AnalysisType, CheckStatus, Confidence, Finding, Severity

REMOTE_PACKAGES = ("com.anydesk.anydeskandroid", "com.teamviewer.teamviewer.market.mobile",
                   "com.carriez.flutter_hbb", "com.teamviewer.host.market")
WARNING_WORDS = ("warning", "security", "screen sharing", "remote access", "active call",
                 "phone call", "transaction blocked", "fraud")


class IndianRegulatoryRuntimeEngine:
    def __init__(self, package_name: str, device_id: Optional[str] = None, adb_path: str = "adb"):
        if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_name):
            raise ValueError("Invalid Android package name")
        self.package_name = package_name
        self.device_id = device_id
        self.adb_path = adb_path

    def _adb(self, args, timeout=15):
        command = [self.adb_path] + (["-s", self.device_id] if self.device_id else []) + args
        return subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, check=False)

    def _shell(self, command, timeout=15):
        return self._adb(["shell", command], timeout)

    def audit(self, official_installers=None):
        return [self.audit_debug_state(), self.audit_remote_display_state(),
                self.audit_network_state(), self.audit_installer(official_installers or [])]

    def _finding(self, check_id, title, status, evidence, description, coverage=None, severity=Severity.INFO):
        return Finding(check_id=check_id, title=title, category="Regulatory Mobile Controls",
            tab_index=8, severity=severity, status=status, analysis_type=AnalysisType.DYNAMIC,
            confidence=Confidence.LOW if status == CheckStatus.NEEDS_REVIEW else Confidence.MEDIUM,
            confidence_score=0.5 if status == CheckStatus.NEEDS_REVIEW else 0.7,
            description=description, evidence=evidence,
            remediation="Validate the applicable control with the product owner and an authorized representative test workflow.",
            coverage={"device": self.device_id, **(coverage or {})})

    def _visible_warning(self):
        # Keep only matched warning keywords; do not place screen text in report evidence.
        remote = "/sdcard/tir_reg_ui.xml"
        try:
            result = self._shell("uiautomator dump " + remote, timeout=20)
            if result.returncode:
                return []
            xml = self._shell("cat " + remote).stdout
            return sorted({word for word in WARNING_WORDS if word in xml.lower()})
        except (OSError, subprocess.TimeoutExpired):
            return []
        finally:
            self._shell("rm -f /sdcard/tir_reg_ui.xml")

    def audit_debug_state(self):
        adb_enabled = self._shell("settings get global adb_enabled").stdout.strip()
        dev_options = self._shell("settings get global development_settings_enabled").stdout.strip()
        focus = self._shell("dumpsys window windows").stdout
        app_focused = self.package_name in focus
        warnings = self._visible_warning() if app_focused else []
        state = f"adb_enabled={adb_enabled or 'unknown'}; development_settings_enabled={dev_options or 'unknown'}; app_focused={app_focused}"
        state += "; visible warning keywords=" + (", ".join(warnings) if warnings else "none observed")
        return self._finding("DYN-REG-01", "USB debugging and developer options response",
            CheckStatus.NEEDS_REVIEW,
            state,
            "ADB and developer settings are read-only observations. A missing warning on an arbitrary screen is not proof that transaction flows lack enforcement.",
            {"probe": "settings read and foreground UI keyword scan"})

    def audit_remote_display_state(self):
        package_out = self._shell("pm list packages").stdout
        found = [pkg for pkg in REMOTE_PACKAGES if ("package:" + pkg) in package_out]
        display_dump = self._shell("dumpsys display").stdout
        virtual_lines = [line.strip() for line in display_dump.splitlines()
                         if re.search(r"virtual display|virtualdisplay|overlay display", line, re.I)]
        warnings = self._visible_warning() if self.package_name in self._shell("dumpsys window windows").stdout else []
        evidence = "Known RAT packages present: " + (", ".join(found) if found else "none observed")
        evidence += f"; virtual display indicators: {len(virtual_lines)}; warning keywords: " + (", ".join(warnings) if warnings else "none observed")
        return self._finding("DYN-REG-03", "Remote access and virtual display response",
            CheckStatus.NEEDS_REVIEW, evidence,
            "The probe inventories visible package/display indicators without installing apps or changing display settings. Validate response on an authorized test build and relevant login/transaction screens.",
            {"probe": "package inventory and dumpsys display", "packages_observed": len(found),
             "display_indicators": len(virtual_lines)})

    def audit_network_state(self):
        proxy = self._shell("settings get global http_proxy").stdout.strip()
        connectivity = self._shell("dumpsys connectivity").stdout
        vpn = bool(re.search(r"\bVPN\b|TRANSPORT_VPN|type: VPN", connectivity, re.I))
        return self._finding("DYN-REG-04", "Proxy, VPN, and TLS policy observation",
            CheckStatus.NEEDS_REVIEW,
            f"Existing global proxy: {proxy or 'none'}; VPN indicators: {'observed' if vpn else 'not observed'}; no device network settings changed.",
            "This check observes configuration only. Confirm TLS rejection, pinning behavior, and sensitive-data exposure with an approved proxy/CA test plan; TIR does not install CAs or bypass pinning.",
            {"probe": "read-only proxy and connectivity inspection", "proxy_active": bool(proxy and proxy.lower() not in ("null", ":0")),
             "vpn_observed": vpn})

    def audit_installer(self, official_installers):
        output = self._shell("pm list packages -i " + self.package_name).stdout
        match = re.search(r"installer=([^\s]+)", output)
        installer = match.group(1) if match else "unknown"
        if official_installers:
            allowed = installer in official_installers
            status = CheckStatus.PASS if allowed else CheckStatus.FAIL
            severity = Severity.INFO if allowed else Severity.MEDIUM
        else:
            status, severity = CheckStatus.NEEDS_REVIEW, Severity.INFO
        return self._finding("DYN-REG-05", "Installed package source evidence",
            status, f"Installer package: {installer}; configured approved installers: {', '.join(official_installers) if official_installers else 'none (not configured)'}.",
            "TIR reports installer metadata without reinstalling the target. A source allow-list is organization-specific; the cited controls concern secure download/install and integrity, not a universal Play Store-only rule.",
            {"probe": "pm list packages -i", "installer": installer}, severity)

    def simulate_emulator_call(self, phone_number="5550100"):
        if not self.device_id or not self.device_id.startswith("emulator-"):
            return self._finding("DYN-REG-02", "Active call response simulation unavailable",
                CheckStatus.NEEDS_REVIEW, "Skipped: selected device is not an Android emulator serial.",
                "The call-state test is restricted to an emulator. No real-device telephony state is changed.")
        if not re.fullmatch(r"[0-9+]{3,20}", phone_number):
            raise ValueError("Invalid simulated phone number")
        target = self.package_name
        accepted = False
        call_attempted = False
        evidence = []
        try:
            call_attempted = True
            call = self._adb(["emu", "gsm", "call", phone_number], timeout=10)
            evidence.append("incoming call command accepted" if call.returncode == 0 else "incoming call command failed")
            if call.returncode != 0:
                return self._finding("DYN-REG-02", "Active call response simulation unavailable",
                    CheckStatus.NEEDS_REVIEW, "; ".join(evidence), "Emulator console did not accept the simulated call.")
            time.sleep(1)
            accept = self._adb(["emu", "gsm", "accept", phone_number], timeout=10)
            accepted = accept.returncode == 0
            evidence.append("call accepted" if accepted else "call acceptance unavailable")
            if not accepted:
                return self._finding("DYN-REG-02", "Active call response simulation unavailable",
                    CheckStatus.NEEDS_REVIEW, "; ".join(evidence), "The emulator did not enter an active-call state.")
            self._shell("am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p " + target)
            time.sleep(2)
            focus = self._shell("dumpsys window windows").stdout
            warnings = self._visible_warning() if target in focus else []
            evidence.append("target foreground=" + str(target in focus))
            evidence.append("warning keywords=" + (", ".join(warnings) if warnings else "none observed"))
            state = CheckStatus.PASS if warnings and target in focus else CheckStatus.NEEDS_REVIEW
            return self._finding("DYN-REG-02", "Active call response simulation",
                state, "; ".join(evidence),
                "Call-state response was sampled on an emulator only. A warning keyword is evidence for review, not proof all sensitive actions are blocked.",
                {"probe": "emulator gsm call/accept; app launch; UI keyword scan", "call_state_entered": accepted})
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._finding("DYN-REG-02", "Active call response simulation unavailable",
                CheckStatus.NEEDS_REVIEW, str(exc)[:200], "The emulator call-state probe could not complete.")
        finally:
            if call_attempted:
                self._adb(["emu", "gsm", "cancel", phone_number], timeout=10)
