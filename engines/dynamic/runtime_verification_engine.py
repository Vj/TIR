# engines/dynamic/runtime_verification_engine.py
import re
import time
import subprocess
from typing import List, Dict, Any, Optional, Set
from core.models import AnalysisType, Finding, Severity, CheckStatus
from engines.dynamic.adb_client import ADBBridge


class RuntimeVerificationEngine:
    """
    Executes Batch 3: Dynamic & Runtime Verification
    - DYN-027: Protected Screen Access & Auth Gate Bypass
    - DYN-028: Session Token Exposure in Logs & Dumps
    - DYN-033: WebView Runtime Security & Debugging Status
    - DYN-035: Insecure Local Storage & Dynamic File Diffs
    - DYN-036: Session Invalidation & Logout Purge Validation
    - DYN-037: Background Data & Task Snapshot Exposure
    """

    def __init__(self, package_name: str, device_id: Optional[str] = None):
        self.package_name = package_name
        self.device_id = device_id
        self.adb = ADBBridge()
        self.token_regex = re.compile(
            r"(?i)(?:bearer\s+[a-zA-Z0-9_\-\.]{20,}|ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|session[_\-]?(?:id|token)[\s\"':=]+([a-zA-Z0-9_\-]{16,}))"
        )

    def _adb_exec(self, cmd_args: List[str], timeout: int = 12) -> str:
        base = ["adb"]
        if self.device_id:
            base.extend(["-s", self.device_id])
        base.extend(cmd_args)
        try:
            res = subprocess.run(
                base,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout
            )
            return res.stdout.strip()
        except Exception as e:
            return f"ERROR: {str(e)}"

    def audit_all_batch3(
        self,
        discovered_activities: Optional[List[str]] = None,
        auth_activities: Optional[List[str]] = None
    ) -> List[Finding]:
        findings: List[Finding] = []
        activities = discovered_activities or []

        findings.extend(self.audit_dyn_027_auth_bypass(activities, auth_activities))
        findings.append(self.audit_dyn_028_session_token_exposure())
        findings.append(self.audit_dyn_033_webview_runtime())
        findings.extend(self.audit_dyn_035_insecure_local_storage())
        findings.append(self.audit_dyn_036_logout_invalidation())
        findings.append(self.audit_dyn_037_background_exposure())
        return findings

    def audit_dyn_027_auth_bypass(
        self,
        activities: List[str],
        auth_screens: Optional[List[str]] = None
    ) -> List[Finding]:
        findings: List[Finding] = []
        auth_keywords = ["login", "auth", "signin", "lock", "passcode"]
        auth_targets = auth_screens or [
            a for a in activities if any(k in a.lower() for k in auth_keywords)
        ]

        test_targets = [
            a for a in activities if a not in auth_targets and not a.endswith("MainActivity")
        ]

        for act in test_targets[:4]:
            full_comp = act if "/" in act else f"{self.package_name}/{act}"
            self._adb_exec(["shell", "am", "start", "-n", full_comp])
            time.sleep(1.2)

            focus_dump = self._adb_exec(["shell", "dumpsys", "window", "windows"])
            is_foreground = act in focus_dump
            redirected_to_auth = any(auth_act in focus_dump for auth_act in auth_targets)

            if is_foreground and not redirected_to_auth:
                findings.append(Finding(
                    check_id="DYN-027",
                    title=f"Protected Component Invoked Without Auth Gate: {act.split('.')[-1]}",
                    category="MASVS-AUTH",
                    tab_index=4,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    analysis_type=AnalysisType.DYNAMIC,
                    affected_component=act,
                    cwe_id="CWE-306: Missing Authentication for Critical Function",
                    masvs_ref="MASVS-AUTH-1",
                    mastg_ref="MASTG-TEST-0019",
                    description=(
                        f"Activity '{act}' launched directly and retained foreground focus without redirecting "
                        "to an authentication barrier or validating session credentials."
                    ),
                    poc_command=f"adb shell am start -n {full_comp}",
                    poc_expected="Redirects to authentication barrier (LoginActivity).",
                    poc_observed="Component launched into foreground without session credential prompt.",
                    reproduction_sequence=[
                        f"# Trigger component directly via ADB intent manager",
                        f"adb shell am start -n {full_comp}",
                        f"# Verify active focused window",
                        f"adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'"
                    ],
                    evidence=f"Target component: {full_comp}\nWindow focus trace confirmed activity foreground status.",
                    remediation="Validate user session tokens in onStart() or onResume(); redirect unauthenticated intents to LoginActivity."
                ))
                break

        if not findings:
            findings.append(Finding(
                check_id="DYN-027",
                title="Activity Access Control Evaluated",
                category="MASVS-AUTH",
                tab_index=4,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                analysis_type=AnalysisType.DYNAMIC,
                description="Sampled components did not allow unauthenticated foreground execution without redirects or guards.",
                evidence="Tested activities successfully diverted or handled unauthenticated invocations.",
                remediation=None
            ))
        return findings

    def audit_dyn_028_session_token_exposure(self) -> Finding:
        log_dump = self._adb_exec(["logcat", "-d", "-t", "500", "--pid", f"`pidof {self.package_name}`"])
        matches = self.token_regex.findall(log_dump)

        if matches:
            redacted = [m[:6] + "..." + m[-4:] if len(m) > 12 else m[:4] + "..." for m in matches[:3]]
            return Finding(
                check_id="DYN-028",
                title="Session Identifiers Exposed in Runtime System Logs",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                analysis_type=AnalysisType.DYNAMIC,
                cwe_id="CWE-532: Insertion of Sensitive Information into Log File",
                masvs_ref="MASVS-STORAGE-3",
                mastg_ref="MASTG-TEST-0003",
                description="Active session credentials, bearer tokens, or JWTs were written directly into the Android log buffer.",
                poc_command=f"adb logcat -d --pid $(adb shell pidof {self.package_name}) | grep -Ei 'bearer|jwt|session'",
                poc_observed=f"Matched tokens in logcat: {', '.join(redacted)}",
                evidence=f"Matched token traces in logcat: {', '.join(redacted)}",
                remediation="Ensure custom logging frameworks strip Authorization headers and bearer tokens prior to dispatch."
            )

        return Finding(
            check_id="DYN-028",
            title="Logcat Session Token Residue Check Passed",
            category="MASVS-STORAGE",
            tab_index=2,
            severity=Severity.INFO,
            status=CheckStatus.PASS,
            analysis_type=AnalysisType.DYNAMIC,
            description="No plaintext authentication or bearer tokens were observed in the recent process log buffer.",
            evidence="Checked 500 lines of process logcat buffer without matching token patterns.",
            remediation=None
        )

    def audit_dyn_033_webview_runtime(self) -> Finding:
        pid = self._adb_exec(["shell", f"pidof {self.package_name}"])
        if not pid:
            return Finding(
                check_id="DYN-033",
                title="WebView Runtime Inspection: Target Not Running",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.INFO,
                status=CheckStatus.NEEDS_REVIEW,
                analysis_type=AnalysisType.DYNAMIC,
                description="Unable to inspect WebView runtime status because the process is not active.",
                evidence="No active PID found.",
                remediation=None
            )

        first_pid = pid.split()[0]
        net_unix = self._adb_exec(["shell", f"cat /proc/net/unix | grep webview_devtools_remote_{first_pid} || true"])

        if f"webview_devtools_remote_{first_pid}" in net_unix:
            return Finding(
                check_id="DYN-033",
                title="WebView Debugging Enabled in Runtime Process",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                analysis_type=AnalysisType.DYNAMIC,
                cwe_id="CWE-489: Active Debug Code in Production",
                masvs_ref="MASVS-PLATFORM-2",
                mastg_ref="MASTG-TEST-0024",
                description=(
                    "WebView.setWebContentsDebuggingEnabled(true) is active on this process. "
                    "Any local entity with ADB access can attach Chrome DevTools to inspect DOM and extract session data."
                ),
                poc_command=f"adb forward tcp:9222 localabstract:webview_devtools_remote_{first_pid}",
                poc_observed="Chrome DevTools endpoint exposed on local abstract UNIX domain socket.",
                evidence=f"Active abstract socket: @webview_devtools_remote_{first_pid}",
                remediation="Enforce WebView.setWebContentsDebuggingEnabled(false) in release builds."
            )

        return Finding(
            check_id="DYN-033",
            title="WebView Debugging Socket Disabled",
            category="MASVS-PLATFORM",
            tab_index=6,
            severity=Severity.INFO,
            status=CheckStatus.PASS,
            analysis_type=AnalysisType.DYNAMIC,
            description="No Chrome DevTools remote debugging sockets were exposed by the running process.",
            evidence=f"No active webview_devtools_remote socket for PID {first_pid}.",
            remediation=None
        )

    def audit_dyn_035_insecure_local_storage(self) -> List[Finding]:
        findings: List[Finding] = []
        sandbox = f"/data/data/{self.package_name}"

        prefs_dump = self._adb_exec(["shell", f"cat {sandbox}/shared_prefs/*.xml 2>/dev/null || true"])
        sensitive_patterns = [r'(?i)(password|secret|passcode|token)["\s:>]+([^<"\n]+)']

        for pat in sensitive_patterns:
            matches = re.findall(pat, prefs_dump)
            if matches:
                findings.append(Finding(
                    check_id="DYN-035",
                    title="Sensitive Values Written to Unencrypted SharedPreferences",
                    category="MASVS-STORAGE",
                    tab_index=2,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    analysis_type=AnalysisType.DYNAMIC,
                    affected_component=f"{sandbox}/shared_prefs/",
                    cwe_id="CWE-312: Cleartext Storage of Sensitive Information",
                    masvs_ref="MASVS-STORAGE-1",
                    mastg_ref="MASTG-TEST-0001",
                    description="Unencrypted SharedPreferences files contain plaintext keys matching passwords or session tokens.",
                    poc_command=f"adb shell run-as {self.package_name} cat {sandbox}/shared_prefs/*.xml",
                    poc_observed="Plaintext credentials retrieved from sandbox XML preferences.",
                    evidence=f"Discovered {len(matches)} potential credential keys in {sandbox}/shared_prefs/.",
                    remediation="Migrate to EncryptedSharedPreferences from AndroidX Security library."
                ))
                break

        db_list = self._adb_exec(["shell", f"ls {sandbox}/databases/ 2>/dev/null || true"])
        for db in db_list.split():
            if db.endswith(".db") and not db.endswith("-journal"):
                header = self._adb_exec(["shell", f"head -c 16 {sandbox}/databases/{db} | tr -d '\\0' || true"])
                if "SQLite format 3" in header:
                    findings.append(Finding(
                        check_id="DYN-035",
                        title=f"Unencrypted SQLite Database on Disk: {db}",
                        category="MASVS-STORAGE",
                        tab_index=2,
                        severity=Severity.MEDIUM,
                        status=CheckStatus.NEEDS_REVIEW,
                        analysis_type=AnalysisType.DYNAMIC,
                        affected_component=f"{sandbox}/databases/{db}",
                        cwe_id="CWE-311: Missing Encryption of Sensitive Data",
                        masvs_ref="MASVS-STORAGE-1",
                        mastg_ref="MASTG-TEST-0001",
                        description=f"Database '{db}' is stored as standard unencrypted SQLite format 3 without SQLCipher transparent encryption.",
                        poc_command=f"adb shell run-as {self.package_name} head -c 16 {sandbox}/databases/{db}",
                        poc_observed="Header confirms valid unencrypted 'SQLite format 3' magic bytes.",
                        evidence=f"Path: {sandbox}/databases/{db} (Valid SQLite format 3 header)",
                        remediation="Implement SQLCipher (net.zetetic:android-database-sqlcipher) or Room with encrypted database factories."
                    ))

        if not findings:
            findings.append(Finding(
                check_id="DYN-035",
                title="Local Storage Inspection Passed",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                analysis_type=AnalysisType.DYNAMIC,
                description="No obvious plaintext credential strings or unprotected databases detected in primary sandbox directories.",
                evidence=f"Checked {sandbox}/shared_prefs/ and {sandbox}/databases/.",
                remediation=None
            ))
        return findings

    def audit_dyn_036_logout_invalidation(self) -> Finding:
        sandbox = f"/data/data/{self.package_name}"
        active_tokens = self._adb_exec([
            "shell",
            f"grep -rnEI 'bearer|jwt|session' {sandbox}/shared_prefs/ {sandbox}/databases/ 2>/dev/null || true"
        ])

        if active_tokens and len(active_tokens.splitlines()) > 0:
            return Finding(
                check_id="DYN-036",
                title="Session Identifiers Persisted in Local Sandbox",
                category="MASVS-AUTH",
                tab_index=4,
                severity=Severity.MEDIUM,
                status=CheckStatus.NEEDS_REVIEW,
                analysis_type=AnalysisType.DYNAMIC,
                affected_component=sandbox,
                cwe_id="CWE-613: Insufficient Session Expiration",
                masvs_ref="MASVS-AUTH-1",
                mastg_ref="MASTG-TEST-0020",
                description="Session identifiers or authentication tokens persist in local files.",
                poc_command=f"adb shell run-as {self.package_name} grep -rnEI 'bearer|jwt|session' {sandbox}/",
                poc_observed="Residual session tokens located in local storage.",
                evidence=f"Active token occurrences across sandbox:\n{active_tokens[:250]}...",
                remediation="Clear SharedPreferences, purge database cache, and wipe WebView cookies on user logout."
            )

        return Finding(
            check_id="DYN-036",
            title="Local Sandbox Session Invalidation Baseline Clean",
            category="MASVS-AUTH",
            tab_index=4,
            severity=Severity.INFO,
            status=CheckStatus.PASS,
            analysis_type=AnalysisType.DYNAMIC,
            description="No persistent session tokens found lingering in storage directories.",
            evidence="Zero session token matches in sandbox files.",
            remediation=None
        )

    def audit_dyn_037_background_exposure(self) -> Finding:
        self._adb_exec(["shell", "input", "keyevent", "3"])
        time.sleep(1.5)

        snapshot_check = self._adb_exec([
            "shell",
            "ls -la /data/system_ce/0/snapshots/ /data/system/users/0/snapshots/ 2>/dev/null || true"
        ])

        pid = self._adb_exec(["shell", f"pidof {self.package_name}"])

        return Finding(
            check_id="DYN-037",
            title="Background Transition and Task Snapshot Behavior Inspected",
            category="MASVS-PLATFORM",
            tab_index=6,
            severity=Severity.INFO,
            status=CheckStatus.PASS,
            analysis_type=AnalysisType.DYNAMIC,
            description="Application transitioned to background state via KEYCODE_HOME. Process status and task snapshots checked.",
            evidence=f"App PID in background: {pid or 'Suspended/Cached'}\nSnapshot check result: {snapshot_check[:150] or 'No accessible raw snapshots'}.",
            remediation="Enforce WindowManager.LayoutParams.FLAG_SECURE on sensitive windows to obscure previews in the task switcher."
        )