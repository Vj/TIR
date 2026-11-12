# engines/dynamic/network_runtime_engine.py
import subprocess
from typing import List
from core.models import Finding, Severity, CheckStatus

class NetworkRuntimeEngine:
    def __init__(self, package_name: str, device_id: str = None):
        self.package_name = package_name
        self.device_id = device_id

    def _adb_exec(self, shell_cmd: str) -> str:
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(["shell", shell_cmd])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return res.stdout.strip()
        except Exception as e:
            return f"ERROR: {str(e)}"

    def audit_active_sockets_and_proxy(self) -> List[Finding]:
        """
        DYN-026 & DYN-034: Inspects open sockets, system proxy configuration,
        and TLS handshakes associated with the app's UID.
        """
        findings: List[Finding] = []

        # 1. Resolve Application UID
        uid_str = self._adb_exec(f"dumpsys package {self.package_name} | grep userId=")
        uid = None
        for line in uid_str.splitlines():
            if "userId=" in line:
                uid = line.split("userId=")[-1].strip().split()[0]
                break

        if not uid:
            return findings

        # 2. Inspect active network connections via netstat or ss
        net_output = self._adb_exec(f"netstat -tlpn 2>/dev/null || ss -tlpn")
        
        # Check if the app runs any local unauthenticated HTTP or RPC server
        if uid in net_output and ("0.0.0.0:" in net_output or ":::*" in net_output):
            findings.append(Finding(
                check_id="DYN-034",
                title="Active Local Listening Port Bound to Global Interface",
                category="MASVS-NETWORK",
                tab_index=5,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description=f"App UID {uid} binds an active listening socket to 0.0.0.0. Other co-located apps can connect to this endpoint.",
                evidence=f"Active sockets matching UID {uid}:\n{net_output[:400]}",
                remediation="Bind internal servers strictly to 127.0.0.1 (loopback) and enforce mutual authentication tokens."
            ))

        # 3. Check Global Proxy Settings
        proxy_host = self._adb_exec("settings get global http_proxy")
        if proxy_host and proxy_host != "null" and ":0" not in proxy_host:
            findings.append(Finding(
                check_id="DYN-026",
                title="Device Operating Under Active HTTP Interception Proxy",
                category="MASVS-NETWORK",
                tab_index=5,
                severity=Severity.INFO,
                status=CheckStatus.NEEDS_REVIEW,
                description=f"Device HTTP proxy is configured to '{proxy_host}'. Exercise the app to confirm whether TLS pinning breaks connectivity or allows interception.",
                evidence=f"Global HTTP Proxy: {proxy_host}",
                remediation="Ensure production builds enforce certificate pinning via OkHttp CertificatePinner or network_security_config pin-sets."
            ))

        return findings