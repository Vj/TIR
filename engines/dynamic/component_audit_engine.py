# engines/dynamic/component_audit_engine.py
import subprocess
import time
import re
from typing import List, Dict, Any, Set
from core.models import AnalysisType, Finding, Severity, CheckStatus, Confidence

class ComponentAuditEngine:
    def __init__(self, package_name: str, device_id: str = None):
        self.package_name = package_name
        self.device_id = device_id

    def _adb_exec(self, cmd_args: List[str]) -> str:
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(cmd_args)
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            return res.stdout.strip()
        except Exception as e:
            return f"ERROR: {str(e)}"

    def discover_components(self) -> Dict[str, List[str]]:
        """Parses dumpsys package to catalog exported activities, receivers, and services."""
        raw_dump = self._adb_exec(["shell", "dumpsys", "package", self.package_name])
        components = {
            "activities": set(),
            "services": set(),
            "receivers": set()
        }

        current_section = None
        for line in raw_dump.splitlines():
            clean = line.strip()
            if "Activity Resolver Table:" in clean:
                current_section = "activities"
                continue
            elif "Receiver Resolver Table:" in clean:
                current_section = "receivers"
                continue
            elif "Service Resolver Table:" in clean:
                current_section = "services"
                continue
            elif "ContentProvider Authorities:" in clean or "Key Set Manager:" in clean:
                current_section = None

            if current_section and f"{self.package_name}/" in clean:
                for token in clean.split():
                    if f"{self.package_name}/" in token:
                        comp = token.split(f"{self.package_name}/")[-1].replace("filter", "").strip()
                        if comp:
                            clean_name = comp if comp.startswith(self.package_name) else f"{self.package_name}.{comp.lstrip('.')}"
                            components[current_section].add(clean_name)

        return {k: sorted(list(v)) for k, v in components.items()}

    def _normalize_static_targets(self, targets: Dict[str, Any]) -> Dict[str, Any]:
        """Accept only package-owned component names and syntactically safe authorities."""
        safe_name = re.compile(r"^[A-Za-z0-9_.$]+$")
        catalog = {"activities": [], "services": [], "receivers": [], "providers": []}
        for kind in catalog:
            for row in targets.get(kind, []):
                name = row.get("name", "") if isinstance(row, dict) else str(row)
                if not safe_name.fullmatch(name):
                    continue
                normalized = name
                if normalized.startswith("."):
                    normalized = self.package_name + normalized
                elif "." not in normalized:
                    normalized = self.package_name + "." + normalized
                if normalized != self.package_name and not normalized.startswith(self.package_name + "."):
                    continue
                entry = dict(row) if isinstance(row, dict) else {"name": normalized}
                entry["name"] = normalized
                if kind == "providers":
                    authority = entry.get("authority", "")
                    if not isinstance(authority, str) or not re.fullmatch(r"[A-Za-z0-9_.;-]+", authority):
                        continue
                catalog[kind].append(entry)
        return catalog

    def audit_exported_components(self, targets: Dict[str, Any] = None) -> List[Finding]:
        """Run bounded component probes; provider reads require explicitly seeded targets."""
        findings: List[Finding] = []
        if targets is None:
            discovered = self.discover_components()
            catalog = {key: [{"name": name} for name in values] for key, values in discovered.items()}
            catalog["providers"] = []
        else:
            catalog = self._normalize_static_targets(targets)

        for row in catalog["activities"]:
            findings.extend(self._test_activity_lifecycle(row["name"]))
        for row in catalog["receivers"]:
            findings.extend(self._test_receiver_resilience(row["name"]))
        for row in catalog["services"]:
            findings.extend(self._test_service_boundary(row["name"]))
        for row in catalog["providers"]:
            findings.extend(self._test_provider_boundary(row))

        return findings

    def _test_service_boundary(self, service_name: str) -> List[Finding]:
        full_target = f"{self.package_name}/{service_name}"
        output = self._adb_exec(["shell", "am", "startservice", "-n", full_target])
        if "SecurityException" in output or "Permission Denial" in output:
            return [Finding(
                check_id="TIR-IPC-SERVICE",
                title=f"Exported service enforces an access boundary: {service_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                analysis_type=AnalysisType.DYNAMIC,
                confidence=Confidence.MEDIUM,
                affected_component=service_name,
                description="ADB invocation was denied by the platform or an explicit component permission.",
                evidence=output[:250],
            )]
        return [Finding(
            check_id="TIR-IPC-SERVICE",
            title=f"Exported service invocation needs authorization review: {service_name.split('.')[-1]}",
            category="MASVS-PLATFORM",
            tab_index=6,
            severity=Severity.INFO,
            status=CheckStatus.NEEDS_REVIEW,
            analysis_type=AnalysisType.DYNAMIC,
            confidence=Confidence.LOW,
            affected_component=service_name,
            description="The ADB shell could invoke or attempt to start the exported service. This does not establish that a normal third-party app can access sensitive functionality.",
            evidence=output[:250] or "No clear invocation result was returned.",
            remediation="Review the service's exported state, permission protection level, and authorization checks.",
        )]

    def _test_provider_boundary(self, row: Dict[str, Any]) -> List[Finding]:
        authority = row.get("authority", "").split(";")[0]
        if not authority or not re.fullmatch(r"[A-Za-z0-9_.]+", authority):
            return []
        uri = f"content://{authority}/"
        output = self._adb_exec(["shell", "content", "query", "--uri", uri])
        denied = "Permission Denial" in output or "SecurityException" in output
        if denied:
            status, severity = CheckStatus.PASS, Severity.INFO
            description = "The provider query was denied by the platform or a provider permission."
            evidence = f"URI: {uri}\nResult: access denied."
        elif output.startswith("ERROR:") or not output:
            status, severity = CheckStatus.NEEDS_REVIEW, Severity.INFO
            description = "The provider query did not produce enough evidence to evaluate its access boundary."
            evidence = f"URI: {uri}\nResult: {output[:200] or 'no output'}"
        else:
            # Never retain provider row contents in reports.
            row_count = sum(1 for line in output.splitlines() if line.strip().startswith("Row:"))
            status, severity = CheckStatus.NEEDS_REVIEW, Severity.MEDIUM
            description = "ADB shell returned provider data. The shell identity may differ from a normal third-party app; validate with a purpose-built unprivileged test app."
            evidence = f"URI: {uri}\nRows returned: {row_count}\nProvider permission: {row.get('permission') or 'none declared'}"
        return [Finding(
            check_id="TIR-IPC-PROVIDER",
            title=f"Content Provider access boundary: {authority}",
            category="MASVS-PLATFORM",
            tab_index=6,
            severity=severity,
            status=status,
            analysis_type=AnalysisType.DYNAMIC,
            confidence=Confidence.MEDIUM if denied else Confidence.LOW,
            affected_component=row.get("name"),
            description=description,
            evidence=evidence,
            remediation="Restrict exported providers with signature or runtime permissions and validate URI paths and query parameters.",
            coverage={"probe": "read-only query", "authority": authority, "device": self.device_id},
        )]

    def _test_activity_lifecycle(self, activity_name: str) -> List[Finding]:
        results: List[Finding] = []
        full_target = f"{self.package_name}/{activity_name}"

        # Baseline start: evaluate whether component requires permissions or crashes on null extras
        cmd_start = ["shell", "am", "start", "-n", full_target]
        start_out = self._adb_exec(cmd_start)

        if "SecurityException" in start_out or "Permission Denial" in start_out:
            results.append(Finding(
                check_id="DYN-031",
                title=f"Exported Activity Enforces Permission Guard: {activity_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                description=f"Activity '{activity_name}' rejected unprivileged invocation with a security exception.",
                evidence=start_out[:250],
                remediation=None
            ))
            return results

        if "FATAL EXCEPTION" in start_out or "has died" in start_out:
            results.append(Finding(
                check_id="DYN-032",
                title=f"Activity Crashed on Null Intent Extras: {activity_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description=f"Activity '{activity_name}' encountered an unhandled exception when invoked without required parameters.",
                evidence=f"Command: am start -n {full_target}\nOutput:\n{start_out[:300]}",
                remediation="Validate intent data with null checks before dereferencing parameters in onCreate()."
            ))

        # Boundary parameter fuzzing: test unexpected types (e.g. type confusion or boundary values)
        fuzz_cmd = [
            "shell", "am", "start", "-n", full_target,
            "--es", "extra_str", "test",
            "--ei", "extra_int", "2147483647",
            "--ez", "extra_bool", "true"
        ]
        fuzz_out = self._adb_exec(fuzz_cmd)

        if "ClassCastException" in fuzz_out or "NullPointerException" in fuzz_out:
            results.append(Finding(
                check_id="DYN-032",
                title=f"Parameter Type Casting Flaw: {activity_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                description=f"Activity '{activity_name}' failed to safely parse intent extras of varying data types.",
                evidence=f"Output:\n{fuzz_out[:300]}",
                remediation="Ensure intent extras are retrieved with fallback defaults and type-safe wrappers."
            ))

        return results

    def _test_receiver_resilience(self, receiver_name: str) -> List[Finding]:
        results: List[Finding] = []
        full_target = f"{self.package_name}/{receiver_name}"

        # Send empty directed broadcast
        bcast_cmd = ["shell", "am", "broadcast", "-n", full_target]
        bcast_out = self._adb_exec(bcast_cmd)

        if "SecurityException" in bcast_out:
            results.append(Finding(
                check_id="DYN-031",
                title=f"Broadcast Receiver Enforces Calling Permission: {receiver_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                description=f"Receiver '{receiver_name}' rejects broadcasts from unauthorized callers.",
                evidence=bcast_out[:250],
                remediation=None
            ))
        elif "FATAL" in bcast_out:
            results.append(Finding(
                check_id="DYN-032",
                title=f"Broadcast Receiver Crashed on Malformed Intent: {receiver_name.split('.')[-1]}",
                category="MASVS-PLATFORM",
                tab_index=6,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description=f"Receiver '{receiver_name}' crashed during onReceive() execution.",
                evidence=bcast_out[:300],
                remediation="Wrap onReceive() handling logic in exception handlers to prevent denial-of-service."
            ))

        return results