# aai_bridge.py
import json
import os
from typing import Dict, Any, List, Optional

from core.orchestrator import TIROrchestrator
from core.models import Finding, CheckStatus, Severity
from engines.dynamic.adb_client import ADBBridge
from engines.dynamic.storage_engine import StorageEngine
from engines.dynamic.root_environment_engine import RootEnvironmentEngine
from engines.dynamic.runtime_behavior_engine import RuntimeBehaviorEngine
from engines.remediation_engine import RemediationEngine
from engines.dynamic.intent_fuzzer_engine import IntentFuzzerEngine
from engines.dynamic.network_runtime_engine import NetworkRuntimeEngine
from engines.dynamic.root_isolation_engine import RootIsolationEngine
from engines.dynamic.runtime_verification_engine import RuntimeVerificationEngine
from engines.dynamic.agent_navigator import AgentNavigator

_global_navigator: Optional[AgentNavigator] = None

def get_navigator(package_name: str, device_id: Optional[str] = None) -> AgentNavigator:
    global _global_navigator
    if _global_navigator is None or _global_navigator.package_name != package_name:
        _global_navigator = AgentNavigator(package_name=package_name, device_id=device_id)
    return _global_navigator


class TIRToolbox:
    """Consolidated Tool Interface exposed to the Agentic AI (Ollama) execution loop."""

    @staticmethod
    def run_static_scan(apk_path: str) -> str:
        """
        Executes automated static security checks across all 13 MASVS categories
        and extended static rules (STA-021 through STA-035).
        Returns a JSON-encoded array of structured findings.
        """
        resolved_path = os.path.abspath(apk_path)
        if not os.path.exists(resolved_path):
            return json.dumps({"error": f"File not found: {resolved_path}"})

        try:
            orchestrator = TIROrchestrator(apk_path=resolved_path)
            findings = orchestrator.execute_all_automated()

            payload = [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "tab": f.tab_index,
                    "category": f.category,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in findings
            ]
            return json.dumps(payload, indent=2)
        except Exception as e:
            return json.dumps({"error": f"Static scan execution failure: {str(e)}"})

    @staticmethod
    def run_dynamic_sandbox_check(package_name: str, device_id: Optional[str] = None) -> str:
        """
        Inspects application sandbox storage (/data/data/<package>) over ADB
        for plaintext tokens, world-accessible XML files, and unencrypted databases.
        """
        try:
            adb = ADBBridge()
            devices = adb.get_connected_devices()
            if not devices:
                return json.dumps({"error": "No connected ADB devices or emulators detected."})

            target_dev = device_id or devices[0]
            storage_engine = StorageEngine(adb, package_name=package_name, device_id=target_dev)

            findings: List[Finding] = []
            findings.extend(storage_engine.execute_stor_01())
            findings.extend(storage_engine.execute_stor_02())

            payload = [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in findings
            ]
            return json.dumps(payload, indent=2)
        except Exception as e:
            return json.dumps({"error": f"Dynamic sandbox check failure: {str(e)}"})

    @staticmethod
    def audit_device_environment(package_name: str, device_id: Optional[str] = None) -> str:
        """
        Evaluates system properties, sandbox directory permissions, and debugging sockets
        on the connected Android test environment (ROT-019 through ROT-026).
        """
        try:
            adb = ADBBridge()
            devices = adb.get_connected_devices()
            if not devices:
                return json.dumps({"error": "No connected ADB devices detected."})

            target_dev = device_id or devices[0]
            engine = RootEnvironmentEngine(package_name=package_name, device_id=target_dev)
            findings = engine.audit_environment()

            payload = [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in findings
            ]
            return json.dumps(payload, indent=2)
        except Exception as e:
            return json.dumps({"error": f"Environment audit failure: {str(e)}"})

    @staticmethod
    def test_runtime_protections(
        package_name: str,
        test_activity: str = "MainActivity",
        device_id: Optional[str] = None
    ) -> str:
        """
        Evaluates runtime defensive controls via ADB:
        tests for FLAG_SECURE window capture protection (DYN-030) and
        inspects the Android system clipboard buffer for sensitive residue (DYN-029).
        """
        try:
            adb = ADBBridge()
            devices = adb.get_connected_devices()
            if not devices:
                return json.dumps({"error": "No connected ADB devices detected."})

            target_dev = device_id or devices[0]
            engine = RuntimeBehaviorEngine(package_name=package_name, device_id=target_dev)

            findings = [
                engine.audit_dyn_030_screenshot_protection(test_activity),
                engine.audit_dyn_029_clipboard_leakage()
            ]

            payload = [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in findings
            ]
            return json.dumps(payload, indent=2)
        except Exception as e:
            return json.dumps({"error": f"Runtime behavior test failure: {str(e)}"})

    @staticmethod
    def generate_code_patch(check_id: str) -> str:
        """
        Generates a defensive Git patch / unified diff corresponding to a specific check ID
        (e.g., manifest hardening, backup exclusion rules, or cipher migrations).
        """
        try:
            patch_data = RemediationEngine.generate_patch(check_id)
            return json.dumps(patch_data, indent=2)
        except Exception as e:
            return json.dumps({"error": f"Patch synthesis failure: {str(e)}"})

    @staticmethod
    def query_audit_context(session_json: str, query: str) -> str:
        """
        Filters and retrieves cached findings by keyword, severity, check ID, or category.
        Enables the agent to retrieve targeted subsections without reloading full datasets.
        """
        try:
            data = json.loads(session_json)
            findings = data.get("findings", []) if isinstance(data, dict) else data
            query_lower = query.lower()

            matched = [
                f for f in findings
                if query_lower in f.get("title", "").lower()
                or query_lower in f.get("check_id", "").lower()
                or query_lower in f.get("category", "").lower()
                or query_lower in f.get("severity", "").lower()
                or query_lower in f.get("status", "").lower()
            ]
            return json.dumps(matched, indent=2)
        except Exception as e:
            return json.dumps({"error": f"Context filtering failure: {str(e)}"})


    @staticmethod
    def test_intent_injection(package_name: str, component_name: str, component_type: str = "activity", device_id: str = None) -> str:
        """
        Executes dynamic intent fuzzing (DYN-031, DYN-032) by sending boundary and malformed
        parameters to target exported components via ADB.
        """
        try:
            fuzzer = IntentFuzzerEngine(package_name=package_name, device_id=device_id)
            findings = fuzzer.test_component_injection(component_name=component_name, component_type=component_type)
            return json.dumps([f.dict() for f in findings], indent=2)
        except Exception as e:
            return json.dumps({"error": f"Intent fuzzer execution failure: {str(e)}"})

    @staticmethod
    def audit_runtime_network(package_name: str, device_id: str = None) -> str:
        """
        Inspects active socket bindings and HTTP proxy enforcement (DYN-026, DYN-034)
        for the target package's runtime process.
        """
        try:
            net_engine = NetworkRuntimeEngine(package_name=package_name, device_id=device_id)
            findings = net_engine.audit_active_sockets_and_proxy()
            return json.dumps([f.dict() for f in findings], indent=2)
        except Exception as e:
            return json.dumps({"error": f"Network runtime audit failure: {str(e)}"})

    @staticmethod
    def audit_root_data_isolation(package_name: str, main_activity: Optional[str] = None, device_id: Optional[str] = None) -> str:
        """
        Executes Batch 2 tests: root detection (ROT-021), bypass resistance (ROT-022),
        runtime process memory inspection (ROT-023), and app data extraction (ROT-026).
        """
        try:
            engine = RootIsolationEngine(package_name=package_name, device_id=device_id)
            findings = engine.audit_all_batch2(main_activity=main_activity)
            payload = [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in findings
            ]
            return json.dumps(payload, indent=2)
        except Exception as e:
            return json.dumps({"error": f"Root data isolation audit failure: {str(e)}"})

    @staticmethod
    def audit_runtime_verification(package_name: str, device_id: Optional[str] = None) -> str:
        """
        Executes Batch 3 tests: Auth bypass (DYN-027), log token exposure (DYN-028),
        WebView debugging (DYN-033), local storage (DYN-035), logout (DYN-036), and background state (DYN-037).
        """
        try:
            engine = RuntimeVerificationEngine(package_name=package_name, device_id=device_id)
            findings = engine.audit_all_batch3()
            payload = [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in findings
            ]
            return json.dumps(payload, indent=2)
        except Exception as e:
            return json.dumps({"error": f"Runtime verification audit failure: {str(e)}"})

    @staticmethod
    def inspect_current_screen(package_name: str) -> str:
        """Inspects current active screen and returns clickable/editable UI elements."""
        nav = get_navigator(package_name)
        return nav.dump_interactive_ui_nodes()

    @staticmethod
    def perform_ui_action(package_name: str, action_type: str, target: str, value: Optional[str] = None) -> str:
        """Performs a user interaction (tap, input_text, launch_activity, press_back)."""
        nav = get_navigator(package_name)
        return nav.execute_interaction(action_type=action_type, target=target, value=value)

    @staticmethod
    def record_finding_with_evidence(
        package_name: str,
        check_id: str,
        title: str,
        severity: str,
        description: str,
        remediation: str
    ) -> str:
        """
        Captures a screenshot, pulls recent logs, records the reproduction path,
        and saves it as verified evidence for the final report.
        """
        nav = get_navigator(package_name)
        evidence = nav.capture_evidence_artifact(check_id=check_id, label=title)
        
        finding_dict = {
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "status": "Fail",
            "description": description,
            "remediation": remediation,
            "evidence_image": evidence["evidence_image"],
            "evidence_log": evidence["evidence_log"],
            "reproduction_sequence": evidence["reproduction_sequence"]
        }
        return json.dumps(finding_dict, indent=2)

    @staticmethod
    def record_finding_with_evidence(
        package_name: str,
        check_id: str,
        title: str,
        severity: str,
        description: str,
        remediation: str
    ) -> str:
        # Guard against premature/hallucinated empty tool calls from LLMs
        if not check_id or not title:
            return json.dumps({
                "status": "skipped",
                "message": "check_id and title cannot be empty. First run scans or inspect screens before recording findings."
            })

        nav = get_navigator(package_name)
        evidence = nav.capture_evidence_artifact(check_id=check_id, label=title)
        
        finding_dict = {
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "status": "Fail",
            "description": description,
            "remediation": remediation,
            "evidence_image": evidence["evidence_image"],
            "evidence_log": evidence["evidence_log"],
            "reproduction_sequence": evidence["reproduction_sequence"]
        }
        return json.dumps(finding_dict, indent=2)