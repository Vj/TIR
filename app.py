# app.py
import argparse
import sys
import os
import time
import datetime
import json

from core.models import AuditSession, CheckStatus
from core.orchestrator import TIROrchestrator
from engines.dynamic.logcat_watcher import LogcatWatcher
from engines.dynamic.adb_client import ADBBridge
from engines.dynamic.storage_engine import StorageEngine
from engines.dynamic.root_environment_engine import RootEnvironmentEngine
from engines.dynamic.runtime_behavior_engine import RuntimeBehaviorEngine
from engines.dynamic.component_audit_engine import ComponentAuditEngine
from engines.dynamic.root_isolation_engine import RootIsolationEngine
from engines.dynamic.runtime_verification_engine import RuntimeVerificationEngine
from engines.dynamic.shell_test_engine import ShellTestEngine
from engines.dynamic.runtime_coverage_engine import RuntimeCoverageEngine
from core.correlation import correlate_findings
from core.standards import enrich_findings

def main():
    parser = argparse.ArgumentParser(description="TIR Standalone Mobile Security Scanner")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # 1. Static Scan Subcommand
    scan_parser = subparsers.add_parser("scan", help="Run automated static analysis across all workspaces")
    scan_parser.add_argument("--apk", required=True, help="Absolute path to target APK")
    scan_parser.add_argument("--output", default="report.pdf", help="Output path for the generated PDF/HTML report")
    scan_parser.add_argument("--targets-output", default="dynamic_targets.json", help="Static-to-dynamic target seed JSON path")

    # 2. Dynamic Live Audit Subcommand
    dyn_parser = subparsers.add_parser("dynamic", help="Run active runtime audit with sandbox, root, and behavior checks")
    dyn_parser.add_argument("--apk", help="Optional path to target APK for static context")
    dyn_parser.add_argument("--package", required=True, help="Target application package name (e.g., com.target.app)")
    dyn_parser.add_argument("--activity", help="Specific target activity name to test for FLAG_SECURE (optional)")
    dyn_parser.add_argument("--device", help="ADB device identifier (optional)")
    dyn_parser.add_argument("--duration", type=int, default=25, help="Monitoring capture duration in seconds")
    dyn_parser.add_argument("--output", default="dynamic_report.html", help="Output report path")
    dyn_parser.add_argument("--targets", help="Optional dynamic_targets.json produced by a static scan")
    dyn_parser.add_argument("--explore", action="store_true", help="Opt in to bounded, non-destructive UI exploration and sandbox file hashing")
    dyn_parser.add_argument("--probe-ipc", action="store_true", help="Opt in to manifest-seeded service and read-only Content Provider probes")
    dyn_parser.add_argument("--max-ui-actions", type=int, default=12, help="Maximum UI taps when --explore is enabled (1-40)")

    args = parser.parse_args()

    if args.command == "scan":
        _handle_static_scan(args)
    elif args.command == "dynamic":
        _handle_dynamic_scan(args)
    else:
        parser.print_help()
        sys.exit(1)

def _handle_static_scan(args):
    apk_path = os.path.abspath(args.apk)
    output_path = os.path.abspath(args.output)

    if not os.path.exists(apk_path):
        print(f"[!] Error: Target APK file not found at: {apk_path}")
        sys.exit(1)

    print(f"[*] Target APK: {apk_path}")
    print(f"[*] Target Output: {output_path}")

    orchestrator = TIROrchestrator(apk_path=apk_path)
    print("[*] Running automated static checks across all 13 tabs + STA extensions...")
    findings = orchestrator.execute_all_automated()
    targets_path = orchestrator.write_dynamic_targets(args.targets_output)
    print(f"[+] Static-to-dynamic targets written: {targets_path}")
    print(f"[+] Total static checks evaluated: {len(findings)}")

    session = AuditSession(
        session_id=f"TIR-{datetime.date.today().strftime('%Y%m%d')}-001",
        target_apk=apk_path,
        package_name=orchestrator.metadata.get("package_name", "Unknown"),
        version_name=orchestrator.metadata.get("version_name", "1.0"),
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=findings
    )

    orchestrator.generate_pdf_report(session, output_pdf_path=output_path)

def _handle_dynamic_scan(args):
    adb = ADBBridge()
    devices = adb.get_connected_devices()

    if not devices:
        print("[!] Error: No connected ADB devices or emulators found.")
        sys.exit(1)

    device_id = args.device or devices[0]
    print(f"[*] Attached Device: {device_id}")
    print(f"[*] Target Package: {args.package}")

    static_findings = []
    targets_data = {}
    static_orchestrator = None
    if args.apk:
        apk_path = os.path.abspath(args.apk)
        if not os.path.isfile(apk_path):
            print(f"[!] Error: APK file not found: {apk_path}")
            sys.exit(2)
        print("[*] Running static analysis to seed and correlate this dynamic audit...")
        static_orchestrator = TIROrchestrator(apk_path=apk_path)
        if static_orchestrator.metadata.get("package_name") != args.package:
            print("[!] APK package name does not match --package.")
            sys.exit(2)
        static_findings = static_orchestrator.execute_all_automated()
        targets_data = static_orchestrator.dynamic_targets
    if args.targets:
        try:
            with open(args.targets, "r", encoding="utf-8") as stream:
                targets_data = json.load(stream)
            if not isinstance(targets_data, dict) or targets_data.get("schema_version") != 1:
                raise ValueError("Unsupported dynamic target schema")
            if targets_data.get("package_name") and targets_data["package_name"] != args.package:
                raise ValueError("Dynamic target package does not match --package")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"[!] Could not load dynamic targets: {exc}")
            sys.exit(2)

    all_dynamic_findings = []
    watcher = LogcatWatcher(device_id=device_id)
    watcher.start(package_name=args.package)

    # 1. Device Environment & Root Security Testing (ROT-019 to ROT-026)
    print("[*] Auditing environment, permissions, and debugging interfaces (ROT-*)...")
    root_engine = RootEnvironmentEngine(package_name=args.package, device_id=device_id)
    try:
        root_findings = root_engine.audit_environment()
        all_dynamic_findings.extend(root_findings)
        print(f"[+] Root/Environment checks complete: {len(root_findings)} checks evaluated.")
    except Exception as e:
        print(f"[!] Root/Environment audit notice: {e}")

    # 1.1 Device Root & Data Isolation Checks (ROT-021, ROT-022, ROT-023, ROT-026)
    print("[*] Auditing root detection, bypass resistance, and data extraction (Batch 2)...")
    isolation_engine = RootIsolationEngine(package_name=args.package, device_id=device_id)
    try:
        isolation_findings = isolation_engine.audit_all_batch2(main_activity=args.activity)
        all_dynamic_findings.extend(isolation_findings)
        print(f"[+] Root & data isolation checks complete: {len(isolation_findings)} checks evaluated.")
    except Exception as e:
        print(f"[!] Root isolation audit notice: {e}")

    # 2. Automated Application Sandbox Storage Audit (Tab 02)
    print("[*] Inspecting application sandbox storage (/data/data/)...")
    storage_scanner = StorageEngine(adb, package_name=args.package, device_id=device_id)
    try:
        pref_findings = storage_scanner.execute_stor_01()
        db_findings = storage_scanner.execute_stor_02()
        all_dynamic_findings.extend(pref_findings)
        all_dynamic_findings.extend(db_findings)
        print(f"[+] Sandbox inspection complete: Found {len(pref_findings)} SharedPreferences issues, {len(db_findings)} database issues.")
    except Exception as e:
        print(f"[!] Sandbox check notice: Could not inspect sandbox directly ({e}).")

   
    # 3. Runtime Behavior & UI Protection Testing (DYN-029, DYN-030, DYN-031, DYN-032)
    print("[*] Evaluating runtime clipboard and component protections (DYN-*)...")
    behavior_engine = RuntimeBehaviorEngine(package_name=args.package, device_id=device_id)

    
    try:
        # Check Clipboard
        clip_finding = behavior_engine.audit_dyn_029_clipboard_leakage()
        all_dynamic_findings.append(clip_finding)

        # Discover or select target activities
        if args.activity:
            activities_to_test = [args.activity]
        else:
            print("[*] Discovering exported activities via dumpsys...")
            activities_to_test = behavior_engine.discover_exported_activities()
            if not activities_to_test:
                activities_to_test = ["MainActivity"]
            print(f"[+] Discovered {len(activities_to_test)} activity target(s): {', '.join(activities_to_test)}")

        # Audit FLAG_SECURE on each discovered activity
        for act in activities_to_test:
            print(f"    -> Auditing FLAG_SECURE on: {act}")
            screen_finding = behavior_engine.audit_dyn_030_screenshot_protection(act)
            all_dynamic_findings.append(screen_finding)

    except Exception as e:
        print(f"[!] Runtime behavior test notice: {e}")
    '''# 3. Runtime Behavior & UI Protection Testing (DYN-029, DYN-030)

    print("[*] Evaluating runtime clipboard and UI protections (DYN-*)...")
    behavior_engine = RuntimeBehaviorEngine(package_name=args.package, device_id=device_id)
    try:
        # Test clipboard
        clip_finding = behavior_engine.audit_dyn_029_clipboard_leakage()
        all_dynamic_findings.append(clip_finding)

        # Test screenshot / task preview protection if an activity is supplied or discovered
        test_act = args.activity or "MainActivity"
        screen_finding = behavior_engine.audit_dyn_030_screenshot_protection(test_act)
        all_dynamic_findings.append(screen_finding)
        print("[+] Clipboard and UI protection checks completed.")
    except Exception as e:
        print(f"[!] Runtime behavior test notice: {e}")

    '''
    # 4. Automated Component Discovery & Resilience Audit (DYN-031, DYN-032)
    print("[*] Auditing exported component launch resilience and parameter parsing...")
    comp_engine = ComponentAuditEngine(package_name=args.package, device_id=device_id)
    try:
        seeded_components = (targets_data.get("components") or None) if args.probe_ipc else None
        comp_findings = comp_engine.audit_exported_components(targets=seeded_components)
        all_dynamic_findings.extend(comp_findings)
        print(f"[+] Component resilience audit complete: {len(comp_findings)} check(s) evaluated.")
    except Exception as e:
        print(f"[!] Component resilience notice: {e}")
        
    # 5. Dynamic & Runtime Verification Suite (Batch 3: DYN-027, DYN-028, DYN-033, DYN-035, DYN-036, DYN-037)
    print("[*] Executing runtime verification suite (Batch 3: DYN-027, DYN-028, DYN-033, DYN-035, DYN-036, DYN-037)...")
    verification_engine = RuntimeVerificationEngine(package_name=args.package, device_id=device_id)
    try:
        batch3_findings = verification_engine.audit_all_batch3(
            discovered_activities=activities_to_test if 'activities_to_test' in locals() else None
        )
        all_dynamic_findings.extend(batch3_findings)
        print(f"[+] Runtime verification complete: {len(batch3_findings)} checks evaluated.")
    except Exception as e:
        print(f"[!] Runtime verification notice: {e}")

        
    # 5. Modular read-only device-side shell checks
    print("[*] Running modular runtime process and package-flag checks...")
    shell_engine = ShellTestEngine(package_name=args.package, device_id=device_id)
    try:
        shell_findings = shell_engine.audit_all()
        all_dynamic_findings.extend(shell_findings)
        print(f"[+] Shell checks complete: {len(shell_findings)} result(s).")
    except Exception as e:
        print(f"[!] Shell checks notice: {e}")

    if args.explore:
        print("[*] Running opted-in bounded UI exploration and file-system diff...")
        try:
            coverage_engine = RuntimeCoverageEngine(package_name=args.package, device_id=device_id)
            coverage_findings = coverage_engine.explore(max_actions=args.max_ui_actions)
            all_dynamic_findings.extend(coverage_findings)
            print(f"[+] UI exploration complete: {len(coverage_findings)} coverage result(s).")
        except Exception as e:
            print(f"[!] UI exploration notice: {e}")

    # Logcat has been monitoring since the start of the dynamic audit.
    print(f"[*] Live Logcat monitoring continues for {args.duration}s...")
    print("[*] Perform user actions on the device now...")

    try:
        for remaining in range(args.duration, 0, -5):
            print(f"    ... {remaining}s remaining ...")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by analyst.")

    log_findings = watcher.stop()
    all_dynamic_findings.extend(log_findings)
    print(f"[+] Log monitoring finished: Captured {len(log_findings)} log findings.")

    # Correlate static and dynamic evidence without converting lack of observation to proof.
    dynamic_findings = [
        item.model_copy(update={"coverage": {**item.coverage, "device": device_id}})
        for item in all_dynamic_findings
    ]
    all_findings = correlate_findings(static_findings, dynamic_findings) if static_findings else enrich_findings(dynamic_findings)

    # 5. Consolidate and Render Final Dynamic Report
    session = AuditSession(
        session_id=f"TIR-DYN-{datetime.date.today().strftime('%Y%m%d')}-001",
        target_apk=args.apk or "Runtime Device Target",
        package_name=args.package,
        version_name="Dynamic Run",
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=all_findings
    )

    orchestrator = static_orchestrator
    if orchestrator:
        orchestrator.generate_pdf_report(session, output_pdf_path=os.path.abspath(args.output))
    else:
        from jinja2 import Environment, FileSystemLoader
        base_dir = os.path.dirname(os.path.abspath(__file__))
        tpl_dir = os.path.join(base_dir, "reporting", "templates")
        env = Environment(loader=FileSystemLoader(tpl_dir))
        template = env.get_template("report_base.html")

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in all_dynamic_findings:
            if f.status == CheckStatus.FAIL:
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        html_out = template.render(
            session=session,
            counts=counts,
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(html_out)
        print(f"[+] Dynamic audit report generated: {os.path.abspath(args.output)}")

if __name__ == "__main__":
    main()