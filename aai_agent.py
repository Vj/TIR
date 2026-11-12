# aai_agent.py
import json
import os
import sys
import datetime
import ollama

from aai_bridge import TIRToolbox
from core.models import Finding, Severity, CheckStatus, AuditSession
from core.orchestrator import TIROrchestrator

# 1. Define Tool Schemas for Ollama Function Calling
TIR_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_static_scan",
            "description": "Runs automated static security analysis on an Android APK across all 13 MASVS workspaces.",
            "parameters": {
                "type": "object",
                "properties": {
                    "apk_path": {
                        "type": "string",
                        "description": "The absolute or relative path to the Android APK file to scan."
                    }
                },
                "required": ["apk_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_dynamic_sandbox_check",
            "description": "Performs live inspection of the application sandbox (/data/data/<package>) on an attached Android device via ADB to check for unencrypted databases and SharedPreferences.",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "The target package identifier, e.g., jakhar.aseem.diva"
                    }
                },
                "required": ["package_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_device_environment",
            "description": "Evaluates environment security on a connected device (ROT-020 file permissions, ROT-024 system properties, ROT-025 JDWP debugging exposure).",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Target application package name."
                    }
                },
                "required": ["package_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "test_runtime_protections",
            "description": "Tests runtime defenses on an active device (DYN-030 FLAG_SECURE window capture protection, DYN-029 clipboard persistence).",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Target application package name."
                    },
                    "test_activity": {
                        "type": "string",
                        "description": "Activity name to test for screen capture protection (e.g., MainActivity)."
                    }
                },
                "required": ["package_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "generate_code_patch",
            "description": "Generates a defensive Git patch/diff for a specific check ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "check_id": {
                        "type": "string",
                        "description": "The check ID to generate a patch for (e.g. AND-RECON-02, AND-STOR-05, AND-CRYP-01)."
                    }
                },
                "required": ["check_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "test_intent_injection",
            "description": "Fuzzes an exported component (activity, service, or receiver) with unexpected extra parameters via ADB (DYN-031, DYN-032).",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {"type": "string", "description": "Target package name."},
                    "component_name": {"type": "string", "description": "Component class name to test."},
                    "component_type": {"type": "string", "enum": ["activity", "service", "receiver"], "default": "activity"}
                },
                "required": ["package_name", "component_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_runtime_network",
            "description": "Checks for local open listening ports and active proxy routing (DYN-026, DYN-034).",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {"type": "string", "description": "Target package name."}
                },
                "required": ["package_name"]
            }
        }
    },
    # In aai_agent.py under TIR_TOOLS
    {
        "type": "function",
        "function": {
            "name": "audit_root_data_isolation",
            "description": "Tests root detection validation (ROT-021), anti-hooking/tracer checks (ROT-022), process memory mapping (ROT-023), and run-as data extraction (ROT-026).",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {"type": "string", "description": "Target package name."},
                    "main_activity": {"type": "string", "description": "Optional main activity name to verify launch lifecycle."}
                },
                "required": ["package_name"]
            }
        }
    },
    # In aai_agent.py under TIR_TOOLS
    {
        "type": "function",
        "function": {
            "name": "audit_runtime_verification",
            "description": "Performs runtime deep checks: auth bypass (DYN-027), session token leaks in logcat (DYN-028), WebView debugging sockets (DYN-033), unencrypted SQLite/preferences storage (DYN-035), logout cleanup (DYN-036), and background snapshot handling (DYN-037).",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {"type": "string", "description": "Target package name."}
                },
                "required": ["package_name"]
            }
        }
    },
    # In aai_agent.py (append to TIR_TOOLS)
    {
        "type": "function",
        "function": {
            "name": "inspect_current_screen",
            "description": "Dumps and parses the active Android UI screen to find interactable buttons, text fields, and coordinates.",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {"type": "string", "description": "Target package name."}
                },
                "required": ["package_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "perform_ui_action",
            "description": "Interacts with the device UI (tap coordinates, enter text, press back, or launch activity) and records the reproduction trail.",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {"type": "string", "description": "Target package name."},
                    "action_type": {"type": "string", "enum": ["tap", "input_text", "launch_activity", "press_back"]},
                    "target": {"type": "string", "description": "Target coordinates 'x,y' for tap, or Activity name for launch_activity."},
                    "value": {"type": "string", "description": "Text value if action_type is input_text."}
                },
                "required": ["package_name", "action_type", "target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "record_finding_with_evidence",
            "description": "Records a verified vulnerability and automatically captures a screenshot, log trace, and the exact reproduction path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {"type": "string", "description": "Target package name."},
                    "check_id": {"type": "string", "description": "Check identifier (e.g., DYN-027, DYN-030)."},
                    "title": {"type": "string", "description": "Concise finding title."},
                    "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Informational"]},
                    "description": {"type": "string", "description": "Explanation of the discovered issue."},
                    "remediation": {"type": "string", "description": "Defensive code patch or fix recommendation."}
                },
                "required": ["package_name", "check_id", "title", "severity", "description", "remediation"]
            }
        }
    }
]

# 2. Map tool names to actual Python callables
TOOL_DISPATCHER = {
    "run_static_scan": lambda args: TIRToolbox.run_static_scan(args["apk_path"]),
    "run_dynamic_sandbox_check": lambda args: TIRToolbox.run_dynamic_sandbox_check(args["package_name"]),
    "audit_device_environment": lambda args: TIRToolbox.audit_device_environment(args["package_name"]),
    "test_runtime_protections": lambda args: TIRToolbox.test_runtime_protections(
        args["package_name"], args.get("test_activity", "MainActivity")
    ),
    "generate_code_patch": lambda args: TIRToolbox.generate_code_patch(args["check_id"]),
}
TOOL_DISPATCHER["test_intent_injection"] = lambda args: TIRToolbox.test_intent_injection(
    args["package_name"], args["component_name"], args.get("component_type", "activity")
)
TOOL_DISPATCHER["audit_runtime_network"] = lambda args: TIRToolbox.audit_runtime_network(args["package_name"])

TOOL_DISPATCHER["audit_root_data_isolation"] = lambda args: TIRToolbox.audit_root_data_isolation(
    args["package_name"], args.get("main_activity")
)

TOOL_DISPATCHER["audit_runtime_verification"] = lambda args: TIRToolbox.audit_runtime_verification(args["package_name"])

TOOL_DISPATCHER["inspect_current_screen"] = lambda args: TIRToolbox.inspect_current_screen(args["package_name"])
TOOL_DISPATCHER["perform_ui_action"] = lambda args: TIRToolbox.perform_ui_action(
    args["package_name"], args["action_type"], args["target"], args.get("value")
)
TOOL_DISPATCHER["record_finding_with_evidence"] = lambda args: TIRToolbox.record_finding_with_evidence(
    args["package_name"], args["check_id"], args["title"], args["severity"], args["description"], args["remediation"]
)

SYSTEM_PROMPT = """You are an autonomous Mobile Application Security Auditor integrated with the TIR (Test, Inspection & Reporting) framework.

Execution Workflow:
1. Always start by executing 'run_static_scan' on the APK.
2. Next, audit device root and dynamic runtime controls ('audit_device_environment', 'audit_root_data_isolation', 'audit_runtime_verification').
3. Use 'inspect_current_screen' and 'perform_ui_action' if dynamic screen navigation is required.
4. Only call 'record_finding_with_evidence' when you have confirmed a specific vulnerability with a valid check_id, title, and technical evidence. Never pass empty string arguments.
5. Provide a thorough synthesis across OWASP MASVS categories.
Your Responsibilities:
1. Invoke TIR tools ('run_static_scan', 'audit_device_environment', 'test_runtime_protections', etc.) against the target application.
2. Critically analyze findings across the 13 OWASP MASVS categories and extended tests, separating genuine flaws from benign design choices.
3. For verified vulnerabilities, clearly state the technical root cause and provide complete, copy-paste ready defensive code snippets (Kotlin, Java, ProGuard, or XML configurations).
4. Deliver an executive-level summary and actionable developer remediation plan. Do not generate weaponized attack payloads."""


def run_agentic_audit(apk_path: str, model_name: str = "llama3.1:8b", output_report: str = "combined_report.html"):
    print(f"[*] Starting TIR Agentic Auditor with model: {model_name}")
    print(f"[*] Target APK: {apk_path}\n")

    client = ollama.Client()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"Please conduct a comprehensive mobile security audit of the APK at '{apk_path}'. Run the scan, evaluate all findings across the 13 MASVS categories, triage false positives, and compile your final remediation synthesis."
        }
    ]

    collected_findings: list[Finding] = []
    orchestrator = TIROrchestrator(apk_path=apk_path)

    # Agent execution loop
    while True:
        response = client.chat(
            model=model_name,
            messages=messages,
            tools=TIR_TOOLS
        )

        message = response["message"]
        messages.append(message)

        tool_calls = message.get("tool_calls")
        # Fallback: Parse markdown text if model printed JSON instead of structured tool_calls
        if not tool_calls and "run_static_scan" in message.get("content", ""):
            import re
            json_match = re.search(r'\{.*"name"\s*:\s*"([^"]+)".*"parameters"\s*:\s*(\{.*?\})\s*\}', message["content"], re.DOTALL)
            if json_match:
                fn_name = json_match.group(1)
                try:
                    fn_args = json.loads(json_match.group(2))
                    tool_calls = [{"function": {"name": fn_name, "arguments": fn_args}}]
                except Exception:
                    pass
                
        if not tool_calls:
            ai_synthesis_text = message["content"]
            print("\n================= AGENT SYNTHESIS COMPLETE =================\n")
            print(ai_synthesis_text[:500] + "...\n[Full analysis included in report]\n")

            if not collected_findings:
                collected_findings = orchestrator.execute_all_automated()

            session = AuditSession(
                session_id=f"TIR-AAI-{datetime.date.today().strftime('%Y%m%d')}-001",
                target_apk=apk_path,
                package_name=orchestrator.metadata.get("package_name", "Unknown"),
                version_name=orchestrator.metadata.get("version_name", "1.0"),
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                findings=collected_findings,
                ai_analysis=ai_synthesis_text
            )

            print(f"[*] Generating combined report at: {output_report}...")
            orchestrator.generate_pdf_report(session, output_pdf_path=os.path.abspath(output_report))
            break

        for tool in tool_calls:
            fn_name = tool["function"]["name"]
            fn_args = tool["function"]["arguments"]

            print(f"[+] Agent executing tool: {fn_name}({fn_args})")
            if fn_name in TOOL_DISPATCHER:
                if fn_name == "run_static_scan":
                    raw_json = TOOL_DISPATCHER[fn_name](fn_args)
                    collected_findings = orchestrator.execute_all_automated()
                    messages.append({"role": "tool", "content": raw_json})
                else:
                    tool_result = TOOL_DISPATCHER[fn_name](fn_args)
                    messages.append({"role": "tool", "content": tool_result})
            else:
                messages.append({
                    "role": "tool",
                    "content": json.dumps({"error": f"Tool '{fn_name}' not recognized."})
                })


def run_interactive_session(apk_path: str, model_name: str = "llama3.1:8b"):
    """Interactive analyst console driven by local Ollama model."""
    print(f"\n[*] Initializing TIR Interactive Console for: {apk_path}")
    orchestrator = TIROrchestrator(apk_path=apk_path)
    
    print("[*] Running baseline static analysis...")
    findings = orchestrator.execute_all_automated()
    print(f"[+] Baseline scan complete. {len(findings)} checks loaded into context.")

    session_summary = json.dumps([
        {
            "check_id": f.check_id,
            "title": f.title,
            "severity": f.severity.value,
            "status": f.status.value,
            "category": f.category,
            "evidence": f.evidence
        }
        for f in findings
    ])

    client = ollama.Client()
    chat_history = [
        {
            "role": "system",
            "content": f"""You are TIR-Assistant, an expert mobile application security auditor.
The current audit findings for the loaded APK are:
{session_summary}

Answer the auditor's queries concisely. Focus on:
1. Explaining root causes and technical risks.
2. Separating false positives from verified flaws.
3. Suggesting concrete defensive code adjustments."""
        }
    ]

    print("\n[✓] Interactive session ready. Enter your question (or type 'exit' / 'quit'):\n")

    while True:
        try:
            user_input = input("TIR-Auditor > ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                print("[*] Exiting interactive console.")
                break

            chat_history.append({"role": "user", "content": user_input})
            response = client.chat(model=model_name, messages=chat_history)
            reply = response["message"]["content"]
            print(f"\nAAI-Agent:\n{reply}\n")
            chat_history.append({"role": "assistant", "content": reply})

        except KeyboardInterrupt:
            print("\n[*] Session aborted.")
            break
        except Exception as e:
            print(f"[!] Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python aai_agent.py <apk_path> [model_name] [--interactive] [--output report.html]")
        sys.exit(1)

    target_apk = os.path.abspath(sys.argv[1])
    selected_model = "llama3.1:8b"
    out_file = "combined_report.html"

    # Argument handling
    for i, arg in enumerate(sys.argv):
        if arg.startswith("--output") and i + 1 < len(sys.argv):
            out_file = sys.argv[i + 1]
        elif not arg.startswith("--") and i == 2:
            selected_model = arg

    if "--interactive" in sys.argv:
        run_interactive_session(target_apk, model_name=selected_model)
    else:
        run_agentic_audit(target_apk, model_name=selected_model, output_report=out_file)