# TIR (Test, Inspection & Reporting)

TIR is an autonomous, standalone security verification and audit orchestration tool designed for Android mobile applications. Built around the OWASP Mobile Application Security Verification Standard (MASVS), TIR executes static analysis, orchestrates dynamic device inspections over ADB, and compiles audit deliverables via WeasyPrint without relying on external decompilation servers or cloud plugins.

---

## Architecture Overview

TIR structures the verification lifecycle across 13 dedicated workspaces:

| Tab | Category | Focus Areas |
| :---: | :--- | :--- |
| **01** | **Information Gathering & Static Setup** | APK identity, v1–v4 signing schemes, manifest permissions, hardcoded secrets, and app links. |
| **02** | **MASVS-STORAGE: Data Storage** | SharedPreferences exposure, SQLite/Room encryption, backup rules, and snapshot caching (`FLAG_SECURE`). |
| **03** | **MASVS-CRYPTO: Cryptography** | Deprecated ciphers (DES/RC4/ECB), weak hashes (MD5/SHA1), static IVs, and PRNG predictability. |
| **04** | **MASVS-AUTH: Authentication & Sessions** | Biometric Keystore bindings (`CryptoObject`), token persistence, and cleartext credential transport. |
| **05** | **MASVS-NETWORK: Network Communication** | Network Security Config (`cleartextTrafficPermitted`), certificate pinning, and custom TrustManagers. |
| **06** | **MASVS-PLATFORM: Platform Interaction** | Custom URL schemes, exported Content Providers without permissions, and unsafe WebView bridge settings. |
| **07** | **MASVS-CODE: Code Quality & Build** | `android:debuggable` flags, native binary mitigations (PIE, Stack Canary, NX, RELRO), and unsafe C imports. |
| **08** | **MASVS-RESILIENCE: Anti-Reversing** | Detection heuristics for root status, managed/native debuggers (`TracerPid`), emulators, and dynamic hooks. |
| **09** | **MASVS-PRIVACY: Privacy Testing** | Dangerous permission minimization, tracker package inventories, and Advertising ID (AAID) vs. hardware IDs. |
| **10** | **Business Logic Testing** | Structured evaluation for price manipulation, IDOR/BOLA vectors, workflow bypasses, and file upload validation. |
| **11** | **Backend API & Server-side Testing** | Query-string token leakage, debug/shadow endpoint identification, and rate-limiting validation. |
| **12** | **Supply Chain & Third-party SDKs** | Software Bill of Materials (SBOM), known library catalogs, and in-app update integrity. |
| **13** | **Logging, Crash Reporting & Alerting** | Unstripped debug logs (`Log.d`/`Log.v`), crash dump sanitization, and security event propagation. |

---

## Directory Structure

```text
tir/
├── app.py                      # Main application entrypoint / CLI runner
├── config/
│   └── settings.yaml           # Global paths, ADB timeouts, and threshold configs
├── core/
│   ├── models.py               # Pydantic data schemas (Findings, Severity, Session)
│   ├── orchestrator.py         # Pipeline execution engine and report dispatcher
│   └── session.py              # Audit session persistence and state management
├── engines/
│   ├── static/                 # Standalone in-process parsers
│   │   ├── axml_parser.py      # Binary XML and manifest parsing
│   │   ├── code_resilience.py  # ELF binary inspector and resilience scanner
│   │   ├── crypto_auth.py      # DEX bytecode cryptographic & auth audits
│   │   ├── network_platform.py # Network config parser and WebView auditors
│   │   ├── privacy.py          # Permissions and analytics telemetry auditor
│   │   ├── recon.py            # APK identity and secrets scanner
│   │   └── supply_logging.py   # Dependency inventory, URLs, and logging checks
│   └── dynamic/
│       ├── adb_client.py       # Direct ADB socket and command bridge
│       └── storage_engine.py   # Sandbox puller and database header scanner
├── reporting/
│   ├── generator.py            # PDF rendering module
│   └── templates/
│       └── report_base.html    # Jinja2 executive and technical report template
└── rules/                      # Declarative YAML rule definitions (Tabs 01–13)


### Prerequisites
1.Python 3.10+
2.Android Debug Bridge (ADB) installed and present in your system PATH.
3.WeasyPrint System Dependencies:
    
    Linux (Debian/Ubuntu):
    sudo apt-get update
    sudo apt-get install -y build-essential python3-dev libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libffi-dev

    macOS:
    brew install pango harfbuzz libffi

    Windows:
    Ensure the GTK3 runtime for Windows is installed and added to the environment variables if required by your WeasyPrint distribution.

### Installation

1. Clone or copy the repository to your local workspace:
    git clone <repository_url> tir
    cd tir

2. Create and activate a virtual environment:
    python -m venv venv
    # Linux/macOS
    source venv/bin/activate
    # Windows
    .\venv\Scripts\activate

3. Install the dependencies:
pip install -r requirements.txt


### Usage
1. Automated Static Verification
Run static analysis across an APK archive and export a WeasyPrint PDF report:

python -X dev app.py scan --apk "C:\Users\ADMIN\Downloads\InsecureBankv2.apk" --output report.pdf
python app.py dynamic --package jakhar.aseem.diva --duration 20 --output dynamic_report.html
Invoke-Item .\dynamic_report.html 


python aai_agent.py "C:\1\research-tools\SISAL\samples\DivaApplication.apk" llama3.1:8b
python aai_agent.py "C:\1\research-tools\SISAL\samples\DivaApplication.apk" llama3.1:8b --interactive 
 (enter - [exit] to end interactive session)
python aai_agent.py "C:\1\research-tools\SISAL\samples\DivaApplication.apk" llama3.1:8b --output unified_audit_report.html
InsecureBankv2.apk
python aai_agent.py "C:\Users\ADMIN\Downloads\InsecureBankv2.apk" llama3.1:8b --output unified_audit_report.html

2. Dynamic Sandbox Auditing
Connect an Android test device with USB debugging enabled, then execute the dynamic storage checks:
python app.py dynamic --device <DEVICE_SERIAL> --package com.example.app

3. Programmatic Execution
Integrate the orchestrator directly into automated CI/CD pipelines or test scripts:
//
from core.models import AuditSession
from core.orchestrator import TIROrchestrator

# Initialize the engine
orchestrator = TIROrchestrator(apk_path="target.apk")

# Run all automated static checks across the 13 tabs
findings = orchestrator.execute_all_automated()

# Populate the session
session = AuditSession(
    session_id="TIR-AUDIT-001",
    target_apk="target.apk",
    package_name=orchestrator.metadata.get("package_name"),
    version_name=orchestrator.metadata.get("version_name"),
    timestamp="2026-11-10",
    findings=findings
)

# Render formal PDF deliverable
orchestrator.generate_pdf_report(session, output_pdf_path="audit_report.pdf")
//


### Security Verification & Reporting Policy
TIR evaluates checks against predefined severity thresholds:
Critical / High: Direct integrity, cryptographic, or storage failures requiring immediate remediation before production deployment.
Medium / Low: Hardening oversights and defense-in-depth gaps.
Needs Review: Guided items (such as business logic workflows, external third-party domains, and biometrics) requiring manual analyst validation.

## Modular dynamic shell checks

The `dynamic` command now runs bundled, read-only Android shell checks through the selected ADB device. The first checks inspect the running app's `TracerPid` and the installed package's `DEBUGGABLE` flag. Script files live in `scripts/dynamic/`; the Python runner allow-lists script names, validates the package identifier, applies a timeout, and maps results into the standard TIR finding model.

Start the target app on the test device before the audit so process-level checks can collect evidence:

```sh
python app.py dynamic --package com.example.app --device DEVICE_SERIAL --duration 25
```

The scripts are read-only and do not install packages, alter device settings, or modify app data. Results that cannot be established (for example, when the app is not running or the package flags are unavailable) are reported as needing analyst review.


## MASVS v2 / MASTG v2 analysis and correlation

TIR writes versioned findings with MASVS controls, MASWE weaknesses, MASTG test references and status, numeric confidence, and verification state. The checked-in `standards/owasp_mobile_catalog.json` records current versus placeholder tests; mappings are evidence references and do not claim OWASP certification.

Static APK analysis now includes:

- Jetpack DataStore and Jetpack Security Crypto API reference detection. These produce review items; a library reference alone does not prove that sensitive values are stored or that a keyset is misconfigured.
- ELF header and program-header review for packaged `.so` files, including executable stack, stack-canary imports, RELRO, and debug-section indicators. Native string scanning reports high-signal secret candidates for analyst review.
- Manifest-derived exported component and deep-link targets, including HTTPS App Link `autoVerify` state; PendingIntent and SDK package fingerprints are reported conservatively.
- A versioned `dynamic_targets.json` handoff. The APK scanner emits it during static scans.

Examples:

```sh
python app.py scan --apk target.apk --targets-output dynamic_targets.json --output report.pdf
python app.py dynamic --apk target.apk --package com.example.app --targets dynamic_targets.json --device DEVICE_SERIAL --duration 25 --probe-ipc --explore --max-ui-actions 12
```

Supply one or more explicit deep links to exercise after the static scan validates their scheme/host. Flow capture and Frida observation are optional:

```sh
python app.py dynamic --apk target.apk --package com.example.app --deep-link 'https://example.com/open' --frida-tls --mitm-flows mitm_metadata.jsonl
```

For network capture, start an analyst-managed mitmproxy instance separately; TIR does not change device proxy or CA settings. Example for PowerShell:

```powershell
$env:TIR_MITM_JSONL = (Resolve-Path .).Path + '\\mitm_metadata.jsonl'
mitmdump -s .\\scripts\\dynamic\\mitm_export.py
```

The exporter records only scheme, host, method, response status, and TLS version. It excludes request/response bodies, headers, paths, query strings, and cookies. Proxy flows are not automatically attributed to the target package, so use a dedicated test device and confirm attribution before treating an observation as a finding.

Install Frida's Python bindings compatible with the device's Frida server before using `--frida-tls`. The observer attaches to an already-running process and records TLS configuration API events; it does not bypass certificate checks. Optional call-graph annotation requires an Androguard version that exposes `Analysis.get_call_graph`; unavailable or unmatched reachability remains unknown and never suppresses a finding.

Dynamic correlation runs the static scan when `--apk` is supplied, validates the target package, and combines matching evidence. Runtime non-observation is kept separate from proven unreachability. UI exploration is opt-in, bounded to 1–40 taps, skips unlabeled controls and controls with common destructive/action labels, enters no text, and never records sandbox file contents. The differential snapshot stores only paths and SHA-256 digests; app-private access may require a debuggable test build, and external-storage coverage depends on Android version and device policy.

SBOM package fingerprints are inventory hints: TIR extracts Maven metadata when packaged but does not establish exact versions for every bundled library or query a vulnerability database. Call-graph reachability is optional and annotates component findings only when the analyzer can prove a match; it never suppresses findings. Frida and proxy capture are optional adapters and require an analyst-configured test environment. No automated MASVS compliance claim is made.
