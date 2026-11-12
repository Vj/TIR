# TIR (Test, Inspection & Reporting)

TIR is an autonomous, standalone security verification and audit orchestration tool designed for Android mobile applications. Built directly around the OWASP Mobile Application Security Verification Standard (MASVS), TIR executes static binary and resource checks, runs dynamic device inspections over ADB, and generates interactive audit reports without requiring external decompilation servers or cloud plugins.

TIR can also operate as a deterministic toolset for an **Agentic AI (AAI)** workflow powered by local LLMs via Ollama.

---

## Key Capabilities

- **100% In-Process & Standalone:** Operates with zero external background servers (no MobSF, Django, or cloud APIs required).
- **13 OWASP MASVS Workspaces:** Maps findings directly to standard verification categories.
- **Deep Static Inspection:**
  - Manifest security configurations, dangerous permissions inventory, and custom URL schemes.
  - Bytecode cryptographic algorithms, weak cipher identification, and static IV analysis.
  - Native shared library (`.so`) hardening audits (Stack Canary, PIE, NX stack, RELRO, and insecure C runtime symbols).
  - Bundled asset and resource scanning (`.jks`, `.keystore`, `.pem`, `.sql`, `.env`, high-entropy secret patterns).
  - ProGuard/R8 class obfuscation ratio scoring and debug symbol verification.
  - Advanced Network Security Config parsing (`<certificates src="user" />`, cleartext domain whitelists, expired pinning).
- **Dynamic Device Verification (ADB):**
  - Application sandbox auditing (`/data/data/<package>/` for unencrypted SQLite databases and SharedPreferences).
  - Real-time Logcat stream monitoring for credentials, auth tokens, PII, and unhandled exception stack traces.
- **Dual Reporting System:** Interactive HTML audit dashboard with client-side category and severity filtering, plus automatic compilation to PDF via WeasyPrint (with graceful HTML fallback).
- **Agentic AI (Ollama) Integration:** Native tool-calling bridge allowing local models (such as `llama3.1:8b` or `qwen2.5-coder`) to run scans, filter false positives, and draft developer-ready remediations.

---

## 13 MASVS Workspaces

| Workspace | Category | Coverage Summary |
| :---: | :--- | :--- |
| **01** | **Information Gathering & Static Setup** | APK identity, v1–v4 signing schemes, manifest permissions inventory, hardcoded secrets, and app links. |
| **02** | **MASVS-STORAGE: Data Storage** | SharedPreferences exposure, SQLite/Room encryption, backup rules (`backup_rules.xml`), and snapshot caching (`FLAG_SECURE`). |
| **03** | **MASVS-CRYPTO: Cryptography** | Deprecated ciphers (DES/RC4/ECB), weak hashes (MD5/SHA1), static IVs, and PRNG predictability. |
| **04** | **MASVS-AUTH: Authentication & Sessions** | Biometric Keystore bindings (`CryptoObject`), token persistence, and cleartext credential transport. |
| **05** | **MASVS-NETWORK: Network Communication** | Network Security Config (`cleartextTrafficPermitted`), user trust anchors, certificate pinning, and custom TrustManagers. |
| **06** | **MASVS-PLATFORM: Platform Interaction** | Custom URL schemes, exported Content Providers without permissions, and unsafe WebView bridge settings. |
| **07** | **MASVS-CODE: Code Quality & Build** | `android:debuggable` flags, native binary mitigations (PIE, Canary, NX, RELRO), ProGuard obfuscation scoring, and asset leaks. |
| **08** | **MASVS-RESILIENCE: Anti-Reversing** | Detection heuristics for root status, managed/native debuggers (`TracerPid`), emulators, and dynamic hooks. |
| **09** | **MASVS-PRIVACY: Privacy Testing** | Dangerous permission minimization, tracker package inventories, and Advertising ID (AAID) vs. hardware IDs. |
| **10** | **Business Logic Testing** | Structured evaluation for price manipulation, IDOR/BOLA vectors, workflow bypasses, and file upload validation. |
| **11** | **Backend API & Server-side Testing** | Query-string token leakage, debug/shadow endpoint identification, and rate-limiting validation. |
| **12** | **Supply Chain & Third-party SDKs** | Software Bill of Materials (SBOM), known library catalogs, and in-app update integrity. |
| **13** | **Logging, Crash Reporting & Alerting** | Unstripped debug logs (`Log.d`/`Log.v`), crash dump sanitization, and security event propagation. |

---

## Project Structure

```text
tir/
├── aai_agent.py                # Agentic AI autonomous auditor runner (Ollama)
├── aai_bridge.py               # Tool definitions and JSON interfaces for LLM function calling
├── app.py                      # Main CLI entrypoint (static scan & dynamic runtime audit)
├── config/
│   └── settings.yaml           # Global timeouts, thresholds, and tool configs
├── core/
│   ├── models.py               # Pydantic data schemas (Finding, Severity, CheckStatus, Session)
│   ├── orchestrator.py         # Static pipeline orchestrator and reporting dispatcher
│   └── session.py              # Audit session persistence and state management
├── engines/
│   ├── static/                 # Standalone in-process static parsers
│   │   ├── asset_file_engine.py       # Bundled keystore, secret, and file scanner
│   │   ├── axml_parser.py             # Binary XML and manifest reader
│   │   ├── code_resilience_engine.py  # ELF binary inspector and anti-reversing scanner
│   │   ├── component_backup_engine.py # Exported component and backup rules evaluator
│   │   ├── crypto_auth_engine.py      # Bytecode cryptography and auth scanner
│   │   ├── network_advanced_engine.py # Network security config and CA trust auditor
│   │   ├── network_platform_engine.py # WebView settings and network config parser
│   │   ├── obfuscation_engine.py      # ProGuard/R8 class minification ratio scorer
│   │   ├── privacy_engine.py          # Permissions and analytics telemetry auditor
│   │   ├── recon_engine.py            # APK identity, signature, and secrets scanner
│   │   └── supply_logging_engine.py   # Dependency inventory, URLs, and logging checks
│   └── dynamic/                # Device runtime controllers
│       ├── adb_client.py              # Native ADB command and socket bridge
│       ├── logcat_watcher.py          # Non-blocking background logcat leak sniffer
│       └── storage_engine.py          # Sandbox file extractor and SQLite header scanner
├── reporting/
│   ├── generator.py            # PDF rendering module
│   └── templates/
│       └── report_base.html    # Interactive HTML/CSS dashboard with client-side filtering
└── rules/                      # Declarative YAML rule definitions (Tabs 01–13)
```

---

## Installation

### 1. Prerequisites
- **Python 3.10+**
- **Android Debug Bridge (ADB)** installed and accessible in your system `PATH`.
- *(Optional for PDF export)* GTK3 runtime libraries for WeasyPrint. If GTK3 is not installed, TIR automatically generates standalone, interactive HTML reports.
- *(Optional for AAI)* [Ollama](https://ollama.com/) installed and running locally.

### 2. Setup
```bash
# Clone the repository
git clone <repository_url> tir
cd tir

# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### 1. Automated Static Verification
Run static analysis across all workspaces and compile an audit report:
```bash
python app.py scan --apk /path/to/target.apk --output report.pdf
```
*Note: If WeasyPrint system dependencies are not configured on Windows, TIR seamlessly outputs `report.html`.*

### 2. Dynamic Sandbox & Logcat Audit
Connect an Android test device or emulator with USB debugging enabled, then execute the live dynamic audit:
```bash
python app.py dynamic --package com.example.app --duration 30 --output dynamic_report.html
```
During the countdown, exercise the target app (logins, navigation, inputs). TIR will inspect the sandbox storage (`/data/data/<package>/`) and capture any runtime log leaks in the background.

### 3. Agentic AI (Ollama) Autonomous Audit
Run an autonomous security review using a local LLM:
```bash
# 1. Pull the model (in a separate terminal)
ollama pull llama3.1:8b

# 2. Run the agentic audit
python aai_agent.py /path/to/target.apk llama3.1:8b
```
The model will invoke TIR tools via function calls, evaluate the findings across the 13 MASVS workspaces, filter out false positives, and output a prioritized vulnerability briefing with tailored remediation code snippets.

---

## Reporting Features

- **Summary Counters:** Instant breakdown of findings across Critical, High, Medium, Low, and Informational tiers.
- **Client-Side Filtering:** Toggle between All Results, Failures Only, Needs Review, or Passed Checks without reloading.
- **Collapsible Workspaces:** Clean accordion grouping for all 13 MASVS verification domains.
- **Actionable Evidence:** Includes class paths, decompiled context snippets, or configuration fragments alongside remediation instructions.