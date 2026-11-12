import struct
import zipfile
import re
from typing import List, Dict, Any, Set
from core.models import Finding, Severity, CheckStatus

class CodeResilienceEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def audit_tab07_code(self) -> List[Finding]:
        findings: List[Finding] = []

        with zipfile.ZipFile(self.apk_path, "r") as z:
            so_files = [f for f in z.namelist() if f.startswith("lib/") and f.endswith(".so")]

            # Group libraries by filename: e.g., 'libdivajni.so' -> ['lib/armeabi/...', 'lib/x86/...']
            lib_map: Dict[str, List[str]] = {}
            for path in so_files:
                name = path.split("/")[-1]
                lib_map.setdefault(name, []).append(path)

            for lib_name, arch_paths in lib_map.items():
                missing_canary_archs: List[str] = []
                missing_mitigations: Dict[str, Set[str]] = {
                    "PIE": set(),
                    "NX": set(),
                    "RELRO": set()
                }
                unsafe_symbols_found: Set[str] = set()

                for path in arch_paths:
                    elf_data = z.read(path)
                    protections = self._parse_elf_headers(elf_data)
                    arch = path.split("/")[1]

                    if not protections["has_canary"]:
                        missing_canary_archs.append(arch)
                    if not protections["is_pie"]:
                        missing_mitigations["PIE"].add(arch)
                    if not protections["nx_stack"]:
                        missing_mitigations["NX"].add(arch)
                    if not protections["relro"]:
                        missing_mitigations["RELRO"].add(arch)

                    for sym in ["strcpy", "strcat", "sprintf", "gets"]:
                        if sym.encode() in elf_data:
                            unsafe_symbols_found.add(sym)

                # AND-CODE-02: Stack Canary & Exploit Mitigations (Grouped by library)
                if missing_canary_archs:
                    findings.append(Finding(
                        check_id="AND-CODE-02",
                        title=f"Missing Stack Canary: {lib_name}",
                        category="MASVS-CODE",
                        tab_index=7,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description=f"Native binary '{lib_name}' lacks stack smashing protection (Stack Canary) across {len(missing_canary_archs)} architecture(s).",
                        evidence=f"Vulnerable architectures ({len(missing_canary_archs)}): {', '.join(missing_canary_archs)}\nLocations:\n" + "\n".join(f"- {p}" for p in arch_paths),
                        remediation="Recompile native code with -fstack-protector-strong."
                    ))
                else:
                    findings.append(Finding(
                        check_id="AND-CODE-02",
                        title=f"Binary Hardening Confirmed: {lib_name}",
                        category="MASVS-CODE",
                        tab_index=7,
                        severity=Severity.INFO,
                        status=CheckStatus.PASS,
                        description=f"Native shared library '{lib_name}' enforces Stack Canaries across all architectures.",
                        evidence=f"Verified across {len(arch_paths)} architecture(s)."
                    ))

                # AND-CODE-05: Insecure Native Function Imports (Grouped by library)
                if unsafe_symbols_found:
                    findings.append(Finding(
                        check_id="AND-CODE-05",
                        title=f"Unsafe C Functions Imported: {lib_name}",
                        category="MASVS-CODE",
                        tab_index=7,
                        severity=Severity.MEDIUM,
                        status=CheckStatus.FAIL,
                        description=f"Native library '{lib_name}' imports memory-unsafe symbols: {', '.join(sorted(unsafe_symbols_found))}.",
                        evidence=f"Library: {lib_name}\nSymbols: {sorted(list(unsafe_symbols_found))}\nFound across {len(arch_paths)} architecture(s).",
                        remediation="Replace legacy C memory routines with bounds-checked alternatives (snprintf, strncpy)."
                    ))

        return findings

    def audit_tab08_resilience(self) -> List[Finding]:
        findings = []

        root_indicators = [b"/system/xbin/su", b"/system/bin/su", b"Superuser.apk", b"magisk", b"test-keys"]
        debug_indicators = [b"isDebuggerConnected", b"TracerPid", b"ptrace"]
        emulator_indicators = [b"goldfish", b"ranchu", b"vbox86", b"qemu"]
        hook_indicators = [b"frida-gadget", b"frida-server", b"xposed", b"27042"]

        found_root = []
        found_debug = []
        found_emulator = []
        found_hook = []

        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_files = [f for f in z.namelist() if f.startswith("classes") and f.endswith(".dex")]
            for dex in dex_files:
                data = z.read(dex)
                for ind in root_indicators:
                    if ind in data and ind.decode() not in found_root:
                        found_root.append(ind.decode())
                for ind in debug_indicators:
                    if ind in data and ind.decode() not in found_debug:
                        found_debug.append(ind.decode())
                for ind in emulator_indicators:
                    if ind in data and ind.decode() not in found_emulator:
                        found_emulator.append(ind.decode())
                for ind in hook_indicators:
                    if ind in data and ind.decode() not in found_hook:
                        found_hook.append(ind.decode())

        # Evaluate AND-RESL-01 (Root Detection)
        findings.append(Finding(
            check_id="AND-RESL-01",
            title="Root Detection Mechanism Analysis",
            category="MASVS-RESILIENCE",
            tab_index=8,
            severity=Severity.INFO if found_root else Severity.LOW,
            status=CheckStatus.PASS if found_root else CheckStatus.NEEDS_REVIEW,
            description="Root detection heuristics detected in application bytecode." if found_root else "No standard root indicator checks were detected in application bytecode.",
            evidence=f"Identified strings/APIs: {found_root}" if found_root else "None"
        ))

        # Evaluate AND-RESL-02 (Anti-Debugging)
        findings.append(Finding(
            check_id="AND-RESL-02",
            title="Anti-Debugging Protection Analysis",
            category="MASVS-RESILIENCE",
            tab_index=8,
            severity=Severity.INFO if found_debug else Severity.LOW,
            status=CheckStatus.PASS if found_debug else CheckStatus.NEEDS_REVIEW,
            description="Anti-debugging calls or tracing checks found." if found_debug else "No native or managed debugger detection mechanisms identified.",
            evidence=f"Identified checks: {found_debug}" if found_debug else "None"
        ))

        # Evaluate AND-RESL-03 (Emulator Detection)
        findings.append(Finding(
            check_id="AND-RESL-03",
            title="Emulator Detection Analysis",
            category="MASVS-RESILIENCE",
            tab_index=8,
            severity=Severity.INFO if found_emulator else Severity.LOW,
            status=CheckStatus.PASS if found_emulator else CheckStatus.NEEDS_REVIEW,
            description="Heuristics checking for virtualized hardware detected." if found_emulator else "No emulator fingerprint detection routines detected.",
            evidence=f"Identified indicators: {found_emulator}" if found_emulator else "None"
        ))

        # Evaluate AND-RESL-05 (Hooking Resistance)
        findings.append(Finding(
            check_id="AND-RESL-05",
            title="Runtime Hooking Resistance Analysis",
            category="MASVS-RESILIENCE",
            tab_index=8,
            severity=Severity.INFO if found_hook else Severity.LOW,
            status=CheckStatus.PASS if found_hook else CheckStatus.NEEDS_REVIEW,
            description="Signatures targeting dynamic hooking or instrumentation frameworks detected." if found_hook else "No runtime checks for dynamic instrumentation frameworks detected.",
            evidence=f"Identified indicators: {found_hook}" if found_hook else "None"
        ))

        return findings

    def _parse_elf_headers(self, data: bytes) -> Dict[str, bool]:
        """Parses basic ELF structures in memory to evaluate compile-time protections."""
        result = {"has_canary": False, "is_pie": False, "nx_stack": True, "relro": False}

        if len(data) < 52 or data[:4] != b"\x7fELF":
            return result

        # Check 32-bit vs 64-bit ELF class
        is_64 = data[4] == 2
        e_type_offset = 16
        e_type = struct.unpack("<H" if data[5] == 1 else ">H", data[e_type_offset:e_type_offset + 2])[0]
        # ET_DYN (value 3) indicates shared library or PIE executable
        result["is_pie"] = (e_type == 3)

        # Detect Stack Canary symbol reference
        if b"__stack_chk_fail" in data or b"__stack_chk_guard" in data:
            result["has_canary"] = True

        # Scan program headers for PT_GNU_STACK and PT_GNU_RELRO
        # Program header types: PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552
        if b"\x51\xe5\x74\x64" in data or b"GNU_STACK" in data:
            result["nx_stack"] = True
        if b"\x52\xe5\x74\x64" in data or b"GNU_RELRO" in data:
            result["relro"] = True

        return result


class EnhancedNativeEngine:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def audit_native_libraries(self) -> List[Finding]:
        """Grouped audit across all native libraries to prevent architecture duplicate cards."""
        findings = []
        unsafe_symbols = [b"strcpy", b"strcat", b"sprintf", b"vsprintf", b"gets"]
        fortified_symbols = [b"__strcpy_chk", b"__sprintf_chk", b"__memcpy_chk"]

        with zipfile.ZipFile(self.apk_path, "r") as z:
            so_files = [f for f in z.namelist() if f.startswith("lib/") and f.endswith(".so")]

            lib_map: Dict[str, List[str]] = {}
            for path in so_files:
                name = path.split("/")[-1]
                lib_map.setdefault(name, []).append(path)

            for lib_name, arch_paths in lib_map.items():
                missing_canary_archs: List[str] = []
                unsafe_found: Set[str] = set()
                fortified_found: Set[str] = set()

                for so_path in arch_paths:
                    elf_bytes = z.read(so_path)
                    if not elf_bytes.startswith(b"\x7fELF"):
                        continue

                    arch = so_path.split("/")[1]
                    has_canary = (b"__stack_chk_fail" in elf_bytes) or (b"__stack_chk_guard" in elf_bytes)

                    if not has_canary:
                        missing_canary_archs.append(arch)

                    for s in unsafe_symbols:
                        if s in elf_bytes:
                            unsafe_found.add(s.decode())
                    for s in fortified_symbols:
                        if s in elf_bytes:
                            fortified_found.add(s.decode())

                if missing_canary_archs:
                    findings.append(Finding(
                        check_id="AND-CODE-02",
                        title=f"Missing Stack Canary: {lib_name}",
                        category="MASVS-CODE",
                        tab_index=7,
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        description=f"Shared library '{lib_name}' lacks stack canaries across {len(missing_canary_archs)} architecture(s).",
                        evidence=f"Vulnerable architectures ({len(missing_canary_archs)}): {', '.join(missing_canary_archs)}\nLocations:\n" + "\n".join(f"- {p}" for p in arch_paths),
                        remediation="Compile with -fstack-protector-strong or -fstack-protector-all."
                    ))

                if unsafe_found and not fortified_found:
                    findings.append(Finding(
                        check_id="AND-CODE-05",
                        title=f"Unfortified Memory Functions: {lib_name}",
                        category="MASVS-CODE",
                        tab_index=7,
                        severity=Severity.MEDIUM,
                        status=CheckStatus.FAIL,
                        description=f"Library '{lib_name}' imports unsafe memory functions without FORTIFY_SOURCE protections: {', '.join(sorted(unsafe_found))}.",
                        evidence=f"Library: {lib_name}\nUnsafe functions: {sorted(list(unsafe_found))}\nFortified equivalents detected: 0\nFound across {len(arch_paths)} architecture(s).",
                        remediation="Define -D_FORTIFY_SOURCE=2 during compilation and migrate to bounds-checked functions (strncpy, snprintf)."
                    ))

        return findings