"""Optional attach-only Frida observer for TLS configuration API use."""
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import AnalysisType, CheckStatus, Confidence, Finding, Severity


class FridaTLSObserver:
    def __init__(self, package_name: str, device_id: Optional[str] = None):
        self.package_name = package_name
        self.device_id = device_id
        self.device = None
        self.session = None
        self.script = None
        self.events: List[Dict[str, Any]] = []
        self.error: Optional[str] = None
        self.script_path = Path(__file__).resolve().parents[2] / "scripts" / "dynamic" / "tls_observer.js"

    def _on_message(self, message, data):
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                self.events.append(payload)
        elif message.get("type") == "error":
            self.error = (message.get("description") or "Frida script error")[:300]

    def start(self) -> None:
        try:
            import frida
            self.device = frida.get_device_manager().get_device(self.device_id, timeout=8) if self.device_id else frida.get_usb_device(timeout=8)
            process = next((p for p in self.device.enumerate_processes() if p.name == self.package_name), None)
            if process is None:
                raise RuntimeError("Target app process is not running; start it before --frida-tls.")
            source = self.script_path.read_text(encoding="utf-8")
            self.session = self.device.attach(process.pid)
            self.script = self.session.create_script(source)
            self.script.on("message", self._on_message)
            self.script.load()
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"[:400]
            self.stop()

    def stop(self) -> Finding:
        try:
            if self.script:
                self.script.unload()
        except Exception:
            pass
        try:
            if self.session:
                self.session.detach()
        except Exception:
            pass

        event_types = sorted({str(item.get("type", "unknown")) for item in self.events})
        if self.error:
            status, confidence = CheckStatus.NEEDS_REVIEW, Confidence.LOW
            description = "Optional Frida TLS observation was unavailable or stopped with an error."
            evidence = self.error
        elif self.events:
            status, confidence = CheckStatus.NEEDS_REVIEW, Confidence.MEDIUM
            description = "TLS configuration APIs were observed. Hook events indicate implementation paths, not whether validation is secure or bypassed."
            evidence = json.dumps({"event_types": event_types, "event_count": len(self.events),
                                   "samples": self.events[:20]}, indent=2, sort_keys=True)
        else:
            status, confidence = CheckStatus.NEEDS_REVIEW, Confidence.LOW
            description = "No monitored TLS API event was observed during the attached session; coverage depends on app actions and runtime implementation."
            evidence = "No TLS configuration hook events captured."
        return Finding(
            check_id="TIR-FRIDA-TLS-HOOKS",
            title="Runtime TLS configuration observation",
            category="MASVS-NETWORK",
            tab_index=5,
            severity=Severity.INFO,
            status=status,
            analysis_type=AnalysisType.DYNAMIC,
            confidence=confidence,
            confidence_score=0.35 if not self.events else 0.65,
            description=description,
            evidence=evidence,
            remediation="Review observed trust manager and pinning call sites alongside the captured network behavior.",
            coverage={"device": self.device_id, "instrumentation": "Frida attach-only"},
        )
