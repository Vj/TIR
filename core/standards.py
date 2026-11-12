"""Load the versioned OWASP MASVS/MASTG/MASWE mapping catalog."""
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from core.models import Finding


CATALOG_PATH = Path(__file__).resolve().parents[1] / "standards" / "owasp_mobile_catalog.json"


def load_catalog() -> Dict[str, Any]:
    with CATALOG_PATH.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def enrich_finding(finding: Finding, catalog: Dict[str, Any] = None) -> Finding:
    """Attach standards IDs and preserve catalog status without claiming certification."""
    catalog = catalog or load_catalog()
    entry = catalog.get("entries", {}).get(finding.check_id)
    if not entry:
        return finding
    mastg_refs = [item["id"] for item in entry.get("mastg", [])]
    statuses = {item["id"]: item.get("status", "unknown") for item in entry.get("mastg", [])}
    return finding.model_copy(update={
        "masvs_ref": finding.masvs_ref or ", ".join(entry.get("masvs", [])),
        "maswe_refs": sorted(set(finding.maswe_refs + entry.get("maswe", []))),
        "mastg_refs": sorted(set(finding.mastg_refs + mastg_refs)),
        "mastg_ref": finding.mastg_ref or (mastg_refs[0] if mastg_refs else None),
        "rule_catalog_version": catalog.get("catalog_version", "unknown"),
        "metadata": {**finding.metadata, "mastg_status": statuses},
    })


def enrich_findings(findings: Iterable[Finding]) -> List[Finding]:
    catalog = load_catalog()
    return [enrich_finding(item, catalog) for item in findings]
