"""Regulatory references and evidence-only readiness summaries."""
import json
from pathlib import Path
from typing import Iterable, List

from core.models import Finding

CATALOG_PATH = Path(__file__).resolve().parents[1] / "standards" / "indian_regulatory_mobile_catalog.json"

def load_regulatory_catalog():
    with CATALOG_PATH.open("r", encoding="utf-8") as stream:
        return json.load(stream)

def enrich_regulatory_findings(findings: Iterable[Finding]) -> List[Finding]:
    catalog = load_regulatory_catalog()
    out = []
    for finding in findings:
        entry = catalog.get("entries", {}).get(finding.check_id)
        if not entry:
            out.append(finding)
            continue
        refs = sorted(set(finding.regulatory_refs + entry.get("refs", [])))
        metadata = {**finding.metadata, "regulatory_scope_note": entry.get("scope_note"),
                    "regulatory_method": entry.get("method")}
        out.append(finding.model_copy(update={"regulatory_refs": refs,
            "regulatory_catalog_version": catalog.get("catalog_version"), "metadata": metadata}))
    return out

def build_regulatory_summary(findings):
    catalog = load_regulatory_catalog()
    by_rule = {}
    for finding in findings:
        by_rule.setdefault(finding.check_id, []).append(finding)
    rows = []
    for rule_id, entry in catalog.get("entries", {}).items():
        observed = by_rule.get(rule_id, [])
        if not observed:
            state = "Not Run"
        elif any(item.status.value == "Fail" for item in observed):
            state = "Observation"
        elif any(item.status.value in ("Needs Review", "Pending") for item in observed):
            state = "Needs Review"
        elif all(item.status.value in ("Pass", "N/A") for item in observed):
            state = "Evidence Collected"
        else:
            state = "Needs Review"
        rows.append({"rule_id": rule_id, "title": entry.get("title", rule_id),
                     "references": entry.get("refs", []), "state": state,
                     "evidence_count": len(observed), "scope_note": entry.get("scope_note", "")})
    return rows
