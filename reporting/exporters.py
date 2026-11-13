"""JSON and SARIF exporters plus stable finding-baseline comparison."""
import json
from pathlib import Path


def _key(item):
    return "|".join((item.check_id, item.affected_component or "", item.source_file or ""))


def _row(item):
    data = item.model_dump(mode="json")
    data["fingerprint"] = _key(item)
    return data


def compare_baseline(findings, baseline_path):
    try:
        previous = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Could not read baseline JSON: " + str(exc))
    rows = previous.get("findings", previous) if isinstance(previous, dict) else previous
    if not isinstance(rows, list):
        raise ValueError("Baseline JSON must contain a findings array")
    old = {row.get("fingerprint") or "|".join((row.get("check_id", ""),
          row.get("affected_component") or "", row.get("source_file") or "")): row for row in rows if isinstance(row, dict)}
    now = {_key(item): item for item in findings}
    states = {}
    for key, item in now.items():
        prior = old.get(key)
        if not prior:
            states[key] = "New"
        elif prior.get("status") != item.status.value or prior.get("severity") != item.severity.value:
            states[key] = "Regressed" if item.status.value in ("Fail", "Needs Review") else "Fixed"
        else:
            states[key] = "Unchanged"
    fixed = sorted(set(old) - set(now))
    return states, fixed


def export_findings(findings, output_path, output_format="json", baseline_path=None):
    rows = [_row(item) for item in findings]
    states, fixed = compare_baseline(findings, baseline_path) if baseline_path else ({}, [])
    for row in rows:
        if states:
            row["change"] = states.get(row["fingerprint"], "Unchanged")
    if output_format == "json":
        payload = {"schema_version": 1, "findings": rows, "fixed_fingerprints": fixed}
    elif output_format == "sarif":
        payload = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          "runs": [{"tool": {"driver": {"name": "TIR", "rules": [{"id": item.check_id, "shortDescription": {"text": item.title}} for item in findings]}},
          "results": [{"ruleId": item.check_id, "level": "error" if item.severity.value in ("Critical", "High") else "warning",
          "message": {"text": item.description}, "locations": ([{"physicalLocation": {"artifactLocation": {"uri": item.source_file}}}] if item.source_file else []),
          "properties": {"status": item.status.value, "verification_status": item.verification_status.value,
          "confidence_score": item.confidence_score, "maswe": item.maswe_refs, "mastg": item.mastg_refs, "regulatory_refs": item.regulatory_refs,
          "fingerprint": _key(item), "change": states.get(_key(item), "Unchanged")}} for item in findings]}]}
    else:
        raise ValueError("Unsupported report format: " + output_format)
    Path(output_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
