"""Conservative static/runtime finding correlation."""
from typing import Dict, List, Set, Tuple

from core.models import AnalysisType, Confidence, Finding, VerificationStatus
from core.standards import enrich_findings


def _keys(finding: Finding) -> Set[str]:
    keys = {f"check:{finding.check_id}"}
    if finding.correlation_key:
        keys.add(f"correlation:{finding.correlation_key}")
    return keys


def correlate_findings(static_findings: List[Finding], dynamic_findings: List[Finding]) -> List[Finding]:
    """Merge matching evidence while distinguishing not-observed from unreachable.

    Runtime absence never proves code unreachable. That status is only accepted when
    static analysis explicitly records both proof and complete entry-point coverage.
    """
    static_items = enrich_findings(static_findings)
    dynamic_items = enrich_findings([
        item.model_copy(update={"analysis_type": AnalysisType.DYNAMIC})
        for item in dynamic_findings
    ])
    by_key: Dict[str, List[int]] = {}
    by_weakness: Dict[str, List[int]] = {}
    for index, item in enumerate(static_items):
        for key in _keys(item):
            by_key.setdefault(key, []).append(index)
        for weakness in item.maswe_refs:
            by_weakness.setdefault(weakness, []).append(index)

    merged: Dict[int, List[Finding]] = {}
    unmatched_dynamic: List[Finding] = []
    for dynamic in dynamic_items:
        matches = set()
        for key in _keys(dynamic):
            matches.update(by_key.get(key, []))
        if not matches:
            # Weakness-level fallback is allowed only when it has one static candidate.
            # This avoids joining unrelated rules that share a broad MASWE category.
            for weakness in dynamic.maswe_refs:
                candidates = set(by_weakness.get(weakness, []))
                if len(candidates) == 1:
                    matches.update(candidates)
        if not matches:
            unmatched_dynamic.append(dynamic.model_copy(update={
                "verification_status": VerificationStatus.DYNAMICALLY_CONFIRMED
                if dynamic.status.value == "Fail" else VerificationStatus.NOT_OBSERVED
                if dynamic.status.value == "Pass" else VerificationStatus.UNVERIFIED,
                "confidence": Confidence.HIGH if dynamic.status.value == "Fail" else dynamic.confidence,
                "confidence_score": 0.95 if dynamic.status.value == "Fail" and dynamic.evidence else 0.5 if dynamic.status.value != "Pass" else 0.7,
            }))
            continue
        for index in matches:
            merged.setdefault(index, []).append(dynamic)

    output: List[Finding] = []
    for index, static in enumerate(static_items):
        evidence = merged.get(index, [])
        if not evidence:
            meta = static.metadata
            proven_unreachable = (
                meta.get("reachability") == "proven_unreachable"
                and meta.get("entrypoint_coverage_complete") is True
            )
            output.append(static.model_copy(update={
                "verification_status": VerificationStatus.UNREACHABLE_AT_RUNTIME
                if proven_unreachable else VerificationStatus.STATIC_ONLY,
                "analysis_type": AnalysisType.STATIC,
            }))
            continue

        confirmed = any(item.status.value == "Fail" for item in evidence)
        runtime_status = (
            VerificationStatus.DYNAMICALLY_CONFIRMED
            if confirmed else VerificationStatus.NOT_OBSERVED
            if all(item.status.value == "Pass" for item in evidence)
            else VerificationStatus.UNVERIFIED
        )
        combined = []
        for item in evidence:
            combined.append({
                "check_id": item.check_id,
                "status": item.status.value,
                "analysis_type": item.analysis_type.value,
                "evidence": item.evidence,
                "device": item.coverage.get("device"),
            })
        text_evidence = static.evidence or ""
        for item in evidence:
            if item.evidence and item.evidence not in text_evidence:
                text_evidence += ("\n\n[Dynamic evidence: " + item.check_id + "]\n" + item.evidence)
        output.append(static.model_copy(update={
            "analysis_type": AnalysisType.HYBRID,
            "verification_status": runtime_status,
            "confidence": Confidence.HIGH if confirmed else Confidence.MEDIUM,
            "confidence_score": 0.95 if confirmed and any(item.evidence for item in evidence) else 0.7 if runtime_status == VerificationStatus.NOT_OBSERVED else 0.5,
            "evidence": text_evidence,
            "metadata": {**static.metadata, "correlated_dynamic_findings": combined},
        }))

    output.extend(unmatched_dynamic)
    return output
