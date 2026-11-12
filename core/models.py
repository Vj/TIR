from enum import Enum
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field

class Severity(str, Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class CheckStatus(str, Enum):
    PASS = "Pass"
    FAIL = "Fail"
    NEEDS_REVIEW = "Needs Review"
    NOT_APPLICABLE = "N/A"
    PENDING = "Pending"

class AnalysisType(str, Enum):
    STATIC = "Static Analysis"
    DYNAMIC = "Dynamic Runtime" 
    HYBRID = "Hybrid Verified"

class VerificationStatus(str, Enum):
    STATIC_ONLY = "STATIC_ONLY"
    DYNAMICALLY_CONFIRMED = "DYNAMICALLY_CONFIRMED"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNREACHABLE_AT_RUNTIME = "UNREACHABLE_AT_RUNTIME"
    UNVERIFIED = "UNVERIFIED"


class Confidence(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Finding(BaseModel):
    check_id: str
    title: str
    category: str
    tab_index: int
    severity: Severity
    status: CheckStatus
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # Enhanced Component, CWE, and Standard References
    affected_component: Optional[str] = None
    source_file: Optional[str] = None
    cwe_id: Optional[str] = None
    masvs_ref: Optional[str] = None
    mastg_ref: Optional[str] = None
    analysis_type: AnalysisType = AnalysisType.STATIC
    maswe_refs: List[str] = Field(default_factory=list)
    mastg_refs: List[str] = Field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.STATIC_ONLY
    confidence: Confidence = Confidence.MEDIUM
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    coverage: Dict[str, Any] = Field(default_factory=dict)
    correlation_key: Optional[str] = None
    rule_catalog_version: str = "owasp-mastg-v2.0.0"
    poc_preconditions: Optional[str] = None
    poc_command: Optional[str] = None
    poc_expected: Optional[str] = None
    poc_observed: Optional[str] = None
    
    # Reproduction / Evidence artifacts
    reproduction_sequence: Optional[List[str]] = None
    evidence_image: Optional[str] = None
    evidence_log: Optional[str] = None

    
class AuditSession(BaseModel):
    session_id: str
    target_apk: str
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    timestamp: str
    findings: List[Finding] = Field(default_factory=list)
    ai_analysis: Optional[str] = None  # Holds Ollama's synthesized assessment
    file_size: Optional[str] = None
    sha256: Optional[str] = None
    min_sdk: Optional[str] = "N/A"
    target_sdk: Optional[str] = "N/A"
    version_code: Optional[str] = "1"
    cert_status: Optional[str] = "Unverified"
    cert_fingerprint: Optional[str] = "N/A"
    cert_issuer: Optional[str] = "N/A"
    permissions: List[Dict[str, Any]] = []

