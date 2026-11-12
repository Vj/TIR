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

