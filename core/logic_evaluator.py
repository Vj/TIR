from typing import Dict, Any, Optional
from core.models import Finding, Severity, CheckStatus

class BusinessLogicRecorder:
    """Manages analyst-driven test cases for Tab 10 (Business Logic Testing)."""

    @staticmethod
    def create_logic_finding(
        check_id: str,
        title: str,
        tested: bool,
        is_vulnerable: bool,
        severity: Severity,
        endpoint: str,
        test_payload: str,
        observed_response: str,
        remediation: str
    ) -> Finding:
        if not tested:
            status = CheckStatus.PENDING
            evidence = "Not yet evaluated by analyst."
        elif is_vulnerable:
            status = CheckStatus.FAIL
            evidence = f"Target Endpoint: {endpoint}\nPayload:\n{test_payload}\nResponse:\n{observed_response}"
        else:
            status = CheckStatus.PASS
            evidence = f"Endpoint {endpoint} correctly enforced validation on tampered parameters."

        return Finding(
            check_id=check_id,
            title=title,
            category="Business Logic Testing",
            tab_index=10,
            severity=severity if is_vulnerable else Severity.INFO,
            status=status,
            description=f"Evaluation of business logic integrity on endpoint: {endpoint or 'N/A'}",
            evidence=evidence,
            remediation=remediation if is_vulnerable else None,
            metadata={
                "endpoint": endpoint,
                "payload": test_payload,
                "response": observed_response
            }
        )