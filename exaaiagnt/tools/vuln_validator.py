"""
Vulnerability Validator - Validates and confirms detected vulnerabilities.

Features:
- Confirmation testing
- PoC generation
- False positive reduction
- Severity assessment
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Callable
from datetime import datetime


logger = logging.getLogger(__name__)


class VulnStatus(Enum):
    """Vulnerability validation status."""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    EXPLOITABLE = "exploitable"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


@dataclass
class VulnerabilityReport:
    """A validated vulnerability report."""
    vuln_id: str
    vuln_type: str
    status: VulnStatus
    severity: Severity
    url: str
    parameter: str
    payload: str
    evidence: str
    poc_steps: list[str] = field(default_factory=list)
    remediation: str = ""
    cvss_score: float = 0.0
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    confirmed_at: Optional[str] = None
    notes: str = ""


@dataclass
class ValidationTest:
    """A validation test case."""
    test_name: str
    test_func: Callable
    required: bool = True


class VulnValidator:
    """
    Vulnerability validation engine.
    
    Features:
    - Confirms vulnerabilities with additional tests
    - Generates PoC steps
    - Calculates CVSS scores
    - Provides remediation advice
    """
    
    _instance: Optional["VulnValidator"] = None
    
    def __new__(cls) -> "VulnValidator":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._reports: dict[str, VulnerabilityReport] = {}
        self._remediation_db = self._load_remediation_db()
        self._initialized = True
        logger.info("VulnValidator initialized")
    
    def _load_remediation_db(self) -> dict[str, dict[str, Any]]:
        """Load remediation advice database."""
        return {
            "sql_injection": {
                "severity": Severity.CRITICAL,
                "cvss_base": 9.8,
                "remediation": """
1. Use parameterized queries (prepared statements)
2. Use ORM frameworks with built-in protection
3. Validate and sanitize all user inputs
4. Apply principle of least privilege to database accounts
5. Enable WAF with SQL injection rules
""",
                "poc_template": [
                    "Navigate to {url}",
                    "Insert payload '{payload}' in parameter '{parameter}'",
                    "Observe the response showing SQL error or data leakage",
                    "Evidence: {evidence}"
                ]
            },
            "xss": {
                "severity": Severity.HIGH,
                "cvss_base": 7.1,
                "remediation": """
1. Encode output based on context (HTML, JS, URL, CSS)
2. Use Content-Security-Policy header
3. Validate and sanitize input
4. Use frameworks with auto-escaping (React, Vue, Angular)
5. Set HttpOnly flag on cookies
""",
                "poc_template": [
                    "Navigate to {url}",
                    "Insert XSS payload '{payload}' in parameter '{parameter}'",
                    "Observe JavaScript execution or DOM modification",
                    "Evidence: {evidence}"
                ]
            },
            "ssrf": {
                "severity": Severity.HIGH,
                "cvss_base": 8.6,
                "remediation": """
1. Validate and whitelist allowed URLs/domains
2. Block requests to internal IP ranges
3. Disable unnecessary URL schemes (file://, gopher://)
4. Use network segmentation
5. Implement proper egress filtering
""",
                "poc_template": [
                    "Navigate to {url}",
                    "Supply internal URL '{payload}' in parameter '{parameter}'",
                    "Observe access to internal resources",
                    "Evidence: {evidence}"
                ]
            },
            "path_traversal": {
                "severity": Severity.HIGH,
                "cvss_base": 7.5,
                "remediation": """
1. Validate and sanitize file paths
2. Use whitelist of allowed files
3. Chroot or sandbox file access
4. Remove ../ sequences from input
5. Use secure file APIs
""",
                "poc_template": [
                    "Navigate to {url}",
                    "Supply path traversal payload '{payload}' in parameter '{parameter}'",
                    "Observe disclosure of system files",
                    "Evidence: {evidence}"
                ]
            },
            "command_injection": {
                "severity": Severity.CRITICAL,
                "cvss_base": 10.0,
                "remediation": """
1. Never pass user input to system commands
2. Use language-specific APIs instead of shell commands
3. If unavoidable, use strict input validation
4. Apply least privilege to application user
5. Use containerization/sandboxing
""",
                "poc_template": [
                    "Navigate to {url}",
                    "Insert command injection payload '{payload}' in parameter '{parameter}'",
                    "Observe command execution on server",
                    "Evidence: {evidence}"
                ]
            },
            "idor": {
                "severity": Severity.MEDIUM,
                "cvss_base": 6.5,
                "remediation": """
1. Implement proper authorization checks
2. Use indirect object references (GUIDs)
3. Verify user has access to requested resource
4. Log and monitor access patterns
5. Implement rate limiting
""",
                "poc_template": [
                    "Authenticate as User A",
                    "Navigate to {url}",
                    "Change parameter '{parameter}' to another user's ID '{payload}'",
                    "Observe access to User B's data",
                    "Evidence: {evidence}"
                ]
            },
            "ssti": {
                "severity": Severity.CRITICAL,
                "cvss_base": 9.8,
                "remediation": """
1. Never pass user input directly to templates
2. Use sandboxed template engines
3. Disable dangerous template features
4. Validate and sanitize input
5. Use Content-Security-Policy
""",
                "poc_template": [
                    "Navigate to {url}",
                    "Insert template payload '{payload}' in parameter '{parameter}'",
                    "Observe template expression evaluation",
                    "Evidence: {evidence}"
                ]
            },
            "open_redirect": {
                "severity": Severity.LOW,
                "cvss_base": 4.7,
                "remediation": """
1. Validate redirect URLs against whitelist
2. Use relative URLs only
3. Remove user control over redirect destination
4. Add confirmation page for external redirects
5. Log redirect attempts
""",
                "poc_template": [
                    "Navigate to {url}",
                    "Supply external URL '{payload}' in parameter '{parameter}'",
                    "Observe redirect to external site",
                    "Evidence: {evidence}"
                ]
            },
        }
    
    def create_report(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        payload: str,
        evidence: str,
        status: VulnStatus = VulnStatus.PENDING
    ) -> VulnerabilityReport:
        """Create a new vulnerability report."""
        vuln_id = f"{vuln_type}_{hash(url + parameter + payload) & 0xFFFFFFFF:08x}"
        
        # Get info from remediation DB
        vuln_info = self._remediation_db.get(vuln_type, {})
        severity = vuln_info.get("severity", Severity.MEDIUM)
        cvss = vuln_info.get("cvss_base", 5.0)
        remediation = vuln_info.get("remediation", "Review and fix the vulnerability.")
        
        # Generate PoC steps
        poc_template = vuln_info.get("poc_template", [])
        poc_steps = [
            step.format(url=url, parameter=parameter, payload=payload, evidence=evidence)
            for step in poc_template
        ]
        
        report = VulnerabilityReport(
            vuln_id=vuln_id,
            vuln_type=vuln_type,
            status=status,
            severity=severity,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            poc_steps=poc_steps,
            remediation=remediation.strip(),
            cvss_score=cvss
        )
        
        self._reports[vuln_id] = report
        logger.info(f"Created vulnerability report: {vuln_id}")
        
        return report
    
    def confirm_vulnerability(self, vuln_id: str, additional_evidence: str = "") -> bool:
        """Mark a vulnerability as confirmed."""
        if vuln_id not in self._reports:
            return False
        
        report = self._reports[vuln_id]
        report.status = VulnStatus.CONFIRMED
        report.confirmed_at = datetime.now().isoformat()
        
        if additional_evidence:
            report.evidence += f"\n\nAdditional evidence:\n{additional_evidence}"
        
        logger.info(f"Confirmed vulnerability: {vuln_id}")
        return True
    
    def mark_exploitable(self, vuln_id: str, exploit_details: str) -> bool:
        """Mark a vulnerability as exploitable with details."""
        if vuln_id not in self._reports:
            return False
        
        report = self._reports[vuln_id]
        report.status = VulnStatus.EXPLOITABLE
        report.notes += f"\n\nExploit details:\n{exploit_details}"
        
        # Increase severity for exploitable vulns
        if report.severity == Severity.MEDIUM:
            report.severity = Severity.HIGH
        elif report.severity == Severity.HIGH:
            report.severity = Severity.CRITICAL
        
        logger.info(f"Marked vulnerability as exploitable: {vuln_id}")
        return True
    
    def mark_false_positive(self, vuln_id: str, reason: str) -> bool:
        """Mark a vulnerability as false positive."""
        if vuln_id not in self._reports:
            return False
        
        report = self._reports[vuln_id]
        report.status = VulnStatus.FALSE_POSITIVE
        report.notes = f"False positive reason: {reason}"
        
        logger.info(f"Marked as false positive: {vuln_id}")
        return True
    
    def get_report(self, vuln_id: str) -> Optional[VulnerabilityReport]:
        """Get a vulnerability report by ID."""
        return self._reports.get(vuln_id)
    
    def get_all_reports(
        self,
        status: Optional[VulnStatus] = None,
        severity: Optional[Severity] = None
    ) -> list[VulnerabilityReport]:
        """Get all reports, optionally filtered."""
        reports = list(self._reports.values())
        
        if status:
            reports = [r for r in reports if r.status == status]
        
        if severity:
            reports = [r for r in reports if r.severity == severity]
        
        return reports
    
    def get_confirmed_vulns(self) -> list[VulnerabilityReport]:
        """Get all confirmed vulnerabilities."""
        return [
            r for r in self._reports.values()
            if r.status in [VulnStatus.CONFIRMED, VulnStatus.EXPLOITABLE]
        ]
    
    def generate_summary(self) -> dict[str, Any]:
        """Generate a summary of all findings."""
        all_reports = list(self._reports.values())
        
        summary = {
            "total": len(all_reports),
            "by_status": {},
            "by_severity": {},
            "by_type": {},
            "critical_count": 0,
            "high_count": 0,
        }
        
        for report in all_reports:
            # By status
            status_key = report.status.value
            summary["by_status"][status_key] = summary["by_status"].get(status_key, 0) + 1
            
            # By severity
            sev_key = report.severity.value
            summary["by_severity"][sev_key] = summary["by_severity"].get(sev_key, 0) + 1
            
            # By type
            summary["by_type"][report.vuln_type] = summary["by_type"].get(report.vuln_type, 0) + 1
            
            # Critical/High counts
            if report.severity == Severity.CRITICAL:
                summary["critical_count"] += 1
            elif report.severity == Severity.HIGH:
                summary["high_count"] += 1
        
        return summary
    
    def clear_reports(self):
        """Clear all reports."""
        self._reports.clear()


# Global instance
_validator: Optional[VulnValidator] = None


def get_vuln_validator() -> VulnValidator:
    """Get or create the global validator instance."""
    global _validator
    if _validator is None:
        _validator = VulnValidator()
    return _validator


def create_vuln_report(
    vuln_type: str,
    url: str,
    parameter: str,
    payload: str,
    evidence: str
) -> VulnerabilityReport:
    """Convenience function to create a vulnerability report."""
    validator = get_vuln_validator()
    return validator.create_report(vuln_type, url, parameter, payload, evidence)
