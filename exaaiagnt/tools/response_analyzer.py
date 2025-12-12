"""
Response Analyzer - Intelligent response analysis for vulnerability detection.

Features:
- Error message detection
- Sensitive data leakage detection
- Response comparison for blind testing
- Timing analysis
"""

import logging
import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from difflib import SequenceMatcher


logger = logging.getLogger(__name__)


class DetectionType(Enum):
    """Types of detections."""
    SQL_ERROR = "sql_error"
    PATH_DISCLOSURE = "path_disclosure"
    STACK_TRACE = "stack_trace"
    VERSION_DISCLOSURE = "version_disclosure"
    SENSITIVE_DATA = "sensitive_data"
    DEBUG_INFO = "debug_info"
    CONFIG_LEAK = "config_leak"
    REFLECTION = "reflection"
    TIMING_ANOMALY = "timing_anomaly"


@dataclass
class Detection:
    """A detection finding."""
    detection_type: DetectionType
    confidence: float  # 0.0 - 1.0
    evidence: str
    location: str = ""
    severity: int = 5  # 1-10


@dataclass
class AnalysisResult:
    """Result of response analysis."""
    detections: list[Detection] = field(default_factory=list)
    response_hash: str = ""
    response_length: int = 0
    response_time_ms: float = 0.0
    is_error: bool = False
    status_code: int = 0


class ResponseAnalyzer:
    """
    Intelligent response analyzer for vulnerability detection.
    
    Detects:
    - SQL/Database errors
    - Path disclosures
    - Stack traces
    - Sensitive data leakage
    - Version information
    - Debug/config information
    """
    
    _instance: Optional["ResponseAnalyzer"] = None
    
    def __new__(cls) -> "ResponseAnalyzer":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._patterns = self._load_patterns()
        self._baseline_responses: dict[str, str] = {}
        self._initialized = True
        logger.info("ResponseAnalyzer initialized")
    
    def _load_patterns(self) -> dict[DetectionType, list[tuple[str, float]]]:
        """Load detection patterns with confidence scores."""
        return {
            DetectionType.SQL_ERROR: [
                (r"SQL syntax.*MySQL", 0.95),
                (r"Warning.*mysql_", 0.9),
                (r"PostgreSQL.*ERROR", 0.95),
                (r"ORA-[0-9]{5}", 0.95),
                (r"Microsoft.*ODBC.*SQL Server", 0.95),
                (r"SQLite3?.*error", 0.9),
                (r"Unclosed quotation mark", 0.85),
                (r"syntax error at or near", 0.85),
                (r"mysql_fetch", 0.8),
                (r"pg_query", 0.8),
                (r"SQLSTATE\[", 0.9),
            ],
            DetectionType.PATH_DISCLOSURE: [
                (r"/var/www/", 0.9),
                (r"C:\\[Ii]netpub\\", 0.9),
                (r"/home/\w+/", 0.85),
                (r"/usr/local/", 0.7),
                (r"DocumentRoot", 0.8),
                (r"DOCUMENT_ROOT", 0.8),
                (r"in\s+/\w+/.+\.php", 0.9),
                (r"at\s+\w+\.py", 0.85),
            ],
            DetectionType.STACK_TRACE: [
                (r"Traceback \(most recent call last\)", 0.95),
                (r"at\s+\S+\.\S+\(\S+\.java:\d+\)", 0.95),
                (r"File\s+\".*\",\s+line\s+\d+", 0.9),
                (r"#\d+\s+\S+\.\S+\s+called at", 0.85),
                (r"Stack trace:", 0.9),
                (r"Exception in thread", 0.9),
            ],
            DetectionType.VERSION_DISCLOSURE: [
                (r"Apache/[\d.]+", 0.8),
                (r"nginx/[\d.]+", 0.8),
                (r"PHP/[\d.]+", 0.85),
                (r"Python/[\d.]+", 0.85),
                (r"ASP\.NET\s+Version:[\d.]+", 0.9),
                (r"X-Powered-By:\s*\S+", 0.7),
                (r"Server:\s*\S+", 0.6),
            ],
            DetectionType.SENSITIVE_DATA: [
                (r"password\s*[=:]\s*['\"]?\w+", 0.9),
                (r"api[_-]?key\s*[=:]\s*['\"]?\w+", 0.95),
                (r"secret[_-]?key\s*[=:]\s*['\"]?\w+", 0.95),
                (r"aws[_-]?access[_-]?key", 0.95),
                (r"sk_live_\w+", 0.95),  # Stripe
                (r"ghp_\w+", 0.95),  # GitHub
                (r"eyJ[A-Za-z0-9_-]+\.eyJ", 0.9),  # JWT
                (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 0.6),  # Email
            ],
            DetectionType.DEBUG_INFO: [
                (r"DEBUG\s*=\s*True", 0.95),
                (r"debug mode is on", 0.9),
                (r"Xdebug", 0.85),
                (r"GLOBALS\[", 0.8),
                (r"var_dump\(", 0.85),
                (r"print_r\(", 0.8),
                (r"console\.log\(", 0.5),
            ],
            DetectionType.CONFIG_LEAK: [
                (r"DB_HOST\s*=", 0.9),
                (r"DATABASE_URL\s*=", 0.9),
                (r"REDIS_URL\s*=", 0.85),
                (r"mongodb://", 0.85),
                (r"mysql://\w+:\w+@", 0.95),
                (r"SECRET_KEY\s*=", 0.95),
            ],
            DetectionType.REFLECTION: [
                # Patterns for reflected input
                (r"<script[^>]*>.*alert.*</script>", 0.95),
                (r"onerror\s*=", 0.9),
                (r"onload\s*=", 0.85),
                (r"javascript:", 0.8),
            ],
        }
    
    def analyze(
        self,
        response_body: str,
        status_code: int = 200,
        response_time_ms: float = 0.0,
        headers: Optional[dict[str, str]] = None
    ) -> AnalysisResult:
        """Analyze a response for vulnerabilities and information leakage."""
        result = AnalysisResult(
            response_hash=self._hash_response(response_body),
            response_length=len(response_body),
            response_time_ms=response_time_ms,
            status_code=status_code,
            is_error=status_code >= 400
        )
        
        # Check response body
        for detection_type, patterns in self._patterns.items():
            for pattern, confidence in patterns:
                matches = re.findall(pattern, response_body, re.IGNORECASE)
                if matches:
                    result.detections.append(Detection(
                        detection_type=detection_type,
                        confidence=confidence,
                        evidence=matches[0] if isinstance(matches[0], str) else str(matches[0]),
                        severity=self._get_severity(detection_type)
                    ))
        
        # Check headers
        if headers:
            header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
            for pattern, confidence in self._patterns.get(DetectionType.VERSION_DISCLOSURE, []):
                matches = re.findall(pattern, header_str, re.IGNORECASE)
                if matches:
                    result.detections.append(Detection(
                        detection_type=DetectionType.VERSION_DISCLOSURE,
                        confidence=confidence,
                        evidence=matches[0],
                        location="headers"
                    ))
        
        # Timing analysis
        if response_time_ms > 5000:  # 5 seconds
            result.detections.append(Detection(
                detection_type=DetectionType.TIMING_ANOMALY,
                confidence=0.7,
                evidence=f"Response time: {response_time_ms}ms",
                severity=6
            ))
        
        return result
    
    def compare_responses(
        self,
        response1: str,
        response2: str,
        threshold: float = 0.9
    ) -> tuple[bool, float]:
        """
        Compare two responses to detect differences.
        
        Returns: (are_similar, similarity_ratio)
        """
        ratio = SequenceMatcher(None, response1, response2).ratio()
        return ratio >= threshold, ratio
    
    def set_baseline(self, endpoint: str, response: str):
        """Set a baseline response for an endpoint."""
        self._baseline_responses[endpoint] = self._hash_response(response)
    
    def is_different_from_baseline(self, endpoint: str, response: str) -> bool:
        """Check if response differs from baseline."""
        if endpoint not in self._baseline_responses:
            return False
        
        current_hash = self._hash_response(response)
        return current_hash != self._baseline_responses[endpoint]
    
    def _hash_response(self, response: str) -> str:
        """Create a hash of the response."""
        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', response.strip())
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def _get_severity(self, detection_type: DetectionType) -> int:
        """Get severity level for a detection type."""
        severity_map = {
            DetectionType.SQL_ERROR: 8,
            DetectionType.PATH_DISCLOSURE: 5,
            DetectionType.STACK_TRACE: 6,
            DetectionType.VERSION_DISCLOSURE: 4,
            DetectionType.SENSITIVE_DATA: 9,
            DetectionType.DEBUG_INFO: 7,
            DetectionType.CONFIG_LEAK: 9,
            DetectionType.REFLECTION: 8,
            DetectionType.TIMING_ANOMALY: 6,
        }
        return severity_map.get(detection_type, 5)
    
    def get_stats(self) -> dict[str, Any]:
        """Get analyzer statistics."""
        return {
            "pattern_count": sum(len(p) for p in self._patterns.values()),
            "detection_types": [t.value for t in DetectionType],
            "baselines_set": len(self._baseline_responses),
        }


# Global instance
_analyzer: Optional[ResponseAnalyzer] = None


def get_response_analyzer() -> ResponseAnalyzer:
    """Get or create the global analyzer instance."""
    global _analyzer
    if _analyzer is None:
        _analyzer = ResponseAnalyzer()
    return _analyzer


def analyze_response(
    response_body: str,
    status_code: int = 200,
    response_time_ms: float = 0.0,
    headers: Optional[dict[str, str]] = None
) -> AnalysisResult:
    """Convenience function to analyze a response."""
    analyzer = get_response_analyzer()
    return analyzer.analyze(response_body, status_code, response_time_ms, headers)
