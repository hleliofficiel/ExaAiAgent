"""
WAF Detection & Bypass Module - Detects and bypasses Web Application Firewalls.
Supports Cloudflare, Akamai, Imperva, AWS WAF, and more.
"""

import re
import base64
import urllib.parse
import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class WAFType(Enum):
    """Known WAF types."""
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    AWS_WAF = "aws_waf"
    MODSECURITY = "modsecurity"
    F5_BIG_IP = "f5_big_ip"
    SUCURI = "sucuri"
    WORDFENCE = "wordfence"
    BARRACUDA = "barracuda"
    FORTIWEB = "fortiweb"
    UNKNOWN = "unknown"


@dataclass
class WAFDetectionResult:
    """Result of WAF detection."""
    detected: bool
    waf_type: WAFType
    confidence: float
    indicators: List[str]
    bypass_suggestions: List[str]


class WAFDetector:
    """Detects WAF presence based on response characteristics."""
    
    # Detection patterns
    DETECTION_PATTERNS: Dict[WAFType, Dict[str, List[str]]] = {
        WAFType.CLOUDFLARE: {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
            "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
            "body": ["cloudflare", "cf-browser-verification", "attention required"],
            "status_pages": ["error 1020", "ray id"],
        },
        WAFType.AKAMAI: {
            "headers": ["akamai", "x-akamai", "akamai-grn"],
            "cookies": ["akamai", "_abck", "bm_sz", "ak_bmsc"],
            "body": ["akamai", "access denied", "reference#"],
        },
        WAFType.IMPERVA: {
            "headers": ["x-iinfo", "x-cdn"],
            "cookies": ["incap_ses", "visid_incap", "nlbi_"],
            "body": ["incapsula", "imperva", "request unsuccessful"],
        },
        WAFType.AWS_WAF: {
            "headers": ["x-amzn-requestid", "x-amz-cf-id"],
            "body": ["aws", "request blocked", "waf"],
        },
        WAFType.MODSECURITY: {
            "headers": ["mod_security", "modsec"],
            "body": ["modsecurity", "not acceptable", "mod_security"],
        },
        WAFType.SUCURI: {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "body": ["sucuri", "cloudproxy"],
        },
    }
    
    def detect(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        cookies: Dict[str, str] = None
    ) -> WAFDetectionResult:
        """Detect WAF from response."""
        cookies = cookies or {}
        indicators = []
        detected_waf = WAFType.UNKNOWN
        max_confidence = 0.0
        
        # Check for blocking status codes
        if status_code in [403, 406, 429, 503]:
            indicators.append(f"Blocking status code: {status_code}")
        
        # Check each WAF type
        for waf_type, patterns in self.DETECTION_PATTERNS.items():
            confidence = 0.0
            waf_indicators = []
            
            # Check headers
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            for pattern in patterns.get("headers", []):
                if any(pattern in h for h in headers_lower.keys()):
                    confidence += 0.3
                    waf_indicators.append(f"Header match: {pattern}")
            
            # Check cookies
            cookies_lower = {k.lower(): v.lower() for k, v in cookies.items()}
            for pattern in patterns.get("cookies", []):
                if any(pattern in c for c in cookies_lower.keys()):
                    confidence += 0.25
                    waf_indicators.append(f"Cookie match: {pattern}")
            
            # Check body
            body_lower = body.lower()
            for pattern in patterns.get("body", []):
                if pattern in body_lower:
                    confidence += 0.2
                    waf_indicators.append(f"Body match: {pattern}")
            
            if confidence > max_confidence:
                max_confidence = confidence
                detected_waf = waf_type
                indicators = waf_indicators
        
        detected = max_confidence > 0.3 or status_code in [403, 406]
        
        return WAFDetectionResult(
            detected=detected,
            waf_type=detected_waf,
            confidence=min(max_confidence, 1.0),
            indicators=indicators,
            bypass_suggestions=self._get_bypass_suggestions(detected_waf) if detected else []
        )
    
    def _get_bypass_suggestions(self, waf_type: WAFType) -> List[str]:
        """Get bypass suggestions for detected WAF."""
        common = [
            "Try Unicode normalization",
            "Use alternate encodings (double URL, hex)",
            "Try HTTP parameter pollution",
            "Use case variation",
            "Add comment injection",
        ]
        
        specific = {
            WAFType.CLOUDFLARE: [
                "Use IP-based bypass if origin exposed",
                "Try header smuggling",
                "Use chunked encoding",
            ],
            WAFType.AKAMAI: [
                "Try JSON smuggling",
                "Use multipart encoding",
                "Header padding techniques",
            ],
            WAFType.IMPERVA: [
                "Try wildcard techniques",
                "Use nested encoding",
            ],
        }
        
        return common + specific.get(waf_type, [])


class PayloadEncoder:
    """Encodes payloads to bypass WAF."""
    
    @staticmethod
    def url_encode(payload: str, double: bool = False) -> str:
        """URL encode payload."""
        encoded = urllib.parse.quote(payload, safe='')
        if double:
            encoded = urllib.parse.quote(encoded, safe='')
        return encoded
    
    @staticmethod
    def unicode_normalize(payload: str) -> str:
        """Apply Unicode normalization."""
        replacements = {
            '<': '\uff1c',
            '>': '\uff1e',
            "'": '\u2019',
            '"': '\u201c',
            '(': '\uff08',
            ')': '\uff09',
            '/': '\u2215',
        }
        result = payload
        for char, replacement in replacements.items():
            result = result.replace(char, replacement)
        return result
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode payload."""
        return ''.join(f'%{ord(c):02x}' for c in payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode payload."""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def add_comments(payload: str, style: str = "sql") -> str:
        """Add comments to break WAF patterns."""
        if style == "sql":
            # Add inline comments to SQL
            return re.sub(r'(\s+)', r'/**/\1/**/', payload)
        elif style == "html":
            return payload.replace('<', '<!--><')
        return payload
    
    @staticmethod
    def case_variation(payload: str) -> str:
        """Apply random case variation."""
        import random
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
    
    @staticmethod
    def null_byte_inject(payload: str) -> str:
        """Inject null bytes."""
        return payload.replace(' ', '%00')
    
    @staticmethod
    def json_smuggle(payload: str) -> str:
        """Create JSON smuggling payload."""
        return json.dumps({"data": payload}).replace('"', '\\"')
    
    @staticmethod
    def header_padding(payload: str, size: int = 8000) -> str:
        """Add header padding."""
        padding = 'A' * (size - len(payload))
        return padding + payload
    
    @staticmethod
    def chunked_encode(payload: str) -> List[str]:
        """Split payload into chunks for chunked transfer."""
        chunk_size = 10
        return [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]


class WAFBypass:
    """
    Main WAF bypass class that combines detection and evasion.
    """
    
    def __init__(self):
        self.detector = WAFDetector()
        self.encoder = PayloadEncoder()
    
    def detect_waf(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        cookies: Dict[str, str] = None
    ) -> WAFDetectionResult:
        """Detect WAF from response."""
        return self.detector.detect(status_code, headers, body, cookies)
    
    def generate_bypass_payloads(
        self,
        original_payload: str,
        waf_type: WAFType = WAFType.UNKNOWN
    ) -> List[Tuple[str, str]]:
        """
        Generate bypass payloads for a given original payload.
        Returns list of (payload, technique) tuples.
        """
        payloads = []
        
        # URL encoding variations
        payloads.append((
            self.encoder.url_encode(original_payload),
            "URL encoded"
        ))
        payloads.append((
            self.encoder.url_encode(original_payload, double=True),
            "Double URL encoded"
        ))
        
        # Unicode normalization
        payloads.append((
            self.encoder.unicode_normalize(original_payload),
            "Unicode normalized"
        ))
        
        # Hex encoding
        payloads.append((
            self.encoder.hex_encode(original_payload),
            "Hex encoded"
        ))
        
        # Case variation
        payloads.append((
            self.encoder.case_variation(original_payload),
            "Case variation"
        ))
        
        # Comment injection (for SQL-like payloads)
        if any(kw in original_payload.lower() for kw in ['select', 'union', 'insert', 'update']):
            payloads.append((
                self.encoder.add_comments(original_payload, "sql"),
                "SQL comment injection"
            ))
        
        # Null byte injection
        payloads.append((
            self.encoder.null_byte_inject(original_payload),
            "Null byte injection"
        ))
        
        # WAF-specific techniques
        if waf_type == WAFType.AKAMAI:
            payloads.append((
                self.encoder.json_smuggle(original_payload),
                "JSON smuggling (Akamai)"
            ))
        
        return payloads
    
    def get_bypass_headers(self, waf_type: WAFType = WAFType.UNKNOWN) -> Dict[str, str]:
        """Get headers that may help bypass WAF."""
        headers = {
            "X-Originating-IP": "127.0.0.1",
            "X-Forwarded-For": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
        }
        
        if waf_type == WAFType.CLOUDFLARE:
            headers["CF-Connecting-IP"] = "127.0.0.1"
        
        return headers


# Global instance
_waf_bypass: Optional[WAFBypass] = None


def get_waf_bypass() -> WAFBypass:
    """Get the global WAFBypass instance."""
    global _waf_bypass
    if _waf_bypass is None:
        _waf_bypass = WAFBypass()
    return _waf_bypass


def detect_waf(status_code: int, headers: Dict, body: str) -> WAFDetectionResult:
    """Convenience function to detect WAF."""
    return get_waf_bypass().detect_waf(status_code, headers, body)


def generate_bypasses(payload: str) -> List[Tuple[str, str]]:
    """Convenience function to generate bypass payloads."""
    return get_waf_bypass().generate_bypass_payloads(payload)
