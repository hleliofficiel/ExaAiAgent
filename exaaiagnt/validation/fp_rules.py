from __future__ import annotations
import hashlib
def dedup_key(vuln_type: str, url: str, param: str, payload_class: str) -> str:
    return hashlib.sha256(f"{vuln_type}|{url}|{param}|{payload_class}".encode()).hexdigest()
def max_band_for(vuln_type: str, has_execution_context: bool = False, has_version_fingerprint: bool = False) -> str:
    if vuln_type=="xss" and not has_execution_context: return "suspected"
    if vuln_type=="version_disclosure" and not has_version_fingerprint: return "suspected"
    return "confirmed"
