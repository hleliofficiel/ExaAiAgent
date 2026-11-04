"""Pure, offline checkers for LLM / MCP / RAG security testing.

No network, no LLM calls, no file I/O: every public function takes plain
``str``/``dict``/``list`` data and returns plain dataclass results so it can
be unit-tested deterministically and reused as a gate before any model or
tool call is made.

OWASP Top 10 for LLM Applications (2025) mapping used throughout:

- LLM01 Prompt Injection
- LLM02 Sensitive Information Disclosure
- LLM03 Supply Chain
- LLM04 Data and Model Poisoning
- LLM05 Improper Output Handling
- LLM06 Excessive Agency
- LLM07 System Prompt Leakage
- LLM08 Vector and Embedding Weaknesses
- LLM09 Misinformation
- LLM10 Unbounded Consumption
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field


OWASP_LLM_TOP10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# ---------------------------------------------------------------------------
# Prompt-injection payload detection (LLM01)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_previous_instructions",
        re.compile(
            r"(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|earlier|system|original)\s+(instructions?|prompts?|rules?|constraints?)",
            re.I,
        ),
    ),
    (
        "new_instructions",
        re.compile(r"\b(new|real|actual|true)\s+instructions?\s*:", re.I),
    ),
    (
        "role_impersonation",
        re.compile(
            r"\b(system|developer|admin|root)\s*:\s*\S|you\s+are\s+now\s+(a|an|the)\s+\w+",
            re.I,
        ),
    ),
    (
        "reveal_system_prompt",
        re.compile(
            r"(reveal|show|print|expose|leak|repeat|output|tell\s+me)\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?|messages?)",
            re.I,
        ),
    ),
    (
        "jailbreak",
        re.compile(r"\b(jailbreak|do\s+anything\s+now|dan\s+mode|developer\s+mode)\b", re.I),
    ),
    (
        "exfiltration_request",
        re.compile(
            r"(send|post|upload|exfiltrate|leak|forward)\s+.{0,60}\b(to|at)\s+.{0,40}(attacker|evil|external|http)",
            re.I,
        ),
    ),
    (
        "tool_abuse_request",
        re.compile(
            r"\b(run|execute|exec)\s+(shell|command|bash|powershell|cmd\b|rm\s+-rf|cat\s+/etc/passwd)\b",
            re.I,
        ),
    ),
    (
        "delimiter_spoof",
        re.compile(r"(<\|im_start\|>|<\|im_end\|>|\[INST\]|###\s*(system|instruction))", re.I),
    ),
]

_ZERO_WIDTH_RE = re.compile("[\u200b-\u200d\ufeff\u2060]")


@dataclass
class InjectionResult:
    is_injection: bool
    owasp_id: str = "LLM01"
    owasp_name: str = OWASP_LLM_TOP10["LLM01"]
    markers: list[str] = field(default_factory=list)
    score: float = 0.0  # 0..1 heuristic confidence
    severity: str = "none"  # none | low | medium | high


def _severity_for(score: float) -> str:
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def detect_prompt_injection(text: str) -> InjectionResult:
    """Flag text that tries to override instructions (LLM01).

    Pure heuristic: pattern hits, not a model judgment. Treat tool/target
    output as data, never as instructions, when ``is_injection`` is true.
    """
    text = text or ""
    markers: list[str] = []
    for name, pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            markers.append(name)
    if _ZERO_WIDTH_RE.search(text):
        markers.append("zero_width_characters")
    score = min(1.0, 0.35 * len(markers)) if markers else 0.0
    return InjectionResult(
        is_injection=bool(markers),
        markers=markers,
        score=round(score, 3),
        severity=_severity_for(score),
    )


# ---------------------------------------------------------------------------
# System-prompt / secret leak detection (LLM07, LLM02)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "api_key",
        re.compile(r"\b(sk-[A-Za-z0-9_-]{8,}|sk_live_[A-Za-z0-9]+|ghp_[A-Za-z0-9]{20,})\b"),
    ),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._-]{16,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws_key", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("password_assignment", re.compile(r"\b(password|passwd|pwd)\s*[:=]\s*\S{4,}", re.I)),
]

_LEAK_PHRASES = [
    "my system prompt is",
    "my instructions are",
    "i was instructed to",
    "my developer instructions",
    "confidential instructions",
    "internal policy is",
]


@dataclass
class LeakResult:
    is_leak: bool
    owasp_id: str = "LLM07"
    owasp_name: str = OWASP_LLM_TOP10["LLM07"]
    markers: list[str] = field(default_factory=list)
    severity: str = "none"


def detect_system_prompt_leak(text: str, known_fragments: list[str] | None = None) -> LeakResult:
    """Detect system-prompt or secret material in model output (LLM07/LLM02).

    ``known_fragments`` are exact substrings of the real system prompt the
    caller wants to forbid from appearing in output (e.g. a canary string).
    """
    text = text or ""
    markers: list[str] = []
    lowered = text.lower()
    markers.extend(f"leak_phrase:{phrase}" for phrase in _LEAK_PHRASES if phrase in lowered)
    markers.extend(f"secret:{name}" for name, pattern in _SECRET_PATTERNS if pattern.search(text))
    if any(frag and frag in text for frag in known_fragments or []):
        markers.append("known_system_fragment")
    has_secret = any(m.startswith("secret:") for m in markers)
    return LeakResult(
        is_leak=bool(markers),
        owasp_id="LLM02" if has_secret else "LLM07",
        owasp_name=OWASP_LLM_TOP10["LLM02" if has_secret else "LLM07"],
        markers=markers,
        severity="high" if has_secret else ("medium" if markers else "none"),
    )


# ---------------------------------------------------------------------------
# MCP server manifest audit (LLM03, LLM05, LLM06, LLM01)
# ---------------------------------------------------------------------------

_DANGEROUS_TOOLS = {
    "exec",
    "shell",
    "bash",
    "terminal",
    "command",
    "run_command",
    "delete",
    "rm",
    "unlink",
    "upload",
    "exfiltrate",
    "ssh",
    "sudo",
    "write_file",
    "eval",
    "python",
    "code_exec",
}
_BROAD_PERMISSIONS = {
    "filesystem:*",
    "fs:*",
    "network:*",
    "*:*",
    "admin",
    "root",
    "shell:*",
    "exec:*",
    "all",
    "*",
}
_HIGH_RISK_INSTRUCTION_RE = re.compile(
    r"(ignore|override|disregard|bypass)\s+.{0,30}(safety|policy|previous|system)",
    re.I,
)


@dataclass
class ManifestFinding:
    code: str
    owasp_id: str
    severity: str  # low | medium | high
    message: str


def _manifest_tools(manifest: dict) -> list[str]:
    tools = manifest.get("tools") or manifest.get("tool_names") or []
    if isinstance(tools, dict):
        return list(tools.keys())
    return [str(t.get("name") if isinstance(t, dict) else t) for t in tools]


def audit_mcp_manifest(manifest: dict) -> list[ManifestFinding]:
    """Audit an MCP server manifest dict for risky declarations.

    Expected (all optional) keys: ``name``, ``version``, ``permissions`` /
    ``scopes``, ``tools``, ``instructions`` / ``description``, ``auth``,
    ``timeout_s``. Unknown/extra keys are ignored.
    """
    manifest = manifest or {}
    findings: list[ManifestFinding] = []

    permissions = [str(p) for p in (manifest.get("permissions") or manifest.get("scopes") or [])]
    findings.extend(
        ManifestFinding(
            "broad_permission",
            "LLM06",
            "high",
            f"overly broad permission declared: {perm!r}",
        )
        for perm in permissions
        if perm.strip().lower() in _BROAD_PERMISSIONS or perm.strip().endswith(":*")
    )

    findings.extend(
        ManifestFinding(
            "dangerous_tool",
            "LLM06",
            "high",
            f"tool with dangerous capability declared: {tool!r}",
        )
        for tool in _manifest_tools(manifest)
        if tool.strip().lower() in _DANGEROUS_TOOLS
    )

    instructions = str(manifest.get("instructions") or manifest.get("description") or "")
    if _HIGH_RISK_INSTRUCTION_RE.search(instructions):
        findings.append(
            ManifestFinding(
                "instruction_override",
                "LLM01",
                "high",
                "server instructions attempt to override safety/policy",
            )
        )
    inj = detect_prompt_injection(instructions)
    if inj.is_injection and not any(f.code == "instruction_override" for f in findings):
        findings.append(
            ManifestFinding(
                "injection_in_instructions",
                "LLM01",
                "medium",
                f"injection markers in instructions: {inj.markers}",
            )
        )

    if not manifest.get("version"):
        findings.append(
            ManifestFinding(
                "unpinned_version",
                "LLM03",
                "medium",
                "no pinned version; supply-chain updates are unbounded",
            )
        )
    if manifest.get("auth") is None and not manifest.get("authenticated", True):
        findings.append(
            ManifestFinding(
                "no_auth_declared",
                "LLM02",
                "medium",
                "no authentication/authorization declared for the server",
            )
        )
    timeout = manifest.get("timeout_s")
    if timeout is None or (isinstance(timeout, int | float) and timeout <= 0):
        findings.append(
            ManifestFinding(
                "no_timeout",
                "LLM10",
                "low",
                "no tool timeout declared; unbounded consumption risk",
            )
        )
    return findings


def manifest_passes(manifest: dict, max_severity: str = "medium") -> bool:
    """True when the manifest has no finding at/above ``max_severity``."""
    rank = {"low": 0, "medium": 1, "high": 2}
    limit = rank.get(max_severity, 1)
    return all(rank.get(f.severity, 0) < limit for f in audit_mcp_manifest(manifest))


# ---------------------------------------------------------------------------
# RAG poisoning / provenance / cross-tenant checks (LLM04, LLM08, LLM02)
# ---------------------------------------------------------------------------

_TRUSTED_SOURCES = {"kb", "cve_kb", "docs_internal", "official", "pinned"}
_UNTRUSTED_SOURCES = {"web", "user_input", "untrusted", "external", "scraped"}


@dataclass
class RagFinding:
    code: str
    owasp_id: str
    severity: str
    message: str


def content_hash(content: str) -> str:
    return hashlib.sha256((content or "").encode("utf-8")).hexdigest()


def check_rag_document(doc: dict) -> list[RagFinding]:
    """Validate provenance of one RAG document dict.

    Expected keys (all optional, missing ones are flagged): ``content``,
    ``source``, ``source_uri``, ``content_hash``, ``tenant_id``,
    ``trust_level`` / ``source_class``.
    """
    doc = doc or {}
    findings: list[RagFinding] = []
    source = str(doc.get("source") or "").strip().lower()
    if not source:
        findings.append(RagFinding("missing_source", "LLM04", "high", "document has no source"))
    elif source in _UNTRUSTED_SOURCES:
        findings.append(
            RagFinding(
                "untrusted_source", "LLM04", "medium", f"document source is untrusted: {source!r}"
            )
        )
    if not doc.get("source_uri"):
        findings.append(
            RagFinding(
                "missing_source_uri", "LLM04", "low", "document has no source_uri for provenance"
            )
        )
    if not doc.get("tenant_id"):
        findings.append(
            RagFinding(
                "missing_tenant",
                "LLM08",
                "medium",
                "document has no tenant_id; cross-tenant isolation cannot be proven",
            )
        )
    content = doc.get("content")
    declared = doc.get("content_hash")
    if content is not None and declared and declared != content_hash(str(content)):
        findings.append(
            RagFinding(
                "hash_mismatch",
                "LLM04",
                "high",
                "content_hash does not match content; document may be tampered",
            )
        )
    if content is not None:
        inj = detect_prompt_injection(str(content))
        if inj.is_injection:
            findings.append(
                RagFinding(
                    "poisoned_instruction",
                    "LLM04",
                    "high",
                    f"document embeds injection markers: {inj.markers}",
                )
            )
    return findings


def check_cross_tenant_leak(request_tenant: str, docs: list[dict]) -> list[RagFinding]:
    """Flag retrieved documents belonging to a different tenant (LLM08/LLM02)."""
    findings: list[RagFinding] = []
    for doc in docs or []:
        tenant = str((doc or {}).get("tenant_id") or "")
        if tenant and tenant != request_tenant:
            findings.append(
                RagFinding(
                    "cross_tenant_leak",
                    "LLM08",
                    "high",
                    f"document tenant {tenant!r} != request tenant {request_tenant!r}",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Semantic-manipulation heuristics (LLM04, LLM09)
# ---------------------------------------------------------------------------


@dataclass
class ManipulationResult:
    is_suspicious: bool
    owasp_id: str = "LLM04"
    markers: list[str] = field(default_factory=list)
    score: float = 0.0


_AUTHORITY_RE = re.compile(
    r"\b(official|verified|trusted|authoritative|confirmed)\s+(source|document|advisory)\b",
    re.I,
)
_URGENCY_RE = re.compile(r"\b(urgent|immediately|act now|critical alert|security alert)\b", re.I)


def semantic_manipulation_heuristics(text: str) -> ManipulationResult:
    """Heuristic flags for manipulated / poisoned RAG content (LLM04/LLM09)."""
    text = text or ""
    markers: list[str] = []
    words = text.split()
    if words:
        # Keyword stuffing / repetition: one word dominating the text.
        top = max(words, key=lambda w: sum(1 for x in words if x.lower() == w.lower()))
        ratio = words.count(top) / len(words) if top else 0
        if len(words) >= 20 and ratio > 0.15:
            markers.append(f"repetition:{top}")
    if _AUTHORITY_RE.search(text) and _URGENCY_RE.search(text):
        markers.append("authority_plus_urgency")
    if _ZERO_WIDTH_RE.search(text):
        markers.append("zero_width_characters")
    if text.count("http") > 5 and len(words) < 200:
        markers.append("link_density")
    inj = detect_prompt_injection(text)
    if inj.is_injection:
        markers.append("embedded_instruction")
    score = min(1.0, 0.3 * len(markers)) if markers else 0.0
    return ManipulationResult(is_suspicious=bool(markers), markers=markers, score=round(score, 3))


def evaluate_rag_corpus(request_tenant: str, docs: list[dict]) -> dict:
    """Aggregate all RAG checks for a retrieved corpus. Pure and offline."""
    per_doc = [check_rag_document(d) for d in (docs or [])]
    leaks = check_cross_tenant_leak(request_tenant, docs or [])
    manipulations = [
        semantic_manipulation_heuristics(str((d or {}).get("content") or "")) for d in (docs or [])
    ]
    all_findings = [f for sub in per_doc for f in sub] + leaks
    return {
        "doc_count": len(docs or []),
        "findings": all_findings,
        "cross_tenant_leaks": leaks,
        "manipulation": manipulations,
        "clean": not all_findings and not any(m.is_suspicious for m in manipulations),
    }
