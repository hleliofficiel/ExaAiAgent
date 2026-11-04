"""2026 browser/JS offline analysis: DOM XSS, postMessage, Service Worker,
JS bundle endpoint/secret extraction. Pure functions over supplied
HTML/JS text; no network, no browser required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# --- DOM XSS ---------------------------------------------------------------

_DOM_SINKS = (
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\s*\(",
    r"insertAdjacentHTML\s*\(",
    r"\.html\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*['\"]",
    r"location\s*=\s*[^;]*location\.(hash|search)",
    r"document\.location\s*=",
)
_DOM_SOURCES = (
    r"location\.(hash|search|href)",
    r"document\.referrer",
    r"window\.name",
    r"postMessage",
    r"document\.cookie",
    r"localStorage|sessionStorage",
)


@dataclass
class DomXssFinding:
    sink: str
    source: str | None
    line: int
    snippet: str
    confidence: float


@dataclass
class PostMessageFinding:
    line: int
    snippet: str
    has_origin_check: bool
    confidence: float


@dataclass
class ServiceWorkerFinding:
    kind: str  # registration / fetch_handler / cache_first / scope_issue
    line: int
    snippet: str
    confidence: float


@dataclass
class JsSecret:
    kind: str
    value_redacted: str
    line: int


@dataclass
class BrowserJsReport:
    dom_xss: list[DomXssFinding] = field(default_factory=list)
    post_message: list[PostMessageFinding] = field(default_factory=list)
    service_workers: list[ServiceWorkerFinding] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    secrets: list[JsSecret] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "dom_xss": [f.__dict__ for f in self.dom_xss],
            "post_message": [f.__dict__ for f in self.post_message],
            "service_workers": [f.__dict__ for f in self.service_workers],
            "endpoints": self.endpoints,
            "secrets": [s.__dict__ for s in self.secrets],
            "source_maps": self.source_maps,
        }


def _lines(text: str) -> list[str]:
    return (text or "").splitlines()


def analyze_dom_xss(js_or_html: str) -> list[DomXssFinding]:
    findings: list[DomXssFinding] = []
    lines = _lines(js_or_html)
    for i, line in enumerate(lines, 1):
        for sink in _DOM_SINKS:
            if re.search(sink, line):
                source = next((s for s in _DOM_SOURCES if re.search(s, line)), None)
                # Look at nearby lines for a source feeding the sink.
                if source is None:
                    window = "\n".join(lines[max(0, i - 3) : min(len(lines), i + 2)])
                    source = next((s for s in _DOM_SOURCES if re.search(s, window)), None)
                findings.append(
                    DomXssFinding(
                        sink=sink,
                        source=source,
                        line=i,
                        snippet=line.strip()[:200],
                        confidence=0.9 if source else 0.5,
                    )
                )
    return findings


def analyze_post_message(js_or_html: str) -> list[PostMessageFinding]:
    findings: list[PostMessageFinding] = []
    lines = _lines(js_or_html)
    has_check = bool(
        re.search(r"event\.origin|e\.origin|origin\s*===?|origin\s*!==?", js_or_html or "")
    )
    for i, line in enumerate(lines, 1):
        if "postMessage" in line:
            findings.append(
                PostMessageFinding(
                    line=i,
                    snippet=line.strip()[:200],
                    has_origin_check=has_check,
                    confidence=0.6 if has_check else 0.85,
                )
            )
    if not findings and re.search(r"addEventListener\s*\(\s*['\"]message['\"]", js_or_html or ""):
        findings.append(
            PostMessageFinding(
                line=0,
                snippet="message listener without postMessage call",
                has_origin_check=has_check,
                confidence=0.6 if has_check else 0.85,
            )
        )
    return findings


def analyze_service_worker(js_or_html: str) -> list[ServiceWorkerFinding]:
    out: list[ServiceWorkerFinding] = []
    for i, line in enumerate(_lines(js_or_html), 1):
        low = line.lower()
        if "navigator.serviceworker.register" in low.replace(" ", ""):
            out.append(ServiceWorkerFinding("registration", i, line.strip()[:200], 0.8))
        if any(s in line for s in ("addEventListener('fetch'", 'addEventListener("fetch"')):
            out.append(ServiceWorkerFinding("fetch_handler", i, line.strip()[:200], 0.7))
        if "cache" in low and ("caches.open" in low or "cache.add" in low or "cache.put" in low):
            out.append(ServiceWorkerFinding("cache_first", i, line.strip()[:200], 0.6))
    return out


_SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    ("api_key", r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{8,})['\"]"),
    ("aws_key", r"(AKIA[0-9A-Z]{16})"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("jwt", r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"),
    (
        "generic_secret",
        r"(?i)(?:secret|passwd|password|token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    ),
    ("stripe", r"(sk_live_[A-Za-z0-9]{16,})"),
    ("github", r"(ghp_[A-Za-z0-9]{20,})"),
    ("slack", r"(xox[bpas]-[A-Za-z0-9-]{10,})"),
)

_ENDPOINT_RE = re.compile(
    r"""['"`](/(?:api|v\d|graphql|rest|auth|login|admin|config)[A-Za-z0-9/_\-.{}:]*)['"`]"""
)
_URL_RE = re.compile(r"""https?://[A-Za-z0-9.\-/_?=&%]+""")


def extract_endpoints(js_or_html: str) -> list[str]:
    found = set(_ENDPOINT_RE.findall(js_or_html or ""))
    found.update(_URL_RE.findall(js_or_html or ""))
    return sorted(found)[:200]


def extract_secrets(js_or_html: str) -> list[JsSecret]:
    out: list[JsSecret] = []
    lines = _lines(js_or_html)
    for kind, pat in _SECRET_PATTERNS:
        for i, line in enumerate(lines, 1):
            m = re.search(pat, line)
            if m:
                val = m.group(1) if m.groups() else m.group(0)
                redacted = (val[:4] + "***" + val[-2:]) if len(val) > 6 else "***"
                out.append(JsSecret(kind=kind, value_redacted=redacted, line=i))
    return out


def extract_source_maps(js_or_html: str) -> list[str]:
    return sorted(set(re.findall(r"sourceMappingURL=([^\s'\"]+)", js_or_html or "")))[:50]


def analyze_browser_js(html_or_js: str) -> BrowserJsReport:
    """Full offline report over supplied HTML/JS text."""
    return BrowserJsReport(
        dom_xss=analyze_dom_xss(html_or_js),
        post_message=analyze_post_message(html_or_js),
        service_workers=analyze_service_worker(html_or_js),
        endpoints=extract_endpoints(html_or_js),
        secrets=extract_secrets(html_or_js),
        source_maps=extract_source_maps(html_or_js),
    )


def analyze_js_bundle(bundle_text: str, bundle_url: str = "") -> dict:
    """Bundle entry point: endpoints, secrets, source maps, DOM XSS."""
    report = analyze_browser_js(bundle_text)
    return {"bundle_url": bundle_url, **report.to_dict()}
