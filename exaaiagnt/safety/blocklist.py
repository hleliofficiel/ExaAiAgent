"""Central blocked paths/modules deny list (offline, deterministic).

Enforced from executor, command_guard and proxy paths. Every denial returns
a ScopeDecision so callers have evidence (rule_id + reason + host/path).
Override via env: EXAAI_BLOCKED_PATHS / EXAAI_BLOCKED_MODULES (csv).
"""

from __future__ import annotations

import os
import posixpath
import re
from urllib.parse import unquote, urlparse

from exaaiagnt.safety.scope import ScopeDecision


# Filesystem paths that tools must never read/write through generic tools.
BLOCKED_PATH_PREFIXES: tuple[str, ...] = (
    "/etc/shadow",
    "/etc/passwd",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/workspace/.env",
    "/workspace/.git",
    "/workspace/.ssh",
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "secrets.json",
)

# Dotted module / tool-module prefixes that must never be loaded/executed.
BLOCKED_MODULE_PREFIXES: tuple[str, ...] = (
    "os.system",
    "subprocess",
    "shutil.rmtree",
    "socket",
    "http.server",
)

# URL path segments denied even when host is in scope (SSRF / traversal aid).
BLOCKED_URL_PATH_SEGMENTS: tuple[str, ...] = (
    "/.git/",
    "/.env",
    "/wp-config.php",
    "/.ssh/",
    "/proc/self/",
    "/etc/passwd",
    "/etc/shadow",
)


def _env_csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.getenv(name, "")
    items = tuple(x.strip() for x in raw.split(",") if x.strip())
    return default + items if items else default


def get_blocked_paths() -> tuple[str, ...]:
    return _env_csv("EXAAI_BLOCKED_PATHS", BLOCKED_PATH_PREFIXES)


def get_blocked_modules() -> tuple[str, ...]:
    return _env_csv("EXAAI_BLOCKED_MODULES", BLOCKED_MODULE_PREFIXES)


def _norm_path(p: str) -> str:
    q = unquote((p or "").replace("\\", "/"))
    # Collapse traversal before prefix checks; keep leading slash.
    q = posixpath.normpath("/" + q.lstrip("/")) if q.startswith("/") else posixpath.normpath(q)
    return q.lower()


def check_blocked_path(path: str | None) -> ScopeDecision:
    """Deny if path matches the blocked-paths list or contains traversal."""
    if not path:
        return ScopeDecision(allow=True, rule_id="ok", reason="no path")
    p = _norm_path(path)
    if ".." in p.split("/"):
        return ScopeDecision(allow=False, rule_id="blocked_traversal", reason=".. in path", host=p)
    for prefix in get_blocked_paths():
        pre = _norm_path(prefix)
        if p == pre or p.startswith(pre.rstrip("/") + "/") or pre in p:
            return ScopeDecision(
                allow=False,
                rule_id="blocked_path",
                reason=f"path blocked: {prefix}",
                host=p,
            )
    return ScopeDecision(allow=True, rule_id="ok", reason="path not blocked", host=p)


def check_blocked_module(module: str | None) -> ScopeDecision:
    if not module:
        return ScopeDecision(allow=True, rule_id="ok", reason="no module")
    m = module.strip().lower()
    for prefix in get_blocked_modules():
        pre = prefix.strip().lower()
        if m == pre or m.startswith(pre):
            return ScopeDecision(
                allow=False,
                rule_id="blocked_module",
                reason=f"module blocked: {prefix}",
                host=m,
            )
    return ScopeDecision(allow=True, rule_id="ok", reason="module not blocked", host=m)


def check_blocked_url(url: str | None) -> ScopeDecision:
    """Deny URLs whose decoded path hits blocked segments."""
    if not url:
        return ScopeDecision(allow=True, rule_id="ok", reason="no url")
    try:
        path = urlparse(url).path or url
    except ValueError:
        path = url
    decoded = unquote(path).lower()
    for seg in BLOCKED_URL_PATH_SEGMENTS:
        if seg in decoded:
            return ScopeDecision(
                allow=False,
                rule_id="blocked_url_path",
                reason=f"url path blocked: {seg}",
                host=decoded,
            )
    cmd = check_blocked_path(decoded)
    if not cmd.allow:
        return cmd
    return ScopeDecision(allow=True, rule_id="ok", reason="url path not blocked")


def check_blocked_text(text: str | None) -> ScopeDecision:
    """Catch shell-style attempts smuggled in a single string argument."""
    if not text:
        return ScopeDecision(allow=True, rule_id="ok", reason="no text")
    for pat in (r"/etc/shadow", r"/etc/passwd", r"rm\s+-rf\s+/", r"mkfs\b", r"dd\s+if="):
        if re.search(pat, text):
            return ScopeDecision(
                allow=False, rule_id="blocked_text", reason=f"blocked pattern {pat}"
            )
    return ScopeDecision(allow=True, rule_id="ok", reason="text not blocked")
