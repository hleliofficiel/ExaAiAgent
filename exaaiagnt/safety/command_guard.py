from __future__ import annotations

import re
import shlex

from exaaiagnt.safety.scope import ScopeDecision, TargetScope


META = [";", "&&", "||", "|", "`", "$(", "\n", ">", "<"]
DENY_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"mkfs",
    r"dd\s+if=",
    r"iptables\s+-F",
    r"curl.*\|\s*bash",
    r"/etc/shadow",
]
ARGV_ALLOW = {
    "nmap",
    "nuclei",
    "sqlmap",
    "ffuf",
    "katana",
    "httpx",
    "whatweb",
    "nikto",
    "subfinder",
    "amass",
    "dnsenum",
    "theharvester",
    "masscan",
    "gobuster",
    "wfuzz",
    "zap.sh",
    "kubectl",
}


_SAFE_BUILTINS = {"echo", "cat", "ls", "pwd", "whoami", "id", "uname", "env", "printenv"}


def _deny_decision(cmd: str, scope: TargetScope | None) -> ScopeDecision | None:
    for pat in DENY_PATTERNS:
        if re.search(pat, cmd):
            if scope and scope.allow_destructive:
                return ScopeDecision(
                    allow=True, rule_id="destructive_allowed", reason="allow_destructive set"
                )
            return ScopeDecision(allow=False, rule_id="denylist", reason=f"denied pattern {pat}")
    return None


def _strict_binary_decision(binary: str) -> ScopeDecision:
    if binary in _SAFE_BUILTINS:
        return ScopeDecision(allow=True, rule_id="safe_builtin", reason="safe builtin")
    return ScopeDecision(
        allow=False,
        rule_id="unknown_binary",
        reason=f"binary {binary} not in argv allowlist (strict)",
    )


def guard_command(command: str, scope: TargetScope | None = None) -> ScopeDecision:
    cmd = (command or "").strip()
    if not cmd:
        return ScopeDecision(allow=False, rule_id="empty", reason="empty command")
    deny = _deny_decision(cmd, scope)
    if deny is not None:
        return deny
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return ScopeDecision(allow=False, rule_id="parse_error", reason="shlex parse failed")
    if not argv:
        return ScopeDecision(allow=False, rule_id="empty_argv", reason="empty argv")
    binary = argv[0].split("/")[-1]
    if binary not in ARGV_ALLOW and scope and scope.strict:
        return _strict_binary_decision(binary)
    return ScopeDecision(allow=True, rule_id="argv_ok", reason="argv parse ok")


def guard_argv(argv: list[str], scope: TargetScope | None = None) -> ScopeDecision:
    if not argv:
        return ScopeDecision(allow=False, rule_id="empty_argv", reason="empty argv")
    binary = argv[0].split("/")[-1]
    if (
        scope
        and scope.strict
        and binary not in ARGV_ALLOW
        and binary
        not in {
            "echo",
            "cat",
            "ls",
            "pwd",
            "whoami",
            "id",
            "uname",
            "env",
            "printenv",
            "python3",
            "python",
        }
    ):
        return ScopeDecision(
            allow=False, rule_id="unknown_binary", reason=f"binary {binary} not in argv allowlist"
        )
    joined = " ".join(argv)
    for pat in DENY_PATTERNS:
        if re.search(pat, joined):
            return ScopeDecision(allow=False, rule_id="denylist", reason=f"denied pattern {pat}")
    return ScopeDecision(allow=True, rule_id="argv_ok", reason="argv ok (no shell)")
