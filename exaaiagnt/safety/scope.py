from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class ScopeDecision(BaseModel):
    allow: bool
    rule_id: str = ""
    reason: str = ""
    host: str | None = None


class TargetScope(BaseModel):
    targets: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    allow_internal_ssrf: bool = False
    allow_destructive: bool = False
    strict: bool = True

    @classmethod
    def from_targets(cls, targets: list[str], **kw) -> TargetScope:
        hosts = []
        for t in targets or []:
            h = _host_of(t)
            if h:
                hosts.append(h)
        return cls(targets=list(targets or []), allowed_hosts=hosts, **kw)

    def _check_ip(self, h: str) -> ScopeDecision | None:
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            return None
        if (ip.is_private or ip.is_loopback or ip.is_link_local) and not self.allow_internal_ssrf:
            return ScopeDecision(
                allow=False,
                rule_id="internal_blocked",
                reason="private IP blocked unless allow_internal_ssrf",
                host=h,
            )
        for c in self.allowed_cidrs:
            try:
                if ip in ipaddress.ip_network(c, strict=False):
                    return ScopeDecision(
                        allow=True, rule_id="cidr_match", reason="ip in allowed cidr", host=h
                    )
            except ValueError:
                pass
        return None

    def check_host(self, host: str | None) -> ScopeDecision:
        if not host:
            return ScopeDecision(allow=False, rule_id="empty_host", reason="no host")
        h = host.lower().strip(".")
        ip_decision = self._check_ip(h)
        if ip_decision is not None:
            return ip_decision
        if h in [x.lower() for x in self.allowed_hosts]:
            return ScopeDecision(allow=True, rule_id="host_match", reason="host in scope", host=h)
        for ah in self.allowed_hosts:
            if ah and (h == ah or h.endswith("." + ah)):
                return ScopeDecision(
                    allow=True, rule_id="subdomain_match", reason="subdomain in scope", host=h
                )
        if not self.strict and not self.allowed_hosts:
            return ScopeDecision(
                allow=True, rule_id="no_scope_configured", reason="strict off, no scope", host=h
            )
        return ScopeDecision(
            allow=False, rule_id="out_of_scope", reason="host not in authorized scope", host=h
        )

    def check_url(self, url: str | None) -> ScopeDecision:
        h = _host_of(url or "")
        return self.check_host(h)

    def check_path(self, path: str | None) -> ScopeDecision:
        p = (path or "").replace("\\", "/")
        if ".." in p.split("/"):
            return ScopeDecision(allow=False, rule_id="path_traversal", reason=".. in path")
        if p.startswith(("/workspace", "workspace/")) or not p.startswith("/"):
            return ScopeDecision(
                allow=True, rule_id="workspace_path", reason="confined to workspace"
            )
        return ScopeDecision(
            allow=False, rule_id="path_outside_workspace", reason="path outside /workspace"
        )


def _host_of(target: str) -> str | None:
    t = (target or "").strip()
    if not t:
        return None
    if "://" in t:
        try:
            return urlparse(t).hostname
        except ValueError:
            return None
    if "/" in t:
        return t.split("/")[0].split(":")[0] or None
    return t.split(":")[0] or None
