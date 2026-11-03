from __future__ import annotations
from exaaiagnt.safety.scope import TargetScope
class TargetTracker:
    def __init__(self, scope: TargetScope | None = None):
        self.scope = scope or TargetScope()
        self.visited: list[str] = []
    def check(self, target: str) -> bool:
        d = self.scope.check_url(target) if "://" in (target or "") else self.scope.check_host(target)
        if d.allow: self.visited.append(target)
        return d.allow
