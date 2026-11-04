from __future__ import annotations

import hashlib
import threading
from typing import Any

from exaaiagnt.grounding.schema import EvidenceRecord


PRIMARY_TOOLS = {
    "browser_action",
    "terminal_execute",
    "send_request",
    "repeat_request",
    "python_action",
    "proxy",
    "list_requests",
    "view_request",
    "list_files",
    "search_files",
    "scan_cluster",
    "check_rbac",
    "check_pod_security",
    "scan_for_prompt_injection",
    "scan_llm_endpoint",
}


class EvidenceStore:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self._store: dict[str, EvidenceRecord] = {}
        self._lock2 = threading.Lock()

    @classmethod
    def instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def record(
        self,
        tool_name: str,
        result: Any,
        agent_id: str = "unknown",
        iteration: int = 0,
        tool_execution_id: int = 0,
        args: dict | None = None,
    ) -> EvidenceRecord:
        args = args or {}
        args_s = str(sorted(args.items()))
        out_s = str(result)[:20000]
        eid = EvidenceRecord.make_id(tool_name, args_s, out_s)
        rec = EvidenceRecord(
            evidence_id=eid,
            tool_name=tool_name,
            tool_execution_id=tool_execution_id,
            agent_id=agent_id,
            iteration=iteration,
            args_hash=hashlib.sha256(args_s.encode()).hexdigest(),
            output_sha256=hashlib.sha256(out_s.encode()).hexdigest(),
            output_excerpt=out_s[:4000],
            target=None,
            source_class="primary" if tool_name in PRIMARY_TOOLS else "secondary",
        )
        with self._lock2:
            self._store[eid] = rec
        return rec

    def get_record(self, eid: str) -> EvidenceRecord | None:
        return self._store.get(eid)

    def get(self, eid: str) -> EvidenceRecord | None:
        return self._store.get(eid)

    def all(self) -> list[EvidenceRecord]:
        return list(self._store.values())

    def by_target(self, target: str) -> list[EvidenceRecord]:
        return [r for r in self._store.values() if r.target == target]

    def clear(self):
        with self._lock2:
            self._store.clear()
