from __future__ import annotations
import hashlib
from datetime import UTC, datetime
from typing import Literal
from pydantic import BaseModel, Field

class Detection(BaseModel):
    family: str = ""
    confidence: float = 0.0

class EvidenceRecord(BaseModel):
    evidence_id: str
    tool_name: str
    tool_execution_id: int = 0
    agent_id: str = "unknown"
    iteration: int = 0
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    args_hash: str = ""
    output_sha256: str = ""
    output_excerpt: str = ""
    target: str | None = None
    source_class: Literal["primary","secondary"] = "primary"
    detections: list[Detection] = Field(default_factory=list)
    kb_refs: list[str] = Field(default_factory=list)

    @staticmethod
    def make_id(tool_name: str, args_s: str, output_s: str) -> str:
        h = hashlib.sha256(f"{tool_name}|{args_s}|{output_s}".encode()).hexdigest()[:12]
        return f"ev_{h}"

class Claim(BaseModel):
    claim_id: str = ""
    claim_type: Literal["finding","cve","endpoint","impact","version"] = "finding"
    text: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    status: Literal["suspected","probable","confirmed","rejected"] = "suspected"
