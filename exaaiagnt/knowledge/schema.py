from __future__ import annotations

from pydantic import BaseModel, Field


class ProductRange(BaseModel):
    vendor: str = ""
    product: str = ""
    version_start: str | None = None
    version_end: str | None = None
    fixed_in: str | None = None


class CVERecord(BaseModel):
    cve_id: str
    aliases: list[str] = Field(default_factory=list)
    descriptions: list[str] = Field(default_factory=list)
    cvss_v3: float | None = None
    cvss_v4: float | None = None
    cvss_vector: str | None = None
    kev_listed: bool = False
    products: list[ProductRange] = Field(default_factory=list)
    published: str = ""
    modified: str = ""
    references: list[str] = Field(default_factory=list)
    source: str = "nvd"
    epss_score: float | None = None
    epss_percentile: float | None = None
    last_updated: str = ""
    verification_status: str = "unverified"
    exploit_verified: bool = False
    record_hash: str = ""
    kb_snapshot_id: str = ""


class KnowledgeManifest(BaseModel):
    kb_version: str = "2026.11.03+seed-v3.0.1"
    snapshot_date: str = "2026-11-03"
    record_count: int = 0
    sources: dict = Field(default_factory=dict)
