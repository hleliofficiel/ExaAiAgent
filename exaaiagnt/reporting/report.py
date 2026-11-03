from __future__ import annotations
import hashlib, json
from datetime import UTC, datetime
from pydantic import BaseModel, Field

SEVERITIES = ["critical","high","medium","low","info"]
class Finding(BaseModel):
    id: str = ""
    title: str
    content: str = ""
    severity: str = "info"
    cvss: float | None = None
    cwe: str | None = None
    owasp: str | None = None
    target: str | None = None
    evidence: list[str] = Field(default_factory=list)
    poc: str = ""
    remediation: str = ""
    confidence: float = 0.0
    first_seen: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    def model_post_init(self, __context):
        if not self.id:
            self.id = hashlib.sha256(f"{self.title}|{self.content}".encode()).hexdigest()[:12]

def normalize_severity(s: str) -> str:
    x=(s or "info").strip().lower()
    return x if x in SEVERITIES else "info"

def build_report(target: str, findings: list[dict], run_name: str = "") -> dict:
    norm=[]
    for f in findings:
        fd = Finding(**f)
        fd.severity = normalize_severity(fd.severity)
        norm.append(fd)
    # dedup by id
    seen=set(); dedup=[]
    for f in norm:
        if f.id not in seen: seen.add(f.id); dedup.append(f)
    counts={s: sum(1 for f in dedup if f.severity==s) for s in SEVERITIES}
    return {"schema":"exaai-report-v3","run_name":run_name,"target":target,"generated_at":datetime.now(UTC).isoformat(),"findings":[f.model_dump() for f in dedup],"summary":{"total":len(dedup),"by_severity":counts}}

def to_sarif(report: dict) -> dict:
    rules=[]; results=[]
    for f in report.get("findings",[]):
        rules.append({"id": f.get("cwe") or "EXAAI-001","name": f.get("title","finding")})
        results.append({"ruleId": f.get("cwe") or "EXAAI-001","level": {"critical":"error","high":"error","medium":"warning","low":"note","info":"note"}.get(f.get("severity","info"),"note"),"message":{"text": f.get("title","")}})
    return {"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"ExaAiAgent","rules":rules}},"results":results}]}
