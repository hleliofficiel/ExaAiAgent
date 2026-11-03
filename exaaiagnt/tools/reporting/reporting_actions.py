import json
import os
from datetime import datetime
from typing import Any

from exaaiagnt.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def create_vulnerability_report(
    title: str,
    content: str,
    severity: str,
    evidence_ids: list[str] | None = None,
) -> dict[str, Any]:
    validation_error = None
    if not title or not title.strip():
        validation_error = "Title cannot be empty"
    elif not content or not content.strip():
        validation_error = "Content cannot be empty"
    elif not severity or not severity.strip():
        validation_error = "Severity cannot be empty"
    else:
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if severity.lower() not in valid_severities:
            validation_error = (
                f"Invalid severity '{severity}'. Must be one of: {', '.join(valid_severities)}"
            )

    if validation_error:
        return {"success": False, "message": validation_error}

    # v3 grounding gate: evidence_ids required (no citation, no claim)
    if os.getenv("EXAAI_GROUNDING", "true").lower() == "true":
        try:
            from exaaiagnt.grounding import validate_claim
            from exaaiagnt.knowledge import CVEStore
            store = CVEStore.get()
            gate = validate_claim(evidence_ids or [], text=content, kb_lookup=store.lookup_cve)
            if not gate.allow:
                return {"success": False, "message": f"Grounding gate rejected report: {gate.reason}. Provide evidence_ids from primary tool executions."}
        except Exception as e:
            import logging
            logging.warning(f"Grounding gate error: {e}")

    # Auto-save report to disk
    report_data = {
        "title": title,
        "content": content,
        "severity": severity,
        "timestamp": datetime.now().isoformat(),
        "agent": os.getenv("EXAAI_AGENT_NAME", "unknown"),
        "evidence_ids": evidence_ids or [],
    }

    # Save to local reports directory
    try:
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        filename = f"vuln_report_{int(datetime.now().timestamp())}_{severity}.json"
        filepath = os.path.join(reports_dir, filename)

        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=2)

    except Exception as e:
        import logging

        logging.warning(f"Failed to save local report: {e}")

    try:
        from exaaiagnt.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            report_id = tracer.add_vulnerability_report(
                title=title,
                content=content,
                severity=severity,
            )

            return {
                "success": True,
                "message": f"Vulnerability report '{title}' created successfully",
                "report_id": report_id,
                "severity": severity.lower(),
                "local_path": filepath,
            }
        import logging

        logging.warning("Global tracer not available - vulnerability report not stored in tracer")

        return {  # noqa: TRY300
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully (saved locally)",
            "warning": "Report not persisted in tracer",
            "local_path": filepath,
        }

    except ImportError:
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully (saved locally)",
            "warning": "Report not persisted - tracer module unavailable",
            "local_path": filepath,
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "message": f"Failed to create vulnerability report: {e!s}"}
