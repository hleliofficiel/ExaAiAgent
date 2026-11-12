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
                return {
                    "success": False,
                    "message": f"Grounding gate rejected report: {gate.reason}. Provide evidence_ids from primary tool executions.",
                }
        except Exception as e:
            import logging

            logging.warning(f"Grounding gate error: {e}")

    # v3.0.1: confidence scoring + FP rules
    confidence_val = 0.0
    confidence_band = "suspected"
    try:
        from exaaiagnt.validation import ConfidenceFeatures, score_confidence
        from exaaiagnt.validation import max_band_for

        feats = ConfidenceFeatures(
            evidence_class="data_sample" if (evidence_ids or []) else "none",
            repeatable_runs=2 if (evidence_ids or []) else 0,
            total_runs=2 if (evidence_ids or []) else 1,
        )
        sc = score_confidence(feats)
        confidence_val, confidence_band = sc.score, sc.band
        capped = (
            max_band_for("xss", has_execution_context=False)
            if "xss" in title.lower()
            else "confirmed"
        )
        if capped == "suspected" and confidence_band == "confirmed":
            confidence_band = "suspected"
    except Exception:  # nosec B110 - intentional best-effort: failure must not break the caller
        pass

    # v3.0.1: LLM hardening metadata (additive; never blocks the report)
    hardening_meta: dict = {}
    try:
        from exaaiagnt.verification.hardening import harden_finding_text

        _h = harden_finding_text(content or "")
        hardening_meta = {
            "clean": _h["clean"],
            "injection": _h["injection"].is_injection,
            "leak": _h["leak"].is_leak,
            "manipulation": _h["manipulation"].is_suspicious,
        }
    except Exception:  # nosec B110 - noqa: BLE001, S110 - hardening is best-effort metadata  # best-effort
        pass

    # Auto-save report to disk
    report_data = {
        "title": title,
        "content": content,
        "severity": severity,
        "timestamp": datetime.now().isoformat(),
        "agent": os.getenv("EXAAI_AGENT_NAME", "unknown"),
        "evidence_ids": evidence_ids or [],
        "confidence": confidence_val,
        "confidence_band": confidence_band,
        "hardening": hardening_meta,
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
            # v3.0.1: also persist unified report.json (build_report) next to legacy file
            try:
                from exaaiagnt.reporting import build_report

                target = os.getenv("EXAAI_TARGET", "")
                unified = build_report(
                    target=target,
                    findings=[report_data],
                    run_name=getattr(tracer, "run_name", "") or "",
                )
                run_dir = None
                try:
                    run_dir = tracer.get_run_dir()  # type: ignore[attr-defined]
                except Exception:
                    run_dir = None
                if run_dir is not None:
                    import json as _json

                    (run_dir / "report.json").write_text(_json.dumps(unified, indent=2))
            except Exception:  # nosec B110 - intentional best-effort: failure must not break the caller
                pass

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
