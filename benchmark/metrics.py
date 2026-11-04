"""Benchmark run metrics: pure aggregation over runner result dicts.

No Docker, no LLM, no I/O. The runner emits one result dict per task (see
``runner.py``); operators/CI may also supply the extra run fields recorded
here: ``tokens``, ``cost_usd``, ``tool_calls``, ``predicted_vulns`` /
``false_positives`` (for false-positive rate).
"""

from __future__ import annotations


def task_metrics(result: dict) -> dict:
    """Normalize one runner result into a metrics record."""
    status = str(result.get("status") or "")
    passed = status == "checked" and result.get("checker_exit") == 0
    return {
        "task": result.get("task", ""),
        "passed": passed,
        "status": status,
        "elapsed_s": float(result.get("elapsed_s") or 0.0),
        "tokens": int(result.get("tokens") or 0),
        "cost_usd": float(result.get("cost_usd") or 0.0),
        "tool_calls": int(result.get("tool_calls") or 0),
    }


def false_positive_rate(results: list[dict]) -> float | None:
    """False positives / total predictions; ``None`` when no prediction data."""
    predicted = 0
    false_pos = 0
    for r in results:
        for name in ("predicted_vulns", "predictions"):
            if r.get(name) is not None:
                v = r[name]
                predicted += len(v) if isinstance(v, list | tuple) else int(v)
        for name in ("false_positives", "false_positive_count"):
            if r.get(name) is not None:
                v = r[name]
                false_pos += len(v) if isinstance(v, list | tuple) else int(v)
    if not predicted:
        return None
    return round(false_pos / predicted, 4)


def summarize(results: list[dict]) -> dict:
    """Aggregate metrics over a list of runner result dicts."""
    records = [task_metrics(r) for r in results]
    total = len(records)
    passed = sum(1 for r in records if r["passed"])
    return {
        "benchmark": "exaai-benchmark-v1",
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "total_elapsed_s": round(sum(r["elapsed_s"] for r in records), 1),
        "total_tokens": sum(r["tokens"] for r in records),
        "total_cost_usd": round(sum(r["cost_usd"] for r in records), 6),
        "total_tool_calls": sum(r["tool_calls"] for r in records),
        "false_positive_rate": false_positive_rate(results),
        "results": records,
    }
