"""Independent benchmark harness (deterministic checkers, no LLM judge). Each task: docker-compose + checker.py."""

from __future__ import annotations
import json, subprocess, sys, time
from pathlib import Path

TASKS = Path(__file__).parent / "tasks"


def run_task(task_id: str, timeout_s: int = 600) -> dict:
    td = TASKS / task_id
    if not td.exists():
        return {"task": task_id, "status": "missing_task_dir"}
    started = time.time()
    try:
        subprocess.run(
            ["docker", "compose", "up", "-d", "--build"],
            cwd=td,
            timeout=timeout_s,
            capture_output=True,
            text=True,
        )
        # NOTE: the agent run itself is invoked by the operator/CI (needs LLM keys); this harness only manages env lifecycle + checker.
        checker = td / "checker.py"
        if checker.exists():
            out = subprocess.run(
                [sys.executable, str(checker)], cwd=td, timeout=120, capture_output=True, text=True
            )
            return {
                "task": task_id,
                "status": "checked",
                "checker_exit": out.returncode,
                "elapsed_s": round(time.time() - started, 1),
                "stdout_tail": out.stdout[-500:],
            }
        return {
            "task": task_id,
            "status": "no_checker",
            "elapsed_s": round(time.time() - started, 1),
        }
    except Exception as e:
        return {"task": task_id, "status": "error", "error": str(e)}
    finally:
        try:
            subprocess.run(
                ["docker", "compose", "down", "-v"], cwd=td, timeout=60, capture_output=True
            )
        except Exception:
            pass


def main() -> int:
    ids = sys.argv[1:] or sorted(p.name for p in TASKS.iterdir() if p.is_dir())
    results = [run_task(t) for t in ids]
    print(json.dumps(summarize_results(results), indent=2))
    return 0


def summarize_results(results: list[dict]) -> dict:
    """Aggregate runner results (pass/fail/time/tokens/cost/FP rate)."""
    try:
        from metrics import summarize  # runner run as a script
    except ImportError:
        try:
            from benchmark.metrics import summarize  # runner imported as module
        except ImportError:
            summarize = None
    if summarize is not None:
        return summarize(results)
    records = [
        {
            "task": r.get("task", ""),
            "passed": r.get("status") == "checked" and r.get("checker_exit") == 0,
            "status": r.get("status", ""),
            "elapsed_s": float(r.get("elapsed_s") or 0.0),
            "tokens": int(r.get("tokens") or 0),
            "cost_usd": float(r.get("cost_usd") or 0.0),
            "tool_calls": int(r.get("tool_calls") or 0),
        }
        for r in results
    ]
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
        "false_positive_rate": None,
        "results": records,
    }


if __name__ == "__main__":
    raise SystemExit(main())
