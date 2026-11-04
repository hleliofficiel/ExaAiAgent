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
    print(json.dumps({"benchmark": "exaai-benchmark-v1", "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
