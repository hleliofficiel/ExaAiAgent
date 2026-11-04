"""httpx + katana + ffuf wrappers (Tier-A MIT, invoke-only). Argv-only allowlists."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


_HTTPX_ALLOWED = {
    "-json",
    "-silent",
    "-title",
    "-status-code",
    "-content-length",
    "-follow-redirects",
    "-timeout",
    "-retries",
    "-threads",
    "-rate-limit",
    "-probe",
    "-td",
    "-sc",
    "-cl",
    "-fr",
}
_KATANA_ALLOWED = {
    "-jsonl",
    "-silent",
    "-d",
    "-depth",
    "-jc",
    "-kf",
    "-timeout",
    "-parallelism",
    "-iqp",
    "-iqp-max",
}
_FFUF_ALLOWED = {"-mc", "-fs", "-t", "-rate", "-timeout", "-of", "-s", "-H", "-e", "-x", "-maxtime"}
_MAX_EXTRA = 30


def _check_extra(extra: list[str] | None, allowed: set[str]) -> list[str]:
    items = list(extra or [])
    if len(items) > _MAX_EXTRA:
        raise ValueError("too_many_extra_args")
    for item in items:
        if not isinstance(item, str):
            raise TypeError("extra args must be strings")
        if item.startswith("-") and item.split("=", 1)[0] not in allowed:
            raise ValueError(f"flag_not_allowed: {item}")
    return items


def build_httpx_argv(target: str, extra: list[str] | None = None, timeout: int = 30) -> list[str]:
    if not target or not target.startswith(("http://", "https://")):
        raise ValueError("target must be http(s) URL")
    argv = ["httpx", "-u", target, "-json", "-silent", "-timeout", str(timeout)]
    argv += _check_extra(extra, _HTTPX_ALLOWED)
    return argv


def build_katana_argv(target: str, extra: list[str] | None = None, depth: int = 2) -> list[str]:
    if not target or not target.startswith(("http://", "https://")):
        raise ValueError("target must be http(s) URL")
    if not 1 <= int(depth) <= 5:
        raise ValueError("depth out of range")
    argv = ["katana", "-u", target, "-jsonl", "-silent", "-d", str(depth)]
    argv += _check_extra(extra, _KATANA_ALLOWED)
    return argv


def build_ffuf_argv(
    url: str,
    wordlist: str,
    extra: list[str] | None = None,
    match_codes: str = "200,301,302,403",
) -> list[str]:
    if not url or "FUZZ" not in url:
        raise ValueError("url must contain FUZZ keyword")
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must be http(s)")
    if not Path(wordlist).is_absolute() or not wordlist.endswith(".txt"):
        raise ValueError("wordlist must be an absolute .txt path")
    argv = ["ffuf", "-u", url, "-w", wordlist, "-mc", match_codes, "-of", "json", "-s"]
    argv += _check_extra(extra, _FFUF_ALLOWED)
    return argv


def _run(binary: str, argv: list[str], timeout: int) -> dict[str, Any]:
    if shutil.which(binary) is None:
        return {
            "success": False,
            "error": f"{binary}_not_installed",
            "hint": f"install {binary} (Tier-A MIT) — see docs/tools.md",
        }
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 30, check=False)  # noqa: S603
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout", "argv": argv}
    except OSError as exc:
        return {"success": False, "error": "run_failed", "detail": str(exc)[:500]}
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    return {
        "success": r.returncode == 0,
        "count": len(lines),
        "lines": lines[:100],
        "stderr_tail": r.stderr[-1000:],
        "argv": argv,
    }


def run_httpx(target: str, extra: list[str] | None = None, timeout: int = 30) -> dict[str, Any]:
    return _run("httpx", build_httpx_argv(target, extra, timeout), timeout)


def run_katana(
    target: str, extra: list[str] | None = None, depth: int = 2, timeout: int = 120
) -> dict[str, Any]:
    return _run("katana", build_katana_argv(target, extra, depth), timeout)


def run_ffuf(
    url: str, wordlist: str, extra: list[str] | None = None, timeout: int = 120
) -> dict[str, Any]:
    return _run("ffuf", build_ffuf_argv(url, wordlist, extra), timeout)
