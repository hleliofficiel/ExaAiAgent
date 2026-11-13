"""exaai mcp - Model Context Protocol (MCP) stdio server for ExaAiAgent.

Exposes a curated, SAFE subset of ExaAiAgent capabilities over MCP stdio:

  - exaai_run_scan   Run a full headless scan equivalent to
                     ``exaai --target <t> -n``. Requires EXAAI_TARGETS to be
                     set and to contain the target (substring match, same
                     semantics as the TargetScope enforcement in the tool
                     executor).
  - exaai_cve_lookup Look up a CVE in the pinned CVE knowledge base.
  - exaai_list_runs  List ``exaai_runs/<name>`` newest first.
  - exaai_get_report Read a run's ``report.json`` summary (counts + top 10
                     findings). Raw report.json is never returned in-band.

Transport: stdio only. All logging goes to stderr; stdout is reserved for
the MCP JSON-RPC channel and must never carry log output.

Claude Desktop configuration example:

    {
      "mcpServers": {
        "exaai": { "command": "exaai", "args": ["mcp"] }
      }
    }

Usage:
    exaai mcp          # start the stdio server (blocks on stdio)
    exaai mcp --help   # show short help and exit 0 (does not start server)

Equivalent module invocation:
    python -m exaaiagnt.mcp_server
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import re
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger("exaaiagnt.mcp")

SERVER_NAME = "exaai-agent"

_RUN_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_MAX_TARGET_LEN = 2048
_REPORT_READ_CAP = 16 * 1024 * 1024  # 16 MiB
_CONFIRMED_CONFIDENCE = 0.85

RUNS_DIR = Path("exaai_runs")


# ---------------------------------------------------------------------------
# Tool catalogue (also used by tests)
# ---------------------------------------------------------------------------


def list_registered_mcp_tools() -> list[dict[str, Any]]:
    """Return the curated MCP tool list as plain dicts."""
    return [
        {
            "name": "exaai_run_scan",
            "description": (
                "Run a full ExaAiAgent scan against a target (equivalent to "
                "'exaai --target <t> -n'). Requires EXAAI_TARGETS to be set and "
                "contain the target. Returns a concise summary: run name, "
                "confirmed/suspected finding counts, report path, and confirmed "
                "findings with evidence ids. Never returns raw report.json."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target to scan (URL, domain, repo URL, or local path).",
                    },
                    "prompt_modules": {
                        "type": "string",
                        "description": (
                            "Optional comma-separated prompt modules "
                            "(e.g. 'kubernetes_security,cloud_security')."
                        ),
                    },
                    "instruction": {
                        "type": "string",
                        "description": "Optional custom instruction for the scan.",
                    },
                    "budget_max_tokens": {
                        "type": "integer",
                        "description": "Optional max scan token budget.",
                        "minimum": 1,
                    },
                },
                "required": ["target"],
            },
        },
        {
            "name": "exaai_cve_lookup",
            "description": (
                "Look up a CVE id (e.g. CVE-2024-1234) in the pinned ExaAiAgent "
                "CVE knowledge base. Returns the KB entry as JSON text."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE identifier, e.g. CVE-2024-1234.",
                    },
                },
                "required": ["cve_id"],
            },
        },
        {
            "name": "exaai_list_runs",
            "description": (
                "List exaai_runs/<name> directories, newest first, with mtime and "
                "whether report.json exists."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max runs to list (default 5).",
                        "minimum": 1,
                        "maximum": 100,
                    },
                },
                "required": [],
            },
        },
        {
            "name": "exaai_get_report",
            "description": (
                "Read the summary of exaai_runs/<run_name>/report.json: confirmed/"
                "suspected counts and the top 10 findings (id/title/severity/"
                "evidence ids). run_name must match ^[A-Za-z0-9_.-]+$."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run_name": {
                        "type": "string",
                        "description": "Run directory name under exaai_runs/ (^[A-Za-z0-9_.-]+$).",
                    },
                },
                "required": ["run_name"],
            },
        },
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _text_result(text: str, is_error: bool = False):
    from mcp import types

    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        isError=is_error,
    )


def _error(text: str):
    return _text_result(text, is_error=True)


def _validate_target(target: Any) -> str:
    if not isinstance(target, str):
        msg = "target must be a string"
        raise TypeError(msg)
    t = target.strip()
    if not t:
        msg = "target must not be empty"
        raise ValueError(msg)
    if len(t) > _MAX_TARGET_LEN:
        msg = f"target too long (max {_MAX_TARGET_LEN} chars)"
        raise ValueError(msg)
    if any(ord(c) < 32 for c in t):
        msg = "target contains control characters"
        raise ValueError(msg)
    return t


def _targets_env_allows(target: str) -> tuple[bool, str]:
    targets_env = os.getenv("EXAAI_TARGETS", "").strip()
    if not targets_env:
        return False, (
            "EXAAI_TARGETS is not set. Refusing to scan: set EXAAI_TARGETS to a "
            "comma-separated list containing the target (same scope gate as the "
            "tool executor)."
        )
    if target not in targets_env:
        return False, (
            f"Target {target!r} is not contained in EXAAI_TARGETS={targets_env!r}. "
            "Refusing to scan (scope gate)."
        )
    return True, ""


def _generate_run_name() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return f"mcp_{stamp}_{secrets.token_hex(3)}"


def _classify_finding(f: dict[str, Any]) -> str:
    try:
        confidence = float(f.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    band = str(f.get("confidence_band", "") or "").lower()
    if band == "confirmed" or confidence >= _CONFIRMED_CONFIDENCE:
        return "confirmed"
    return "suspected"


def _finding_evidence_ids(f: dict[str, Any]) -> list[str]:
    ids = f.get("evidence_ids")
    if not isinstance(ids, list) or not ids:
        ids = f.get("evidence")
    if not isinstance(ids, list):
        return []
    return [str(i) for i in ids]


def _summarize_report(report: dict[str, Any], run_name: str) -> str:
    findings = report.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    confirmed = [f for f in findings if isinstance(f, dict) and _classify_finding(f) == "confirmed"]
    suspected = len(findings) - len(confirmed)
    lines = [
        f"Run: {run_name}",
        f"Report: {RUNS_DIR / run_name / 'report.json'}",
        f"Findings: {len(findings)} total ({len(confirmed)} confirmed, {suspected} suspected)",
    ]
    summary = report.get("summary")
    if isinstance(summary, dict):
        by_sev = summary.get("by_severity")
        if isinstance(by_sev, dict):
            sev_str = ", ".join(f"{k}={v}" for k, v in by_sev.items())
            lines.append(f"By severity: {sev_str}")
    if confirmed:
        lines.append("Confirmed findings:")
        for f in confirmed[:10]:
            fid = f.get("id", "?")
            title = str(f.get("title", ""))[:120]
            sev = f.get("severity", "?")
            ev = ", ".join(_finding_evidence_ids(f)) or "none"
            lines.append(f"- [{sev}] {fid} {title} (evidence_ids: {ev})")
    return "\n".join(lines)


def _load_report(run_name: str) -> dict[str, Any]:
    run_dir = (RUNS_DIR / run_name).resolve()
    runs_root = RUNS_DIR.resolve()
    if run_dir.parent != runs_root:
        msg = f"Invalid run_name {run_name!r}: resolves outside {RUNS_DIR}/"
        raise ValueError(msg)
    report_path = run_dir / "report.json"
    if not report_path.is_file():
        msg = f"No report.json for run {run_name!r} (expected {report_path})"
        raise FileNotFoundError(msg)
    if report_path.stat().st_size > _REPORT_READ_CAP:
        msg = f"report.json for run {run_name!r} exceeds size cap"
        raise ValueError(msg)
    with report_path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        msg = f"report.json for run {run_name!r} is not a JSON object"
        raise TypeError(msg)
    return data


def _invoke_scan_pipeline(argv: list[str], env_overrides: dict[str, str]) -> int:
    """Run the CLI pipeline synchronously (called in a worker thread).

    Equivalent to ``exaai --target ... -n``; stdout is redirected to stderr so
    the MCP stdio channel is never polluted. Returns the process exit code
    semantics (0 = ok, 2 = ok with vulnerabilities found, 1 = failure).
    """
    import exaaiagnt.interface.main as main_module

    old_argv = sys.argv
    old_env: dict[str, str | None] = {}
    for key, value in env_overrides.items():
        old_env[key] = os.environ.get(key)
        os.environ[key] = value
    sys.argv = argv
    code = 0
    try:
        with contextlib.redirect_stdout(sys.stderr):
            try:
                main_module.main()
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    finally:
        sys.argv = old_argv
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return code


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def tool_exaai_run_scan(arguments: dict[str, Any]):  # noqa: PLR0911
    try:
        target = _validate_target(arguments.get("target"))
    except ValueError as exc:
        return _error(f"Invalid target: {exc}")

    allowed, reason = _targets_env_allows(target)
    if not allowed:
        return _error(reason)

    prompt_modules = arguments.get("prompt_modules")
    if prompt_modules is not None and not isinstance(prompt_modules, str):
        return _error("prompt_modules must be a comma-separated string")
    instruction = arguments.get("instruction")
    if instruction is not None and not isinstance(instruction, str):
        return _error("instruction must be a string")
    budget = arguments.get("budget_max_tokens")
    if budget is not None and (
        not isinstance(budget, int) or isinstance(budget, bool) or budget < 1
    ):
        return _error("budget_max_tokens must be a positive integer")

    run_name = _generate_run_name()
    argv = ["exaai", "--target", target, "-n", "--run-name", run_name]
    if prompt_modules and prompt_modules.strip():
        argv += ["--prompt-modules", prompt_modules.strip()]
    if instruction and instruction.strip():
        argv += ["--instruction", instruction]

    env_overrides: dict[str, str] = {}
    if budget is not None:
        env_overrides["EXAAI_MAX_SCAN_TOKENS"] = str(budget)

    logger.info("mcp exaai_run_scan: target=%s run_name=%s", target, run_name)
    try:
        code = await asyncio.to_thread(_invoke_scan_pipeline, argv, env_overrides)
    except Exception as exc:
        logger.exception("scan pipeline raised")
        return _error(f"Scan failed to run: {type(exc).__name__}: {exc}")

    if code not in (0, 2):
        return _error(
            f"Scan pipeline exited with code {code}. See stderr/logs for details. "
            f"Run name: {run_name}"
        )

    report_path = RUNS_DIR / run_name / "report.json"
    if not report_path.is_file():
        return _text_result(
            f"Scan finished (exit code {code}) but no report.json was found at "
            f"{report_path}. Findings may not have been reported. Run name: {run_name}"
        )
    try:
        report = _load_report(run_name)
    except Exception as exc:  # noqa: BLE001
        return _error(f"Scan finished but report.json could not be read: {exc}")
    return _text_result(_summarize_report(report, run_name))


async def tool_exaai_cve_lookup(arguments: dict[str, Any]):
    cve_id = arguments.get("cve_id")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return _error("cve_id must be a non-empty string (e.g. CVE-2024-1234)")
    cve_id = cve_id.strip().upper()
    if not _CVE_ID_RE.match(cve_id):
        return _error(f"Invalid cve_id format: {cve_id!r} (expected CVE-YYYY-NNNN...)")

    try:
        from exaaiagnt.tools.executor import execute_tool

        result = await execute_tool("cve_lookup", None, cve_id=cve_id)
    except Exception as exc:
        logger.exception("cve_lookup failed")
        return _error(f"cve_lookup failed: {type(exc).__name__}: {exc}")

    if not isinstance(result, dict):
        return _text_result(str(result))
    if not result.get("found"):
        return _error(f"{cve_id} not found in the pinned CVE knowledge base")
    record = result.get("record")
    return _text_result(json.dumps(record, indent=2, default=str))


async def tool_exaai_list_runs(arguments: dict[str, Any]):
    limit = arguments.get("limit", 5)
    if isinstance(limit, bool) or not isinstance(limit, int):
        return _error("limit must be an integer")
    if limit < 1:
        return _error("limit must be >= 1")
    limit = min(limit, 100)

    runs_root = RUNS_DIR
    if not runs_root.is_dir():
        return _text_result("No exaai_runs/ directory found (no runs yet).")
    try:
        entries = [p for p in runs_root.iterdir() if p.is_dir()]
    except OSError as exc:
        return _error(f"Could not list {runs_root}: {exc}")
    entries.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    lines = []
    for p in entries[:limit]:
        try:
            mtime = datetime.fromtimestamp(p.stat().st_mtime, UTC).isoformat()
        except OSError:
            mtime = "unknown"
        has_report = (p / "report.json").is_file()
        lines.append(f"{p.name}\tmtime={mtime}\treport.json={'yes' if has_report else 'no'}")
    if not lines:
        return _text_result("No runs found in exaai_runs/.")
    return _text_result("\n".join(lines))


async def tool_exaai_get_report(arguments: dict[str, Any]):
    run_name = arguments.get("run_name")
    if not isinstance(run_name, str) or not run_name:
        return _error("run_name must be a non-empty string")
    if not _RUN_NAME_RE.match(run_name):
        return _error(f"Invalid run_name {run_name!r}: must match ^[A-Za-z0-9_.-]+$")
    try:
        report = _load_report(run_name)
    except FileNotFoundError as exc:
        return _error(str(exc))
    except (ValueError, TypeError, json.JSONDecodeError, OSError) as exc:
        return _error(f"Could not read report for run {run_name!r}: {exc}")

    findings = report.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    confirmed = [f for f in findings if isinstance(f, dict) and _classify_finding(f) == "confirmed"]
    lines = [
        f"Run: {run_name}",
        f"Findings: {len(findings)} total "
        f"({len(confirmed)} confirmed, {len(findings) - len(confirmed)} suspected)",
    ]
    summary = report.get("summary")
    if isinstance(summary, dict):
        by_sev = summary.get("by_severity")
        if isinstance(by_sev, dict):
            lines.append("By severity: " + ", ".join(f"{k}={v}" for k, v in by_sev.items()))
    lines.append("Top findings:")
    for f in findings[:10]:
        if not isinstance(f, dict):
            continue
        fid = f.get("id", "?")
        title = str(f.get("title", ""))[:120]
        sev = f.get("severity", "?")
        ev = ", ".join(_finding_evidence_ids(f)) or "none"
        lines.append(f"- [{sev}] {fid} {title} (evidence_ids: {ev})")
    return _text_result("\n".join(lines))


_TOOL_HANDLERS = {
    "exaai_run_scan": tool_exaai_run_scan,
    "exaai_cve_lookup": tool_exaai_cve_lookup,
    "exaai_list_runs": tool_exaai_list_runs,
    "exaai_get_report": tool_exaai_get_report,
}


# ---------------------------------------------------------------------------
# MCP server wiring
# ---------------------------------------------------------------------------


def create_server():
    from mcp import types
    from mcp.server.lowlevel import Server

    server = Server(SERVER_NAME)

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=t["name"],
                description=t["description"],
                inputSchema=t["inputSchema"],
            )
            for t in list_registered_mcp_tools()
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any]):
        handler = _TOOL_HANDLERS.get(name)
        if handler is None:
            return _error(f"Unknown tool: {name}")
        try:
            return await handler(arguments or {})
        except Exception as exc:
            logger.exception("tool %s raised", name)
            return _error(f"Tool {name} failed: {type(exc).__name__}: {exc}")

    return server


async def run_mcp_server() -> None:
    from mcp.server.stdio import stdio_server

    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


_MCP_HELP = """\
usage: exaai mcp [--help]

Start the ExaAiAgent MCP (Model Context Protocol) stdio server.

  exaai mcp          Start the stdio server (blocks on stdio).
  exaai mcp --help   Show this help and exit 0 without starting the server.

Tools exposed: exaai_run_scan, exaai_cve_lookup, exaai_list_runs, exaai_get_report

Claude Desktop config example:
  { "mcpServers": { "exaai": { "command": "exaai", "args": ["mcp"] } } }
"""


def run_mcp_command(argv: list[str]) -> int:
    """Entry point for `exaai mcp`. Returns process exit code."""
    parser = argparse.ArgumentParser(
        prog="exaai mcp",
        description="Start the ExaAiAgent MCP stdio server.",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="store_true", help="Show help and exit")
    try:
        args, unknown = parser.parse_known_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    if args.help:
        sys.stdout.write(_MCP_HELP)
        return 0
    if unknown:
        sys.stderr.write(f"exaai mcp: unrecognized arguments: {' '.join(unknown)}\n\n")
        sys.stderr.write(_MCP_HELP)
        return 2
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger.info("starting exaai mcp stdio server")
    try:
        asyncio.run(run_mcp_server())
    except KeyboardInterrupt:
        logger.info("mcp server interrupted")
        return 130
    return 0


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(run_mcp_server())


if __name__ == "__main__":
    main()
