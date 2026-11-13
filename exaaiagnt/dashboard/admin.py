"""Helpers for the dashboard admin API.

Covers provider discovery from the environment, a cached PyPI update check,
the dashboard audit log (JSONL, never secrets), an atomic .env writer with
timestamped backup, and the full-run zip export builder.
"""

import contextlib
import io
import json
import logging
import os
import shutil
import tempfile
import time
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from exaaiagnt import version as _version


logger = logging.getLogger(__name__)

ENV_ALLOWLIST = [
    "EXAAI_LLM_PROVIDER",
    "LITELLM_MODEL",
    "LLM_API_KEY",
    "LLM_API_BASE",
    "OPENAI_API_KEY",
    "OPENAI_API_BASE",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "OPENROUTER_API_BASE",
    "OLLAMA_API_BASE",
    "AZURE_API_KEY",
    "AZURE_API_BASE",
]

_PYPI_URL = "https://pypi.org/pypi/exaai-agent/json"
_PYPI_PAGE = "https://pypi.org/project/exaai-agent/"
_UPDATE_CACHE_TTL = 6 * 3600  # 6h
_update_cache: dict = {"expires": 0.0, "latest": None, "update_available": None, "checked_at": None}

_EXPORT_FILES = ["report.json", "report.sarif", "report.csv", "report.html", "report.md"]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def masked_key(key: str | None) -> str | None:
    """Return a last-4-only masked rendering of a key, or None. Never the full key."""
    if not key:
        return None
    tail = key[-4:]
    head = key[:3] if len(key) > 7 else ""
    return f"{head}…{tail}"


def base_host(url: str | None) -> str | None:
    """Return scheme://host[:port] for a URL, or None. Strips path and any userinfo."""
    if not url:
        return None
    try:
        parsed = urlsplit(url if "://" in url else f"https://{url}")
    except ValueError:
        return None
    host = parsed.hostname
    if not host:
        return None
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    scheme = parsed.scheme or "https"
    return f"{scheme}://{netloc}"


def _provider_specs() -> list[dict]:
    """Static spec table for known providers. Keys/bases come from env at call time."""
    return [
        {
            "name": "openai",
            "key_envs": ["OPENAI_API_KEY"],
            "base_env": "OPENAI_API_BASE",
            "default_base": "https://api.openai.com/v1",
            "models_path": "/models",
            "auth": True,
        },
        {
            "name": "anthropic",
            "key_envs": ["ANTHROPIC_API_KEY"],
            "base_env": None,
            "default_base": "https://api.anthropic.com",
            "models_path": "/v1/models",
            "auth": True,
        },
        {
            "name": "gemini",
            "key_envs": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
            "base_env": None,
            "default_base": "https://generativelanguage.googleapis.com/v1beta",
            "models_path": "/models",
            "auth": True,
        },
        {
            "name": "openrouter",
            "key_envs": ["OPENROUTER_API_KEY"],
            "base_env": "OPENROUTER_API_BASE",
            "default_base": "https://openrouter.ai/api/v1",
            "models_path": "/models",
            "auth": True,
        },
        {
            "name": "ollama",
            "key_envs": [],
            "base_env": "OLLAMA_API_BASE",
            "default_base": "http://localhost:11434",
            "models_path": "/api/tags",
            "auth": False,
        },
        {
            "name": "azure",
            "key_envs": ["AZURE_API_KEY"],
            "base_env": "AZURE_API_BASE",
            "default_base": None,  # AZURE_API_BASE only, no sane default
            "models_path": "/models",
            "auth": True,
        },
        {
            "name": "litellm",
            "key_envs": ["LLM_API_KEY"],
            "base_env": "LLM_API_BASE",
            "default_base": "http://localhost:4000",
            "models_path": "/models",
            "auth": True,
        },
    ]


def _first_env(names: list[str]) -> tuple[str | None, str | None]:
    """Return (env_name, value) for the first set env var in names."""
    for name in names:
        value = os.getenv(name)
        if value:
            return name, value
    return None, None


def active_provider() -> str | None:
    provider = os.getenv("EXAAI_LLM_PROVIDER", "").strip().lower()
    if provider:
        return provider
    if os.getenv("LLM_API_KEY"):
        return "litellm"
    return None


def discover_providers() -> dict:
    """Build the GET /api/providers payload from the environment. Never returns key values."""
    active = active_provider()
    model = os.getenv("LITELLM_MODEL") or None
    providers = []
    for spec in _provider_specs():
        key_env, key = _first_env(spec["key_envs"])
        base_env = spec["base_env"]
        base_val = os.getenv(base_env) if base_env else None
        base = base_host(base_val) or base_host(spec["default_base"])
        configured = bool(key) or bool(base_val)
        if spec["name"] == "ollama":
            configured = bool(base_val)
        source = key_env or (base_env if base_val else None)
        providers.append(
            {
                "name": spec["name"],
                "configured": configured,
                "masked_key": masked_key(key),
                "base": base,
                "source": source,
                "active": active == spec["name"],
            }
        )
    return {"active": {"provider": active, "model": model}, "providers": providers}


def _sanitize_detail(detail: str, secrets: list[str | None]) -> str:
    for secret in secrets:
        if secret and secret in detail:
            detail = detail.replace(secret, "***")
    return detail[:300]


def test_provider(provider: str) -> dict:
    """Probe a provider's models endpoint. Never raises; never leaks key bytes."""
    name = (provider or "").strip().lower()
    spec = next((s for s in _provider_specs() if s["name"] == name), None)
    if spec is None:
        return {"ok": False, "latency_ms": None, "detail": f"unknown provider: {name or 'empty'}"}

    base_env = spec["base_env"]
    base = (os.getenv(base_env) if base_env else None) or spec["default_base"]
    if not base:
        return {"ok": False, "latency_ms": None, "detail": f"{base_env} not configured"}
    _, key = _first_env(spec["key_envs"])
    url = base.rstrip("/") + spec["models_path"]
    if urlsplit(url).scheme not in ("http", "https"):
        return {"ok": False, "latency_ms": None, "detail": "unsupported base URL scheme"}

    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    req = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 - fixed https/http URLs
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:  # noqa: S310  # nosec B310 - scheme validated above
            status = getattr(resp, "status", 200)
            resp.read(1024)
        latency_ms = int((time.monotonic() - start) * 1000)
        ok = 200 <= int(status) < 400
        detail = f"HTTP {status} from {base_host(base) or 'provider'}"
        return {
            "ok": ok,
            "latency_ms": latency_ms,
            "detail": _sanitize_detail(detail, [key]),
        }
    except Exception as exc:  # noqa: BLE001 - reachability probe must not raise
        latency_ms = int((time.monotonic() - start) * 1000)
        detail = _sanitize_detail(f"{type(exc).__name__}: {exc}", [key])
        return {"ok": False, "latency_ms": latency_ms, "detail": detail}


def _version_tuple(text: str) -> tuple[int, ...]:
    parts = []
    for chunk in str(text).strip().lstrip("vV").split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _fetch_pypi_latest() -> str | None:
    req = urllib.request.Request(  # noqa: S310 - fixed PyPI URL
        _PYPI_URL, headers={"Accept": "application/json"}, method="GET"
    )
    with urllib.request.urlopen(req, timeout=4) as resp:  # noqa: S310  # nosec B310 - fixed PyPI https URL
        data = json.loads(resp.read().decode("utf-8"))
    latest = data.get("info", {}).get("version")
    return str(latest) if latest else None


def get_update_status() -> dict:
    """Return update status dict. 6h module-level cache; errors degrade to nulls, never raise."""
    now = time.time()
    current = _version.__version__
    if _update_cache["checked_at"] and now < _update_cache["expires"]:
        return {
            "current": current,
            "latest": _update_cache["latest"],
            "update_available": _update_cache["update_available"],
            "url": _PYPI_PAGE,
            "checked_at": _update_cache["checked_at"],
            "cached": True,
        }

    checked_at = _now_iso()
    latest: str | None = None
    update_available: bool | None = None
    try:
        latest = _fetch_pypi_latest()
        if latest:
            update_available = _version_tuple(latest) > _version_tuple(current)
    except Exception as exc:  # noqa: BLE001 - update check must never break the dashboard
        logger.warning("PyPI update check failed: %s", type(exc).__name__)
        latest = None
        update_available = None

    _update_cache.update(
        {
            "expires": now + _UPDATE_CACHE_TTL,
            "latest": latest,
            "update_available": update_available,
            "checked_at": checked_at,
        }
    )
    return {
        "current": current,
        "latest": latest,
        "update_available": update_available,
        "url": _PYPI_PAGE,
        "checked_at": checked_at,
        "cached": False,
    }


def reset_update_cache() -> None:
    """Test hook: clear the 6h update cache."""
    _update_cache.update(
        {"expires": 0.0, "latest": None, "update_available": None, "checked_at": None}
    )


def audit_path(cwd: Path | None = None) -> Path:
    return Path(cwd or Path.cwd()) / "exaai_runs" / "_dashboard_audit.jsonl"


def append_audit(action: str, detail: str, cwd: Path | None = None) -> None:
    """Append one audit entry. Callers must pass secret-free details."""
    path = audit_path(cwd)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"ts": _now_iso(), "action": action, "detail": str(detail)[:500]}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=True) + "\n")


def read_audit(limit: int = 20, cwd: Path | None = None) -> list[dict]:
    limit = max(1, min(int(limit), 100))
    path = audit_path(cwd)
    if not path.is_file():
        return []
    entries: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for raw in lines[-limit * 4:]:  # tolerate a few malformed lines near the tail
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "ts" in obj and "action" in obj:
            entries.append(
                {"ts": obj.get("ts"), "action": obj.get("action"), "detail": obj.get("detail")}
            )
    return entries[-limit:]


def write_env_var(key: str, value: str, cwd: Path | None = None) -> Path | None:
    """Atomically set key=value in <cwd>/.env, backing up any original first.

    Returns the backup path (or None when no prior .env existed). chmod 0600.
    Raises ValueError for disallowed keys or values containing newlines.
    """
    if key not in ENV_ALLOWLIST:
        raise ValueError(f"key not in allowlist: {key}")
    if "\n" in value or "\r" in value:
        raise ValueError("value must not contain newlines")

    root = Path(cwd or Path.cwd())
    env_path = root / ".env"

    backup_path: Path | None = None
    if env_path.is_file():
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup_path = root / f".env.bak-{ts}"
        shutil.copy2(env_path, backup_path)
        with contextlib.suppress(OSError):
            backup_path.chmod(0o600)

    existing_lines: list[str] = []
    if env_path.is_file():
        existing_lines = env_path.read_text(encoding="utf-8").splitlines()

    new_line = f"{key}={value}"
    replaced = False
    out_lines: list[str] = []
    for line in existing_lines:
        stripped = line.strip()
        candidate = stripped[7:] if stripped.startswith("export ") else stripped
        name = candidate.split("=", 1)[0].strip() if "=" in candidate else None
        if name == key and not replaced:
            out_lines.append(new_line)
            replaced = True
        else:
            out_lines.append(line)
    if not replaced:
        out_lines.append(new_line)

    content = "\n".join(out_lines) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".env.", suffix=".tmp", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        Path(tmp_name).chmod(0o600)
        Path(tmp_name).replace(env_path)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(tmp_name).unlink()
        raise
    return backup_path


def build_full_export(run_dir: Path, run_name: str) -> tuple[bytes, list[str]] | None:
    """Build an in-memory zip of the run's report files + manifest.json.

    Returns (zip_bytes, files_included) or None when no report files exist.
    """
    existing = [name for name in _EXPORT_FILES if (run_dir / name).is_file()]
    if not existing:
        return None
    manifest = {
        "run_name": run_name,
        "generated_at": _now_iso(),
        "files": list(existing),
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in existing:
            zf.write(run_dir / name, arcname=name)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
    return buffer.getvalue(), existing
