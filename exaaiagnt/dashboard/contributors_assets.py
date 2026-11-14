"""In-process SVG badge-card generator for the public /contributors/badge route.

Cards are small, self-contained SVGs (dark plate, badge artwork nested from the
repo's contributor_system/badges/<id>.svg, name + public GitHub login + wordmark).
Results are cached in an in-process dict; no network, no PII beyond the login.
"""

from __future__ import annotations

import re
from pathlib import Path

from exaaiagnt.contributors import badges as badge_defs

_REPO_ROOT = Path(__file__).resolve().parents[2]
BADGES_DIR = _REPO_ROOT / "contributor_system" / "badges"

_cache: dict[tuple[str, str], str] = {}

_SVG_OPEN_RE = re.compile(r"<svg[^>]*>", re.DOTALL)
_SVG_CLOSE_RE = re.compile(r"</svg>\s*$", re.DOTALL)


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _badge_inner(badge_id: str) -> tuple[str, str]:
    """Return (inner_svg_markup, viewBox) for a badge artwork file."""
    path = BADGES_DIR / f"{badge_id}.svg"
    raw = path.read_text(encoding="utf-8")
    m = _SVG_OPEN_RE.search(raw)
    viewbox = "0 0 512 640"
    if m:
        vb = re.search(r'viewBox="([^"]+)"', m.group(0))
        if vb:
            viewbox = vb.group(1)
    inner = _SVG_OPEN_RE.sub("", raw, count=1)
    inner = _SVG_CLOSE_RE.sub("", inner)
    return inner, viewbox


def render_badge_card(login: str, badge_id: str) -> str | None:
    """Render a cached SVG card, or None if the badge id is unknown."""
    badge = badge_defs.BADGES_BY_ID.get(badge_id)
    if badge is None:
        return None
    key = (login.lower(), badge_id)
    cached = _cache.get(key)
    if cached is not None:
        return cached
    try:
        inner, viewbox = _badge_inner(badge_id)
    except OSError:
        return None
    palette = badge.palette
    ring = palette.get("ring", badge.color)
    plate = palette.get("plate", "#141E2A")
    safe_login = _esc(login)
    safe_name = _esc(badge.name)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="340" height="150" viewBox="0 0 340 150" role="img" aria-label="{safe_login} - {safe_name} - ExaAiAgent">
  <rect x="1" y="1" width="338" height="148" rx="14" fill="{plate}" stroke="{ring}" stroke-width="2.5"/>
  <g transform="translate(18,13)">
    <svg x="0" y="0" width="99" height="124" viewBox="{viewbox}">{inner}</svg>
  </g>
  <text x="132" y="62" font-family="system-ui,-apple-system,'Segoe UI',sans-serif" font-size="17" font-weight="700" fill="#E2E8F0">{safe_name}</text>
  <text x="132" y="86" font-family="system-ui,-apple-system,'Segoe UI',sans-serif" font-size="12" fill="#8CA0BD">@{safe_login}</text>
  <text x="132" y="112" font-family="system-ui,-apple-system,'Segoe UI',sans-serif" font-size="10" letter-spacing="2" fill="{ring}">EXAAIAGENT</text>
</svg>
"""
    _cache[key] = svg
    return svg
