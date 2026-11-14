# ruff: noqa: S310 - fixed https api.github.com URLs only, best-effort with 4s timeout
"""GitHub public-API client for the Contributor Achievement System.

Stdlib urllib only (same style as exaaiagnt/intelligence/feeds.py).
4s timeout, UA ``ExaAiAgent-Contributors/3.1.1``. Token from
``EXAAI_GITHUB_TOKEN`` else ``GH_TOKEN``; never printed, never returned,
never written to disk. Unauthenticated public API fallback with a clear
rate-limit notice (403/429 -> RateLimitError surfaced, sync best-effort).
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor


API = "https://api.github.com"
DEFAULT_REPO = "hleliofficiel/ExaAiAgent"
UA = "ExaAiAgent-Contributors/3.1.1"
TIMEOUT = 6
RETRIES = 3


class RateLimitError(RuntimeError):
    """GitHub API rate limit / abuse detection hit (403 or 429)."""


class GitHubError(RuntimeError):
    """Generic GitHub API failure."""


def _token() -> str | None:
    return os.environ.get("EXAAI_GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None


def has_token() -> bool:
    return bool(_token())


def _get_json(url: str, timeout: int = TIMEOUT):
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    tok = _token()
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(url, headers=headers)
    last_error: Exception | None = None
    # Intermittent networks: retry transient transport failures with a small backoff.
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - fixed https api.github.com URLs only
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):  # rate limit / abuse detection
                raise RateLimitError(
                    f"GitHub API rate limit hit (HTTP {e.code}). "
                    "Set EXAAI_GITHUB_TOKEN (or GH_TOKEN) for a higher limit; sync is best-effort."
                ) from e
            raise GitHubError(f"GitHub API error HTTP {e.code} for {url}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            last_error = e
            if attempt + 1 < RETRIES:
                time.sleep(1.5 * (attempt + 1))
    raise GitHubError(f"GitHub API unreachable after {RETRIES} attempts for {url}: {last_error}") from last_error


def _paginate(url: str, limit: int, timeout: int = TIMEOUT) -> list[dict]:
    out: list[dict] = []
    page = 1
    sep = "&" if "?" in url else "?"
    while len(out) < limit:
        chunk = _get_json(f"{url}{sep}per_page=100&page={page}", timeout=timeout)
        if not isinstance(chunk, list) or not chunk:
            break
        out.extend(chunk)
        if len(chunk) < 100:
            break
        page += 1
    return out[:limit]


def get_user(login: str) -> dict:
    data = _get_json(f"{API}/users/{urllib.parse.quote(login)}")
    return {
        "github_id": int(data["id"]),
        "login": data.get("login", login),
        "name": data.get("name"),
        "avatar_url": data.get("avatar_url"),
        "profile_url": data.get("html_url"),
    }


def _pr_files(repo: str, number: int, timeout: int = TIMEOUT) -> list[dict]:
    try:
        files = _get_json(f"{API}/repos/{repo}/pulls/{number}/files?per_page=100", timeout=timeout)
    except GitHubError:
        return []
    if not isinstance(files, list):
        return []
    return [{"filename": f.get("filename", ""), "status": f.get("status", "")} for f in files]


def fetch_merged_prs(
    repo: str = DEFAULT_REPO, since: str | None = None, limit: int = 300
) -> list[dict]:
    """Return merged PRs (public repo). Each: number,title,labels,url,merged_at,author,files."""
    q = f"repo:{repo} is:pr is:merged"
    if since:
        q += f" merged:>={since}"
    url = f"{API}/search/issues?q={urllib.parse.quote(q)}&sort=created&order=desc"
    data = _get_json(url)
    items = data.get("items", []) if isinstance(data, dict) else []
    # Fetch PR file lists in parallel (bounded): latency dominates serial syncs.
    numbers = [it.get("number") for it in items[:limit]]
    files_map: dict[int, list[dict]] = {}
    if any(n is not None for n in numbers):
        with ThreadPoolExecutor(max_workers=8) as pool:
            for number, files in zip(
                numbers,
                pool.map(lambda n: _pr_files(repo, n) if n is not None else [], numbers),
            ):
                files_map[number] = files
    out: list[dict] = []
    for it in items[:limit]:
        number = it.get("number")
        labels = [lbl.get("name", "") for lbl in it.get("labels", [])]
        files = files_map.get(number, []) if number is not None else []
        user = it.get("user") or {}
        out.append(
            {
                "number": number,
                "title": it.get("title") or "",
                "labels": labels,
                "url": it.get("pull_request", {}).get("html_url") or it.get("html_url"),
                "merged_at": it.get("closed_at"),
                "author": user.get("login"),
                "author_id": user.get("id"),
                "files": files,
            }
        )
    return out


def fetch_reviews(
    repo: str = DEFAULT_REPO, user: str = "", limit: int = 100, scan: int = 50
) -> list[dict]:
    """Return formal PR reviews authored by ``user`` (public repo).

    GitHub has no global "reviews by user" endpoint, so we scan the most
    recent merged PRs (bounded by ``scan``) and collect reviews by ``user``.
    """
    q = f"repo:{repo} is:pr is:merged"
    url = f"{API}/search/issues?q={urllib.parse.quote(q)}&sort=created&order=desc"
    data = _get_json(url)
    items = (data.get("items", []) if isinstance(data, dict) else [])[:scan]
    out: list[dict] = []
    for it in items:
        if len(out) >= limit:
            break
        number = it.get("number")
        if number is None:
            continue
        try:
            reviews = _get_json(f"{API}/repos/{repo}/pulls/{number}/reviews?per_page=100")
        except GitHubError:
            continue
        if not isinstance(reviews, list):
            continue
        for r in reviews:
            author = (r.get("user") or {}).get("login", "")
            if user and author.lower() != user.lower():
                continue
            out.append(
                {
                    "ref": f"review:{r.get('id')}",
                    "title": (r.get("body") or "")[:200],
                    "url": r.get("html_url"),
                    "created_at": r.get("submitted_at"),
                }
            )
    return out[:limit]


def fetch_issue_comments(repo: str = DEFAULT_REPO, user: str = "", limit: int = 100) -> list[dict]:
    """Return issue comments authored by ``user`` on the repo (public repo only).

    ``on_others`` is resolved best-effort by fetching the parent issue once per
    distinct issue (public data). Failures degrade to False.
    """
    url = f"{API}/repos/{repo}/issues/comments?sort=created&direction=desc"
    comments = _paginate(url, limit * 3)
    user_comments = [
        c for c in comments if (c.get("user") or {}).get("login", "").lower() == user.lower()
    ][:limit]
    issue_author_cache: dict[str, str | None] = {}

    def _issue_author(issue_url: str) -> str | None:
        if issue_url not in issue_author_cache:
            try:
                data = _get_json(issue_url)
                issue_author_cache[issue_url] = (data.get("user") or {}).get("login")
            except GitHubError:
                issue_author_cache[issue_url] = None
        return issue_author_cache[issue_url]

    out: list[dict] = []
    for c in user_comments:
        issue_url = c.get("issue_url", "")
        author = _issue_author(issue_url) if issue_url else None
        issue_number = issue_url.rstrip("/").rsplit("/", 1)[-1] if issue_url else str(c.get("id"))
        out.append(
            {
                "ref": f"issue:{issue_number}#comment-{c.get('id')}",
                "title": (c.get("body") or "")[:200],
                "url": c.get("html_url"),
                "created_at": c.get("created_at"),
                "on_others": bool(author) and author.lower() != user.lower(),
            }
        )
    return out
