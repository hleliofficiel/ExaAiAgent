# Contributor Achievement System

Recognize and reward people who contribute to ExaAiAgent — automatically,
from public GitHub activity, with a local, deterministic evaluator. Badges
are shown on a dedicated contributors page (dashboard) and can be embedded in
GitHub profile READMEs. **Badges are not shown on the dashboard main page.**

## How it works

1. `exaai contributors sync` reads public GitHub API data (merged PRs, PR
   reviews, issue comments) for the repo and stores normalized events in a
   local SQLite database.
2. A deterministic engine evaluates badge criteria from stored events and
   awards achievements (`source='auto'`). Manual grants are stored with
   `source='manual'` and are never revoked by a re-sync.
3. `exaai contributors` CLI exposes list/profile/sync/grant/revoke/badges/export.

## Badge list & criteria

| Badge | Color | Points | Criteria (deterministic) |
| --- | --- | --- | --- |
| First Contributor | Copper `#CD7F32` | 25 | ≥ 1 merged PR |
| Code Contributor | Blue/Silver `#4FC3F7` | 25 | ≥ 1 merged non-docs PR |
| Bug Hunter | Gold `#FFD700` | 25 | ≥ 1 merged PR labelled `bug`, or title matching `(?i)(fix|bug|hotfix|security fix|critical|cve)` |
| Documentation Hero | Emerald `#2E8B57` | 25 | ≥ 1 merged PR touching `docs/**` or `*.md` with no `.py`/`.ts` changes |
| Feature Builder | Purple `#A855F7` | 25 | ≥ 1 merged PR adding new files or labelled `feature` |
| Testing Champion | Cyan `#22D3EE` | 25 | ≥ 1 merged PR touching `tests/**` |
| Top Contributor | Red `#EF4444` | 100 | ≥ 5 merged PRs |
| Core Maintainer | Platinum `#E5E7EB` | 150 | **Manual grant only** |
| Community Hero | Rose `#F472B6` | 100 | ≥ 5 PR reviews or issue comments authored |
| Open Source Advocate | Lime/Anthracite gold `#D4AF37` | 75 | ≥ 3 issue comments on others' issues + ≥ 1 merged PR |

"Bug Hunter" title regex is applied case-insensitively to the PR title.
"Docs-only" requires every changed file to be under `docs/` or end in a
Markdown/RST/TXT-like doc extension **and** at least one such file, with no
`.py`/`.ts` files in the PR. If GitHub returns no file metadata for a merged
PR, it is conservatively counted as a *code* PR (not docs-only).

## Levels (points)

| Level | Points |
| --- | --- |
| Novice | 0 |
| Contributor | 100 |
| Veteran | 300 |
| Maintainer | 600 |
| Legend | 1000 |

Points model (deterministic, idempotent):

* 50 points per merged PR
* points of each awarded badge (credited once — achievements are unique per
  `(github_id, badge_id)`)
* 10 points per PR review
* 2 points per issue comment

## Data storage

SQLite, stdlib `sqlite3`, WAL mode, foreign keys ON:

1. `$EXAAI_DATA_DIR/contributors.db` (override; used by tests)
2. `$XDG_DATA_HOME/exaai-agent/contributors.db`
3. `~/.local/share/exaai-agent/contributors.db`

Schema: `contributors`, `events` (UNIQUE per `(github_id, kind, ref)`),
`achievements` (PK `(github_id, badge_id)`), `meta`. Anti-manipulation:
events come only from the GitHub API, PRs must be merged, and one row exists
per `(user, kind, ref)`. `verified_at` stamps when the event was synced.
Re-syncs are idempotent upserts. **Sync never revokes achievements.**

## GitHub API setup

Public data only; no private repositories are accessed.

```bash
export EXAAI_GITHUB_TOKEN=ghp_...   # or GH_TOKEN
```

* Token is read from the environment, never printed, never written to disk.
* Without a token the client falls back to the unauthenticated public API
  (60 req/h); rate-limit hits (HTTP 403/429) surface a clear notice and the
  sync completes best-effort with whatever was fetched.
* API client: stdlib `urllib`, 4s timeout, UA `ExaAiAgent-Contributors/3.1.1`.

## CLI usage

```bash
exaai contributors list [--repo owner/name]
exaai contributors profile <login>
exaai contributors sync [--repo owner/name] [--user login] [--since YYYY-MM-DD] [--update]
exaai contributors grant <login> <badge_id> [--reason "..."] [--by admin]
exaai contributors revoke <login> <badge_id> [--reason "..."]
exaai contributors badges
exaai contributors export <login>   # ready-to-paste profile README Markdown
```

Default repo: `hleliofficiel/ExaAiAgent`.

## Embedding in a profile README

```bash
exaai contributors export <your-login> >> README.md
```

or directly:

```html
<img src="https://github.com/hleliofficiel/ExaAiAgent/raw/main/contributor_system/badges/bug_hunter.svg" width="128" alt="Bug Hunter" />
```

Only badges you have actually earned are emitted by `export`. Badge SVGs are
hand-written vector files with transparent backgrounds — no JPGs, no external
assets.

## Roadmap

* Dashboard dedicated `/contributors` page (in progress, frontend agent)
* Per-release leaderboard snapshot (`meta` table)
* Optional signed badge attestations
* GitHub Action to auto-sync on merged PRs
