"""Badge definitions for the Contributor Achievement System.

Pure data. Evaluator functions live in ``engine.py`` and are keyed by badge
id. Points model (deterministic, idempotent):

* 50 points per merged PR event
* badge ``points`` are credited once per award (achievements are UNIQUE per
  (github_id, badge_id), so re-sync never double counts)
* 10 points per review event, 2 points per issue_comment event

Levels (total points): Novice 0, Contributor 100, Veteran 300,
Maintainer 600, Legend 1000.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Shared level thresholds: (level name, minimum points)
LEVELS: list[tuple[str, int]] = [
    ("Novice", 0),
    ("Contributor", 100),
    ("Veteran", 300),
    ("Maintainer", 600),
    ("Legend", 1000),
]


@dataclass(frozen=True)
class Badge:
    """A single achievement badge."""

    id: str
    name: str
    description: str
    icon: str
    color: str  # primary metal hex
    palette: dict[str, str]  # metallic palette: ring, light, dark, plate, ribbon, ribbon_edge
    points: int
    criteria: dict = field(default_factory=dict)  # machine-readable rule summary
    manual_only: bool = False

    @property
    def filename(self) -> str:
        return f"{self.id}.svg"


def _palette(
    ring: str, light: str, dark: str, plate: str, ribbon: str, edge: str
) -> dict[str, str]:
    return {
        "ring": ring,
        "light": light,
        "dark": dark,
        "plate": plate,
        "ribbon": ribbon,
        "ribbon_edge": edge,
    }


# Ordered list - display order everywhere (CLI, docs, export).
BADGES: list[Badge] = [
    Badge(
        id="first_contributor",
        name="First Contributor",
        description="Merged your first pull request into the repository.",
        icon="octocat",
        color="#CD7F32",
        palette=_palette("#CD7F32", "#F4C27A", "#8C4A1E", "#2A211B", "#3A2E24", "#CD7F32"),
        points=25,
        criteria={"kind": "pr_merged", "min": 1},
    ),
    Badge(
        id="code_contributor",
        name="Code Contributor",
        description="Merged at least one non-documentation pull request.",
        icon="code",
        color="#4FC3F7",
        palette=_palette("#4FC3F7", "#B3E5FC", "#1B6FA8", "#141E2A", "#152238", "#4FC3F7"),
        points=25,
        criteria={"kind": "pr_merged", "min": 1, "rule": "non_docs_pr"},
    ),
    Badge(
        id="bug_hunter",
        name="Bug Hunter",
        description=(
            "Merged a pull request labelled 'bug' or whose title matches "
            "fix/bug/hotfix/security fix/critical/cve."
        ),
        icon="bug",
        color="#FFD700",
        palette=_palette("#FFD700", "#FFF59D", "#A67C00", "#241F0A", "#332B07", "#FFD700"),
        points=25,
        criteria={
            "kind": "pr_merged",
            "min": 1,
            "rule": "bug_pr",
            "label": "bug",
            "title_regex": r"(?i)(fix|bug|hotfix|security fix|critical|cve)",
        },
    ),
    Badge(
        id="documentation_hero",
        name="Documentation Hero",
        description="Merged a pull request touching docs/** or *.md with no .py/.ts changes.",
        icon="book",
        color="#2E8B57",
        palette=_palette("#2E8B57", "#7BD3A2", "#17472B", "#12231A", "#17301F", "#2E8B57"),
        points=25,
        criteria={"kind": "pr_merged", "min": 1, "rule": "docs_only_pr"},
    ),
    Badge(
        id="feature_builder",
        name="Feature Builder",
        description="Merged a pull request adding new files or labelled 'feature'.",
        icon="rocket",
        color="#A855F7",
        palette=_palette("#A855F7", "#D8B4FE", "#5B21B6", "#1F1430", "#2A1B40", "#A855F7"),
        points=25,
        criteria={"kind": "pr_merged", "min": 1, "rule": "feature_pr", "label": "feature"},
    ),
    Badge(
        id="testing_champion",
        name="Testing Champion",
        description="Merged a pull request touching tests/**.",
        icon="flask",
        color="#22D3EE",
        palette=_palette("#22D3EE", "#A5F3FC", "#0E7490", "#0F2228", "#143038", "#22D3EE"),
        points=25,
        criteria={"kind": "pr_merged", "min": 1, "rule": "tests_pr"},
    ),
    Badge(
        id="top_contributor",
        name="Top Contributor",
        description="Merged at least 5 pull requests.",
        icon="crown",
        color="#EF4444",
        palette=_palette("#EF4444", "#FCA5A5", "#991B1B", "#2A1215", "#3B181C", "#EF4444"),
        points=100,
        criteria={"kind": "pr_merged", "min": 5},
    ),
    Badge(
        id="core_maintainer",
        name="Core Maintainer",
        description="Trusted with maintainer-level responsibility. Manual grant only.",
        icon="shield",
        color="#E5E7EB",
        palette=_palette("#E5E7EB", "#FFFFFF", "#6B7280", "#1E2126", "#2A2D33", "#E5E7EB"),
        points=150,
        criteria={"kind": "manual", "manual": True},
        manual_only=True,
    ),
    Badge(
        id="community_hero",
        name="Community Hero",
        description="Authored at least 5 PR reviews or issue comments.",
        icon="hands",
        color="#F472B6",
        palette=_palette("#F472B6", "#FBCFE8", "#9D174D", "#2A1420", "#3B1B2C", "#F472B6"),
        points=100,
        criteria={"kind": "review_or_comment", "min": 5},
    ),
    Badge(
        id="open_source_advocate",
        name="Open Source Advocate",
        description="At least 3 issue comments on other people's issues and at least 1 merged PR.",
        icon="megaphone",
        color="#D4AF37",
        palette=_palette("#D4AF37", "#F6E27A", "#7A6210", "#24210F", "#332F17", "#D4AF37"),
        points=75,
        criteria={
            "kind": "issue_comment",
            "min_others": 3,
            "requires": {"kind": "pr_merged", "min": 1},
        },
    ),
]

BADGES_BY_ID: dict[str, Badge] = {b.id: b for b in BADGES}

PR_POINTS = 50
REVIEW_POINTS = 10
COMMENT_POINTS = 2


def level_for_points(pts: int) -> str:
    """Return the level name for a total point value."""
    current = LEVELS[0][0]
    for name, threshold in LEVELS:
        if pts >= threshold:
            current = name
        else:
            break
    return current
