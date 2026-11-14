"""Contributor Achievement System for ExaAiAgent.

Badge definitions, a local SQLite store, a GitHub public-API client and a
deterministic evaluation engine. No network listener lives here - this is a
CLI + DB only package. Tokens are read from the environment, never printed
and never persisted by this code.
"""

from exaaiagnt.contributors.badges import BADGES, LEVELS, Badge
from exaaiagnt.contributors.engine import (
    SyncReport,
    evaluate,
    grant,
    level,
    points,
    profile,
    revoke,
    sync,
)


__all__ = [
    "BADGES",
    "LEVELS",
    "Badge",
    "SyncReport",
    "evaluate",
    "grant",
    "level",
    "points",
    "profile",
    "revoke",
    "sync",
]

__version__ = "3.1.1"
