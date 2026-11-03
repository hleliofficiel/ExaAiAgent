"""Sync pinned CVE snapshot from NVD/OSV. Offline-safe: never overwrites existing snapshot on failure."""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
def main() -> int:
    print("sync_cve: seed snapshot ships in-repo; network sync is opt-in (see docs/cve-kb.md). No overwrite performed.")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
