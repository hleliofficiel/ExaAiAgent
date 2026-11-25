"""
Shared Memory Bus - Central memory store for inter-agent data sharing.
Prevents duplicated scanning and enables coordinated discovery.
"""

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from collections.abc import Callable
from typing import Any, Optional


logger = logging.getLogger(__name__)


class DataCategory(Enum):
    """Categories of shared data."""

    URLS = "urls"
    ENDPOINTS = "endpoints"
    PARAMETERS = "parameters"
    SUBDOMAINS = "subdomains"
    IDOR_LEADS = "idor_leads"
    VULNERABILITIES = "vulnerabilities"
    CREDENTIALS = "credentials"
    TOKENS = "tokens"
    HEADERS = "headers"
    COOKIES = "cookies"
    TECHNOLOGIES = "technologies"
    SCAN_RESULTS = "scan_results"


class AccessLevel(Enum):
    """Access permission levels."""

    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"


@dataclass
class MemoryEntry:
    """Single entry in shared memory."""

    key: str
    value: Any
    category: DataCategory
    source_agent: str
    timestamp: float = field(default_factory=time.time)
    accessed_by: set[str] = field(default_factory=set)
    access_count: int = 0
    ttl: float | None = None  # Time-to-live in seconds


class SharedMemory:
    """
    Global memory bus for inter-agent communication.

    Features:
    - Categorized data storage
    - Read/write access control
    - Deduplication
    - TTL support
    - Access tracking
    """

    _instance: Optional["SharedMemory"] = None
    _instance_lock = threading.Lock()

    # Per-category cap so a long scan cannot grow memory without bound.
    MAX_ENTRIES_PER_CATEGORY = 5000

    def __new__(cls) -> "SharedMemory":
        with cls._instance_lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._initialized = False
                cls._instance = inst
        return cls._instance

    def __init__(self):
        with self._instance_lock:
            if self._initialized:
                return
            self._init_state()

    def _init_state(self) -> None:
        self._data: dict[DataCategory, dict[str, MemoryEntry]] = defaultdict(dict)
        self._lock = threading.RLock()
        self._agent_permissions: dict[str, dict[DataCategory, AccessLevel]] = {}
        self._subscribers: dict[DataCategory, list[Callable[..., Any]]] = defaultdict(list)
        self._scanned: dict[str, set[str]] = defaultdict(set)

        # Deduplication sets
        self._seen_urls: set[str] = set()
        self._seen_endpoints: set[str] = set()
        self._seen_params: set[str] = set()

        self._initialized = True
        logger.info("SharedMemory initialized")

    def store(
        self,
        category: DataCategory,
        key: str,
        value: Any,
        source_agent: str,
        ttl: float | None = None,
        deduplicate: bool = True,
    ) -> bool:
        """
        Store data in shared memory.

        Returns True if stored, False if duplicate.
        """
        with self._lock:
            # Check permissions
            if not self._has_write_permission(source_agent, category):
                logger.warning(f"Agent {source_agent} lacks write permission for {category}")
                return False

            # Deduplication check: based on live (non-expired) entries so an
            # expired or evicted key can be stored again.
            existing = self._data[category].get(key)
            if existing is not None and self._is_expired(existing):
                self._remove(category, key)
                existing = None
            if deduplicate and existing is not None and category in self._DEDUP_CATEGORIES:
                return False

            # Store entry
            entry = MemoryEntry(
                key=key, value=value, category=category, source_agent=source_agent, ttl=ttl
            )
            self._data[category][key] = entry
            if category in self._DEDUP_CATEGORIES:
                self._seen_set(category).add(key)
            self._evict_if_needed(category)

            # Notify subscribers
            self._notify_subscribers(category, key, value)

            logger.debug(f"Stored {category.value}/{key} from {source_agent}")
            return True

    _DEDUP_CATEGORIES = frozenset(
        {DataCategory.URLS, DataCategory.ENDPOINTS, DataCategory.PARAMETERS}
    )

    @staticmethod
    def _is_expired(entry: MemoryEntry, now: float | None = None) -> bool:
        if not entry.ttl:
            return False
        return (now if now is not None else time.time()) - entry.timestamp > entry.ttl

    def _seen_set(self, category: DataCategory) -> set[str]:
        return {
            DataCategory.URLS: self._seen_urls,
            DataCategory.ENDPOINTS: self._seen_endpoints,
            DataCategory.PARAMETERS: self._seen_params,
        }[category]

    def _remove(self, category: DataCategory, key: str) -> None:
        self._data[category].pop(key, None)
        if category in self._DEDUP_CATEGORIES:
            self._seen_set(category).discard(key)

    def _evict_if_needed(self, category: DataCategory) -> None:
        bucket = self._data[category]
        overflow = len(bucket) - self.MAX_ENTRIES_PER_CATEGORY
        if overflow <= 0:
            return
        # Drop expired first, then the oldest entries.
        now = time.time()
        for k in [k for k, e in bucket.items() if self._is_expired(e, now)]:
            self._remove(category, k)
        overflow = len(bucket) - self.MAX_ENTRIES_PER_CATEGORY
        if overflow > 0:
            for k in sorted(bucket, key=lambda k: bucket[k].timestamp)[:overflow]:
                self._remove(category, k)

    def purge_expired(self) -> int:
        """Remove all expired entries. Returns how many were removed."""
        removed = 0
        with self._lock:
            now = time.time()
            for category in list(self._data):
                for k in [k for k, e in self._data[category].items() if self._is_expired(e, now)]:
                    self._remove(category, k)
                    removed += 1
        return removed

    def retrieve(self, category: DataCategory, key: str, requester_agent: str) -> Any | None:
        """Retrieve data from shared memory."""
        with self._lock:
            if not self._has_read_permission(requester_agent, category):
                return None

            entry = self._data.get(category, {}).get(key)
            if entry is None:
                return None

            # Check TTL
            if self._is_expired(entry):
                self._remove(category, key)
                return None

            # Track access
            entry.accessed_by.add(requester_agent)
            entry.access_count += 1

            return entry.value

    def get_all(
        self, category: DataCategory, requester_agent: str, limit: int = 100
    ) -> list[MemoryEntry]:
        """Get all entries in a category."""
        with self._lock:
            if not self._has_read_permission(requester_agent, category):
                return []

            now = time.time()
            for k in [k for k, e in self._data.get(category, {}).items() if self._is_expired(e, now)]:
                self._remove(category, k)

            return list(self._data.get(category, {}).values())[: max(limit, 0)]

    def bulk_store_urls(self, urls: list[str], source_agent: str) -> int:
        """Store multiple URLs with deduplication. Returns count of new URLs."""
        stored = 0
        for url in urls:
            if self.store(DataCategory.URLS, url, url, source_agent):
                stored += 1
        return stored

    def bulk_store_endpoints(self, endpoints: list[dict[str, Any]], source_agent: str) -> int:
        """Store multiple endpoints. Returns count of new endpoints."""
        stored = 0
        for endpoint in endpoints:
            key = f"{endpoint.get('method', 'GET')}:{endpoint.get('path', '')}"
            if self.store(DataCategory.ENDPOINTS, key, endpoint, source_agent):
                stored += 1
        return stored

    def get_unscanned_urls(self, requester_agent: str, limit: int = 50) -> list[str]:
        """Get live URLs this agent has not yet marked as scanned."""
        with self._lock:
            if not self._has_read_permission(requester_agent, DataCategory.URLS):
                return []
            now = time.time()
            done = self._scanned[requester_agent]
            urls: list[str] = []
            for entry in self._data.get(DataCategory.URLS, {}).values():
                if self._is_expired(entry, now) or entry.key in done:
                    continue
                urls.append(entry.value)
                if len(urls) >= limit:
                    break
            return urls

    def mark_scanned(self, url: str, requester_agent: str) -> None:
        """Mark a URL as scanned by this agent so it is not handed out again."""
        with self._lock:
            self._scanned[requester_agent].add(url)

    def claim_unscanned_urls(self, requester_agent: str, limit: int = 50) -> list[str]:
        """Atomically fetch and mark URLs so two agents never get the same one."""
        with self._lock:
            claimed: list[str] = []
            all_agents = set(self._scanned)
            all_agents.add(requester_agent)
            for url in self.get_unscanned_urls(requester_agent, limit * 4):
                if any(url in self._scanned[a] for a in all_agents):
                    continue
                self._scanned[requester_agent].add(url)
                claimed.append(url)
                if len(claimed) >= limit:
                    break
            return claimed

    def set_agent_permissions(
        self, agent_id: str, permissions: dict[DataCategory, AccessLevel]
    ) -> None:
        """Set permissions for an agent."""
        with self._lock:
            self._agent_permissions[agent_id] = permissions

    def grant_full_access(self, agent_id: str) -> None:
        """Grant full read/write access to all categories."""
        permissions = dict.fromkeys(DataCategory, AccessLevel.READ_WRITE)
        self.set_agent_permissions(agent_id, permissions)

    def _has_read_permission(self, agent_id: str, category: DataCategory) -> bool:
        """Check if agent has read permission."""
        if agent_id not in self._agent_permissions:
            return True  # Default allow for backward compatibility

        level = self._agent_permissions[agent_id].get(category)
        return level in [AccessLevel.READ, AccessLevel.READ_WRITE]

    def _has_write_permission(self, agent_id: str, category: DataCategory) -> bool:
        """Check if agent has write permission."""
        if agent_id not in self._agent_permissions:
            return True

        level = self._agent_permissions[agent_id].get(category)
        return level in [AccessLevel.WRITE, AccessLevel.READ_WRITE]

    def subscribe(self, category: DataCategory, callback: Callable[..., Any]) -> None:
        """Subscribe to updates in a category."""
        with self._lock:
            self._subscribers[category].append(callback)

    def _notify_subscribers(self, category: DataCategory, key: str, value: Any) -> None:
        """Notify subscribers of new data."""
        for callback in list(self._subscribers.get(category, [])):
            try:
                callback(category, key, value)
            except Exception as e:
                logger.exception(f"Subscriber callback error: {e}")

    def get_stats(self) -> dict[str, Any]:
        """Get memory statistics."""
        with self._lock:
            return {
                "urls": len(self._data.get(DataCategory.URLS, {})),
                "endpoints": len(self._data.get(DataCategory.ENDPOINTS, {})),
                "parameters": len(self._data.get(DataCategory.PARAMETERS, {})),
                "total_entries": sum(len(d) for d in self._data.values()),
                "categories": {cat.value: len(self._data.get(cat, {})) for cat in DataCategory},
            }

    def clear(self) -> None:
        """Clear all shared memory."""
        with self._lock:
            self._data.clear()
            self._seen_urls.clear()
            self._seen_endpoints.clear()
            self._seen_params.clear()
            self._scanned.clear()
            logger.info("SharedMemory cleared")


# Global instance
def get_shared_memory() -> SharedMemory:
    """Get the global SharedMemory instance."""
    return SharedMemory()


# Convenience functions
def store_url(url: str, source_agent: str) -> bool:
    """Store a URL in shared memory."""
    return get_shared_memory().store(DataCategory.URLS, url, url, source_agent)


def store_endpoint(endpoint: dict, source_agent: str) -> bool:
    """Store an endpoint in shared memory."""
    key = f"{endpoint.get('method', 'GET')}:{endpoint.get('path', '')}"
    return get_shared_memory().store(DataCategory.ENDPOINTS, key, endpoint, source_agent)


def store_vulnerability(vuln_id: str, vuln_data: dict, source_agent: str) -> bool:
    """Store a vulnerability finding."""
    return get_shared_memory().store(DataCategory.VULNERABILITIES, vuln_id, vuln_data, source_agent)
