"""
Shared Memory Bus - Central memory store for inter-agent data sharing.
Prevents duplicated scanning and enables coordinated discovery.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from enum import Enum
from collections import defaultdict
import threading

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
    accessed_by: Set[str] = field(default_factory=set)
    access_count: int = 0
    ttl: Optional[float] = None  # Time-to-live in seconds


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
    
    def __new__(cls) -> "SharedMemory":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._data: Dict[DataCategory, Dict[str, MemoryEntry]] = defaultdict(dict)
        self._lock = threading.RLock()
        self._agent_permissions: Dict[str, Dict[DataCategory, AccessLevel]] = {}
        self._subscribers: Dict[DataCategory, List[callable]] = defaultdict(list)
        
        # Deduplication sets
        self._seen_urls: Set[str] = set()
        self._seen_endpoints: Set[str] = set()
        self._seen_params: Set[str] = set()
        
        self._initialized = True
        logger.info("SharedMemory initialized")
    
    def store(
        self,
        category: DataCategory,
        key: str,
        value: Any,
        source_agent: str,
        ttl: Optional[float] = None,
        deduplicate: bool = True
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
            
            # Deduplication check
            if deduplicate:
                dedup_key = f"{category.value}:{key}"
                if category == DataCategory.URLS:
                    if key in self._seen_urls:
                        return False
                    self._seen_urls.add(key)
                elif category == DataCategory.ENDPOINTS:
                    if key in self._seen_endpoints:
                        return False
                    self._seen_endpoints.add(key)
                elif category == DataCategory.PARAMETERS:
                    if key in self._seen_params:
                        return False
                    self._seen_params.add(key)
            
            # Store entry
            entry = MemoryEntry(
                key=key,
                value=value,
                category=category,
                source_agent=source_agent,
                ttl=ttl
            )
            self._data[category][key] = entry
            
            # Notify subscribers
            self._notify_subscribers(category, key, value)
            
            logger.debug(f"Stored {category.value}/{key} from {source_agent}")
            return True
    
    def retrieve(
        self,
        category: DataCategory,
        key: str,
        requester_agent: str
    ) -> Optional[Any]:
        """Retrieve data from shared memory."""
        with self._lock:
            if not self._has_read_permission(requester_agent, category):
                return None
            
            entry = self._data.get(category, {}).get(key)
            if entry is None:
                return None
            
            # Check TTL
            if entry.ttl and (time.time() - entry.timestamp > entry.ttl):
                del self._data[category][key]
                return None
            
            # Track access
            entry.accessed_by.add(requester_agent)
            entry.access_count += 1
            
            return entry.value
    
    def get_all(
        self,
        category: DataCategory,
        requester_agent: str,
        limit: int = 100
    ) -> List[MemoryEntry]:
        """Get all entries in a category."""
        with self._lock:
            if not self._has_read_permission(requester_agent, category):
                return []
            
            entries = list(self._data.get(category, {}).values())
            
            # Filter expired
            now = time.time()
            valid_entries = [
                e for e in entries
                if not e.ttl or (now - e.timestamp <= e.ttl)
            ]
            
            return valid_entries[:limit]
    
    def bulk_store_urls(
        self,
        urls: List[str],
        source_agent: str
    ) -> int:
        """Store multiple URLs with deduplication. Returns count of new URLs."""
        stored = 0
        for url in urls:
            if self.store(DataCategory.URLS, url, url, source_agent):
                stored += 1
        return stored
    
    def bulk_store_endpoints(
        self,
        endpoints: List[Dict[str, Any]],
        source_agent: str
    ) -> int:
        """Store multiple endpoints. Returns count of new endpoints."""
        stored = 0
        for endpoint in endpoints:
            key = f"{endpoint.get('method', 'GET')}:{endpoint.get('path', '')}"
            if self.store(DataCategory.ENDPOINTS, key, endpoint, source_agent):
                stored += 1
        return stored
    
    def get_unscanned_urls(self, requester_agent: str, limit: int = 50) -> List[str]:
        """Get URLs that haven't been scanned by this agent."""
        with self._lock:
            urls = []
            for key, entry in self._data.get(DataCategory.URLS, {}).items():
                if requester_agent not in entry.accessed_by:
                    urls.append(entry.value)
                    if len(urls) >= limit:
                        break
            return urls
    
    def set_agent_permissions(
        self,
        agent_id: str,
        permissions: Dict[DataCategory, AccessLevel]
    ) -> None:
        """Set permissions for an agent."""
        with self._lock:
            self._agent_permissions[agent_id] = permissions
    
    def grant_full_access(self, agent_id: str) -> None:
        """Grant full read/write access to all categories."""
        permissions = {cat: AccessLevel.READ_WRITE for cat in DataCategory}
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
    
    def subscribe(self, category: DataCategory, callback: callable) -> None:
        """Subscribe to updates in a category."""
        self._subscribers[category].append(callback)
    
    def _notify_subscribers(self, category: DataCategory, key: str, value: Any) -> None:
        """Notify subscribers of new data."""
        for callback in self._subscribers.get(category, []):
            try:
                callback(category, key, value)
            except Exception as e:
                logger.error(f"Subscriber callback error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        with self._lock:
            return {
                "urls": len(self._seen_urls),
                "endpoints": len(self._seen_endpoints),
                "parameters": len(self._seen_params),
                "total_entries": sum(len(d) for d in self._data.values()),
                "categories": {
                    cat.value: len(self._data.get(cat, {}))
                    for cat in DataCategory
                }
            }
    
    def clear(self) -> None:
        """Clear all shared memory."""
        with self._lock:
            self._data.clear()
            self._seen_urls.clear()
            self._seen_endpoints.clear()
            self._seen_params.clear()
            logger.info("SharedMemory cleared")


# Global instance
def get_shared_memory() -> SharedMemory:
    """Get the global SharedMemory instance."""
    return SharedMemory()


# Convenience functions
def store_url(url: str, source_agent: str) -> bool:
    """Store a URL in shared memory."""
    return get_shared_memory().store(DataCategory.URLS, url, url, source_agent)


def store_endpoint(endpoint: Dict, source_agent: str) -> bool:
    """Store an endpoint in shared memory."""
    key = f"{endpoint.get('method', 'GET')}:{endpoint.get('path', '')}"
    return get_shared_memory().store(DataCategory.ENDPOINTS, key, endpoint, source_agent)


def store_vulnerability(vuln_id: str, vuln_data: Dict, source_agent: str) -> bool:
    """Store a vulnerability finding."""
    return get_shared_memory().store(
        DataCategory.VULNERABILITIES, vuln_id, vuln_data, source_agent
    )
