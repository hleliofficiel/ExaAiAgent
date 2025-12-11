"""
Scan Modes - Operational modes for different scanning intensities.
Supports Stealth, Standard, and Aggressive modes.
"""

import os
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ScanMode(Enum):
    """Available scanning modes."""
    STEALTH = "stealth"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


@dataclass
class ModeConfig:
    """Configuration for a scan mode."""
    name: str
    description: str
    
    # Request limits
    max_requests_per_minute: int
    max_concurrent_requests: int
    request_delay_ms: int
    
    # Token limits
    max_tokens_per_agent: int
    max_total_tokens: int
    
    # Behavior
    enable_fuzzing: bool
    enable_exploitation: bool
    enable_poc: bool
    max_payloads_per_param: int
    
    # Safety
    respect_robots_txt: bool
    avoid_logout_endpoints: bool
    avoid_destructive_actions: bool
    
    # Tools
    allowed_tools: list
    blocked_tools: list


# Predefined mode configurations
MODE_CONFIGS: Dict[ScanMode, ModeConfig] = {
    ScanMode.STEALTH: ModeConfig(
        name="Stealth",
        description="Minimal requests, safe for production, low token usage",
        max_requests_per_minute=10,
        max_concurrent_requests=1,
        request_delay_ms=3000,
        max_tokens_per_agent=50000,
        max_total_tokens=200000,
        enable_fuzzing=False,
        enable_exploitation=False,
        enable_poc=False,
        max_payloads_per_param=3,
        respect_robots_txt=True,
        avoid_logout_endpoints=True,
        avoid_destructive_actions=True,
        allowed_tools=["browser_action", "terminal_execute", "web_search"],
        blocked_tools=["nuclei", "sqlmap", "ffuf"],
    ),
    
    ScanMode.STANDARD: ModeConfig(
        name="Standard",
        description="Moderate fuzzing, safe for bug bounty programs",
        max_requests_per_minute=60,
        max_concurrent_requests=3,
        request_delay_ms=500,
        max_tokens_per_agent=200000,
        max_total_tokens=1000000,
        enable_fuzzing=True,
        enable_exploitation=False,
        enable_poc=True,
        max_payloads_per_param=20,
        respect_robots_txt=False,
        avoid_logout_endpoints=True,
        avoid_destructive_actions=True,
        allowed_tools=[],  # All allowed
        blocked_tools=[],
    ),
    
    ScanMode.AGGRESSIVE: ModeConfig(
        name="Aggressive",
        description="Deep exploitation, full PoC development, maximum coverage",
        max_requests_per_minute=300,
        max_concurrent_requests=10,
        request_delay_ms=100,
        max_tokens_per_agent=500000,
        max_total_tokens=5000000,
        enable_fuzzing=True,
        enable_exploitation=True,
        enable_poc=True,
        max_payloads_per_param=100,
        respect_robots_txt=False,
        avoid_logout_endpoints=False,
        avoid_destructive_actions=False,
        allowed_tools=[],
        blocked_tools=[],
    ),
}


class ScanModeManager:
    """
    Manages scan modes and enforces restrictions.
    """
    
    _instance: Optional["ScanModeManager"] = None
    
    def __new__(cls) -> "ScanModeManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        # Default mode from environment or STANDARD
        mode_env = os.getenv("EXAAI_SCAN_MODE", "standard").lower()
        try:
            self._current_mode = ScanMode(mode_env)
        except ValueError:
            self._current_mode = ScanMode.STANDARD
        
        self._config = MODE_CONFIGS[self._current_mode]
        self._request_count = 0
        self._token_usage: Dict[str, int] = {}
        self._total_tokens = 0
        
        self._initialized = True
        logger.info(f"ScanModeManager initialized in {self._current_mode.value} mode")
    
    @property
    def mode(self) -> ScanMode:
        return self._current_mode
    
    @property
    def config(self) -> ModeConfig:
        return self._config
    
    def set_mode(self, mode: ScanMode) -> None:
        """Change the current scan mode."""
        self._current_mode = mode
        self._config = MODE_CONFIGS[mode]
        logger.info(f"Scan mode changed to {mode.value}")
    
    def can_fuzz(self) -> bool:
        """Check if fuzzing is allowed."""
        return self._config.enable_fuzzing
    
    def can_exploit(self) -> bool:
        """Check if exploitation is allowed."""
        return self._config.enable_exploitation
    
    def can_poc(self) -> bool:
        """Check if PoC development is allowed."""
        return self._config.enable_poc
    
    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed in current mode."""
        if self._config.blocked_tools and tool_name in self._config.blocked_tools:
            return False
        if self._config.allowed_tools and tool_name not in self._config.allowed_tools:
            return False
        return True
    
    def get_request_delay(self) -> float:
        """Get delay between requests in seconds."""
        return self._config.request_delay_ms / 1000.0
    
    def get_max_payloads(self) -> int:
        """Get max payloads per parameter."""
        return self._config.max_payloads_per_param
    
    def check_agent_token_budget(self, agent_id: str, tokens_to_use: int) -> bool:
        """Check if agent can use more tokens."""
        current = self._token_usage.get(agent_id, 0)
        if current + tokens_to_use > self._config.max_tokens_per_agent:
            logger.warning(f"Agent {agent_id} would exceed token budget")
            return False
        return True
    
    def check_total_token_budget(self, tokens_to_use: int) -> bool:
        """Check if total token budget allows more usage."""
        if self._total_tokens + tokens_to_use > self._config.max_total_tokens:
            logger.warning("Total token budget would be exceeded")
            return False
        return True
    
    def record_token_usage(self, agent_id: str, tokens: int) -> None:
        """Record token usage for an agent."""
        self._token_usage[agent_id] = self._token_usage.get(agent_id, 0) + tokens
        self._total_tokens += tokens
    
    def get_agent_token_usage(self, agent_id: str) -> int:
        """Get token usage for an agent."""
        return self._token_usage.get(agent_id, 0)
    
    def get_total_token_usage(self) -> int:
        """Get total token usage."""
        return self._total_tokens
    
    def get_mode_prompt_context(self) -> str:
        """Get context string to add to prompts based on mode."""
        if self._current_mode == ScanMode.STEALTH:
            return """
STEALTH MODE ACTIVE:
- Minimize requests
- No active fuzzing
- No exploitation attempts
- Focus on passive reconnaissance
- Report findings without verification
"""
        elif self._current_mode == ScanMode.STANDARD:
            return """
STANDARD MODE ACTIVE:
- Moderate fuzzing allowed
- No destructive actions
- Develop safe PoCs only
- Avoid logout endpoints
- Standard bug bounty rules apply
"""
        else:  # AGGRESSIVE
            return """
AGGRESSIVE MODE ACTIVE:
- Full fuzzing enabled
- Exploitation allowed
- Deep PoC development
- Maximum coverage
- Push boundaries aggressively
"""
    
    def get_stats(self) -> Dict[str, Any]:
        """Get mode statistics."""
        return {
            "mode": self._current_mode.value,
            "total_tokens": self._total_tokens,
            "token_budget": self._config.max_total_tokens,
            "agents": dict(self._token_usage),
        }


# Global instance
def get_scan_mode_manager() -> ScanModeManager:
    """Get the global ScanModeManager instance."""
    return ScanModeManager()


def get_current_mode() -> ScanMode:
    """Get the current scan mode."""
    return get_scan_mode_manager().mode


def is_stealth() -> bool:
    """Check if in stealth mode."""
    return get_current_mode() == ScanMode.STEALTH


def is_aggressive() -> bool:
    """Check if in aggressive mode."""
    return get_current_mode() == ScanMode.AGGRESSIVE
