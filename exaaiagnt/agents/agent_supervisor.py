"""
Agent Supervisor - Monitors and manages agent lifecycle.
Provides timeout detection, heartbeat monitoring, and self-healing capabilities.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Dict
from weakref import WeakValueDictionary

logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    """Agent lifecycle states."""
    INIT = "init"
    RUNNING = "running"
    WAITING = "waiting"
    PAUSED = "paused"
    TIMEOUT = "timeout"
    FAILED = "failed"
    RECOVERED = "recovered"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    BUDGET_EXCEEDED = "budget_exceeded"


class AgentPriority(Enum):
    """Agent priority levels."""
    HIGH = 3
    MEDIUM = 2
    LOW = 1


@dataclass
class AgentHealth:
    """Health status of an agent with priority and token tracking."""
    agent_id: str
    agent_name: str
    status: AgentStatus = AgentStatus.INIT
    priority: AgentPriority = AgentPriority.MEDIUM
    last_heartbeat: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    error_count: int = 0
    timeout_count: int = 0
    recovery_attempts: int = 0
    last_error: Optional[str] = None
    parent_id: Optional[str] = None
    # Token budget tracking
    token_budget: int = 200000  # Default 200k tokens
    token_used: int = 0
    # Cost tracking
    estimated_cost: float = 0.0


class AgentSupervisor:
    """
    Central supervisor for monitoring and managing agents.
    
    Features:
    - Heartbeat monitoring
    - Timeout detection
    - Automatic recovery
    - Agent restart/replacement
    - Self-healing mechanism
    - Priority-based scheduling
    - Token budget enforcement
    """
    
    # Configuration
    DEFAULT_TIMEOUT = 300  # 5 minutes
    HEARTBEAT_INTERVAL = 10  # seconds
    MAX_RECOVERY_ATTEMPTS = 3
    HEALTH_CHECK_INTERVAL = 5  # seconds
    
    _instance: Optional["AgentSupervisor"] = None
    
    def __new__(cls) -> "AgentSupervisor":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._agents: Dict[str, AgentHealth] = {}
        self._agent_instances: WeakValueDictionary = WeakValueDictionary()
        self._timeout_handlers: Dict[str, Callable] = {}
        self._recovery_handlers: Dict[str, Callable] = {}
        self._monitor_task: Optional[asyncio.Task] = None
        self._running = False
        self._callbacks: Dict[str, list] = {
            "on_timeout": [],
            "on_failure": [],
            "on_recovery": [],
            "on_status_change": [],
        }
        self._initialized = True
        logger.info("AgentSupervisor initialized")
    
    def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        agent_instance: Any = None,
        parent_id: Optional[str] = None,
        timeout: Optional[float] = None,
        priority: AgentPriority = AgentPriority.MEDIUM,
        token_budget: int = 200000
    ) -> None:
        """Register an agent for monitoring with priority and token budget."""
        health = AgentHealth(
            agent_id=agent_id,
            agent_name=agent_name,
            parent_id=parent_id,
            priority=priority,
            token_budget=token_budget,
        )
        self._agents[agent_id] = health
        
        if agent_instance:
            self._agent_instances[agent_id] = agent_instance
        
        if timeout:
            self._timeout_handlers[agent_id] = timeout
        
        logger.info(f"Registered agent: {agent_name} ({agent_id}) priority={priority.name}")
        self._notify_status_change(agent_id, AgentStatus.INIT, AgentStatus.RUNNING)
    
    def set_priority(self, agent_id: str, priority: AgentPriority) -> None:
        """Change agent priority."""
        if agent_id in self._agents:
            self._agents[agent_id].priority = priority
            logger.info(f"Agent {agent_id} priority set to {priority.name}")
    
    def record_tokens(self, agent_id: str, tokens: int) -> bool:
        """Record token usage. Returns False if budget exceeded."""
        if agent_id not in self._agents:
            return True
        
        health = self._agents[agent_id]
        health.token_used += tokens
        
        # Check budget
        if health.token_used > health.token_budget:
            logger.warning(f"Agent {agent_id} exceeded token budget: {health.token_used}/{health.token_budget}")
            old_status = health.status
            health.status = AgentStatus.BUDGET_EXCEEDED
            self._notify_status_change(agent_id, old_status, AgentStatus.BUDGET_EXCEEDED)
            return False
        
        return True
    
    def get_token_usage(self, agent_id: str) -> Dict[str, int]:
        """Get token usage for an agent."""
        if agent_id in self._agents:
            health = self._agents[agent_id]
            return {
                "used": health.token_used,
                "budget": health.token_budget,
                "remaining": health.token_budget - health.token_used
            }
        return {"used": 0, "budget": 0, "remaining": 0}
    
    def pause_agent(self, agent_id: str) -> bool:
        """Pause an agent."""
        if agent_id in self._agents:
            health = self._agents[agent_id]
            if health.status == AgentStatus.RUNNING:
                old_status = health.status
                health.status = AgentStatus.PAUSED
                self._notify_status_change(agent_id, old_status, AgentStatus.PAUSED)
                logger.info(f"Paused agent {agent_id}")
                return True
        return False
    
    def resume_agent(self, agent_id: str) -> bool:
        """Resume a paused agent."""
        if agent_id in self._agents:
            health = self._agents[agent_id]
            if health.status == AgentStatus.PAUSED:
                health.status = AgentStatus.RUNNING
                health.last_activity = time.time()
                self._notify_status_change(agent_id, AgentStatus.PAUSED, AgentStatus.RUNNING)
                logger.info(f"Resumed agent {agent_id}")
                return True
        return False
    
    def get_agents_by_priority(self) -> Dict[AgentPriority, list]:
        """Get agents grouped by priority."""
        result = {p: [] for p in AgentPriority}
        for agent_id, health in self._agents.items():
            result[health.priority].append(agent_id)
        return result
    
    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent from monitoring."""
        if agent_id in self._agents:
            del self._agents[agent_id]
        if agent_id in self._timeout_handlers:
            del self._timeout_handlers[agent_id]
        if agent_id in self._recovery_handlers:
            del self._recovery_handlers[agent_id]
        logger.info(f"Unregistered agent: {agent_id}")
    
    def heartbeat(self, agent_id: str) -> None:
        """Record a heartbeat from an agent."""
        if agent_id in self._agents:
            now = time.time()
            health = self._agents[agent_id]
            health.last_heartbeat = now
            health.last_activity = now
            
            # Reset error count on successful heartbeat
            if health.status == AgentStatus.TIMEOUT:
                health.status = AgentStatus.RECOVERED
                health.recovery_attempts = 0
                self._notify_status_change(agent_id, AgentStatus.TIMEOUT, AgentStatus.RECOVERED)
    
    def record_activity(self, agent_id: str) -> None:
        """Record activity from an agent (tool execution, message, etc.)."""
        if agent_id in self._agents:
            self._agents[agent_id].last_activity = time.time()
    
    def record_error(self, agent_id: str, error: str) -> None:
        """Record an error for an agent."""
        if agent_id in self._agents:
            health = self._agents[agent_id]
            health.error_count += 1
            health.last_error = error
            health.last_activity = time.time()
            
            if health.error_count >= 3:
                old_status = health.status
                health.status = AgentStatus.FAILED
                self._notify_status_change(agent_id, old_status, AgentStatus.FAILED)
    
    def update_status(self, agent_id: str, status: AgentStatus) -> None:
        """Update agent status."""
        if agent_id in self._agents:
            old_status = self._agents[agent_id].status
            self._agents[agent_id].status = status
            self._agents[agent_id].last_activity = time.time()
            self._notify_status_change(agent_id, old_status, status)
    
    def get_health(self, agent_id: str) -> Optional[AgentHealth]:
        """Get health status of an agent."""
        return self._agents.get(agent_id)
    
    def get_all_health(self) -> Dict[str, AgentHealth]:
        """Get health status of all agents."""
        return dict(self._agents)
    
    def get_stuck_agents(self, threshold: float = None) -> list[str]:
        """Get list of agents that appear stuck (no activity)."""
        threshold = threshold or self.DEFAULT_TIMEOUT
        now = time.time()
        stuck = []
        
        for agent_id, health in self._agents.items():
            if health.status in [AgentStatus.COMPLETED, AgentStatus.CANCELLED]:
                continue
            
            inactive_time = now - health.last_activity
            if inactive_time > threshold:
                stuck.append(agent_id)
        
        return stuck
    
    def on_callback(self, event: str, callback: Callable) -> None:
        """Register a callback for events."""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def _notify_status_change(
        self, agent_id: str, old_status: AgentStatus, new_status: AgentStatus
    ) -> None:
        """Notify callbacks of status change."""
        for callback in self._callbacks.get("on_status_change", []):
            try:
                callback(agent_id, old_status, new_status)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    async def start_monitoring(self) -> None:
        """Start the monitoring loop."""
        if self._running:
            return
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Agent monitoring started")
    
    async def stop_monitoring(self) -> None:
        """Stop the monitoring loop."""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Agent monitoring stopped")
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                await self._check_agent_health()
                await asyncio.sleep(self.HEALTH_CHECK_INTERVAL)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(1)
    
    async def _check_agent_health(self) -> None:
        """Check health of all agents."""
        now = time.time()
        
        for agent_id, health in list(self._agents.items()):
            if health.status in [AgentStatus.COMPLETED, AgentStatus.CANCELLED]:
                continue
            
            timeout = self._timeout_handlers.get(agent_id, self.DEFAULT_TIMEOUT)
            inactive_time = now - health.last_activity
            
            if inactive_time > timeout and health.status != AgentStatus.TIMEOUT:
                logger.warning(
                    f"Agent {health.agent_name} ({agent_id}) timed out "
                    f"after {inactive_time:.0f}s of inactivity"
                )
                
                old_status = health.status
                health.status = AgentStatus.TIMEOUT
                health.timeout_count += 1
                
                self._notify_status_change(agent_id, old_status, AgentStatus.TIMEOUT)
                
                # Trigger timeout callbacks
                for callback in self._callbacks.get("on_timeout", []):
                    try:
                        callback(agent_id, health)
                    except Exception as e:
                        logger.error(f"Timeout callback error: {e}")
                
                # Attempt recovery
                await self._attempt_recovery(agent_id, health)
    
    async def _attempt_recovery(self, agent_id: str, health: AgentHealth) -> bool:
        """Attempt to recover a timed-out agent."""
        if health.recovery_attempts >= self.MAX_RECOVERY_ATTEMPTS:
            logger.error(
                f"Agent {health.agent_name} ({agent_id}) exceeded max recovery attempts"
            )
            health.status = AgentStatus.FAILED
            
            for callback in self._callbacks.get("on_failure", []):
                try:
                    callback(agent_id, health)
                except Exception as e:
                    logger.error(f"Failure callback error: {e}")
            
            return False
        
        health.recovery_attempts += 1
        logger.info(
            f"Attempting recovery for {health.agent_name} "
            f"(attempt {health.recovery_attempts}/{self.MAX_RECOVERY_ATTEMPTS})"
        )
        
        # Check if agent instance is available for recovery
        agent = self._agent_instances.get(agent_id)
        if agent:
            try:
                # Send recovery signal
                if hasattr(agent, "state") and hasattr(agent.state, "resume_from_waiting"):
                    agent.state.resume_from_waiting()
                    health.status = AgentStatus.RECOVERED
                    health.last_activity = time.time()
                    
                    for callback in self._callbacks.get("on_recovery", []):
                        try:
                            callback(agent_id, health)
                        except Exception as e:
                            logger.error(f"Recovery callback error: {e}")
                    
                    return True
            except Exception as e:
                logger.error(f"Recovery failed for {agent_id}: {e}")
                health.last_error = str(e)
        
        return False
    
    async def force_timeout(self, agent_id: str) -> None:
        """Force a timeout on an agent (for testing or manual intervention)."""
        if agent_id in self._agents:
            health = self._agents[agent_id]
            health.last_activity = 0  # Force timeout on next check
            await self._check_agent_health()
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get a summary of all agent statuses."""
        summary = {
            "total": len(self._agents),
            "running": 0,
            "waiting": 0,
            "timeout": 0,
            "failed": 0,
            "completed": 0,
        }
        
        for health in self._agents.values():
            status_key = health.status.value
            if status_key in summary:
                summary[status_key] += 1
        
        return summary


# Global supervisor instance
def get_supervisor() -> AgentSupervisor:
    """Get the global AgentSupervisor instance."""
    return AgentSupervisor()


# Async context manager for agent monitoring
class MonitoredAgent:
    """Context manager for monitoring an agent with automatic timeout."""
    
    def __init__(
        self,
        agent_id: str,
        agent_name: str,
        timeout: float = AgentSupervisor.DEFAULT_TIMEOUT,
        on_timeout: Optional[Callable] = None
    ):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.timeout = timeout
        self.on_timeout = on_timeout
        self._supervisor = get_supervisor()
    
    async def __aenter__(self):
        self._supervisor.register_agent(
            self.agent_id,
            self.agent_name,
            timeout=self.timeout
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._supervisor.update_status(
            self.agent_id,
            AgentStatus.COMPLETED if exc_type is None else AgentStatus.FAILED
        )
        self._supervisor.unregister_agent(self.agent_id)
    
    def heartbeat(self):
        self._supervisor.heartbeat(self.agent_id)
    
    def activity(self):
        self._supervisor.record_activity(self.agent_id)
