"""
Adaptive LLM Traffic Controller - Intelligent rate limiting and queue management.

Features:
- Single LLM request at a time (serialized)
- Non-blocking queue for waiting agents
- Automatic rate limit detection and delay
- Tool-first execution mode
- Automatic recovery with smart retry
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from collections import deque


logger = logging.getLogger(__name__)


class RequestPriority(Enum):
    """Priority levels for LLM requests."""
    CRITICAL = 3  # Must execute ASAP (auth, security critical)
    NORMAL = 2    # Standard agent requests
    LOW = 1       # Background tasks, summaries


@dataclass
class QueuedRequest:
    """A queued LLM request with metadata."""
    request_id: str
    agent_id: str
    priority: RequestPriority
    request_func: Callable
    args: tuple
    kwargs: dict
    created_at: float = field(default_factory=time.time)
    future: asyncio.Future = field(default_factory=lambda: asyncio.get_event_loop().create_future())


class AdaptiveLLMController:
    """
    Adaptive Multi-Agent LLM Traffic Controller.
    
    Implements:
    1. Single concurrent LLM request (serialized calls)
    2. Non-blocking queue for agents
    3. Intelligent throttling with adaptive delays
    4. Tool-first execution mode
    5. Automatic recovery from rate limits
    """
    
    _instance: Optional["AdaptiveLLMController"] = None
    
    def __new__(cls) -> "AdaptiveLLMController":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        # Core state
        self._queue: deque[QueuedRequest] = deque()
        self._is_processing = False
        self._lock = asyncio.Lock()
        
        # Rate limiting state
        self._last_request_time = 0.0
        self._consecutive_rate_limits = 0
        self._base_delay = 4.0  # Base delay between requests
        self._current_delay = 4.0
        self._max_delay = 30.0
        
        # Statistics
        self._total_requests = 0
        self._successful_requests = 0
        self._rate_limit_hits = 0
        self._retries = 0
        
        # Tool execution mode
        self._tool_executing = False
        self._tool_execution_lock = asyncio.Lock()
        
        # Configuration
        self._max_retries = 10  # Increased for Gemini
        self._rate_limit_wait = 15.0  # Longer wait after rate limit
        self._enable_verbose_logging = False
        
        self._initialized = True
        logger.info("AdaptiveLLMController initialized - Traffic Control Enabled")
    
    async def queue_request(
        self,
        request_func: Callable,
        *args,
        agent_id: str = "unknown",
        priority: RequestPriority = RequestPriority.NORMAL,
        **kwargs
    ) -> Any:
        """
        Queue an LLM request and wait for result.
        
        Non-blocking for the caller - they just await the result.
        Internally, requests are processed one at a time.
        """
        request_id = f"{agent_id}_{int(time.time() * 1000)}"
        
        # Create future for this request
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        
        queued = QueuedRequest(
            request_id=request_id,
            agent_id=agent_id,
            priority=priority,
            request_func=request_func,
            args=args,
            kwargs=kwargs,
            future=future
        )
        
        # Add to queue
        async with self._lock:
            # Insert by priority
            if priority == RequestPriority.CRITICAL:
                self._queue.appendleft(queued)
            else:
                self._queue.append(queued)
            
            queue_size = len(self._queue)
            if queue_size > 1 and not self._enable_verbose_logging:
                logger.debug(f"Request queued: {request_id}, queue size: {queue_size}")
        
        # Start processing if not already running
        asyncio.create_task(self._process_queue())
        
        # Wait for result
        return await future
    
    async def _process_queue(self):
        """Process queued requests one at a time."""
        async with self._lock:
            if self._is_processing:
                return
            self._is_processing = True
        
        try:
            while True:
                # Get next request
                async with self._lock:
                    if not self._queue:
                        break
                    request = self._queue.popleft()
                
                # Wait if tool is executing
                if self._tool_executing:
                    async with self._tool_execution_lock:
                        pass  # Wait for tool to finish
                
                # Execute request with rate limiting
                await self._execute_request(request)
                
        finally:
            async with self._lock:
                self._is_processing = False
    
    async def _execute_request(self, request: QueuedRequest):
        """Execute a single request with rate limiting and retry."""
        self._total_requests += 1
        
        # Adaptive delay
        await self._apply_rate_limit_delay()
        
        # Try request with retry
        last_error = None
        for attempt in range(self._max_retries + 1):
            try:
                # Execute the request
                result = await self._call_with_timeout(
                    request.request_func,
                    *request.args,
                    **request.kwargs
                )
                
                # Success!
                self._successful_requests += 1
                self._consecutive_rate_limits = 0
                self._current_delay = self._base_delay  # Reset delay
                
                request.future.set_result(result)
                return
                
            except Exception as e:
                last_error = e
                error_str = str(e).lower()
                
                # Check for rate limit
                if "rate" in error_str and "limit" in error_str:
                    self._rate_limit_hits += 1
                    self._consecutive_rate_limits += 1
                    self._retries += 1
                    
                    # Increase delay exponentially
                    self._current_delay = min(
                        self._current_delay * 1.5,
                        self._max_delay
                    )
                    
                    if attempt < self._max_retries:
                        wait_time = self._rate_limit_wait * (attempt + 1)
                        logger.warning(
                            f"Rate limit hit (attempt {attempt + 1}/{self._max_retries + 1}), "
                            f"waiting {wait_time}s before retry"
                        )
                        await asyncio.sleep(wait_time)
                        continue
                
                # Other errors - log and continue to next attempt
                if attempt < self._max_retries:
                    logger.warning(f"Request failed (attempt {attempt + 1}): {e}")
                    self._retries += 1
                    await asyncio.sleep(2.0 * (attempt + 1))
                    continue
        
        # All retries failed
        request.future.set_exception(last_error or Exception("Request failed"))
    
    async def _call_with_timeout(self, func: Callable, *args, **kwargs) -> Any:
        """Call function with timeout."""
        timeout = kwargs.pop('timeout', 300)
        
        if asyncio.iscoroutinefunction(func):
            return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
        else:
            # Run sync function in thread
            loop = asyncio.get_event_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(None, lambda: func(*args, **kwargs)),
                timeout=timeout
            )
    
    async def _apply_rate_limit_delay(self):
        """Apply intelligent rate limiting delay."""
        now = time.time()
        time_since_last = now - self._last_request_time
        
        # Calculate required delay
        required_delay = self._current_delay - time_since_last
        
        if required_delay > 0:
            # Add jitter to prevent thundering herd
            jitter = required_delay * 0.1 * (0.5 - asyncio.get_event_loop().time() % 1)
            total_delay = max(0, required_delay + jitter)
            
            if total_delay > 0.5 and not self._enable_verbose_logging:
                logger.debug(f"Rate limiting: waiting {total_delay:.2f}s")
            
            await asyncio.sleep(total_delay)
        
        self._last_request_time = time.time()
    
    # Tool execution mode
    async def enter_tool_mode(self):
        """Enter tool-first execution mode - pause LLM calls."""
        await self._tool_execution_lock.acquire()
        self._tool_executing = True
    
    async def exit_tool_mode(self):
        """Exit tool mode - resume LLM calls."""
        self._tool_executing = False
        if self._tool_execution_lock.locked():
            self._tool_execution_lock.release()
    
    def is_tool_executing(self) -> bool:
        """Check if tool is currently executing."""
        return self._tool_executing
    
    # Statistics
    def get_stats(self) -> dict[str, Any]:
        """Get traffic controller statistics."""
        return {
            "total_requests": self._total_requests,
            "successful_requests": self._successful_requests,
            "rate_limit_hits": self._rate_limit_hits,
            "retries": self._retries,
            "queue_size": len(self._queue),
            "current_delay": self._current_delay,
            "consecutive_rate_limits": self._consecutive_rate_limits,
            "is_processing": self._is_processing,
            "tool_executing": self._tool_executing,
        }
    
    def reset_stats(self):
        """Reset statistics."""
        self._total_requests = 0
        self._successful_requests = 0
        self._rate_limit_hits = 0
        self._retries = 0
    
    def set_base_delay(self, delay: float):
        """Set base delay between requests."""
        self._base_delay = delay
        self._current_delay = delay
    
    def set_verbose(self, enabled: bool):
        """Enable/disable verbose logging."""
        self._enable_verbose_logging = enabled


# Global instance
_controller: Optional[AdaptiveLLMController] = None


def get_traffic_controller() -> AdaptiveLLMController:
    """Get or create the global traffic controller."""
    global _controller
    if _controller is None:
        _controller = AdaptiveLLMController()
    return _controller


def reset_traffic_controller():
    """Reset the global traffic controller."""
    global _controller
    _controller = None


# Convenience decorator for LLM requests
def with_traffic_control(priority: RequestPriority = RequestPriority.NORMAL):
    """Decorator to route LLM requests through traffic controller."""
    def decorator(func: Callable):
        async def wrapper(*args, agent_id: str = "unknown", **kwargs):
            controller = get_traffic_controller()
            return await controller.queue_request(
                func, *args,
                agent_id=agent_id,
                priority=priority,
                **kwargs
            )
        return wrapper
    return decorator


# Export confirmation
logger.info("Adaptive LLM Traffic Control Module Loaded")
