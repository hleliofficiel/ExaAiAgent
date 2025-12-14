"""
Enhanced LLM Request Queue with intelligent rate limiting, retry logic, and fallback support.
"""

import asyncio
import logging
import os
import random
import threading
import time
from typing import Any

import litellm
from litellm import ModelResponse, completion
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)


logger = logging.getLogger(__name__)


def should_retry_exception(exception: Exception) -> bool:
    """Determine if an exception should trigger a retry."""
    status_code = None

    if hasattr(exception, "status_code"):
        status_code = exception.status_code
    elif hasattr(exception, "response") and hasattr(exception.response, "status_code"):
        status_code = exception.response.status_code

    # Always retry rate limit errors
    if isinstance(exception, litellm.RateLimitError):
        logger.warning("Rate limit hit, will retry with backoff...")
        return True
    
    # Retry on timeout
    if isinstance(exception, (litellm.Timeout, asyncio.TimeoutError)):
        logger.warning("Request timeout, will retry...")
        return True
    
    # Retry on server errors
    if isinstance(exception, (litellm.ServiceUnavailableError, litellm.InternalServerError)):
        logger.warning("Server error, will retry...")
        return True

    if status_code is not None:
        return bool(litellm._should_retry(status_code))
    
    return True


class LLMRequestQueue:
    """
    Enhanced request queue with:
    - Intelligent rate limiting with jitter
    - Exponential backoff on failures
    - Fallback model support
    - Request timeout handling
    """
    
    def __init__(
        self,
        max_concurrent: int = 2,
        delay_between_requests: float = 4.0,
        request_timeout: int = 300,
    ):
        # Load configuration from environment
        rate_limit_delay = os.getenv("LLM_RATE_LIMIT_DELAY")
        if rate_limit_delay:
            delay_between_requests = float(rate_limit_delay)

        rate_limit_concurrent = os.getenv("LLM_RATE_LIMIT_CONCURRENT")
        if rate_limit_concurrent:
            max_concurrent = int(rate_limit_concurrent)
        
        timeout_env = os.getenv("LLM_REQUEST_TIMEOUT")
        if timeout_env:
            request_timeout = int(timeout_env)

        self.max_concurrent = max_concurrent
        self.delay_between_requests = delay_between_requests
        self.request_timeout = request_timeout
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._last_request_time = 0.0
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._max_consecutive_failures = 5
        
        # Fallback models configuration
        self._fallback_models = self._load_fallback_models()
        
        logger.info(
            f"LLM Queue initialized: concurrent={max_concurrent}, "
            f"delay={delay_between_requests}s, timeout={request_timeout}s"
        )

    def _load_fallback_models(self) -> list[str]:
        """Load fallback models from environment."""
        fallback_env = os.getenv("EXAAI_FALLBACK_MODELS", "")
        if fallback_env:
            return [m.strip() for m in fallback_env.split(",") if m.strip()]
        return []

    def _add_jitter(self, delay: float) -> float:
        """Add random jitter to delay to prevent thundering herd."""
        jitter = random.uniform(0.1, 0.5) * delay
        return delay + jitter

    async def make_request(self, completion_args: dict[str, Any]) -> ModelResponse:
        """Make an LLM request with rate limiting and retry logic."""
        try:
            # Acquire semaphore with timeout
            acquire_start = time.time()
            while not self._semaphore.acquire(timeout=0.5):
                if time.time() - acquire_start > 60:
                    raise TimeoutError("Failed to acquire request slot after 60s")
                await asyncio.sleep(0.2)

            # Calculate delay with adaptive backoff
            with self._lock:
                now = time.time()
                time_since_last = now - self._last_request_time
                
                # Increase delay if we've had failures
                adaptive_delay = self.delay_between_requests
                if self._consecutive_failures > 0:
                    adaptive_delay *= (1.5 ** self._consecutive_failures)
                    adaptive_delay = min(adaptive_delay, 30.0)  # Cap at 30s
                
                sleep_needed = max(0, adaptive_delay - time_since_last)
                sleep_needed = self._add_jitter(sleep_needed)
                self._last_request_time = now + sleep_needed

            if sleep_needed > 0:
                logger.debug(f"Rate limiting: waiting {sleep_needed:.2f}s")
                await asyncio.sleep(sleep_needed)

            # Make the request with timeout
            try:
                response = await asyncio.wait_for(
                    self._reliable_request(completion_args),
                    timeout=self.request_timeout
                )
                # Reset failure counter on success
                with self._lock:
                    self._consecutive_failures = 0
                return response
                
            except asyncio.TimeoutError:
                logger.error(f"Request timed out after {self.request_timeout}s")
                with self._lock:
                    self._consecutive_failures += 1
                raise litellm.Timeout(f"Request timed out after {self.request_timeout}s")
                
        finally:
            self._semaphore.release()

    @retry(
        stop=stop_after_attempt(15),  # Increased for rate limits
        wait=wait_exponential(multiplier=3, min=10, max=180),  # Longer delays
        retry=retry_if_exception(should_retry_exception),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    async def _reliable_request(self, completion_args: dict[str, Any]) -> ModelResponse:
        """Make a reliable request with automatic retry."""
        try:
            response = completion(**completion_args, stream=False)
            if isinstance(response, ModelResponse):
                return response
            self._raise_unexpected_response()
            raise RuntimeError("Unreachable code")
            
        except litellm.RateLimitError as e:
            # Track consecutive failures
            with self._lock:
                self._consecutive_failures += 1
            
            # Try fallback model if available and we've failed multiple times
            if self._consecutive_failures >= 3 and self._fallback_models:
                fallback_response = await self._try_fallback_models(completion_args)
                if fallback_response:
                    return fallback_response
            raise
        
        except (litellm.ServiceUnavailableError, litellm.InternalServerError):
            with self._lock:
                self._consecutive_failures += 1
            raise

    async def _try_fallback_models(
        self, completion_args: dict[str, Any]
    ) -> ModelResponse | None:
        """Try fallback models when primary fails."""
        original_model = completion_args.get("model", "")
        
        for fallback_model in self._fallback_models:
            if fallback_model == original_model:
                continue
                
            logger.warning(f"Trying fallback model: {fallback_model}")
            try:
                fallback_args = completion_args.copy()
                fallback_args["model"] = fallback_model
                
                response = completion(**fallback_args, stream=False)
                if isinstance(response, ModelResponse):
                    logger.info(f"Fallback model {fallback_model} succeeded")
                    return response
                    
            except Exception as e:
                logger.warning(f"Fallback model {fallback_model} failed: {e}")
                continue
        
        return None

    def _raise_unexpected_response(self) -> None:
        raise RuntimeError("Unexpected response type")

    def get_stats(self) -> dict[str, Any]:
        """Get queue statistics."""
        return {
            "consecutive_failures": self._consecutive_failures,
            "max_concurrent": self.max_concurrent,
            "delay_between_requests": self.delay_between_requests,
            "fallback_models": self._fallback_models,
        }


_global_queue: LLMRequestQueue | None = None


def get_global_queue() -> LLMRequestQueue:
    global _global_queue
    if _global_queue is None:
        _global_queue = LLMRequestQueue()
    return _global_queue


def reset_global_queue() -> None:
    """Reset the global queue (useful for testing or reconfiguration)."""
    global _global_queue
    _global_queue = None
