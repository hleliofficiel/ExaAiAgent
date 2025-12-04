"""
LLM Fallback and Load Balancing System for ExaaiAgnt.

This module provides intelligent model fallback and load balancing capabilities
for improved reliability and performance in LLM interactions.
"""

import asyncio
import logging
import os
import random
from dataclasses import dataclass, field
from typing import Any

import litellm
from litellm import ModelResponse


logger = logging.getLogger(__name__)


@dataclass
class ModelConfig:
    """Configuration for a single LLM model."""
    
    name: str
    weight: int = 1  # Higher weight = more likely to be selected
    max_retries: int = 3
    timeout: int = 600
    enabled: bool = True
    failed_count: int = 0
    
    def is_healthy(self) -> bool:
        """Check if model is healthy (not too many failures)."""
        return self.failed_count < self.max_retries and self.enabled
    
    def mark_failure(self) -> None:
        """Mark a failure for this model."""
        self.failed_count += 1
        if self.failed_count >= self.max_retries:
            logger.warning(f"Model {self.name} disabled after {self.failed_count} failures")
    
    def reset_failures(self) -> None:
        """Reset failure count (call on success)."""
        if self.failed_count > 0:
            logger.info(f"Model {self.name} recovered, resetting failure count")
        self.failed_count = 0


@dataclass
class FallbackResult:
    """Result from a fallback attempt."""
    
    response: ModelResponse | None = None
    model_used: str = ""
    attempts: int = 0
    success: bool = False
    error: str | None = None


class LLMFallbackManager:
    """
    Manages fallback between multiple LLM models.
    
    Features:
    - Automatic failover to backup models
    - Weighted model selection
    - Health tracking and circuit breaker pattern
    - Exponential backoff for retries
    """
    
    def __init__(self, models: list[str] | None = None):
        """
        Initialize the fallback manager.
        
        Args:
            models: List of model names to use. If None, uses defaults.
        """
        self.models: list[ModelConfig] = []
        
        if models:
            for i, model in enumerate(models):
                # First model has highest weight
                weight = max(10 - i, 1)
                self.models.append(ModelConfig(name=model, weight=weight))
        else:
            # Default fallback chain
            self._setup_default_models()
    
    def _setup_default_models(self) -> None:
        """Setup default model fallback chain with multi-provider support."""
        # Check for primary model from environment
        primary_model = os.getenv("EXAAI_LLM")
        
        # Check for custom API base (Ollama, LMStudio, OpenRouter, etc.)
        api_base = (
            os.getenv("LLM_API_BASE")
            or os.getenv("OPENAI_API_BASE")
            or os.getenv("LITELLM_BASE_URL")
            or os.getenv("OLLAMA_API_BASE")
        )
        
        if primary_model:
            self.models.append(ModelConfig(name=primary_model, weight=15))
        
        # Default fallback chain based on provider availability
        default_models = []
        
        # If using custom API base, assume local/custom models
        if api_base:
            # Local/Custom provider models
            default_models = [
                ("openai/gpt-4", 10),  # Works with OpenRouter via openai/ prefix
                ("openai/gpt-3.5-turbo", 8),
            ]
        else:
            # Cloud providers
            default_models = [
                ("openai/gpt-5", 10),
                ("anthropic/claude-sonnet-4-5", 8),
                ("google/gemini-2.0-flash", 6),
                ("deepseek/deepseek-chat", 4),
                ("openrouter/auto", 2),  # OpenRouter auto-select
            ]
        
        for model_name, weight in default_models:
            if model_name != primary_model:
                self.models.append(ModelConfig(name=model_name, weight=weight))
    
    def get_available_models(self) -> list[ModelConfig]:
        """Get list of healthy, available models."""
        return [m for m in self.models if m.is_healthy()]
    
    def select_model(self) -> ModelConfig | None:
        """
        Select a model using weighted random selection.
        
        Returns:
            Selected model config or None if no models available.
        """
        available = self.get_available_models()
        if not available:
            # Try to recover - reset all models
            logger.warning("No healthy models available, resetting all models")
            for model in self.models:
                model.reset_failures()
            available = self.get_available_models()
        
        if not available:
            return None
        
        # Weighted random selection
        total_weight = sum(m.weight for m in available)
        r = random.uniform(0, total_weight)
        
        cumulative = 0
        for model in available:
            cumulative += model.weight
            if r <= cumulative:
                return model
        
        return available[-1]  # Fallback to last model
    
    async def make_request_with_fallback(
        self,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> FallbackResult:
        """
        Make a request with automatic fallback on failure.
        
        Args:
            messages: Chat messages to send.
            **kwargs: Additional arguments for litellm.
            
        Returns:
            FallbackResult containing the response or error info.
        """
        result = FallbackResult()
        
        tried_models: set[str] = set()
        max_total_attempts = len(self.models) * 2  # Allow some retries
        
        while result.attempts < max_total_attempts:
            model_config = self.select_model()
            if not model_config:
                result.error = "No models available"
                break
            
            if model_config.name in tried_models and len(tried_models) >= len(self.models):
                # We've tried all models at least once
                break
            
            tried_models.add(model_config.name)
            result.attempts += 1
            result.model_used = model_config.name
            
            try:
                # Exponential backoff if retrying same model
                if result.attempts > 1:
                    delay = min(2 ** (result.attempts - 1), 30)
                    await asyncio.sleep(delay)
                
                response = await litellm.acompletion(
                    model=model_config.name,
                    messages=messages,
                    timeout=model_config.timeout,
                    **kwargs,
                )
                
                # Success!
                model_config.reset_failures()
                result.response = response
                result.success = True
                logger.info(f"Request succeeded with model {model_config.name}")
                return result
                
            except (
                litellm.RateLimitError,
                litellm.ServiceUnavailableError,
                litellm.Timeout,
                litellm.APIConnectionError,
            ) as e:
                # Transient errors - try another model
                model_config.mark_failure()
                result.error = str(e)
                logger.warning(f"Model {model_config.name} failed with transient error: {e}")
                continue
                
            except (
                litellm.AuthenticationError,
                litellm.NotFoundError,
            ) as e:
                # Permanent errors for this model - disable and try another
                model_config.enabled = False
                result.error = str(e)
                logger.error(f"Model {model_config.name} permanently disabled: {e}")
                continue
                
            except Exception as e:
                # Unknown error
                model_config.mark_failure()
                result.error = str(e)
                logger.exception(f"Model {model_config.name} failed with unexpected error")
                continue
        
        return result


class LLMLoadBalancer:
    """
    Load balancer for distributing requests across multiple models.
    
    Strategies:
    - Round-robin: Equal distribution
    - Weighted: Based on model weights
    - Least-failures: Prefer models with fewer failures
    """
    
    def __init__(
        self,
        models: list[str],
        strategy: str = "weighted",
    ):
        """
        Initialize the load balancer.
        
        Args:
            models: List of model names to balance across.
            strategy: Load balancing strategy ('round-robin', 'weighted', 'least-failures').
        """
        self.models = [ModelConfig(name=m, weight=10 - i) for i, m in enumerate(models)]
        self.strategy = strategy
        self._round_robin_index = 0
    
    def get_next_model(self) -> str:
        """
        Get the next model based on the selected strategy.
        
        Returns:
            Name of the selected model.
        """
        available = [m for m in self.models if m.is_healthy()]
        if not available:
            # Reset and try again
            for m in self.models:
                m.reset_failures()
            available = self.models
        
        if self.strategy == "round-robin":
            model = available[self._round_robin_index % len(available)]
            self._round_robin_index += 1
            return model.name
            
        elif self.strategy == "least-failures":
            model = min(available, key=lambda m: m.failed_count)
            return model.name
            
        else:  # weighted (default)
            total_weight = sum(m.weight for m in available)
            r = random.uniform(0, total_weight)
            cumulative = 0
            for model in available:
                cumulative += model.weight
                if r <= cumulative:
                    return model.name
            return available[-1].name
    
    def report_success(self, model_name: str) -> None:
        """Report a successful request for a model."""
        for model in self.models:
            if model.name == model_name:
                model.reset_failures()
                break
    
    def report_failure(self, model_name: str) -> None:
        """Report a failed request for a model."""
        for model in self.models:
            if model.name == model_name:
                model.mark_failure()
                break


# Global fallback manager instance
_global_fallback_manager: LLMFallbackManager | None = None


def get_fallback_manager() -> LLMFallbackManager:
    """Get or create the global fallback manager."""
    global _global_fallback_manager
    if _global_fallback_manager is None:
        # Initialize with models from environment or defaults
        models_env = os.getenv("EXAAI_FALLBACK_MODELS")
        models = models_env.split(",") if models_env else None
        _global_fallback_manager = LLMFallbackManager(models)
    return _global_fallback_manager


def reset_fallback_manager() -> None:
    """Reset the global fallback manager."""
    global _global_fallback_manager
    _global_fallback_manager = None
