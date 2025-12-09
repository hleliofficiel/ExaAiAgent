"""
LLM Configuration with optimized settings for performance and reliability.
"""

import os


class LLMConfig:
    """
    Enhanced LLM configuration with:
    - Token optimization settings
    - Rate limiting controls
    - Lightweight mode for faster responses
    - Smart defaults for optimal performance
    """
    
    def __init__(
        self,
        model_name: str | None = None,
        enable_prompt_caching: bool = True,
        prompt_modules: list[str] | None = None,
        timeout: int | None = None,
        # Token optimization settings
        max_tokens_per_request: int | None = None,
        optimize_prompts: bool = True,
        lightweight_mode: bool = False,
        min_reasoning_depth: int = 1,
        max_reasoning_depth: int = 3,
        # Rate limiting settings
        rate_limit_delay: float | None = None,
        max_concurrent_requests: int | None = None,
    ):
        # Model configuration
        self.model_name = model_name or os.getenv("EXAAI_LLM", "openai/gpt-5")

        if not self.model_name:
            raise ValueError("EXAAI_LLM environment variable must be set and not empty")

        self.enable_prompt_caching = enable_prompt_caching
        self.prompt_modules = prompt_modules or []

        # Timeout with reasonable default (5 minutes)
        self.timeout = timeout or int(os.getenv("LLM_TIMEOUT", "300"))
        
        # Token optimization: limit output tokens to reduce consumption
        # Default 4096 for better quality responses
        self.max_tokens_per_request = max_tokens_per_request or int(
            os.getenv("EXAAI_MAX_TOKENS", "4096")
        )
        
        # Enable prompt optimization by default
        self.optimize_prompts = optimize_prompts
        
        # Lightweight mode: reduces sub-agent creation and uses direct execution
        self.lightweight_mode = lightweight_mode or os.getenv(
            "EXAAI_LIGHTWEIGHT_MODE", "false"
        ).lower() == "true"
        
        # Reasoning depth limits
        self.min_reasoning_depth = min_reasoning_depth
        self.max_reasoning_depth = max_reasoning_depth
        
        # Rate limiting settings - optimized defaults
        self.rate_limit_delay = rate_limit_delay or float(
            os.getenv("LLM_RATE_LIMIT_DELAY", "1.5")
        )
        self.max_concurrent_requests = max_concurrent_requests or int(
            os.getenv("LLM_RATE_LIMIT_CONCURRENT", "5")
        )
        
        # Fallback models for resilience
        fallback_env = os.getenv("EXAAI_FALLBACK_MODELS", "")
        self.fallback_models = [m.strip() for m in fallback_env.split(",") if m.strip()]
    
    def to_dict(self) -> dict:
        """Convert config to dictionary for logging/debugging."""
        return {
            "model_name": self.model_name,
            "enable_prompt_caching": self.enable_prompt_caching,
            "timeout": self.timeout,
            "max_tokens_per_request": self.max_tokens_per_request,
            "lightweight_mode": self.lightweight_mode,
            "rate_limit_delay": self.rate_limit_delay,
            "max_concurrent_requests": self.max_concurrent_requests,
            "fallback_models": self.fallback_models,
        }
