import os


class LLMConfig:
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
    ):
        self.model_name = model_name or os.getenv("EXAAI_LLM", "openai/gpt-5")

        if not self.model_name:
            raise ValueError("EXAAI_LLM environment variable must be set and not empty")

        self.enable_prompt_caching = enable_prompt_caching
        self.prompt_modules = prompt_modules or []

        self.timeout = timeout or int(os.getenv("LLM_TIMEOUT", "600"))
        
        # Token optimization: limit output tokens to reduce consumption
        self.max_tokens_per_request = max_tokens_per_request or int(
            os.getenv("EXAAI_MAX_TOKENS", "2048")
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
