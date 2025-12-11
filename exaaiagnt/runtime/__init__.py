import os

from .runtime import AbstractRuntime
from .tool_manager import (
    get_tool_manager,
    ToolManager,
    ToolExecution,
    ToolStatus,
    run_tool,
    kill_tool,
)


def get_runtime() -> AbstractRuntime:
    runtime_backend = os.getenv("EXAAI_RUNTIME_BACKEND", "docker")

    if runtime_backend == "docker":
        from .docker_runtime import DockerRuntime

        return DockerRuntime()

    raise ValueError(
        f"Unsupported runtime backend: {runtime_backend}. Only 'docker' is supported for now."
    )


__all__ = [
    "AbstractRuntime",
    "get_runtime",
    # Tool Manager
    "get_tool_manager",
    "ToolManager",
    "ToolExecution",
    "ToolStatus",
    "run_tool",
    "kill_tool",
]
