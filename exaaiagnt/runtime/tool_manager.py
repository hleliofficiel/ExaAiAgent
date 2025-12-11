"""
Tool Manager - Manages tool lifecycle with process isolation.
Provides monitoring, restart, and graceful degradation capabilities.
"""

import asyncio
import logging
import os
import signal
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """Tool lifecycle states."""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    KILLED = "killed"


@dataclass
class ToolExecution:
    """Represents a single tool execution."""
    tool_id: str
    tool_name: str
    args: Dict[str, Any] = field(default_factory=dict)
    status: ToolStatus = ToolStatus.IDLE
    start_time: float = 0
    end_time: float = 0
    process_id: Optional[int] = None
    output: Any = None
    error: Optional[str] = None
    timeout: float = 300  # 5 minutes default
    retries: int = 0
    max_retries: int = 3


class ToolManager:
    """
    Manages tool lifecycle with process isolation.
    
    Features:
    - Process isolation per tool
    - Tool health monitoring
    - Automatic restart on failure
    - Graceful degradation
    - Kill/restart capabilities
    """
    
    DEFAULT_TIMEOUT = 300  # 5 minutes
    MAX_CONCURRENT_TOOLS = 5
    HEALTH_CHECK_INTERVAL = 10
    
    _instance: Optional["ToolManager"] = None
    
    def __new__(cls) -> "ToolManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._executions: Dict[str, ToolExecution] = {}
        self._running_processes: Dict[str, asyncio.subprocess.Process] = {}
        self._tool_semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_TOOLS)
        self._monitor_task: Optional[asyncio.Task] = None
        self._running = False
        self._executor = ThreadPoolExecutor(max_workers=10)
        
        # Callbacks
        self._on_failure_callbacks: List[Callable] = []
        self._on_complete_callbacks: List[Callable] = []
        
        # Statistics
        self._stats = {
            "total_executions": 0,
            "successful": 0,
            "failed": 0,
            "timeouts": 0,
            "retries": 0,
        }
        
        self._initialized = True
        logger.info("ToolManager initialized")
    
    async def execute(
        self,
        tool_name: str,
        command: str,
        args: Dict[str, Any] = None,
        timeout: float = None,
        cwd: str = None,
        env: Dict[str, str] = None,
        retry_on_failure: bool = True
    ) -> ToolExecution:
        """
        Execute a tool with process isolation.
        
        Args:
            tool_name: Name of the tool
            command: Command to execute
            args: Arguments for the tool
            timeout: Execution timeout in seconds
            cwd: Working directory
            env: Environment variables
            retry_on_failure: Whether to retry on failure
            
        Returns:
            ToolExecution with results
        """
        tool_id = f"{tool_name}_{int(time.time() * 1000)}"
        execution = ToolExecution(
            tool_id=tool_id,
            tool_name=tool_name,
            args=args or {},
            timeout=timeout or self.DEFAULT_TIMEOUT,
        )
        
        self._executions[tool_id] = execution
        self._stats["total_executions"] += 1
        
        async with self._tool_semaphore:
            try:
                result = await self._run_with_timeout(
                    execution, command, cwd, env
                )
                
                if result.status == ToolStatus.FAILED and retry_on_failure:
                    result = await self._retry_execution(
                        execution, command, cwd, env
                    )
                
                return result
                
            except Exception as e:
                execution.status = ToolStatus.FAILED
                execution.error = str(e)
                self._stats["failed"] += 1
                logger.error(f"Tool {tool_name} failed: {e}")
                
                self._notify_failure(execution)
                return execution
    
    async def _run_with_timeout(
        self,
        execution: ToolExecution,
        command: str,
        cwd: str = None,
        env: Dict[str, str] = None
    ) -> ToolExecution:
        """Run command with timeout handling."""
        execution.status = ToolStatus.RUNNING
        execution.start_time = time.time()
        
        # Prepare environment
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        
        try:
            # Create subprocess
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=process_env,
            )
            
            execution.process_id = process.pid
            self._running_processes[execution.tool_id] = process
            
            try:
                # Wait with timeout
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=execution.timeout
                )
                
                execution.end_time = time.time()
                execution.output = stdout.decode('utf-8', errors='replace')
                
                if process.returncode == 0:
                    execution.status = ToolStatus.COMPLETED
                    self._stats["successful"] += 1
                else:
                    execution.status = ToolStatus.FAILED
                    execution.error = stderr.decode('utf-8', errors='replace')
                    self._stats["failed"] += 1
                    
            except asyncio.TimeoutError:
                execution.status = ToolStatus.TIMEOUT
                execution.error = f"Timeout after {execution.timeout}s"
                execution.end_time = time.time()
                self._stats["timeouts"] += 1
                
                # Kill the process
                await self._kill_process(execution.tool_id)
                
            finally:
                # Cleanup
                if execution.tool_id in self._running_processes:
                    del self._running_processes[execution.tool_id]
                    
        except Exception as e:
            execution.status = ToolStatus.FAILED
            execution.error = str(e)
            execution.end_time = time.time()
            self._stats["failed"] += 1
            
        self._notify_complete(execution)
        return execution
    
    async def _retry_execution(
        self,
        execution: ToolExecution,
        command: str,
        cwd: str = None,
        env: Dict[str, str] = None
    ) -> ToolExecution:
        """Retry failed execution."""
        while execution.retries < execution.max_retries:
            execution.retries += 1
            self._stats["retries"] += 1
            
            logger.info(
                f"Retrying {execution.tool_name} "
                f"(attempt {execution.retries}/{execution.max_retries})"
            )
            
            # Wait before retry (exponential backoff)
            await asyncio.sleep(min(2 ** execution.retries, 30))
            
            # Reset for retry
            execution.status = ToolStatus.IDLE
            execution.error = None
            
            result = await self._run_with_timeout(execution, command, cwd, env)
            
            if result.status == ToolStatus.COMPLETED:
                return result
        
        logger.error(
            f"Tool {execution.tool_name} failed after "
            f"{execution.max_retries} retries"
        )
        return execution
    
    async def _kill_process(self, tool_id: str) -> bool:
        """Kill a running process."""
        if tool_id not in self._running_processes:
            return False
        
        process = self._running_processes[tool_id]
        
        try:
            # Try graceful termination first
            process.terminate()
            
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                # Force kill
                process.kill()
                await process.wait()
            
            logger.info(f"Killed process for tool {tool_id}")
            
            if tool_id in self._executions:
                self._executions[tool_id].status = ToolStatus.KILLED
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to kill process {tool_id}: {e}")
            return False
        finally:
            if tool_id in self._running_processes:
                del self._running_processes[tool_id]
    
    async def kill_tool(self, tool_id: str) -> bool:
        """Public method to kill a tool by ID."""
        return await self._kill_process(tool_id)
    
    async def kill_all(self) -> int:
        """Kill all running tools."""
        killed = 0
        for tool_id in list(self._running_processes.keys()):
            if await self._kill_process(tool_id):
                killed += 1
        return killed
    
    def get_execution(self, tool_id: str) -> Optional[ToolExecution]:
        """Get execution by ID."""
        return self._executions.get(tool_id)
    
    def get_running_tools(self) -> List[ToolExecution]:
        """Get list of currently running tools."""
        return [
            self._executions[tid]
            for tid in self._running_processes.keys()
            if tid in self._executions
        ]
    
    def get_stats(self) -> Dict[str, int]:
        """Get execution statistics."""
        return dict(self._stats)
    
    def on_failure(self, callback: Callable[[ToolExecution], None]) -> None:
        """Register callback for tool failures."""
        self._on_failure_callbacks.append(callback)
    
    def on_complete(self, callback: Callable[[ToolExecution], None]) -> None:
        """Register callback for tool completion."""
        self._on_complete_callbacks.append(callback)
    
    def _notify_failure(self, execution: ToolExecution) -> None:
        """Notify failure callbacks."""
        for callback in self._on_failure_callbacks:
            try:
                callback(execution)
            except Exception as e:
                logger.error(f"Failure callback error: {e}")
    
    def _notify_complete(self, execution: ToolExecution) -> None:
        """Notify completion callbacks."""
        for callback in self._on_complete_callbacks:
            try:
                callback(execution)
            except Exception as e:
                logger.error(f"Complete callback error: {e}")
    
    async def start_monitoring(self) -> None:
        """Start the tool monitoring loop."""
        if self._running:
            return
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Tool monitoring started")
    
    async def stop_monitoring(self) -> None:
        """Stop the tool monitoring loop."""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Tool monitoring stopped")
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop for tools."""
        while self._running:
            try:
                await self._check_tool_health()
                await asyncio.sleep(self.HEALTH_CHECK_INTERVAL)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Tool monitoring error: {e}")
                await asyncio.sleep(1)
    
    async def _check_tool_health(self) -> None:
        """Check health of all running tools."""
        now = time.time()
        
        for tool_id, execution in list(self._executions.items()):
            if execution.status != ToolStatus.RUNNING:
                continue
            
            # Check if process still exists
            if tool_id in self._running_processes:
                process = self._running_processes[tool_id]
                if process.returncode is not None:
                    # Process has ended
                    execution.status = ToolStatus.COMPLETED if process.returncode == 0 else ToolStatus.FAILED
                    execution.end_time = now
                    del self._running_processes[tool_id]
            
            # Check timeout
            if execution.start_time > 0:
                elapsed = now - execution.start_time
                if elapsed > execution.timeout:
                    logger.warning(
                        f"Tool {execution.tool_name} ({tool_id}) timed out "
                        f"after {elapsed:.0f}s"
                    )
                    await self._kill_process(tool_id)


# Global instance
def get_tool_manager() -> ToolManager:
    """Get the global ToolManager instance."""
    return ToolManager()


# Convenience functions
async def run_tool(
    tool_name: str,
    command: str,
    timeout: float = 300,
    **kwargs
) -> ToolExecution:
    """Run a tool with the global ToolManager."""
    return await get_tool_manager().execute(
        tool_name, command, timeout=timeout, **kwargs
    )


async def kill_tool(tool_id: str) -> bool:
    """Kill a tool by ID."""
    return await get_tool_manager().kill_tool(tool_id)
