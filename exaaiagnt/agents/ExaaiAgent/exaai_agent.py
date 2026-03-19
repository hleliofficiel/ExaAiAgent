from typing import Any, Optional

from exaaiagnt.agents.base_agent import BaseAgent
from exaaiagnt.agents.agent_supervisor import AgentRole, get_supervisor
from exaaiagnt.llm.config import LLMConfig


class ExaaiAgent(BaseAgent):
    max_iterations = 300

    def __init__(self, config: dict[str, Any]):
        self.role = config.get("role", AgentRole.RECON)
        default_modules = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_modules = ["root_agent"]
            self.role = AgentRole.SUPERVISOR

        # Set specific modules based on role
        role_modules = {
            AgentRole.RECON: ["subdomain_enumeration", "port_scanning", "technology_fingerprinting"],
            AgentRole.ATTACK: ["sql_injection", "xss", "rce", "idor", "waf_bypass"],
            AgentRole.AUDITOR: ["api_security", "kubernetes_security", "cloud_security"],
        }
        
        if self.role in role_modules:
            default_modules.extend(role_modules[self.role])

        incoming_llm_config = config.get("llm_config")
        merged_modules = list(default_modules)
        if incoming_llm_config and getattr(incoming_llm_config, "prompt_modules", None):
            for module_name in incoming_llm_config.prompt_modules:
                if module_name not in merged_modules:
                    merged_modules.append(module_name)

        if incoming_llm_config:
            config["llm_config"] = LLMConfig(
                model_name=incoming_llm_config.model_name,
                enable_prompt_caching=incoming_llm_config.enable_prompt_caching,
                prompt_modules=merged_modules,
                timeout=incoming_llm_config.timeout,
                max_tokens_per_request=incoming_llm_config.max_tokens_per_request,
                optimize_prompts=incoming_llm_config.optimize_prompts,
                lightweight_mode=incoming_llm_config.lightweight_mode,
                min_reasoning_depth=incoming_llm_config.min_reasoning_depth,
                max_reasoning_depth=incoming_llm_config.max_reasoning_depth,
                rate_limit_delay=incoming_llm_config.rate_limit_delay,
                max_concurrent_requests=incoming_llm_config.max_concurrent_requests,
            )
        else:
            config["llm_config"] = LLMConfig(prompt_modules=merged_modules)

        self.default_llm_config = config["llm_config"]

        super().__init__(config)
        
        # Update role in supervisor
        try:
            supervisor = get_supervisor()
            if self.state.agent_id in supervisor._agents:
                supervisor._agents[self.state.agent_id].role = self.role
        except Exception:
            pass

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        user_instructions = scan_config.get("user_instructions", "")
        targets = scan_config.get("targets", [])

        repositories = []
        local_code = []
        urls = []
        ip_addresses = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])

        task_parts = []

        if repositories:
            task_parts.append("\n\nRepositories:")
            for repo in repositories:
                if repo["workspace_path"]:
                    task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
                else:
                    task_parts.append(f"- {repo['url']}")

        if local_code:
            task_parts.append("\n\nLocal Codebases:")
            task_parts.extend(
                f"- {code['path']} (available at: {code['workspace_path']})" for code in local_code
            )

        if urls:
            task_parts.append("\n\nURLs:")
            task_parts.extend(f"- {url}" for url in urls)

        if ip_addresses:
            task_parts.append("\n\nIP Addresses:")
            task_parts.extend(f"- {ip}" for ip in ip_addresses)

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        return await self.agent_loop(task=task_description)
