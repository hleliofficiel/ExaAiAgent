import os

from .executor import (
    execute_tool,
    execute_tool_invocation,
    execute_tool_with_validation,
    extract_screenshot_from_result,
    process_tool_invocations,
    remove_screenshot_from_result,
    validate_tool_availability,
)
from .k8s_scanner import (
    K8sScanner,
    check_pod_security,
    check_rbac,
    scan_cluster,
)
from .prompt_injection import (
    PromptInjectionScanner,
    analyze_llm_response,
    detect_jailbreak_success,
    generate_injection_payloads,
    scan_for_prompt_injection,
)
from .registry import (
    ImplementedInClientSideOnlyError,
    get_tool_by_name,
    get_tool_names,
    get_tools_prompt,
    needs_agent_state,
    register_tool,
    tools,
)
from .response_analyzer import (
    Detection,
    DetectionType,
    ResponseAnalyzer,
    analyze_response,
    get_response_analyzer,
)
from .smart_fuzzer import (
    FuzzPayload,
    ParamType,
    SmartFuzzer,
    VulnCategory,
    fuzz_parameter,
    get_smart_fuzzer,
)
from .tool_prompts import (
    get_all_tool_prompts,
    get_analyzer_prompt,
    get_fuzzer_prompt,
    get_security_testing_prompt,
    get_validator_prompt,
    get_waf_bypass_prompt,
)
from .vuln_validator import (
    Severity,
    VulnerabilityReport,
    VulnStatus,
    VulnValidator,
    create_vuln_report,
    get_vuln_validator,
)
from .waf_bypass import (
    WAFBypass,
    WAFDetector,
    WAFType,
    detect_waf,
    generate_bypasses,
    get_waf_bypass,
)


SANDBOX_MODE = os.getenv("EXAAI_SANDBOX_MODE", "false").lower() == "true"

HAS_PERPLEXITY_API = bool(os.getenv("PERPLEXITY_API_KEY"))

if not SANDBOX_MODE:
    from .agents_graph import *  # noqa: F403
    from .browser import *  # noqa: F403
    from .file_edit import *  # noqa: F403
    from .finish import *  # noqa: F403
    from .notes import *  # noqa: F403
    from .proxy import *  # noqa: F403
    from .python import *  # noqa: F403
    from .reporting import *  # noqa: F403
    from .terminal import *  # noqa: F403
    from .thinking import *  # noqa: F403

    if HAS_PERPLEXITY_API:
        from .web_search import *  # noqa: F403
else:
    # Sandbox workers still need coordination/finalization tools so sub-agents can
    # wait, report completion, and exchange messages with parents.
    from .agents_graph import *  # noqa: F403
    from .browser import *  # noqa: F403
    from .file_edit import *  # noqa: F403
    from .finish import *  # noqa: F403
    from .notes import *  # noqa: F403
    from .proxy import *  # noqa: F403
    from .python import *  # noqa: F403
    from .terminal import *  # noqa: F403
    from .thinking import *  # noqa: F403

__all__ = [
    "Detection",
    "DetectionType",
    "FuzzPayload",
    "ImplementedInClientSideOnlyError",
    # K8s Scanner
    "K8sScanner",
    "ParamType",
    # Prompt Injection Scanner
    "PromptInjectionScanner",
    "ResponseAnalyzer",
    "Severity",
    "SmartFuzzer",
    "VulnCategory",
    "VulnStatus",
    "VulnValidator",
    "VulnerabilityReport",
    "WAFBypass",
    "WAFDetector",
    "WAFType",
    "analyze_llm_response",
    "analyze_response",
    "check_pod_security",
    "check_rbac",
    "create_vuln_report",
    "detect_jailbreak_success",
    "detect_waf",
    "execute_tool",
    "execute_tool_invocation",
    "execute_tool_with_validation",
    "extract_screenshot_from_result",
    "fuzz_parameter",
    "generate_bypasses",
    "generate_injection_payloads",
    "get_all_tool_prompts",
    "get_analyzer_prompt",
    # Tool Prompts
    "get_fuzzer_prompt",
    # Response Analyzer
    "get_response_analyzer",
    "get_security_testing_prompt",
    # Smart Fuzzer
    "get_smart_fuzzer",
    "get_tool_by_name",
    "get_tool_names",
    "get_tools_prompt",
    "get_validator_prompt",
    # Vulnerability Validator
    "get_vuln_validator",
    # WAF Bypass
    "get_waf_bypass",
    "get_waf_bypass_prompt",
    "needs_agent_state",
    "process_tool_invocations",
    "register_tool",
    "remove_screenshot_from_result",
    "scan_cluster",
    "scan_for_prompt_injection",
    "tools",
    "validate_tool_availability",
]
