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
from .registry import (
    ImplementedInClientSideOnlyError,
    get_tool_by_name,
    get_tool_names,
    get_tools_prompt,
    needs_agent_state,
    register_tool,
    tools,
)
from .waf_bypass import (
    get_waf_bypass,
    WAFBypass,
    WAFDetector,
    WAFType,
    detect_waf,
    generate_bypasses,
)
from .smart_fuzzer import (
    get_smart_fuzzer,
    SmartFuzzer,
    ParamType,
    VulnCategory,
    FuzzPayload,
    fuzz_parameter,
)
from .response_analyzer import (
    get_response_analyzer,
    ResponseAnalyzer,
    DetectionType,
    Detection,
    analyze_response,
)
from .vuln_validator import (
    get_vuln_validator,
    VulnValidator,
    VulnStatus,
    Severity,
    VulnerabilityReport,
    create_vuln_report,
)
from .tool_prompts import (
    get_fuzzer_prompt,
    get_analyzer_prompt,
    get_validator_prompt,
    get_waf_bypass_prompt,
    get_security_testing_prompt,
    get_all_tool_prompts,
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
    from .browser import *  # noqa: F403
    from .file_edit import *  # noqa: F403
    from .notes import *  # noqa: F403
    from .proxy import *  # noqa: F403
    from .python import *  # noqa: F403
    from .terminal import *  # noqa: F403

__all__ = [
    "ImplementedInClientSideOnlyError",
    "execute_tool",
    "execute_tool_invocation",
    "execute_tool_with_validation",
    "extract_screenshot_from_result",
    "get_tool_by_name",
    "get_tool_names",
    "get_tools_prompt",
    "needs_agent_state",
    "process_tool_invocations",
    "register_tool",
    "remove_screenshot_from_result",
    "tools",
    "validate_tool_availability",
    # WAF Bypass
    "get_waf_bypass",
    "WAFBypass",
    "WAFDetector",
    "WAFType",
    "detect_waf",
    "generate_bypasses",
    # Smart Fuzzer
    "get_smart_fuzzer",
    "SmartFuzzer",
    "ParamType",
    "VulnCategory",
    "FuzzPayload",
    "fuzz_parameter",
    # Response Analyzer
    "get_response_analyzer",
    "ResponseAnalyzer",
    "DetectionType",
    "Detection",
    "analyze_response",
    # Vulnerability Validator
    "get_vuln_validator",
    "VulnValidator",
    "VulnStatus",
    "Severity",
    "VulnerabilityReport",
    "create_vuln_report",
    # Tool Prompts
    "get_fuzzer_prompt",
    "get_analyzer_prompt",
    "get_validator_prompt",
    "get_waf_bypass_prompt",
    "get_security_testing_prompt",
    "get_all_tool_prompts",
]
