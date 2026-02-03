"""
AI Prompt Injection Security Module

This module provides comprehensive testing capabilities for AI/LLM applications,
focusing on prompt injection vulnerabilities that are increasingly critical in 2026.

## Attack Categories

### 1. Direct Prompt Injection
User-controlled input that manipulates LLM behavior directly.

### 2. Indirect Prompt Injection  
Malicious content in external data sources (websites, documents, emails) that
gets processed by the LLM and influences its behavior.

### 3. Jailbreaking
Attempts to bypass safety restrictions and content policies.

### 4. Data Extraction
Techniques to extract system prompts, training data, or configuration.

### 5. Data Exfiltration
Methods to leak sensitive conversation data to external servers.

## Usage

```python
from exaaiagnt.tools.prompt_injection import (
    PromptInjectionScanner,
    scan_for_prompt_injection,
    generate_injection_payloads,
)

# Quick scan
def my_llm_call(prompt: str) -> str:
    # Your LLM API call here
    return response

results = scan_for_prompt_injection(my_llm_call)
print(results)

# Advanced scanning
scanner = PromptInjectionScanner(verbose=True)
scanner.scan(my_llm_call)
print(scanner.export_results())
```

## Payloads Included

- 20+ Direct injection payloads
- 10+ Jailbreak techniques (DAN, Developer Mode, Roleplay)
- 5+ Extraction payloads
- 5+ Exfiltration payloads
- 10+ Delimiter escape techniques

## CVSS Scoring

Prompt injection vulnerabilities typically score:
- **Critical (9.0-10.0)**: Data exfiltration, credential leakage
- **High (7.0-8.9)**: System prompt extraction, jailbreaking
- **Medium (4.0-6.9)**: Behavior manipulation, role bypass
- **Low (0.1-3.9)**: Minor information disclosure

## Remediation

1. **Input Validation**: Sanitize and validate all user inputs
2. **Output Filtering**: Filter responses for sensitive patterns
3. **Prompt Hardening**: Use structured prompts with clear boundaries
4. **Defense in Depth**: Multiple security layers
5. **Monitoring**: Log and alert on suspicious patterns
"""
