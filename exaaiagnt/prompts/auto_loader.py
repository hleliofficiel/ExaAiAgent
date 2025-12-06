"""
Auto Module Loader - Intelligent prompt module detection and loading.
Automatically detects target type and loads relevant security modules.
"""

import re
from urllib.parse import urlparse
from typing import List, Set


# Module detection patterns
MODULE_PATTERNS = {
    # GraphQL detection
    "graphql_security": {
        "url_patterns": [
            r"/graphql",
            r"/graphiql",
            r"/gql",
            r"/api/graphql",
            r"/v\d+/graphql",
        ],
        "keywords": ["graphql", "query", "mutation", "schema"],
    },
    
    # WebSocket detection
    "websocket_security": {
        "url_patterns": [
            r"^wss?://",
            r"/ws/?$",
            r"/websocket",
            r"/socket\.io",
            r"/sockjs",
            r"/realtime",
        ],
        "keywords": ["websocket", "socket", "realtime", "ws://", "wss://"],
    },
    
    # OAuth/OIDC detection
    "oauth_oidc": {
        "url_patterns": [
            r"/oauth",
            r"/oauth2",
            r"/auth",
            r"/authorize",
            r"/token",
            r"/\.well-known/openid",
            r"/oidc",
            r"/sso",
            r"/login",
            r"/signin",
        ],
        "keywords": ["oauth", "oidc", "openid", "authorization", "token", "sso", "jwt"],
    },
    
    # Subdomain takeover detection (domain-only targets)
    "subdomain_takeover": {
        "url_patterns": [],
        "keywords": ["subdomain", "takeover", "dns", "cname", "enumerate"],
        "domain_only": True,  # Triggered when target is just a domain
    },
    
    # WAF bypass (always useful, detect WAF keywords)
    "waf_bypass": {
        "url_patterns": [],
        "keywords": ["waf", "firewall", "cloudflare", "akamai", "blocked", "forbidden"],
    },
    
    # SQL Injection
    "sql_injection": {
        "url_patterns": [
            r"\?.*=",  # URL with parameters
            r"/api/",
            r"/search",
            r"/login",
            r"/user",
        ],
        "keywords": ["sql", "database", "query", "injection", "sqli"],
    },
    
    # XSS
    "xss": {
        "url_patterns": [
            r"\?.*=",
            r"/search",
            r"/comment",
            r"/message",
            r"/post",
        ],
        "keywords": ["xss", "script", "javascript", "cross-site"],
    },
    
    # SSRF
    "ssrf": {
        "url_patterns": [
            r"/api/",
            r"/fetch",
            r"/proxy",
            r"/url",
            r"/load",
            r"/image",
        ],
        "keywords": ["ssrf", "server-side", "internal", "metadata"],
    },
    
    # Authentication/JWT
    "authentication_jwt": {
        "url_patterns": [
            r"/login",
            r"/auth",
            r"/api/auth",
            r"/token",
            r"/session",
        ],
        "keywords": ["auth", "jwt", "token", "session", "login", "password"],
    },
}


def detect_modules_from_target(target: str, instruction: str = "") -> List[str]:
    """
    Automatically detect which prompt modules should be loaded based on target URL and instruction.
    
    Args:
        target: The target URL or domain
        instruction: The user's instruction/task description
        
    Returns:
        List of module names to load
    """
    detected_modules: Set[str] = set()
    
    # Normalize inputs
    target_lower = target.lower()
    instruction_lower = instruction.lower() if instruction else ""
    combined_text = f"{target_lower} {instruction_lower}"
    
    # Parse URL
    parsed = urlparse(target if "://" in target else f"https://{target}")
    url_path = parsed.path.lower()
    
    for module_name, patterns in MODULE_PATTERNS.items():
        should_load = False
        
        # Check URL patterns
        for pattern in patterns.get("url_patterns", []):
            if re.search(pattern, target_lower) or re.search(pattern, url_path):
                should_load = True
                break
        
        # Check keywords in target or instruction
        for keyword in patterns.get("keywords", []):
            if keyword in combined_text:
                should_load = True
                break
        
        # Special case: domain-only targets
        if patterns.get("domain_only") and not parsed.path.strip("/"):
            if any(kw in instruction_lower for kw in ["subdomain", "enumerate", "recon"]):
                should_load = True
        
        if should_load:
            detected_modules.add(module_name)
    
    # Always include base modules for comprehensive scans
    if any(kw in instruction_lower for kw in ["full", "comprehensive", "thorough", "complete"]):
        detected_modules.update(["sql_injection", "xss", "authentication_jwt"])
    
    return list(detected_modules)


def get_recommended_modules(target: str, instruction: str = "") -> dict:
    """
    Get recommended modules with confidence scores.
    
    Returns:
        Dict with 'auto_load' (high confidence) and 'suggested' (medium confidence) modules
    """
    all_detected = detect_modules_from_target(target, instruction)
    
    # High confidence: target URL matches patterns
    auto_load = []
    suggested = []
    
    parsed = urlparse(target if "://" in target else f"https://{target}")
    
    for module in all_detected:
        patterns = MODULE_PATTERNS.get(module, {})
        url_match = any(
            re.search(p, target.lower()) 
            for p in patterns.get("url_patterns", [])
        )
        
        if url_match:
            auto_load.append(module)
        else:
            suggested.append(module)
    
    return {
        "auto_load": auto_load,
        "suggested": suggested,
    }


# Example usage
if __name__ == "__main__":
    # Test cases
    tests = [
        ("https://api.example.com/graphql", "test for vulnerabilities"),
        ("wss://chat.example.com/socket", "security assessment"),
        ("https://auth.example.com/oauth/authorize", "test auth flow"),
        ("example.com", "enumerate subdomains and check for takeover"),
        ("https://app.example.com/api/users?id=1", "full penetration test"),
    ]
    
    for target, instruction in tests:
        modules = detect_modules_from_target(target, instruction)
        print(f"Target: {target}")
        print(f"Instruction: {instruction}")
        print(f"Auto-detected modules: {modules}")
        print("-" * 50)
