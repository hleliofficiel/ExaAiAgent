"""
Output Processor - Preprocesses tool outputs to reduce token consumption.
Implements filtering, summarization, and batching of large outputs.
"""

import re
import json
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class OutputConfig:
    """Configuration for output processing."""
    max_urls: int = 100
    max_lines: int = 200
    max_chars: int = 10000
    summarize_threshold: int = 5000
    deduplicate: bool = True
    filter_duplicates: bool = True
    group_similar: bool = True


class OutputProcessor:
    """
    Processes tool outputs to reduce token consumption.
    
    Features:
    - URL deduplication and limiting
    - Large output summarization
    - Irrelevant data filtering
    - Smart batching
    - Output caching
    """
    
    def __init__(self, config: Optional[OutputConfig] = None):
        self.config = config or OutputConfig()
        self._cache: Dict[str, str] = {}
        self._url_seen: set = set()
        
    def process(self, tool_name: str, output: Any) -> str:
        """Process tool output based on tool type."""
        if output is None:
            return "No output"
        
        # Convert to string if needed
        if isinstance(output, dict):
            output_str = json.dumps(output, indent=2, default=str)
        elif isinstance(output, (list, tuple)):
            output_str = self._process_list(output)
        else:
            output_str = str(output)
        
        # Check cache
        cache_key = self._get_cache_key(tool_name, output_str)
        if cache_key in self._cache:
            return f"[Cached Result]\n{self._cache[cache_key]}"
        
        # Route to specific processor
        processed = self._route_processor(tool_name, output_str)
        
        # Cache the result
        self._cache[cache_key] = processed
        
        return processed
    
    def _route_processor(self, tool_name: str, output: str) -> str:
        """Route to specific processor based on tool name."""
        tool_lower = tool_name.lower()
        
        # URL discovery tools
        if any(t in tool_lower for t in ["katana", "httpx", "subfinder", "waybackurls", "gau"]):
            return self._process_urls(output)
        
        # Port scanning
        if any(t in tool_lower for t in ["nmap", "masscan", "rustscan"]):
            return self._process_ports(output)
        
        # Directory/file discovery
        if any(t in tool_lower for t in ["ffuf", "dirsearch", "gobuster", "feroxbuster"]):
            return self._process_directories(output)
        
        # Nuclei/vulnerability scanners
        if any(t in tool_lower for t in ["nuclei", "nikto", "wapiti"]):
            return self._process_vulnerabilities(output)
        
        # Default processing
        return self._process_generic(output)
    
    def _process_urls(self, output: str) -> str:
        """Process URL lists with deduplication and prioritization."""
        lines = output.strip().split('\n')
        urls = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Extract URL if line contains other data
            url_match = re.search(r'https?://[^\s]+', line)
            if url_match:
                url = url_match.group(0)
            else:
                url = line
            
            # Deduplicate
            if self.config.deduplicate:
                normalized = self._normalize_url(url)
                if normalized in self._url_seen:
                    continue
                self._url_seen.add(normalized)
            
            urls.append(url)
        
        # Prioritize interesting URLs
        prioritized = self._prioritize_urls(urls)
        
        # Limit count
        limited = prioritized[:self.config.max_urls]
        
        # Generate summary
        total = len(urls)
        shown = len(limited)
        
        result = f"[URL Discovery Summary]\n"
        result += f"Total URLs found: {total}\n"
        result += f"Showing top {shown} prioritized URLs:\n\n"
        result += '\n'.join(limited)
        
        if total > shown:
            result += f"\n\n[{total - shown} additional URLs omitted]"
        
        return result
    
    def _prioritize_urls(self, urls: List[str]) -> List[str]:
        """Prioritize URLs by potential interest."""
        high_priority = []
        medium_priority = []
        low_priority = []
        
        high_patterns = [
            r'/admin', r'/api', r'/auth', r'/login', r'/upload',
            r'/config', r'/backup', r'/debug', r'/test', r'/internal',
            r'\.json$', r'\.xml$', r'\.yaml$', r'\.env',
            r'/graphql', r'/rest', r'/v1/', r'/v2/',
        ]
        
        medium_patterns = [
            r'/user', r'/account', r'/profile', r'/dashboard',
            r'/search', r'/query', r'\?.*=',
        ]
        
        for url in urls:
            url_lower = url.lower()
            
            if any(re.search(p, url_lower) for p in high_patterns):
                high_priority.append(url)
            elif any(re.search(p, url_lower) for p in medium_patterns):
                medium_priority.append(url)
            else:
                low_priority.append(url)
        
        return high_priority + medium_priority + low_priority
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        # Remove trailing slashes, query params for comparison
        url = re.sub(r'\?.*$', '', url)
        url = url.rstrip('/')
        return url.lower()
    
    def _process_ports(self, output: str) -> str:
        """Process port scan results."""
        lines = output.strip().split('\n')
        
        open_ports = []
        services = defaultdict(list)
        
        for line in lines:
            # Parse common nmap/masscan output formats
            port_match = re.search(r'(\d+)/(tcp|udp)\s+open\s+(\S+)?', line)
            if port_match:
                port = port_match.group(1)
                proto = port_match.group(2)
                service = port_match.group(3) or "unknown"
                open_ports.append(f"{port}/{proto}")
                services[service].append(f"{port}/{proto}")
        
        if not open_ports:
            return self._process_generic(output)
        
        result = f"[Port Scan Summary]\n"
        result += f"Open ports: {len(open_ports)}\n\n"
        
        result += "By Service:\n"
        for service, ports in sorted(services.items()):
            result += f"  {service}: {', '.join(ports)}\n"
        
        result += f"\nAll open ports: {', '.join(sorted(open_ports, key=lambda x: int(x.split('/')[0])))}"
        
        return result
    
    def _process_directories(self, output: str) -> str:
        """Process directory/file discovery results."""
        lines = output.strip().split('\n')
        
        found = {
            "directories": [],
            "files": [],
            "interesting": [],
            "status_codes": defaultdict(list)
        }
        
        interesting_patterns = [
            r'\.env', r'\.config', r'\.git', r'\.svn',
            r'backup', r'admin', r'secret', r'private',
            r'\.sql', r'\.bak', r'\.old', r'\.log',
        ]
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Parse status code
            status_match = re.search(r'\[(\d{3})\]', line)
            status = status_match.group(1) if status_match else "unknown"
            
            # Extract path
            path_match = re.search(r'(https?://[^\s]+|/[^\s\[\]]+)', line)
            path = path_match.group(1) if path_match else line
            
            found["status_codes"][status].append(path)
            
            if any(re.search(p, path.lower()) for p in interesting_patterns):
                found["interesting"].append(f"[{status}] {path}")
            elif path.endswith('/'):
                found["directories"].append(path)
            else:
                found["files"].append(path)
        
        result = f"[Directory Discovery Summary]\n"
        result += f"Total entries: {sum(len(v) for v in found['status_codes'].values())}\n\n"
        
        if found["interesting"]:
            result += f"🔴 Interesting findings ({len(found['interesting'])}):\n"
            for item in found["interesting"][:20]:
                result += f"  {item}\n"
            result += "\n"
        
        result += "By Status Code:\n"
        for status, paths in sorted(found["status_codes"].items()):
            result += f"  [{status}]: {len(paths)} entries\n"
        
        return result
    
    def _process_vulnerabilities(self, output: str) -> str:
        """Process vulnerability scan results."""
        lines = output.strip().split('\n')
        
        findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        for line in lines:
            line_lower = line.lower()
            if 'critical' in line_lower:
                findings["critical"].append(line)
            elif 'high' in line_lower:
                findings["high"].append(line)
            elif 'medium' in line_lower:
                findings["medium"].append(line)
            elif 'low' in line_lower:
                findings["low"].append(line)
            elif any(k in line_lower for k in ['info', 'informational']):
                findings["info"].append(line)
        
        total = sum(len(v) for v in findings.values())
        
        if total == 0:
            return self._process_generic(output)
        
        result = f"[Vulnerability Scan Summary]\n"
        result += f"Total findings: {total}\n\n"
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            if findings[severity]:
                result += f"{severity.upper()} ({len(findings[severity])}):\n"
                for finding in findings[severity][:10]:
                    result += f"  • {finding[:200]}\n"
                if len(findings[severity]) > 10:
                    result += f"  ... and {len(findings[severity]) - 10} more\n"
                result += "\n"
        
        return result
    
    def _process_generic(self, output: str) -> str:
        """Generic processing for unknown tool outputs."""
        if len(output) <= self.config.summarize_threshold:
            return output
        
        lines = output.split('\n')
        
        if len(lines) > self.config.max_lines:
            # Truncate with summary
            shown_lines = lines[:self.config.max_lines]
            result = '\n'.join(shown_lines)
            result += f"\n\n[Output truncated: showed {self.config.max_lines} of {len(lines)} lines]"
            return result
        
        if len(output) > self.config.max_chars:
            result = output[:self.config.max_chars]
            result += f"\n\n[Output truncated: showed {self.config.max_chars} of {len(output)} characters]"
            return result
        
        return output
    
    def _process_list(self, items: List[Any]) -> str:
        """Process list outputs."""
        if not items:
            return "Empty list"
        
        # Convert items to strings
        str_items = [str(item) for item in items]
        
        # Check if these are URLs
        if all(re.match(r'https?://', item) for item in str_items[:10]):
            return self._process_urls('\n'.join(str_items))
        
        # Limit items
        if len(str_items) > self.config.max_lines:
            shown = str_items[:self.config.max_lines]
            result = '\n'.join(shown)
            result += f"\n\n[{len(str_items) - self.config.max_lines} items omitted]"
            return result
        
        return '\n'.join(str_items)
    
    def _get_cache_key(self, tool_name: str, output: str) -> str:
        """Generate cache key for output."""
        combined = f"{tool_name}:{output}"
        return hashlib.md5(combined.encode()).hexdigest()[:16]
    
    def clear_cache(self) -> None:
        """Clear the output cache."""
        self._cache.clear()
        self._url_seen.clear()
    
    def get_stats(self) -> Dict[str, int]:
        """Get processing statistics."""
        return {
            "cache_size": len(self._cache),
            "unique_urls": len(self._url_seen),
        }


# Global processor instance
_processor: Optional[OutputProcessor] = None


def get_output_processor() -> OutputProcessor:
    """Get the global OutputProcessor instance."""
    global _processor
    if _processor is None:
        _processor = OutputProcessor()
    return _processor


def process_tool_output(tool_name: str, output: Any) -> str:
    """Convenience function to process tool output."""
    return get_output_processor().process(tool_name, output)
