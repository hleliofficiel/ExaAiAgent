"""Supply-chain: SBOM parsing and CVE comparison (pure functions)."""

from exaaiagnt.supplychain.sbom import (
    CVEStore,
    compare_cves,
    parse_cargo_lock,
    parse_package_json,
    parse_requirements,
    to_cyclonedx_lite,
)


__all__ = [
    "CVEStore",
    "compare_cves",
    "parse_cargo_lock",
    "parse_package_json",
    "parse_requirements",
    "to_cyclonedx_lite",
]
