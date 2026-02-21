"""
Kubernetes Security Scanner - Core Actions

Comprehensive security testing for Kubernetes clusters including:
- RBAC analysis (excessive permissions)
- Pod Security Standards (PSS) compliance
- Network Policy auditing
- Secret management checks
- API Server configuration review
- Container vulnerability scanning integration

Author: ALhilali
Version: 2.2.2
"""

import json
import logging
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any


logger = logging.getLogger(__name__)


class CheckStatus(Enum):
    """Status of a security check."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    ERROR = "ERROR"
    SKIP = "SKIP"


class Severity(Enum):
    """Severity of a finding."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SecurityFinding:
    """Represents a security finding in the cluster."""
    check_id: str
    title: str
    description: str
    severity: Severity
    resource_kind: str
    resource_name: str
    namespace: str
    remediation: str
    status: CheckStatus = CheckStatus.FAIL


from exaaiagnt.tools.registry import register_tool


@register_tool
class K8sScanner:
    """
    Kubernetes Security Scanner.
    Uses kubectl and specialized logic to audit cluster security.
    """

    def __init__(self, context: str | None = None, verbose: bool = False):
        self.context = context
        self.verbose = verbose
        self.findings: list[SecurityFinding] = []
        self._check_kubectl_availability()

    def _check_kubectl_availability(self):
        """Ensure kubectl is installed and accessible."""
        try:
            subprocess.run(["kubectl", "version", "--client"], capture_output=True, check=True)  # nosec: B603 B607
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("kubectl not found. Some checks may fail.")

    def _run_kubectl(self, args: list[str]) -> dict[str, Any]:
        """Run a kubectl command and return JSON output."""
        cmd = ["kubectl"] + args + ["-o", "json"]
        if self.context:
            cmd.extend(["--context", self.context])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)  # nosec: B603
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"kubectl command failed: {e.stderr}")
            return {}
        except json.JSONDecodeError:
            logger.error("Failed to decode kubectl output")
            return {}

    def scan(self, namespaces: list[str] | None = None) -> list[SecurityFinding]:
        """Run all enabled security checks."""
        target_ns = namespaces or self._get_all_namespaces()

        logger.info(f"Scanning namespaces: {target_ns}")

        # Cluster-wide checks (run once)
        self._check_cluster_rbac()

        # Namespace-scoped checks
        for ns in target_ns:
            self._check_rbac(ns)
            self._check_pod_security(ns)
            self._check_network_policies(ns)
            self._check_secrets(ns)

        return self.findings

    def _check_cluster_rbac(self):
        """Check cluster-wide RBAC configurations."""
        # Check ClusterRoleBindings for cluster-admin
        bindings = self._run_kubectl(["get", "clusterrolebindings"])
        for binding in bindings.get("items", []):
            role_name = binding.get("roleRef", {}).get("name", "")
            binding_name = binding["metadata"]["name"]

            # Skip system bindings
            if binding_name.startswith("system:"):
                continue

            if role_name == "cluster-admin":
                for subject in binding.get("subjects", []):
                    if subject.get("kind") == "ServiceAccount":
                        self.findings.append(SecurityFinding(
                            check_id="RBAC-002",
                            title="ServiceAccount with cluster-admin",
                            description=f"ServiceAccount '{subject.get('name')}' in namespace '{subject.get('namespace', 'default')}' has cluster-admin binding via '{binding_name}'.",
                            severity=Severity.CRITICAL,
                            resource_kind="ClusterRoleBinding",
                            resource_name=binding_name,
                            namespace=subject.get("namespace", "cluster-wide"),
                            remediation="Remove cluster-admin binding. Create a scoped Role with minimum required permissions."
                        ))
                    elif subject.get("kind") == "User" and not subject.get("name", "").startswith("system:"):
                        self.findings.append(SecurityFinding(
                            check_id="RBAC-003",
                            title="User with cluster-admin",
                            description=f"User '{subject.get('name')}' has cluster-admin binding via '{binding_name}'.",
                            severity=Severity.HIGH,
                            resource_kind="ClusterRoleBinding",
                            resource_name=binding_name,
                            namespace="cluster-wide",
                            remediation="Review if user truly needs cluster-admin. Apply least privilege principle."
                        ))

    def _get_all_namespaces(self) -> list[str]:
        """Get list of all namespaces."""
        data = self._run_kubectl(["get", "namespaces"])
        return [item["metadata"]["name"] for item in data.get("items", [])]

    def _check_rbac(self, namespace: str):
        """Check for risky RBAC configurations."""
        # Check 1: Roles with '*' verb
        roles = self._run_kubectl(["get", "roles", "-n", namespace])
        for role in roles.get("items", []):
            name = role["metadata"]["name"]
            for rule in role.get("rules", []):
                if "*" in rule.get("verbs", []) and "*" in rule.get("resources", []):
                    self.findings.append(SecurityFinding(
                        check_id="RBAC-001",
                        title="Cluster Admin-like Role",
                        description=f"Role '{name}' has wildcard permissions (*/*).",
                        severity=Severity.CRITICAL,
                        resource_kind="Role",
                        resource_name=name,
                        namespace=namespace,
                        remediation="Apply least privilege. Remove wildcard permissions."
                    ))

        # Check 2: ServiceAccounts with cluster-admin binding
        # (Simplified check - full graph analysis requires more logic)

    def _check_pod_security(self, namespace: str):
        """Check pods against Pod Security Standards (PSS)."""
        pods = self._run_kubectl(["get", "pods", "-n", namespace])
        for pod in pods.get("items", []):
            name = pod["metadata"]["name"]
            spec = pod.get("spec", {})

            # Check 1: Security Context and Capabilities
            for container in spec.get("containers", []):
                container_name = container.get("name", "unknown")
                security_context = container.get("securityContext", {})

                # Privileged containers
                if security_context.get("privileged", False):
                    self.findings.append(SecurityFinding(
                        check_id="PSS-001",
                        title="Privileged Container",
                        description=f"Container '{container_name}' in pod '{name}' runs as privileged.",
                        severity=Severity.HIGH,
                        resource_kind="Pod",
                        resource_name=name,
                        namespace=namespace,
                        remediation="Remove 'privileged: true' from securityContext."
                    ))

                # Allow Privilege Escalation
                if security_context.get("allowPrivilegeEscalation", True):
                    self.findings.append(SecurityFinding(
                        check_id="PSS-003",
                        title="Privilege Escalation Allowed",
                        description=f"Container '{container_name}' in pod '{name}' allows privilege escalation.",
                        severity=Severity.MEDIUM,
                        resource_kind="Pod",
                        resource_name=name,
                        namespace=namespace,
                        remediation="Set 'allowPrivilegeEscalation: false' in securityContext."
                    ))

                # Read Only Root Filesystem
                if not security_context.get("readOnlyRootFilesystem", False):
                    self.findings.append(SecurityFinding(
                        check_id="PSS-004",
                        title="Writable Root Filesystem",
                        description=f"Container '{container_name}' in pod '{name}' has a writable root filesystem.",
                        severity=Severity.LOW,
                        resource_kind="Pod",
                        resource_name=name,
                        namespace=namespace,
                        remediation="Set 'readOnlyRootFilesystem: true' in securityContext."
                    ))

                # Capabilities
                capabilities = security_context.get("capabilities", {})
                add_caps = capabilities.get("add", [])
                if add_caps:
                    self.findings.append(SecurityFinding(
                        check_id="PSS-005",
                        title="Dangerous Capabilities Added",
                        description=f"Container '{container_name}' in pod '{name}' adds capabilities: {add_caps}.",
                        severity=Severity.MEDIUM,
                        resource_kind="Pod",
                        resource_name=name,
                        namespace=namespace,
                        remediation="Review and remove unnecessary capabilities. Drop 'ALL' and add only required ones."
                    ))

            # Check 2: Host PID/Network/IPC
            if spec.get("hostPID") or spec.get("hostNetwork") or spec.get("hostIPC"):
                self.findings.append(SecurityFinding(
                    check_id="PSS-002",
                    title="Host Namespace Usage",
                    description=f"Pod '{name}' shares host namespaces (PID/Net/IPC).",
                    severity=Severity.HIGH,
                    resource_kind="Pod",
                    resource_name=name,
                    namespace=namespace,
                    remediation="Disable hostPID, hostNetwork, and hostIPC."
                ))

    def _check_network_policies(self, namespace: str):
        """Check if network policies are defined."""
        policies = self._run_kubectl(["get", "networkpolicies", "-n", namespace])
        if not policies.get("items"):
            self.findings.append(SecurityFinding(
                check_id="NET-001",
                title="Missing Network Policy",
                description=f"Namespace '{namespace}' has no NetworkPolicies defined. Traffic is unrestricted.",
                severity=Severity.MEDIUM,
                resource_kind="Namespace",
                resource_name=namespace,
                namespace=namespace,
                remediation="Define a default deny-all NetworkPolicy."
            ))

    def _check_secrets(self, namespace: str):
        """Check for secrets issues."""
        pods = self._run_kubectl(["get", "pods", "-n", namespace])
        for pod in pods.get("items", []):
            name = pod["metadata"]["name"]
            spec = pod.get("spec", {})

            for container in spec.get("containers", []):
                container_name = container.get("name", "unknown")

                # Check for secrets in plain env vars (bad practice)
                for env in container.get("env", []):
                    env_name = env.get("name", "").lower()
                    env_value = env.get("value", "")

                    # Skip if using secretKeyRef (proper method)
                    if env.get("valueFrom", {}).get("secretKeyRef"):
                        continue

                    # Check for suspicious env var names with plain values
                    sensitive_keywords = ["password", "secret", "key", "token",
                                         "api_key", "apikey", "auth", "credential",
                                         "private", "access_key", "secret_key"]

                    if any(kw in env_name for kw in sensitive_keywords) and env_value:
                        self.findings.append(SecurityFinding(
                            check_id="SEC-001",
                            title="Secret in Plain Environment Variable",
                            description=f"Container '{container_name}' in pod '{name}' has sensitive data in plain env var '{env.get('name')}'.",
                            severity=Severity.HIGH,
                            resource_kind="Pod",
                            resource_name=name,
                            namespace=namespace,
                            remediation="Use Kubernetes Secrets with secretKeyRef instead of plain values. Never commit secrets in manifests."
                        ))

                # Check for automountServiceAccountToken
                if spec.get("automountServiceAccountToken", True):
                    # Only flag if not system namespace
                    if namespace not in ["kube-system", "kube-public", "kube-node-lease"]:
                        self.findings.append(SecurityFinding(
                            check_id="SEC-002",
                            title="ServiceAccount Token Auto-Mounted",
                            description=f"Pod '{name}' has automountServiceAccountToken enabled (default).",
                            severity=Severity.LOW,
                            resource_kind="Pod",
                            resource_name=name,
                            namespace=namespace,
                            remediation="Set automountServiceAccountToken: false unless the pod needs K8s API access."
                        ))

    def export_report(self) -> dict[str, Any]:
        """Export findings summary."""
        return {
            "total_findings": len(self.findings),
            "findings": [
                {
                    "id": f.check_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "resource": f"{f.namespace}/{f.resource_kind}/{f.resource_name}",
                    "remediation": f.remediation
                }
                for f in self.findings
            ]
        }


# === Convenience Functions ===

@register_tool
def scan_cluster(context: str | None = None) -> dict[str, Any]:
    """Run a full cluster scan."""
    scanner = K8sScanner(context=context)
    scanner.scan()
    return scanner.export_report()


@register_tool
def check_rbac(namespace: str = "default") -> list[dict[str, Any]]:
    """Run RBAC checks only."""
    scanner = K8sScanner()
    scanner._check_rbac(namespace)
    return scanner.export_report()["findings"]


@register_tool
def check_pod_security(namespace: str = "default") -> list[dict[str, Any]]:
    """Run Pod Security checks only."""
    scanner = K8sScanner()
    scanner._check_pod_security(namespace)
    return scanner.export_report()["findings"]
