import json
import pytest
from unittest.mock import patch, MagicMock
from exaaiagnt.tools.k8s_scanner.k8s_actions import K8sScanner, Severity, CheckStatus

@pytest.fixture
def scanner():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="Client Version: v1.28.0", returncode=0)
        return K8sScanner()

def test_check_pod_security_privileged(scanner):
    mock_pods = {
        "items": [{
            "metadata": {"name": "privileged-pod"},
            "spec": {
                "containers": [{
                    "name": "hacker-container",
                    "securityContext": {"privileged": True}
                }]
            }
        }]
    }
    
    with patch.object(scanner, "_run_kubectl", return_value=mock_pods):
        findings = scanner.scan(namespaces=["default"])
        
        privileged_findings = [f for f in findings if f.check_id == "PSS-001"]
        assert len(privileged_findings) == 1
        assert privileged_findings[0].severity == Severity.HIGH
        assert "privileged" in privileged_findings[0].description

def test_check_secrets_plain_env(scanner):
    mock_pods = {
        "items": [{
            "metadata": {"name": "leaky-pod"},
            "spec": {
                "containers": [{
                    "name": "app-container",
                    "env": [
                        {"name": "DB_PASSWORD", "value": "p@ssword123"},
                        {"name": "SAFE_VAR", "value": "normal_value"}
                    ]
                }]
            }
        }]
    }
    
    with patch.object(scanner, "_run_kubectl", return_value=mock_pods):
        scanner.findings = [] # Clear findings
        scanner._check_secrets("default")
        
        secret_findings = [f for f in scanner.findings if f.check_id == "SEC-001"]
        assert len(secret_findings) == 1
        assert "DB_PASSWORD" in secret_findings[0].description

def test_check_network_policies_missing(scanner):
    mock_policies = {"items": []}
    
    with patch.object(scanner, "_run_kubectl", return_value=mock_policies):
        scanner.findings = []
        scanner._check_network_policies("default")
        
        net_findings = [f for f in scanner.findings if f.check_id == "NET-001"]
        assert len(net_findings) == 1
        assert net_findings[0].severity == Severity.MEDIUM
