import pytest
from exaaiagnt.prompts.auto_loader import detect_modules_from_target

def test_detect_graphql():
    target = "https://api.example.com/graphql"
    modules = detect_modules_from_target(target)
    assert "graphql_security" in modules

def test_detect_websocket():
    target = "wss://chat.example.com/socket"
    modules = detect_modules_from_target(target)
    assert "websocket_security" in modules

def test_detect_subdomain_takeover():
    target = "example.com"
    instruction = "enumerate subdomains and check for takeover"
    modules = detect_modules_from_target(target, instruction)
    assert "subdomain_takeover" in modules
    assert "subdomain_enumeration" in modules

def test_detect_kubernetes():
    target = "https://k8s-api.internal:6443"
    modules = detect_modules_from_target(target)
    assert "kubernetes_security" in modules

def test_detect_prompt_injection():
    target = "https://ai.example.com/chat"
    modules = detect_modules_from_target(target)
    assert "prompt_injection" in modules

def test_detect_recon_new_modules():
    target = "target.com"
    instruction = "perform full reconnaissance and port scanning"
    modules = detect_modules_from_target(target, instruction)
    assert "port_scanning" in modules
    assert "subdomain_enumeration" in modules


def test_detect_technology_fingerprinting():
    target = "target.com"
    instruction = "perform technology fingerprinting on the target"
    modules = detect_modules_from_target(target, instruction)
    assert "technology_fingerprinting" in modules
