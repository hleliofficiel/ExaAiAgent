from exaaiagnt.safety import TargetScope, guard_command, guard_argv


def test_scope_allow():
    sc = TargetScope.from_targets(["https://example.com"])
    assert sc.check_url("https://example.com/path").allow
    assert not sc.check_url("https://evil.com/").allow
    assert not sc.check_host("10.0.0.1").allow


def test_scope_path():
    sc = TargetScope.from_targets(["https://example.com"])
    assert sc.check_path("/workspace/foo").allow
    assert not sc.check_path("/etc/passwd").allow
    assert not sc.check_path("../secret").allow


def test_command_guard():
    sc = TargetScope.from_targets(["https://example.com"])
    assert guard_argv(["nmap", "-sV", "example.com"], sc).allow
    assert not guard_command("rm -rf /", sc).allow
    assert not guard_argv(["evilbinary", "x"], sc).allow
