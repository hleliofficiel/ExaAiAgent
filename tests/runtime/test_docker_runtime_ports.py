from exaaiagnt.runtime.docker_runtime import DockerRuntime


def test_port_bindings_use_container_port_keys() -> None:
    bindings = DockerRuntime._build_port_bindings(18080, 19090)

    assert bindings == {
        "18080/tcp": ("127.0.0.1", 18080),
        "19090/tcp": ("127.0.0.1", 19090),
    }
    # The Docker daemon rejects keys that embed the host IP, so every key must be
    # a bare "port/protocol" container reference.
    for key in bindings:
        port, _, protocol = key.partition("/")
        assert port.isdigit()
        assert protocol == "tcp"
