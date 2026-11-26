from types import SimpleNamespace

from exaaiagnt.runtime import docker_runtime as dr
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


def test_create_container_run_kwargs(monkeypatch) -> None:
    captured = {}

    class FakeImage:
        id = "img"
        attrs = {"Id": "img"}

    class FakeContainers:
        def get(self, name):
            raise dr.NotFound("no such container")

        def run(self, image, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(id="cid", attrs={})

    class FakeImages:
        def get(self, name):
            return FakeImage()

    client = SimpleNamespace(containers=FakeContainers(), images=FakeImages())
    monkeypatch.setattr(dr.docker, "from_env", lambda: client)

    runtime = DockerRuntime()
    monkeypatch.setattr(runtime, "_initialize_container", lambda *args: None)

    runtime._create_container_with_retry("scan-x")

    ports = captured["ports"]
    for key, value in ports.items():
        port, _, protocol = key.partition("/")
        assert port.isdigit() and protocol == "tcp"
        assert value[0] == "127.0.0.1"  # bound to localhost only

    # sudo in the sandbox entrypoint cannot elevate under no-new-privileges;
    # setting it makes the container exit during startup.
    assert "no-new-privileges:true" not in (captured.get("security_opt") or [])
