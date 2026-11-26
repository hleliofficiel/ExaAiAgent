import asyncio
import threading
from queue import Queue

import pytest

from exaaiagnt.llm.llm_traffic_controller import (
    get_traffic_controller,
    reset_traffic_controller,
)

_KEEPERS = []


async def test_cancelled_queued_request_is_skipped() -> None:
    """A caller cancelled while queued must not burn an LLM call (no duplicates)."""
    reset_traffic_controller()
    controller = get_traffic_controller()
    controller.set_base_delay(0.0)

    started = asyncio.Event()
    release = asyncio.Event()

    async def blocker():
        started.set()
        await release.wait()
        return "first"

    ran = []

    async def second():
        ran.append(1)
        return "second"

    task1 = asyncio.create_task(controller.queue_request(blocker, agent_id="a1"))
    await started.wait()

    task2 = asyncio.create_task(controller.queue_request(second, agent_id="a2"))
    for _ in range(10):  # let task2 enqueue
        await asyncio.sleep(0)
    task2.cancel()

    release.set()
    assert await task1 == "first"
    for _ in range(10):
        await asyncio.sleep(0)

    assert not ran
    assert task2.cancelled()


async def test_transient_error_retries_at_most_three_attempts(monkeypatch) -> None:
    """One retry layer only: 2 retries = 3 total attempts, no tenacity multiply."""
    reset_traffic_controller()
    controller = get_traffic_controller()
    controller.set_base_delay(0.0)

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)

    calls = []

    async def flaky():
        calls.append(1)
        raise ConnectionError("boom")

    with pytest.raises(ConnectionError):
        await controller.queue_request(flaky, agent_id="x")

    assert len(calls) == 3


def test_controller_instances_are_distinct_per_event_loop() -> None:
    """get_traffic_controller must not hand the same instance to two loops."""
    reset_traffic_controller()

    async def controller_id() -> int:
        controller = get_traffic_controller()
        _KEEPERS.append(controller)
        return id(controller)

    main_loop = asyncio.new_event_loop()
    try:
        main_id = main_loop.run_until_complete(controller_id())
    finally:
        main_loop.close()

    results: Queue[int] = Queue()

    def worker() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results.put(loop.run_until_complete(controller_id()))
        finally:
            loop.close()

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=10)

    worker_id = results.get(timeout=5)
    assert main_id != worker_id
