import asyncio
import threading
from queue import Queue

from exaaiagnt.llm.llm_traffic_controller import (
    _controllers_by_loop,
    get_traffic_controller,
    reset_traffic_controller,
)


_KEEPERS = []


def test_get_traffic_controller_is_scoped_per_event_loop() -> None:
    reset_traffic_controller()

    main_loop = asyncio.new_event_loop()
    try:
        main_result = main_loop.run_until_complete(_get_controller_info())
    finally:
        main_loop.close()

    results: Queue[tuple[int, int]] = Queue()

    def worker() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results.put(loop.run_until_complete(_get_controller_info()))
        finally:
            loop.close()

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=10)

    worker_result = results.get(timeout=5)

    assert main_result[0] != worker_result[0]
    assert len(_controllers_by_loop) >= 2


async def _get_controller_info() -> tuple[int, int]:
    loop = asyncio.get_running_loop()
    controller = get_traffic_controller()
    _KEEPERS.append(controller)
    return id(loop), id(controller)
