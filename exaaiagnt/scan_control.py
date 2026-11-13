"""Module-level scan stop signal for the dashboard /api/scan/stop endpoint.

The dashboard runs in a background thread of the same process as the scan, so a
process-local threading.Event is sufficient and honest: it cannot stop a scan
running in another process, and it does not pretend to.
"""

import threading


_stop_event = threading.Event()


class StopScan(Exception):  # noqa: N818 - contract-mandated name
    """Raised at a tool-call boundary when a scan stop has been requested."""


def request_stop() -> None:
    _stop_event.set()


def should_stop() -> bool:
    return _stop_event.is_set()


def clear() -> None:
    _stop_event.clear()
