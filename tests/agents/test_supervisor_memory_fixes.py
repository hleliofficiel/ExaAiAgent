import asyncio
import time

import pytest

from exaaiagnt.agents.agent_supervisor import AgentStatus, AgentSupervisor
from exaaiagnt.agents.shared_memory import DataCategory, SharedMemory


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


@pytest.fixture
def sup():
    AgentSupervisor._instance = None
    s = AgentSupervisor()
    yield s
    AgentSupervisor._instance = None


@pytest.fixture
def mem():
    SharedMemory._instance = None
    m = SharedMemory()
    yield m
    SharedMemory._instance = None


def test_registered_agent_is_running_and_can_pause(sup):
    sup.register_agent("a1", "A")
    assert sup.get_health("a1").status == AgentStatus.RUNNING
    assert sup.pause_agent("a1") is True
    assert sup.resume_agent("a1") is True
    assert sup.get_status_summary()["running"] == 1


def test_status_summary_counts_every_status(sup):
    sup.register_agent("a1", "A")
    sup.update_status("a1", AgentStatus.PAUSED)
    s = sup.get_status_summary()
    assert s["paused"] == 1 and s["total"] == 1


def test_errors_are_consecutive_not_cumulative(sup):
    sup.register_agent("a1", "A")
    for _ in range(5):
        sup.record_error("a1", "x")
        sup.record_success("a1")
    assert sup.get_health("a1").status == AgentStatus.RUNNING
    assert sup.get_health("a1").error_count == 0
    for _ in range(3):
        sup.record_error("a1", "x")
    assert sup.get_health("a1").status == AgentStatus.FAILED


def test_waiting_agent_is_not_timed_out_or_woken(sup):
    state = _Obj(waiting_for_input=True, completed=False, stop_requested=False)
    woken = []
    state.resume_from_waiting = lambda *a, **k: woken.append(1)
    agent = _Obj(state=state)
    sup.register_agent("a1", "A", agent_instance=agent, timeout=1)
    sup.get_health("a1").last_activity = time.time() - 1000
    asyncio.run(sup._check_agent_health())
    assert sup.get_health("a1").status == AgentStatus.RUNNING
    assert woken == []
    assert sup.get_stuck_agents(threshold=1) == []


def test_truly_stuck_agent_is_flagged(sup):
    state = _Obj(waiting_for_input=False, completed=False, stop_requested=False)
    state.resume_from_waiting = lambda *a, **k: None
    sup.register_agent("a1", "A", agent_instance=_Obj(state=state), timeout=1)
    sup.get_health("a1").last_activity = time.time() - 1000
    assert sup.get_stuck_agents(threshold=1) == ["a1"]
    asyncio.run(sup._check_agent_health())
    assert sup.get_health("a1").timeout_count == 1


def test_expired_url_can_be_stored_again(mem):
    assert mem.store(DataCategory.URLS, "http://x/a", "http://x/a", "ag", ttl=0.01)
    assert not mem.store(DataCategory.URLS, "http://x/a", "http://x/a", "ag")
    time.sleep(0.05)
    assert mem.store(DataCategory.URLS, "http://x/a", "http://x/a", "ag")


def test_dedupe_set_cleared_on_retrieve_of_expired(mem):
    mem.store(DataCategory.ENDPOINTS, "GET:/a", {"path": "/a"}, "ag", ttl=0.01)
    time.sleep(0.05)
    assert mem.retrieve(DataCategory.ENDPOINTS, "GET:/a", "ag") is None
    assert mem.store(DataCategory.ENDPOINTS, "GET:/a", {"path": "/a"}, "ag")


def test_claim_unscanned_urls_is_exclusive(mem):
    mem.bulk_store_urls([f"http://x/{i}" for i in range(6)], "recon")
    a = mem.claim_unscanned_urls("agent_a", 4)
    b = mem.claim_unscanned_urls("agent_b", 4)
    assert len(a) == 4 and len(b) == 2
    assert not set(a) & set(b)
    assert mem.get_unscanned_urls("agent_a") == [u for u in mem.get_unscanned_urls("agent_a")]
    assert mem.claim_unscanned_urls("agent_a", 4) == []


def test_mark_scanned_hides_url(mem):
    mem.store(DataCategory.URLS, "u1", "u1", "r")
    mem.mark_scanned("u1", "a")
    assert mem.get_unscanned_urls("a") == []
    assert mem.get_unscanned_urls("b") == ["u1"]


def test_category_cap_evicts_oldest(mem):
    mem.MAX_ENTRIES_PER_CATEGORY = 10
    for i in range(25):
        mem.store(DataCategory.URLS, f"u{i}", f"u{i}", "r")
    assert mem.get_stats()["urls"] == 10
    assert mem.store(DataCategory.URLS, "u0", "u0", "r")  # evicted key is storable again
    mem.MAX_ENTRIES_PER_CATEGORY = 5000


def test_get_all_drops_expired_and_purge(mem):
    mem.store(DataCategory.URLS, "a", "a", "r", ttl=0.01)
    mem.store(DataCategory.URLS, "b", "b", "r")
    time.sleep(0.05)
    assert [e.key for e in mem.get_all(DataCategory.URLS, "r")] == ["b"]
    mem.store(DataCategory.URLS, "c", "c", "r", ttl=0.01)
    time.sleep(0.05)
    assert mem.purge_expired() == 1


def test_singletons_are_thread_safe():
    import threading

    AgentSupervisor._instance = None
    SharedMemory._instance = None
    out = []
    ts = [
        threading.Thread(target=lambda: out.append((id(AgentSupervisor()), id(SharedMemory()))))
        for _ in range(20)
    ]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(set(out)) == 1
