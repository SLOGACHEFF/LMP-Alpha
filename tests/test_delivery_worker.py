import pytest

from lmp_core.messaging.delivery import DeliveryWorker
from lmp_core.storage.message_store import SQLiteMessageStore


@pytest.mark.asyncio
async def test_delivery_worker_marks_durable_remote_acceptance_delivered():
    store = SQLiteMessageStore()
    store.store(sender="s", message_id="m1", recipient="r", body={"text": "hello"})

    async def sender(message):
        assert message.message_id == "m1"
        return True

    result = await DeliveryWorker(store, sender, worker_id="worker-a").run_once("r")
    assert (result.claimed, result.delivered, result.retried, result.failed, result.lease_lost) == (1, 1, 0, 0, 0)
    assert store.pending_for("r") == []
    store.close()


@pytest.mark.asyncio
async def test_delivery_worker_retries_failed_send_with_backoff():
    store = SQLiteMessageStore()
    store.store(sender="s", message_id="m1", recipient="r", body="hello")

    async def sender(_message):
        return False

    worker = DeliveryWorker(store, sender, worker_id="worker-a", base_retry_seconds=1)
    result = await worker.run_once("r")
    assert result.claimed == 1 and result.retried == 1
    assert result.delivered == result.failed == result.lease_lost == 0
    pending = store.pending_for("r")
    assert len(pending) == 1
    assert pending[0].attempts == 1
    assert pending[0].available_at > pending[0].created_at
    store.close()


@pytest.mark.asyncio
async def test_delivery_worker_marks_message_failed_after_attempt_limit():
    store = SQLiteMessageStore()
    store.store(sender="s", message_id="m1", recipient="r", body="hello")

    async def sender(_message):
        raise OSError("remote node unavailable")

    worker = DeliveryWorker(store, sender, worker_id="worker-a", max_attempts=1)
    result = await worker.run_once("r")
    assert result.claimed == 1 and result.failed == 1
    assert store.pending_for("r") == []
    store.close()


def test_delivery_worker_rejects_unsafe_configuration():
    store = SQLiteMessageStore()
    with pytest.raises(ValueError):
        DeliveryWorker(store, lambda _message: True, max_attempts=0)
    with pytest.raises(ValueError):
        DeliveryWorker(store, lambda _message: True, lease_seconds=0)
    store.close()
