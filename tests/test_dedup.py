from lmp_core.messaging.deduplication import DedupCache


def test_dedup_cache_marks_repeat():
    cache = DedupCache(capacity=2)
    assert cache.seen_or_add("m1") is False
    assert cache.seen_or_add("m1") is True


def test_dedup_cache_is_bounded():
    cache = DedupCache(capacity=2)
    cache.seen_or_add("m1")
    cache.seen_or_add("m2")
    cache.seen_or_add("m3")
    assert len(cache._items) == 2


def test_repeated_id_refreshes_ttl_position():
    cache = DedupCache(capacity=2)
    assert cache.seen_or_add("m1") is False
    assert cache.seen_or_add("m2") is False
    assert cache.seen_or_add("m1") is True
    assert list(cache._items.keys()) == ["m2", "m1"]
