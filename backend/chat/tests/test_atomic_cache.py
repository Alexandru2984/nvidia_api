from concurrent.futures import ProcessPoolExecutor
import multiprocessing

from chat.cache import AtomicFileCache


def _count_requests(directory):
    cache = AtomicFileCache(directory, {})
    first = cache.add('requests', 1, timeout=60)
    if not first:
        cache.incr('requests')
    for _ in range(39):
        cache.incr('requests')
    return first


def test_counters_are_atomic_across_worker_processes(tmp_path):
    directory = str(tmp_path / 'cache')
    with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context('fork')) as pool:
        created = list(pool.map(_count_requests, [directory] * 8))
    assert sum(created) == 1
    assert AtomicFileCache(directory, {}).get('requests') == 320
