import functools
import threading
from typing import Callable, Self

import atomicx

class concurrent_dict:  # noqa: N801
    def __init__(
        self,
        default_capacity: int = 8,  # 2的幂次喵 并非是8个桶 是指2**8个桶喵
    ):
        self.capacity = default_capacity
        self._entry_count = atomicx.AtomicInt()
        self._buckets: list[dict] = [dict() for _ in range(1 << self.capacity)]
        self._buckets_locks: list[threading.Lock] = [
            threading.Lock() for _ in range(1 << self.capacity)
        ]
        self._lock_on_change = threading.Lock()
        self._ops_executing = atomicx.AtomicInt()
        self._is_changeing = atomicx.AtomicBool(False)

    @staticmethod
    def _non_atomised_wrapper(func: Callable):
        @functools.wraps(func)
        def wrapfunc(self: Self, *args, **kwargs):  # pyright: ignore[reportRedeclaration]
            while self._is_changeing.load():
                pass
            self._ops_executing.inc()
            try:
                res = func(self, *args, **kwargs)
            finally:
                self._ops_executing.dec()
            return res

        return wrapfunc

    def change_capacity(self, capacity: int):
        if self.capacity == capacity:  # DCL 检查喵
            return  # 虽然感觉没什么用但是写了更规范喵

        # 需要对这一段到底在干什么做出解释，我不明白 -- Cbscfe
        with self._lock_on_change:
            while self._ops_executing.load() > 0:
                pass
            self._is_changeing.store(True)
            self.capacity = capacity
            new_buckets: list[dict] = [
                dict() for _ in range(1 << self.capacity)
            ]
            for bucket in self._buckets:
                for key, value in bucket.items():
                    h = hash(key)
                    suffix = h & ((1 << self.capacity) - 1)
                    new_buckets[suffix][key] = value
            self._buckets = new_buckets
            self._buckets_locks: list[threading.Lock] = [
                threading.Lock() for _ in range(1 << self.capacity)
            ]
            self._is_changeing.store(False)

    @_non_atomised_wrapper
    def put(self, key, value):
        h = hash(key)
        suffix = h & ((1 << self.capacity) - 1)
        with self._buckets_locks[suffix]:
            if key not in self._buckets[suffix]:
                self._entry_count.inc()
            self._buckets[suffix][key] = value

    @_non_atomised_wrapper
    def get(self, key, default=None):
        h = hash(key)
        suffix = h & ((1 << self.capacity) - 1)
        with self._buckets_locks[suffix]:
            if default is None:
                return self._buckets[suffix][key]
            value = self._buckets[suffix].get(key, default)
            return value

    @_non_atomised_wrapper
    def rmv(self, key):
        h = hash(key)
        suffix = h & ((1 << self.capacity) - 1)
        with self._buckets_locks[suffix]:
            del self._buckets[suffix][key]  # 有可能抛异常喵
        self._entry_count.dec()

    @_non_atomised_wrapper
    def rmv_slient(self, key):
        h = hash(key)
        suffix = h & ((1 << self.capacity) - 1)
        with self._buckets_locks[suffix]:
            if key in self._buckets[suffix]:
                del self._buckets[suffix][key]
                self._entry_count.dec()

    @_non_atomised_wrapper
    def items_inaccurate(self, last_bucket_index: int = 0):
        """
        遍历字典某个桶里的所有键值对喵
        (注: 不保证一次能遍历所有键值对 有锁占用的会直接跳过喵 为了高性能)
        """
        if last_bucket_index >= (1 << self.capacity):
            last_bucket_index = 0
        if not self._buckets_locks[last_bucket_index].acquire(blocking=False):
            return last_bucket_index + 1, [], False
        try:
            items_snap = list(self._buckets[last_bucket_index].items())
        finally:
            self._buckets_locks[last_bucket_index].release()
        return last_bucket_index + 1, items_snap, True

    @_non_atomised_wrapper
    def rmv_inaccurate(self, key):
        h = hash(key)
        suffix = h & ((1 << self.capacity) - 1)
        if not self._buckets_locks[suffix].acquire(blocking=False):
            return False
        try:
            if key in self._buckets[suffix]:
                del self._buckets[suffix][key]
                self._entry_count.dec()
        finally:
            self._buckets_locks[suffix].release()
        return True

    @_non_atomised_wrapper
    def to_dict(self):
        res = {}
        state = [False] * (1 << self.capacity)
        while True:
            for index, (bucket, lock) in enumerate(
                zip(self._buckets, self._buckets_locks)
            ):
                if not lock.acquire(blocking=False):
                    continue
                try:
                    res.update(bucket)
                    state[index] = True
                finally:
                    lock.release()
            if all(state):
                break
        return res

    @_non_atomised_wrapper
    def clear(self):
        self._entry_count.set(0)
        state = [False] * (1 << self.capacity)
        while True:
            for index, (bucket, lock) in enumerate(
                zip(self._buckets, self._buckets_locks)
            ):
                if not lock.acquire(blocking=False):
                    continue
                try:
                    bucket.clear()
                    state[index] = True
                finally:
                    lock.release()
            if all(state):
                break
        self._entry_count.set(0)

    def size(self):
        return self._entry_count.load()

    def is_empty(self):
        return self._entry_count.load() == 0


# 读完了喵? 是的就这些注释了喵

if __name__ == "__main__":
    cd = concurrent_dict()
    cd.put("key1", "value1")
    cd.put("key2", "value2")
    print(cd.get("key1"))
    cd.change_capacity(16)
    print(cd.get("key3", "default_value"))
    cd.rmv("key1")
    print(cd.get("key1", "default_value"))
    cd.rmv_slient("key2")
    print(cd.get("key2"))  # 报错是正常的喵 应该报错
