import functools
import threading
from typing import Callable, Self, Any, Iterable, Literal

import atomicx

class concurrent_dict:  # noqa: N801
    def __init__(
        self,
        default_capacity: int = 8,  # 2的幂次喵 并非是8个桶 是指2**8个桶喵
    ):
        self.capacity = default_capacity
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
        # 需要对这一段到底在干什么做出解释，我不明白 -- Cbscfe
        with self._lock_on_change:
            if self.capacity == capacity:  # DCL 检查喵
                return  # 虽然感觉没什么用但是写了更规范喵
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
    def put(self, key, value, inaccurate: bool = False):
        h = hash(key)
        suffix = h & ((1 << self.capacity) - 1)
        if not self._buckets_locks[suffix].acquire(blocking=not inaccurate):
            return
        try:
            self._buckets[suffix][key] = value
        finally:
            self._buckets_locks[suffix].release()

    @_non_atomised_wrapper
    def puts(self, items: list[tuple[Any, Any]], inaccurate: bool = False):
        pre_calc_buckets = [dict() for _ in range(1 << self.capacity)]
        for key, value in items:
            h = hash(key)
            suffix = h & ((1 << self.capacity) - 1)
            pre_calc_buckets[suffix][key] = value
        for suffix, bucket_append in enumerate(pre_calc_buckets):
            if bucket_append:
                if not self._buckets_locks[suffix].acquire(blocking=not inaccurate):
                    continue
                try:
                    self._buckets[suffix].update(bucket_append)
                finally:
                    self._buckets_locks[suffix].release()
    
    @_non_atomised_wrapper
    def get(self, key, default = None, inaccurate: bool = False):
        h = hash(key)
        suffix = h & ((1 << self.capacity) - 1)
        if not self._buckets_locks[suffix].acquire(blocking=not inaccurate):
            return
        try:
            if default is None:
                return self._buckets[suffix][key]
            value = self._buckets[suffix].get(key, default)
            return value
        finally:
            self._buckets_locks[suffix].release()

    @_non_atomised_wrapper
    def gets(self, keys: Iterable[Any], default = None, inaccurate: bool = False):
        keys_bucket = [list() for _ in range(1 << self.capacity)]
        for key in keys:
            h = hash(key)
            suffix = h & ((1 << self.capacity) - 1)
            keys_bucket[suffix].append(key)
        results = {}
        for suffix, keys_need_get in enumerate(keys_bucket):
            if keys_need_get:
                if not self._buckets_locks[suffix].acquire(blocking=not inaccurate):
                    return
                try:
                    if default is None:
                        return self._buckets[suffix][key]
                    value = self._buckets[suffix].get(key, default)
                    results[key] = value
                finally:
                    self._buckets_locks[suffix].release()
    
    @_non_atomised_wrapper
    def remove(self, key, slient: bool = False, inaccurate: bool = False):
        h = hash(key)
        suffix = h & ((1 << self.capacity) - 1)
        with self._buckets_locks[suffix]:
            if not self._buckets_locks[suffix].acquire(blocking=not inaccurate):
                return
            try:
                if key in self._buckets[suffix]:
                    del self._buckets[suffix][key]
                elif not slient:
                    raise KeyError(f'{key} not found in the concurrent dict')
            finally:
                self._buckets_locks[suffix].release()

    @_non_atomised_wrapper
    def items(self, inaccurate: bool = False):
        for bucket_index in range(1 << self.capacity):
            if not self._buckets_locks[bucket_index].acquire(blocking=not inaccurate):
                yield []
            try:
                items_snap = list(self._buckets[bucket_index].items())
            finally:
                self._buckets_locks[bucket_index].release()
            yield items_snap
    
    @_non_atomised_wrapper
    def to_dict(self):
        res = {}
        state = [False] * (1 << self.capacity)
        while True:
            for index, (bucket, lock) in enumerate(
                zip(self._buckets, self._buckets_locks)
            ):
                if state[index]: continue
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
        state = [False] * (1 << self.capacity)
        while True:
            for index, (bucket, lock) in enumerate(
                zip(self._buckets, self._buckets_locks)
            ):
                if state[index]: continue
                if not lock.acquire(blocking=False):
                    continue
                try:
                    bucket.clear()
                    state[index] = True
                finally:
                    lock.release()
            if all(state):
                break

    def size(self):
        return sum(len(bucket) for bucket in self._buckets)

    def is_empty(self):
        return self.size() == 0

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
