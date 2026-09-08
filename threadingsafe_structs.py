import threading
from typing import (
    Any,
    Callable,
    Iterable,
    Iterator,
    MutableMapping,
    Self,
    TypeVar,
)

import atomicx

# 说真的我也不知道他能不能跑
# 记得有空尝试实现一下 MutableMapping abc -- Cbscfe
K = TypeVar("K")
V = TypeVar("V")
D = TypeVar("D")


class concurrent_dict(MutableMapping[K, V]):  # noqa: N801
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
        # @functools.wraps(func)  # 会导致pyright报错无法识别隐式传递的self
        def wrapfunc(self: Self, *args, **kwargs):
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
        with self._lock_on_change:
            if self.capacity == capacity:  # DCL 检查喵
                return  # 虽然感觉没什么用但是写了更规范喵
            while self._ops_executing.load() > 0:
                pass
            self._is_changeing.store(True)
            self.capacity = capacity
            new_buckets: list[dict] = [dict() for _ in range(1 << self.capacity)]
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
        if not self._buckets_locks[suffix].acquire(not inaccurate):
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
                if not self._buckets_locks[suffix].acquire(not inaccurate):
                    continue
                try:
                    self._buckets[suffix].update(bucket_append)
                finally:
                    self._buckets_locks[suffix].release()

    @_non_atomised_wrapper
    def get(self, key, default: D = None, inaccurate: bool = False) -> D | V:
        h = hash(key)
        suffix = h & ((1 << self.capacity) - 1)
        if not self._buckets_locks[suffix].acquire(not inaccurate):
            return  # pyright: ignore[reportReturnType]
        try:
            if default is None:
                return self._buckets[suffix][key]
            value = self._buckets[suffix].get(key, default)
            return value
        finally:
            self._buckets_locks[suffix].release()

    @_non_atomised_wrapper
    def gets(self, keys: Iterable[Any], default=None, inaccurate: bool = False):
        keys_bucket = [list() for _ in range(1 << self.capacity)]
        for key in keys:
            h = hash(key)
            suffix = h & ((1 << self.capacity) - 1)
            keys_bucket[suffix].append(key)
        results = {}
        for suffix, keys_need_get in enumerate(keys_bucket):
            if keys_need_get:
                if not self._buckets_locks[suffix].acquire(blocking = not inaccurate):  # fmt: skip
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
        if not self._buckets_locks[suffix].acquire(not inaccurate):
                return
        try:
                if key in self._buckets[suffix]:
                    del self._buckets[suffix][key]
                elif not slient:
                    raise KeyError(f"{key} not found in the concurrent dict")
        finally:
                self._buckets_locks[suffix].release()

    @_non_atomised_wrapper
    def items(self, inaccurate: bool = False):
        for bucket_index in range(1 << self.capacity):
            if not self._buckets_locks[bucket_index].acquire(not inaccurate):
                yield []
                continue
            try:
                items_snap = list(self._buckets[bucket_index].items())
            finally:
                self._buckets_locks[bucket_index].release()
            yield items_snap

    @_non_atomised_wrapper
    def to_dict(self) -> dict[K, V]:
        res = {}
        state = [False] * (1 << self.capacity)
        while True:
            for index, (bucket, lock) in enumerate(
                zip(self._buckets, self._buckets_locks)
            ):
                if state[index]:
                    continue
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
                if state[index]:
                    continue
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

    # 临时实现
    __len__ = size
    __getitem__ = get
    __delitem__ = remove
    __setitem__ = put

    def __iter__(self) -> Iterator[K]:
        return self.to_dict().__iter__()


if __name__ == "__main__":
    cd: concurrent_dict[str, str] = concurrent_dict()

    cd.put("key1", "value1")
    cd["key2"] = "value2"
    print(cd["key1"])
    cd.change_capacity(16)
    print(cd.get("key3", "default_value"))
    print(cd.to_dict())
    for key in cd:
        print(key)

    del cd["key1"] 
    print(cd.get("key1", "default_value"))
    del cd["key2"]
    print(cd.get("key2"))  # 报错是正常的喵 应该报错
