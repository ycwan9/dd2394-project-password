#!/usr/bin/env python3
from typing import Tuple, Dict, List, Iterable, Callable, Optional


class LookupBenchmarkMixin():
    """
    A mixin class to benchmark the lookup process by counting reduction function calls.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._reduction_calls = 0

    def reduction_function(self, hash: bytes, position: int = 0) -> bytes:
        """
        Overrides the reduction function to count calls.
        """
        self._reduction_calls += 1
        return super().reduction_function(hash, position)

    def lookup_hash(self, target_hash: bytes) -> Tuple[Optional[bytes], int]:
        """
        Overrides the lookup function to return the found password and the reduction call count.
        """
        self._reduction_calls = 0  # Reset the counter before each lookup
        found_pwd = super().lookup_hash(target_hash)
        return found_pwd, self._reduction_calls
