#!/usr/bin/env python3
from typing import Callable, Optional

from .base import BaseRainbowTable


class RainbowTable(BaseRainbowTable):
    """
    Concrete implementation of a Rainbow Table using a simple reduction function.

    This class extends BaseRainbowTable and provides a specific implementation
    for the abstract reduction_function.
    """
    def __init__(self, charset: bytes, max_len: int, chain_len: int, hash_function: Callable[[bytes], bytes], table_file: Optional = None):
        """
        Initializes a RainbowTable object.

        Args:
            charset: The byte string containing the characters allowed in passwords.
            max_len: The maximum length of passwords to consider.
            chain_len: The length of the chains in the rainbow table.
            hash_function: A callable that takes bytes and returns bytes (e.g., hashlib.sha1().digest).
            table_file: An optional file-like object to load the rainbow table from.
        """
        super().__init__(chain_len, hash_function, table_file)
        self.charset = charset
        self.max_len = max_len

    def reduction_function(self, hash: bytes) -> bytes:
        """
        Very simple reduction function:
        - Use the hash to produce a number,
        - map that number into the space of possible passwords.
        Deterministic but toy — not cryptographically meaningful.
        """
        # take a few bytes, convert to int, map to string
        hash_int = int.from_bytes(hash, 'big')

        # number of total possible strings
        total_combinations = (len(self.charset) ** (self.max_len+1) - 1) // (len(self.charset) - 1)

        # mod by total number
        hash_int %= total_combinations

        # Map the integer to a byte string of length up to max_len
        num = hash_int
        charset_len = len(self.charset)

        # Loop over string lengths from 0 to max_len
        for length in range(self.max_len + 1):
            # Number of possible strings of this length
            total_combinations = charset_len ** length

            if num < total_combinations:
                # Find the string of the current length corresponding to `num`
                result = bytearray()
                for _ in range(length):
                    result.append(self.charset[num % charset_len])
                    num //= charset_len
                # The result list is in reverse order, so reverse it
                self.logger.debug("reduce: %s", result) # Add debug log here
                return bytes(result)

            # If `num` is larger than the current length's total combinations, reduce `num`
            num -= total_combinations

        raise RuntimeError("This should not be reached")

