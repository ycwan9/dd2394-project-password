#!/usr/bin/env python3
import hashlib
import itertools
from typing import Tuple, Dict, List, Iterable, Callable, Optional
import pickle # Import the pickle module
from abc import ABC, abstractmethod # Import necessary modules for abstract classes
import logging # Import logging module

class BaseRainbowTable(ABC): # Inherit from ABC to make it an abstract base class
    """
    Base class for Rainbow Table implementations.

    This class provides the core structure and common methods for building and
    using rainbow tables, leaving the specific reduction function to be
    implemented by subclasses.
    """
    def __init__(self, charset: bytes, max_len: int, chain_len: int, hash_function: Callable[[bytes], bytes], file_object: Optional = None):
        """
        Initializes a BaseRainbowTable object.

        Args:
            charset: The byte string containing the characters allowed in passwords.
            max_len: The maximum length of passwords to consider.
            chain_len: The length of the chains in the rainbow table.
            hash_function: A callable that takes bytes and returns bytes (e.g., hashlib.sha1().digest).
            file_object: An optional file-like object to load the rainbow table from.
        """
        self.charset = charset
        self.max_len = max_len
        self.chain_len = chain_len
        self.hash_function = hash_function
        self.logger = logging.getLogger(self.__class__.__name__) # Initialize logger with class name


        if file_object:
            self.load_table(file_object)
        else:
            self.table: Dict[bytes, bytes] = {}


    @abstractmethod
    def reduction_function(self, hash: bytes) -> bytes:
        """
        Abstract method for the reduction function.
        This method should be implemented by subclasses.
        """
        raise NotImplementedError("Subclass must implement abstract method")


    def build_chain(self, start_pwd: bytes) -> Tuple[bytes, bytes]:
        """
        Build a chain starting from start_pwd.
        Return (start_pwd, end_value) where end_value is the final reduced password after chain_len steps.
        """
        cur = start_pwd
        for _ in range(self.chain_len):
            h = self.hash_function(cur)
            cur = self.reduction_function(h) # Call the reduction function (implemented in child class)
        return (start_pwd, cur)


    def build_table(self, seeds: Iterable[bytes]):
        """
        Build a tiny rainbow table as a dict mapping end_of_chain -> start_of_chain.
        (Many practical rainbow tables store many chains and use multiple reduction functions;
        this is a simplified version.)
        """
        self.table = {}
        for pwd in seeds:
            start, end = self.build_chain(pwd)
            self.table[end] = start

    def save_table(self, file_object):
        """Saves the rainbow table to a file-like object."""
        pickle.dump(self.table, file_object)

    def load_table(self, file_object):
        """Loads a rainbow table from a file-like object."""
        self.table = pickle.load(file_object)


    def lookup_hash(self, target_hash: bytes) -> bytes:
        """
        Try to find a password that hashes to target_hash using the rainbow table.
        Returns the found plaintext password or None.
        Optimized version.
        """
        cur_hash = target_hash
        for i in range(self.chain_len):
            # Apply reduction
            candidate = self.reduction_function(cur_hash) # Call the reduction function (implemented in child class)

            # Check if the candidate (which is an end-of-chain value in this logic) is in the table
            if candidate in self.table:
                # Recreate the chain from the matching start to find the exact password
                start = self.table[candidate]
                cur = start
                for k in range(self.chain_len):
                    h = self.hash_function(cur)
                    if h == target_hash:
                        return cur  # found
                    # Re-apply reduction using the same logic as when building the table
                    cur = self.reduction_function(h)

            # If not found, hash the candidate and continue the loop
            cur_hash = self.hash_function(candidate)

        return None

# Child class inheriting from BaseRainbowTable
class RainbowTable(BaseRainbowTable):
    """
    Concrete implementation of a Rainbow Table using a simple reduction function.

    This class extends BaseRainbowTable and provides a specific implementation
    for the abstract reduction_function.
    """
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


def run_demo():
    """
    Runs a demo of the RainbowTable class.
    """
    logging.basicConfig(level=logging.DEBUG)  # Set logging level to DEBUG
    
    # Redefine constants inside the function
    CHARSET = b"ab"            # tiny charset
    MAX_LEN = 2               # tiny length -> only 4 possible passwords: 'a','b','aa','ab','ba','bb' (actually 6 incl length 1 and 2)
    CHAIN_LENGTH = 3          # short chains for demo

    # Define a hash function that returns bytes
    def sha1_hash(data: bytes) -> bytes:
        return hashlib.sha1(data).digest()

    # Build the rainbow table with seeds 'a' and 'b' using the new class
    seeds = [b'a', b'b']
    rainbow_table_obj = RainbowTable(CHARSET, MAX_LEN, CHAIN_LENGTH, sha1_hash)
    rainbow_table_obj.build_table(seeds)

    print("Rainbow Table:")
    print(rainbow_table_obj.table)

    # Generate all possible passwords within the defined charset and max_len
    all_passwords = []
    for length in range(1, MAX_LEN + 1):
        for combo in itertools.product(CHARSET, repeat=length):
            all_passwords.append(bytes(combo))

    print("\nTesting all possible passwords:")
    cracked_count = 0
    total_passwords = len(all_passwords)

    # Test if the table can crack each password
    for pwd in all_passwords:
        hashed_pwd = sha1_hash(pwd)
        found_pwd = rainbow_table_obj.lookup_hash(hashed_pwd)

        if found_pwd:
            print(f"Password: {pwd.decode()} -> Cracked: {found_pwd.decode()}")
            cracked_count += 1
        else:
            print(f"Password: {pwd.decode()} -> Not cracked")

    print(f"\nCracked {cracked_count} out of {total_passwords} possible passwords.")


if __name__ == "__main__":
    # Run the demo
    run_demo()
