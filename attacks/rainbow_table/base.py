#!/usr/bin/env python3
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
    def __init__(self, chain_len: int, hash_function: Callable[[bytes], bytes], table_file: Optional = None):
        """
        Initializes a BaseRainbowTable object.

        Args:
            chain_len: The length of the chains in the rainbow table.
            hash_function: A callable that takes bytes and returns bytes (e.g., hashlib.sha1().digest).
            table_file: An optional file-like object to load the rainbow table from.
        """
        self.chain_len = chain_len
        self.hash_function = hash_function
        self.logger = logging.getLogger(self.__class__.__name__) # Initialize logger with class name


        if table_file:
            self.load_table(table_file)
        else:
            self.table: Dict[bytes, bytes] = {}


    @abstractmethod
    def reduction_function(self, hash: bytes, position: int = 0) -> bytes:
        """
        Abstract method for the reduction function.
        This method should be implemented by subclasses.

        Args:
            hash: The hash value to reduce.
            position: The position in the chain (0-indexed).

        Returns:
            The reduced password candidate as bytes.
        """
        raise NotImplementedError("Subclass must implement abstract method")


    def build_chain(self, start_pwd: bytes) -> Tuple[bytes, bytes]:
        """
        Build a chain starting from start_pwd.
        Return (start_pwd, end_value) where end_value is the final reduced password after chain_len steps.
        """
        self.logger.debug("Building chain starting from: %s", start_pwd)
        cur = start_pwd
        for i in range(self.chain_len):
            h = self.hash_function(cur)
            cur = self.reduction_function(h, i) # Pass the chain position
        return (start_pwd, cur)


    def build_table(self, seeds: Iterable[bytes]):
        """
        Build a tiny rainbow table as a dict mapping end_of_chain -> start_of_chain.
        (Many practical rainbow tables store many chains and use multiple reduction functions;
        this is a simplified version.)
        """
        self.logger.info("Building rainbow table.")
        self.table = {}
        for pwd in seeds:
            start, end = self.build_chain(pwd)
            self.table[end] = start


    def save_table(self, table_file):
        """Saves the rainbow table to a file-like object."""
        pickle.dump(self.table, table_file)
        self.logger.info("Rainbow table saved with %d chains.", len(self.table))


    def load_table(self, table_file):
        """Loads a rainbow table from a file-like object."""
        self.table = pickle.load(table_file)
        self.logger.info("Rainbow table loaded with %d chains.", len(self.table))

    def lookup_hash(self, target_hash: bytes) -> Optional[bytes]:
        """
        Try to find a password that hashes to target_hash using the rainbow table.
        Returns the found plaintext password (bytes) or None if not found.

        Algorithm:
        For each possible position i in [chain_len-1 .. 0]:
            - Assume target_hash is the hash at position i.
            - For j in [i .. chain_len-1]: reduce the hash (with position j) to a candidate
            plaintext, then hash that candidate to produce the next hash — this simulates
            continuing the chain to the end. The final plaintext is an end-of-chain candidate.
            - If that end-of-chain candidate is in the table, rebuild the chain from its start
            and check each step to see if any hash equals target_hash. If found, return the
            plaintext that produced that hash.
        """
        self.logger.info("Looking up hash: %s", target_hash.hex())

        # For each possible position in the chain (work backwards)
        for i in range(self.chain_len - 1, -1, -1):
            # Start with the target_hash as if it appears at position i
            simulated_hash = target_hash

            # Simulate the remainder of the chain from position i to the chain end
            # At each step: reduce(simulated_hash, pos) -> candidate_plain, then
            # simulated_hash = hash_function(candidate_plain)
            end_candidate_plain = None
            for pos in range(i, self.chain_len):
                candidate_plain = self.reduction_function(simulated_hash, pos)
                simulated_hash = self.hash_function(candidate_plain)
                end_candidate_plain = candidate_plain

            # end_candidate_plain is the plaintext at the end of the simulated chain
            if end_candidate_plain in self.table:
                # Found a chain whose end matches our simulated end — rebuild and scan it
                start_plain = self.table[end_candidate_plain]
                cur = start_plain
                for pos in range(self.chain_len):
                    h = self.hash_function(cur)
                    if h == target_hash:
                        self.logger.info("Found matching plaintext for hash: %s", target_hash.hex())
                        return cur
                    # advance chain
                    cur = self.reduction_function(h, pos)

                # If we didn't find the exact hash in this chain, continue searching
                self.logger.debug("Chain found but no matching hash inside it (end candidate: %s).",
                                end_candidate_plain)

        # Not found
        self.logger.info("Hash not found in rainbow table: %s", target_hash.hex())
        return None
