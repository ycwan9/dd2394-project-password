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
        self.logger.debug("Building chain starting from: %s", start_pwd)
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
        self.logger.info("Building rainbow table")
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
