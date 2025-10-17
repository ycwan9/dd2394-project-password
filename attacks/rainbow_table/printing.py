#!/usr/bin/env python3
from typing import Tuple, Dict, List, Iterable, Callable, Optional


class DemoPrintingMixin():
    """
    A mixin class to add printing of intermediate steps during chain building and cracking.
    This is for demonstration and debugging purposes.
    """

    def build_chain(self, start_pwd: bytes) -> Tuple[bytes, bytes]:
        """
        Build a chain starting from start_pwd with printing of steps.
        """
        print(f"\n--- Building chain starting from: {start_pwd.decode()} ---")
        cur = start_pwd
        for i in range(self.chain_len):
            h = self.hash_function(cur)
            print(f"Step {i}: Password: {cur.decode()} -> Hash: {h.hex()}")
            cur = self.reduction_function(h)
            print(f"Step {i}: Reduced Hash -> Password: {cur.decode()}")
        print(f"--- Chain built: Start: {start_pwd.decode()} -> End: {cur.decode()} ---")
        return (start_pwd, cur)

    def lookup_hash(self, target_hash: bytes) -> bytes:
        """
        Try to find a password that hashes to target_hash with printing of steps.
        """
        print(f"\n--- Looking up hash: {target_hash.hex()} ---")
        cur_hash = target_hash
        for i in range(self.chain_len):
            print(f"Lookup Step {i}: Current hash: {cur_hash.hex()}")
            candidate = self.reduction_function(cur_hash)
            print(f"Lookup Step {i}: Reduced hash -> Candidate password: {candidate.decode()}")

            if candidate in self.table:
                print(f"Lookup Step {i}: Candidate '{candidate.decode()}' found in table. Recreating chain...")
                start = self.table[candidate]
                cur = start
                print(f"Lookup Step {i}: Starting chain recreation from: {start.decode()}")
                for k in range(self.chain_len):
                    h = self.hash_function(cur)
                    print(f"Lookup Step {i}, Chain Step {k}: Password: {cur.decode()} -> Hash: {h.hex()}")
                    if h == target_hash:
                        print(f"Lookup Step {i}, Chain Step {k}: Target hash matched! Found password: {cur.decode()}")
                        return cur  # found
                    cur = self.reduction_function(h)
                    print(f"Lookup Step {i}, Chain Step {k}: Reduced Hash -> Password: {cur.decode()}")

            cur_hash = self.hash_function(candidate)
            print(f"Lookup Step {i}: Candidate not found in table. Hashing candidate for next step: {cur_hash.hex()}")


        print("--- Lookup failed: Password not found ---")
        return None
