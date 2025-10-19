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
            cur = self.reduction_function(h, i) # Pass the chain position
            print(f"Step {i}: Reduced Hash -> Password: {cur.decode()}")
        print(f"--- Chain built: Start: {start_pwd.decode()} -> End: {cur.decode()} ---")
        return (start_pwd, cur)


    def lookup_hash(self, target_hash: bytes) -> bytes:
        """
        Try to find a password that hashes to target_hash with printing of steps.
        """
        print(f"\n--- Looking up hash: {target_hash.hex()} ---")
        # For each possible position in the chain (work backwards)
        for i in range(self.chain_len - 1, -1, -1):
            print(f"Lookup Attempt starting from simulated position: {i}")
            # Start with the target_hash as if it appears at position i
            simulated_hash = target_hash

            # Simulate the remainder of the chain from position i to the chain end
            # At each step: reduce(simulated_hash, pos) -> candidate_plain, then
            # simulated_hash = hash_function(candidate_plain)
            end_candidate_plain = None
            for pos in range(i, self.chain_len):
                print(f"Lookup Step {i}, Simulation Step {pos}: Current hash: {simulated_hash.hex()}")
                candidate_plain = self.reduction_function(simulated_hash, pos) # Pass the position here
                print(f"Lookup Step {i}, Simulation Step {pos}: Reduced hash -> Candidate password: {candidate_plain.decode()}")
                simulated_hash = self.hash_function(candidate_plain)
                end_candidate_plain = candidate_plain


            # end_candidate_plain is the plaintext at the end of the simulated chain
            print(f"Lookup Step {i}: End candidate from simulation: {end_candidate_plain.decode()}")
            if end_candidate_plain in self.table:
                print(f"Lookup Step {i}: Candidate '{end_candidate_plain.decode()}' found in table. Recreating chain...")
                start_plain = self.table[end_candidate_plain]
                cur = start_plain
                print(f"Lookup Step {i}: Starting chain recreation from: {start_plain.decode()}")
                for k in range(self.chain_len):
                    h = self.hash_function(cur)
                    print(f"Lookup Step {i}, Chain Step {k}: Password: {cur.decode()} -> Hash: {h.hex()}")
                    if h == target_hash:
                        print(f"Lookup Step {i}, Chain Step {k}: Target hash matched! Found password: {cur.decode()}")
                        return cur  # found
                    cur = self.reduction_function(h, k) # Pass the position here
                    print(f"Lookup Step {i}, Chain Step {k}: Reduced Hash -> Password: {cur.decode()}")

            # If not found in the rebuilt chain, continue to the next starting position simulation
            print(f"Lookup Step {i}: No matching hash found. Continuing to next simulated position.")


        print("--- Lookup failed: Password not found ---")
        return None
