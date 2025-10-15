#!/usr/bin/env python3
import logging
import hashlib
import itertools

from . import RainbowTable

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

