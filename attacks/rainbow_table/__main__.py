#!/usr/bin/env python3
import os
import argparse # Import the argparse module
import logging # Import logging module
import hashlib # Import hashlib to get available algorithms
import sys
import itertools

from . import RainbowTable, RandomSeededRainbowTable


def build_and_save_table(args, hash_func):
    """
    Builds the rainbow table based on arguments and optionally saves it.
    """
    CHARSET = args.charset.encode()
    MAX_LEN = args.max_len
    CHAIN_LENGTH = args.chain_len


    if args.random_seeds is not None:
        rainbow_table_obj = RandomSeededRainbowTable(CHARSET, MAX_LEN, CHAIN_LENGTH, hash_func)
        print(f"\nBuilding table with {args.random_seeds} random seeds.")
        rainbow_table_obj.build_random_table(args.random_seeds)

    else:
        seeds = [seed.encode() for seed in args.seeds.split(',')]
        rainbow_table_obj = RainbowTable(CHARSET, MAX_LEN, CHAIN_LENGTH, hash_func)
        print(f"\nBuilding table with provided seeds.")
        rainbow_table_obj.build_table(seeds)

    if args.save_path:
        print(f"\nSaving table to {args.save_path}")
        with open(args.save_path, 'wb') as f:
            rainbow_table_obj.save_table(f)
        print("Table saved.")

    return rainbow_table_obj # Return the built table object


def load_and_crack_passwords(args, hash_func, built_table_obj=None):
    """
    Loads a rainbow table from a file or uses a provided table object and cracks passwords.
    """
    CHARSET = args.charset.encode()
    MAX_LEN = args.max_len
    CHAIN_LENGTH = args.chain_len


    if args.load_path:
        print(f"\nLoading table from {args.load_path}")
        with open(args.load_path, 'rb') as f:
            loaded_rainbow_table_obj = RainbowTable(CHARSET, MAX_LEN, CHAIN_LENGTH, hash_func, table_file=f)
        print(f"Table loaded with {len(loaded_rainbow_table_obj.table)} chains.")
    elif built_table_obj:
        loaded_rainbow_table_obj = built_table_obj
        print("\nUsing in-memory built table for cracking.")
    else:
        print("\nNo table provided or loaded for cracking.")
        return # Exit if no table to crack with


    # Generate all possible passwords within the defined charset and max_len
    all_passwords = []
    for length in range(1, MAX_LEN + 1):
        for combo in itertools.product(CHARSET, repeat=length):
            all_passwords.append(bytes(combo))

    print("\nTesting all possible passwords with loaded table:")
    cracked_count = 0
    total_passwords = len(all_passwords)

    # Test if the loaded table can crack each password
    for pwd in all_passwords:
        hashed_pwd = hash_func(pwd) # Use the selected hash function
        found_pwd = loaded_rainbow_table_obj.lookup_hash(hashed_pwd)

        if found_pwd:
            print(f"Password: {pwd.decode()} -> Cracked: {found_pwd.decode()}")
            cracked_count += 1
        else:
            print(f"Password: {pwd.decode()} -> Not cracked")

    print(f"\nCracked {cracked_count} out of {total_passwords} possible passwords using loaded table.")


def run_save_load_demo(args_list=None):
    """
    Runs a demo of saving and loading the RainbowTable class.

    Args:
        args_list: A list of strings to be parsed as command-line arguments.
                   If None, uses sys.argv (standard command-line arguments).
    """
    # Define and parse arguments
    parser = argparse.ArgumentParser(
        description="Rainbow Table Save/Load Demo",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-c', '--charset', type=str, default='ab', help='The character set to use for passwords.')
    parser.add_argument('-m', '--max-len', type=int, default=2, help='The maximum length of passwords.')
    parser.add_argument('-l', '--chain-len', type=int, default=3, help='The length of the chains in the rainbow table.')
    parser.add_argument('-s', '--seeds', type=str, default='a,b', help='Comma-separated list of seeds to use.')
    parser.add_argument('-r', '--random-seeds', type=int, help='Number of random seeds to generate.')
    parser.add_argument('--log-level', type=str, default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).')
    parser.add_argument('--save-path', '-S', type=str, help='Path to save the rainbow table.')
    parser.add_argument('--load-path', '-L', type=str, help='Path to load the rainbow table from.')
    # Add argument for hash algorithm
    hash_algorithms = hashlib.algorithms_guaranteed # Use all guaranteed algorithms
    parser.add_argument('-a', '--hash-algorithm', type=str, default='sha1', choices=hash_algorithms,
                        help=f"Hash algorithm to use. Available: {', '.join(hash_algorithms)}")

    # Parse arguments from the provided list or sys.argv
    args = parser.parse_args(args_list)

    # Configure logging
    logging.basicConfig(level=getattr(logging, args.log_level.upper()))

    # Get the selected hash function
    try:
        hash_func = lambda data: getattr(hashlib, args.hash_algorithm)(data).digest()
    except AttributeError:
        raise RuntimeError(f"Error: Invalid hash algorithm '{args.hash_algorithm}'.")

    built_table = None
    if not args.load_path: # Only build if not loading from a file
        built_table = build_and_save_table(args, hash_func)
        if built_table is None: # Check if build failed
            return

    # Crack passwords using either the loaded table or the newly built table
    load_and_crack_passwords(args, hash_func, built_table_obj=built_table)


if __name__ == "__main__":
    # Run the demo
    run_save_load_demo(sys.argv[1:])

