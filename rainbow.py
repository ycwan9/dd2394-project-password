import argparse
import hashlib
from typing import Tuple, Dict, List, Iterable, Callable, Optional
import logging
import sys


from attacks.rainbow_table import RandomSeededRainbowTableMixin, DemoPrintingMixin, RainbowTable


# Combine mixins and base class based on arguments
def get_rainbow_table_class(use_random_seeds: bool, use_printing: bool):
    if use_random_seeds and use_printing:
        class CustomRainbowTable(RandomSeededRainbowTableMixin, DemoPrintingMixin, RainbowTable):
            pass
        return CustomRainbowTable
    elif use_random_seeds:
        class CustomRainbowTable(RandomSeededRainbowTableMixin, RainbowTable):
            pass
        return CustomRainbowTable
    elif use_printing:
        class CustomRainbowTable(DemoPrintingMixin, RainbowTable):
            pass
        return CustomRainbowTable
    else:
        return RainbowTable


def build_table_cli(args, hash_func):
    """Builds a rainbow table based on CLI arguments."""
    RainbowTableClass = get_rainbow_table_class(args.random_seeds is not None, args.print_steps)
    rainbow_table_obj = RainbowTableClass(args.charset.encode(), args.max_len, args.chain_len, hash_func)

    if args.random_seeds is not None:
        rainbow_table_obj.build_random_table(args.random_seeds)
    else:
        print("Enter seeds (one per line), press Ctrl+D (EOF) to finish:")
        rainbow_table_obj.build_table(l.rstrip("\r\n").encode() for l in sys.stdin)

    if args.table_file:
        with open(args.table_file, 'wb') as f:
            rainbow_table_obj.save_table(f)
        print(f"Rainbow table built and saved to {args.table_file}")
    else:
        print("Rainbow table built in memory.")


def crack_table_cli(args, hash_func):
    """Cracks hashes from stdin using a loaded rainbow table."""
    assert args.table_file, "Table file path (--table_file) is required for cracking mode."

    try:
        # Determine the class to use based on arguments for loading
        RainbowTableClass = get_rainbow_table_class(False, args.print_steps) # No random seeds when cracking

        with open(args.table_file, 'rb') as f:
             rainbow_table_obj = RainbowTableClass(args.charset.encode(), args.max_len, args.chain_len, hash_func, table_file=f)
        print(f"Rainbow table loaded from {args.table_file} with {len(rainbow_table_obj.table)} chains.")

        print("Enter hex hashes to crack (one per line), press Ctrl+D (EOF) to finish:")
        cracked_count = 0
        total_hashes = 0
        for line in sys.stdin:
            total_hashes += 1
            try:
                target_hash = bytes.fromhex(line.strip())
            except ValueError:
                print(f"Invalid hex hash: {line.strip()}")
            found_pwd = rainbow_table_obj.lookup_hash(target_hash)
            if found_pwd:
                print(f"Cracked {line.strip()}: {found_pwd.decode()}")
                cracked_count += 1
            else:
                print(f"Failed to crack {line.strip()}")
        print(f"\nCracked {cracked_count} out of {total_hashes} provided hashes.")

    except FileNotFoundError:
        print(f"Error: Table file not found at {args.table_file}")
        sys.exit(1)


def main(args_list=None):
    parser = argparse.ArgumentParser(
        description="Rainbow Table Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('mode', choices=['build', 'crack'], help='Mode of operation: build or crack.')
    parser.add_argument('-c', '--charset', type=str, default='ab', help='The character set to use for passwords.')
    parser.add_argument('-m', '--max-len', type=int, default=2, help='The maximum length of passwords.')
    parser.add_argument('-l', '--chain-len', type=int, default=3, help='The length of the chains in the rainbow table.')
    parser.add_argument('-a', '--hash-algorithm', type=str, default='sha1', choices=hashlib.algorithms_guaranteed,
                        help="Hash algorithm to use.")
    parser.add_argument('--table-file', '-f', type=str, help='Path to save/load the rainbow table file.')
    parser.add_argument('--random-seeds', '-r', type=int, help='Number of random seeds to generate (for build mode).')
    parser.add_argument('--print-steps', '-p', action='store_true', help='Print intermediate steps during chain building and cracking.')
    # Add argument for log level
    parser.add_argument('--log-level', '-L', type=str, default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).')


    args = parser.parse_args(args_list)

    # Configure logging
    logging.basicConfig(level=getattr(logging, args.log_level.upper()))

    # Get the selected hash function
    try:
        hash_func = lambda data: getattr(hashlib, args.hash_algorithm)(data).digest()
    except AttributeError:
        raise RuntimeError(f"Invalid hash algorithm '{args.hash_algorithm}'.")

    if args.mode == 'build':
        build_table_cli(args, hash_func)
    elif args.mode == 'crack':
        crack_table_cli(args, hash_func)


if __name__ == "__main__":
    main()


# Example of how to run the main function in Colab:
# To build a table with seeds 'a' and 'b' and save it to 'my_table.pkl':
# main(['build', '--seeds', 'a,b', '--table_file', 'my_table.pkl'])

# To build a table with 100 random seeds and save it:
# main(['build', '--random_seeds', '100', '--table_file', 'random_table.pkl'])

# To load a table and crack a hash (replace with a real hash from your built table):
# main(['crack', '--table_file', 'my_table.pkl'])
# Then, when prompted, enter the hex hash and press Enter.

# To build a table with printing enabled:
# main(['build', '--seeds', 'a,b', '--print_steps'])

# To crack a hash with printing enabled (requires loading a table first):
# main(['crack', '--table_file', 'my_table.pkl', '--print_steps'])
# Then, when prompted, enter the hex hash and press Enter.

# Note: When running in a non-interactive environment like a script or Colab cell,
# reading from stdin with `input()` might behave differently or require specific
# handling. For simple testing in Colab, you can manually type input and press Enter.
# For automated testing, you might need to pipe input or use a different approach.

# Example of running build mode with random seeds directly in Colab:
# main(['build', '--random_seeds', '10', '--charset', 'abc', '--max_len', '3', '--chain_len', '5'])

# Example of running crack mode with a pre-built table file:
# First, build a table and save it:
# main(['build', '--seeds', 'a,b,c', '--table_file', 'small_table.pkl'])
# Then, run crack mode (you will be prompted to enter hashes):
# main(['crack', '--table_file', 'small_table.pkl'])
# Enter a hash like 'a' -> hash -> copy hex output -> paste into crack prompt.

# To run the main function with arguments in Colab:
# main(['build', '--random_seeds', '100', '--table_file', 'random_table.pkl'])
# main(['crack', '--table_file', 'random_table.pkl', '--print_steps']) # Example cracking with printing
