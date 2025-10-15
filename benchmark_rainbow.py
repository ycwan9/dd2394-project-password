import timeit
import statistics
import argparse
import hashlib
import itertools
import logging # Import logging to suppress output
import random # Import random for Monte Carlo method

from attacks.rainbow_table import RandomSeededRainbowTable


def run_benchmark(args_list=None):
    """
    Runs a benchmark of the RainbowTable class.

    Args:
        args_list: A list of strings to be parsed as command-line arguments.
                   If None, uses sys.argv (standard command-line arguments).
    """
    # Define and parse arguments
    parser = argparse.ArgumentParser(description="Rainbow Table Benchmark")
    parser.add_argument('-c', '--charset', type=str, default='abcdefghijklmnopqrstuvwxyz', help='The character set to use for passwords.') # Enlarged charset
    parser.add_argument('-m', '--max-len', type=int, default=3, help='The maximum length of passwords.')
    parser.add_argument('-l', '--chain-len', type=int, default=10, help='The length of the chains in the rainbow table.')
    parser.add_argument('-r', '--random-seeds', type=int, default=2000, help='Number of random seeds to generate.') # Added default value
    parser.add_argument('-a', '--hash-algorithm', type=str, default='sha1', choices=hashlib.algorithms_guaranteed,
                        help="Hash algorithm to use")
    parser.add_argument('-k', '--cracking-method', type=str, default='montecarlo', choices=['all', 'montecarlo'], # Made montecarlo default
                        help='Method for cracking benchmark ("all" passwords or "montecarlo" simulation).')
    parser.add_argument('-s', '--montecarlo-samples', type=int, default=1000,
                        help='Number of samples to use for Monte Carlo cracking benchmark.')
    parser.add_argument('--log-level', type=str, default='ERROR', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).')

    # Parse arguments from the provided list or sys.argv
    args = parser.parse_args(args_list)

    # Configure logging
    logging.basicConfig(level=getattr(logging, args.log_level.upper()))

    CHARSET = args.charset.encode()
    MAX_LEN = args.max_len
    CHAIN_LENGTH = args.chain_len
    NUM_RANDOM_SEEDS = args.random_seeds

    # Get the selected hash function
    try:
        hash_func = lambda data: getattr(hashlib, args.hash_algorithm)(data).digest()
    except AttributeError:
        # print(f"Error: Invalid hash algorithm '{args.hash_algorithm}'.") # Do not print errors in benchmark
        return # Exit if invalid hash algorithm

    # Initialize the table object outside of timeit
    rainbow_table_obj = RandomSeededRainbowTable(CHARSET, MAX_LEN, CHAIN_LENGTH, hash_func)

    # Measure build time using timeit
    # Only time the call to build_random_table
    build_time = timeit.timeit(
        stmt=lambda: rainbow_table_obj.build_random_table(NUM_RANDOM_SEEDS),
        number=1
    )

    # Define generator for all possible passwords
    def all_passwords_generator():
        for length in range(1, MAX_LEN + 1):
            for combo in itertools.product(CHARSET, repeat=length):
                yield bytes(combo)

    # Define generator for Monte Carlo sampled passwords
    def monte_carlo_passwords_generator():
        """
        Generates random passwords by feeding random binary data into the reduction function.
        """
        for _ in range(args.montecarlo_samples):
            # Generate random binary data and use the reduction function to map it to a password candidate
            random_seed = random.getrandbits(256).to_bytes(32, 'big') # Generate 32 random bytes
            password_candidate = rainbow_table_obj.reduction_function(random_seed)
            yield password_candidate


    # Select the appropriate password generator based on cracking method
    if args.cracking_method == 'all':
        password_generator = all_passwords_generator()
    elif args.cracking_method == 'montecarlo':
        password_generator = monte_carlo_passwords_generator()
    else:
        assert False


    # Measure time to crack each password using timeit
    cracking_times = []
    cracked_count = 0 # Counter for cracked passwords

    # Convert generator to list to iterate multiple times if needed (though not needed for timeit(number=1))
    # This also allows getting the total number of passwords being cracked
    total_passwords_to_crack = 0


    for pwd in password_generator:
        total_passwords_to_crack += 1
        hashed_pwd = hash_func(pwd)

        # Use number=1 for measuring individual crack time
        try:
            start_time = timeit.default_timer() # Use default_timer for potentially better resolution
            found_pwd = rainbow_table_obj.lookup_hash(hashed_pwd)
            end_time = timeit.default_timer()
            cracking_times.append(end_time - start_time)

            if found_pwd:
                cracked_count += 1

        except Exception as e:
            raise RuntimeError() from e
            #pass


    # Calculate and print statistics
    if cracking_times:
        min_time = min(cracking_times)
        max_time = max(cracking_times)
        avg_time = statistics.mean(cracking_times)
        stdev_time = statistics.stdev(cracking_times) if len(cracking_times) > 1 else 0
        success_rate = (cracked_count / total_passwords_to_crack) * 100 if total_passwords_to_crack > 0 else 0


        print(f"Build time: {build_time:.6f}")
        print(f"Crack time (min): {min_time:.6f}")
        print(f"Crack time (max): {max_time:.6f}")
        print(f"Crack time (average): {avg_time:.6f}")
        print(f"Crack time (stdev): {stdev_time:.6f}")
        print(f"Cracking success rate: {success_rate:.2f}%")

    else:
        # print("No passwords to crack for the given parameters.") # Do not print in benchmark
        pass


if __name__ == "__main__":
    run_benchmark()
