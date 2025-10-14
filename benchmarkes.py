# benchmark.py
import time
import matplotlib.pyplot as plt

from attacks.brute_force_attack import (
    brute_force_hashed_with_salt,
    brute_force_hashed_no_salt,
    brute_force_plaintext,
)
from attacks.dictionary_attack import dictionary_attack
from attacks.rainbow_table_attacks import rainbow_table_attack, generate_rainbow_table
from utils.hashing import hash_password  # expects supported algos: sha1, sha224, md5

SUPPORTED_ALGOS = {"sha1", "sha224", "md5"}


def benchmark_attacks(target_password: str, salt: str | None, max_length: int, hash_algo: str):
    """
    Run each attack against the provided target and return a dict of elapsed times (seconds).
    Note: For hashed attacks we first compute the hash using utils.hashing.hash_password.
    """
    if hash_algo not in SUPPORTED_ALGOS:
        raise ValueError(f"Unsupported algorithm: {hash_algo}. Supported: {', '.join(sorted(SUPPORTED_ALGOS))}")

    print(f"🔧 Benchmarking attacks for algorithm={hash_algo} | max_length={max_length} | salt={'provided' if salt else 'none'}")
    # Compute the target hash (using the project's hashing util)
    target_hash = hash_password(target_password, hash_algo)

    results: dict[str, float] = {}

    # 1) Plaintext brute-force (compare plaintext)
    start = time.time()
    brute_force_plaintext(target_password, max_length)
    results["Brute Force (Plaintext)"] = time.time() - start

    # 2) Brute force (hashed, no salt)
    start = time.time()
    brute_force_hashed_no_salt(target_hash, max_length, hash_algo)
    results["Brute Force (Hashed, No Salt)"] = time.time() - start

    # 3) Brute force (hashed with salt) — only runs if salt provided
    if salt:
        start = time.time()
        # Our brute_force_hashed_with_salt signature: (hash_value, max_length, hash_algo, salt=None, ...)
        brute_force_hashed_with_salt(target_hash, max_length, hash_algo, salt=salt)
        results["Brute Force (Hashed with Salt)"] = time.time() - start
    else:
        results["Brute Force (Hashed with Salt)"] = float("nan")
        print("⚠️ Salt not provided: skipping salted brute-force (not feasible without salt).")

    # 4) Dictionary attack (uses project's dictionary attack; pass algorithm and optional salt)
    start = time.time()
    # dictionary_attack signature: dictionary_attack(hash_value, hash_algo, wordlist_file="wordlist.txt", salt=None)
    dictionary_attack(target_hash, hash_algo, wordlist_file="wordlist.txt", salt=salt)
    results["Dictionary Attack"] = time.time() - start

    # 5) Rainbow table attack — generate (or load) then lookup
    # generate_rainbow_table(hash_algo, wordlist_file="wordlist.txt", table_file="rainbow_table.pkl", salt=None)
    rainbow_table = generate_rainbow_table(hash_algo, wordlist_file="wordlist.txt", table_file="rainbow_table.pkl", salt=salt)
    if rainbow_table:
        start = time.time()
        rainbow_table_attack(target_hash, rainbow_table)
        results["Rainbow Table Attack"] = time.time() - start
    else:
        results["Rainbow Table Attack"] = float("nan")
        print("⚠️ Rainbow table not available (generation failed or unsupported).")

    print("✅ Benchmark complete.")
    return results


def plot_benchmark_results(results: dict[str, float]):
    # Filter out NaN values for plotting (but show them in labels)
    attack_names = list(results.keys())
    times = [results[k] if isinstance(results[k], (int, float)) and not (isinstance(results[k], float) and results[k] != results[k]) else 0 for k in attack_names]
    # (we use 0 seconds for NaN bars but will annotate them)

    plt.figure(figsize=(10, 6))
    bars = plt.barh(attack_names, times)
    plt.xlabel("Time Taken (seconds)")
    plt.title("Benchmark Results: Password Cracking Methods")

    # Annotate bars with actual values or "skipped"
    for rect, key in zip(bars, attack_names):
        val = results[key]
        x = rect.get_width()
        label = f"{val:.2f}s" if isinstance(val, (int, float)) and not (isinstance(val, float) and val != val) else "skipped"
        plt.text(x + 0.01, rect.get_y() + rect.get_height() / 2, label, va='center')

    plt.tight_layout()
    plt.show()


def run_benchmark():
    try:
        target_password = input("Enter the target password for benchmarking: ").strip()
        salt_input = input("Enter the salt value to use (leave empty to skip): ").strip()
        salt = salt_input if salt_input != "" else None
        max_length = int(input("Enter the maximum password length for brute force (e.g., 4): ").strip())
        hash_algo = input("Enter the hashing algorithm (sha1, sha224, md5): ").strip().lower()

        if hash_algo not in SUPPORTED_ALGOS:
            print(f"Unsupported algorithm: {hash_algo}. Supported: {', '.join(sorted(SUPPORTED_ALGOS))}")
            return

        results = benchmark_attacks(target_password, salt, max_length, hash_algo)
        plot_benchmark_results(results)

    except ValueError as ve:
        print(f"Input error: {ve}")
    except KeyboardInterrupt:
        print("\nAborted by user.")


if __name__ == "__main__":
    run_benchmark()
