# attacks/brute_force_attack.py
import itertools
import hashlib
import time


def compute_hash(plain: str, algo: str, salt: bytes | None = None) -> str:
    """
    Compute hex digest for supported algorithms: sha1, sha224, md5.
    If salt is provided, it is prepended to the plaintext bytes.
    Returns hex string.
    """
    data = (salt or b"") + plain.encode()
    if algo == "sha1":
        return hashlib.sha1(data).hexdigest()
    elif algo == "sha224":
        return hashlib.sha224(data).hexdigest()
    elif algo == "md5":
        return hashlib.md5(data).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")


def brute_force_plaintext(target_password: str, max_length: int, charset: str = "abcdefghijklmnopqrstuvwxyz"):
    start_time = time.time()
    print(f"🔎 Starting plaintext brute-force for target: {target_password!r}")
    for length in range(1, max_length + 1):
        for tup in itertools.product(charset, repeat=length):
            guess = "".join(tup)
            if guess == target_password:
                elapsed = time.time() - start_time
                print(f"✅ Password found: {guess!r}  — Time: {elapsed:.2f}s")
                return guess

    elapsed = time.time() - start_time
    print(f"❌ Password not found (tried up to length {max_length}). Total time: {elapsed:.2f}s")
    return None


def brute_force_hashed_no_salt(hash_value: str, max_length: int, hash_algo: str, charset: str = "abcdefghijklmnopqrstuvwxyz"):
    start_time = time.time()
    print(f"🔎 Starting brute-force on hash: {hash_value}  (algo: {hash_algo})")

    # validate algorithm early
    supported = {"sha1", "sha224", "md5"}
    if hash_algo not in supported:
        print(f"⚠️ Unsupported algorithm: {hash_algo}. Supported: {', '.join(sorted(supported))}")
        return None

    for length in range(1, max_length + 1):
        for tup in itertools.product(charset, repeat=length):
            guess = "".join(tup)
            guess_hash = compute_hash(guess, hash_algo, salt=None)

            if guess_hash == hash_value:
                elapsed = time.time() - start_time
                print(f"✅ Password found: {guess!r}  — Time: {elapsed:.2f}s")
                return guess

    elapsed = time.time() - start_time
    print(f"❌ Password not found. Tried lengths 1..{max_length}. Total time: {elapsed:.2f}s")
    return None


def brute_force_hashed_with_salt(hash_value: str, max_length: int, hash_algo: str, salt: str | None = None, charset: str = "abcdefghijklmnopqrstuvwxyz"):
    """
    Brute force when a salt is provided. If salt is None, warn and abort because
    brute-forcing a hash with unknown salt is generally infeasible.
    """
    start_time = time.time()
    print(f"🔎 Starting brute-force on salted hash: {hash_value}  (algo: {hash_algo})")

    supported = {"sha1", "sha224", "md5"}
    if hash_algo not in supported:
        print(f"⚠️ Unsupported algorithm: {hash_algo}. Supported: {', '.join(sorted(supported))}")
        return None

    if salt is None:
        print("⚠️ No salt provided. Cannot run a meaningful salted-hash brute force without the salt.")
        return None

    salt_bytes = str(salt).encode()

    for length in range(1, max_length + 1):
        for tup in itertools.product(charset, repeat=length):
            guess = "".join(tup)
            guess_hash = compute_hash(guess, hash_algo, salt=salt_bytes)

            if guess_hash == hash_value:
                elapsed = time.time() - start_time
                print(f"✅ Password found: {guess!r}  — Time: {elapsed:.2f}s")
                return guess

    elapsed = time.time() - start_time
    print(f"❌ Password not found (with provided salt). Tried lengths 1..{max_length}. Total time: {elapsed:.2f}s")
    return None
