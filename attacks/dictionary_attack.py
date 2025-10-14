# attacks/dictionary_attack.py
import hashlib
import time
from typing import Optional

SUPPORTED_ALGOS = {"sha1", "sha224", "md5"}


def compute_hash(plain: str, algo: str, salt: bytes | None = None) -> str:
    """
    Compute hex digest for supported algorithms: sha1, sha224, md5.
    Salt, if provided, is prepended to the plaintext bytes.
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


def dictionary_attack(hash_value: str, hash_algo: str, wordlist_file: str = "wordlist.txt", salt: str | None = None) -> Optional[str]:
    """
    Try to find the plaintext password by hashing each word from the wordlist
    using the specified algorithm (supports sha1, sha224, md5).
    If salt is provided, it is prepended before hashing.
    Returns the found password (str) or None if not found.
    """
    start_time = time.time()
    print(f"🔎 Starting dictionary attack (algo={hash_algo}) against hash: {hash_value}")

    if hash_algo not in SUPPORTED_ALGOS:
        print(f"⚠️ Unsupported algorithm: {hash_algo}. Supported: {', '.join(sorted(SUPPORTED_ALGOS))}")
        return None

    salt_bytes = str(salt).encode() if salt is not None else None

    try:
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                word = line.strip()
                if not word:
                    continue

                word_hash = compute_hash(word, hash_algo, salt=salt_bytes)

                if word_hash == hash_value:
                    elapsed = time.time() - start_time
                    print(f"✅ Password found: {word!r} (line {idx}) — Time: {elapsed:.2f}s")
                    return word

                # optional: show progress every N lines (disabled by default)
                # if idx % 10000 == 0:
                #     print(f"Processed {idx} words...")

        elapsed = time.time() - start_time
        print(f"❌ Password not found in {wordlist_file}. Total time: {elapsed:.2f}s")
        return None

    except FileNotFoundError:
        print(f"⚠️ Wordlist file not found: {wordlist_file}")
        return None
