# attacks/rainbow_table_attacks.py
import hashlib
import time
import pickle
import os
from typing import Optional, Dict

SUPPORTED_ALGOS = {"sha1", "sha224", "md5"}


def _compute_hash(plain: str, algo: str, salt: bytes | None = None) -> str:
    """
    Compute hex digest for supported algorithms: sha1, sha224, md5.
    If salt is provided, it is prepended to the plaintext bytes.
    """
    data = (salt or b"") + plain.encode()
    if algo == "sha1":
        return hashlib.sha1(data).hexdigest()
    if algo == "sha224":
        return hashlib.sha224(data).hexdigest()
    if algo == "md5":
        return hashlib.md5(data).hexdigest()
    raise ValueError(f"Unsupported algorithm: {algo}")


def generate_rainbow_table(hash_algo: str, wordlist_file: str = "wordlist.txt", table_file: str = "rainbow_table.pkl", salt: str | None = None) -> Optional[Dict[str, str]]:
    """
    Generate a rainbow table (hash -> plaintext) from the provided wordlist.
    Supports sha1, sha224, md5 only.
    Returns the generated dict or None on error.
    """
    start_time = time.time()
    print(f"🔧 Generating rainbow table (algo={hash_algo}) from {wordlist_file} ...")

    if hash_algo not in SUPPORTED_ALGOS:
        print(f"⚠️ Unsupported algorithm: {hash_algo}. Supported: {', '.join(sorted(SUPPORTED_ALGOS))}")
        return None

    salt_bytes = str(salt).encode() if salt is not None else None
    rainbow_table: Dict[str, str] = {}

    try:
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                word = line.strip()
                if not word:
                    continue
                hash_value = _compute_hash(word, hash_algo, salt=salt_bytes)
                rainbow_table[hash_value] = word

                # optional progress feedback every N lines
                # if idx % 10000 == 0:
                #     print(f"Processed {idx} words...")

        with open(table_file, "wb") as tf:
            pickle.dump(rainbow_table, tf)

        elapsed = time.time() - start_time
        print(f"✅ Rainbow table saved to {table_file}  — Entries: {len(rainbow_table)}  — Time: {elapsed:.2f}s")
        return rainbow_table

    except FileNotFoundError:
        print(f"⚠️ Wordlist file not found: {wordlist_file}")
        return None
    except Exception as e:
        print(f"⚠️ Error while generating rainbow table: {e}")
        return None


def load_rainbow_table(table_file: str = "rainbow_table.pkl") -> Optional[Dict[str, str]]:
    """
    Load a previously saved rainbow table file.
    """
    if not os.path.exists(table_file):
        print(f"⚠️ Rainbow table file does not exist: {table_file}")
        return None

    try:
        with open(table_file, "rb") as f:
            rt = pickle.load(f)
            print(f"📂 Loaded rainbow table from {table_file}  — Entries: {len(rt)}")
            return rt
    except Exception as e:
        print(f"⚠️ Error loading rainbow table: {e}")
        return None


def rainbow_table_attack(hash_value: str, rainbow_table: Dict[str, str]) -> Optional[str]:
    """
    Lookup the hash in the provided rainbow_table dict.
    Returns the plaintext if found, otherwise None.
    """
    start_time = time.time()
    print(f"🔎 Performing rainbow-table lookup for hash: {hash_value}")

    if not rainbow_table:
        print("⚠️ No rainbow table provided or table is empty.")
        return None

    if hash_value in rainbow_table:
        elapsed = time.time() - start_time
        plaintext = rainbow_table[hash_value]
        print(f"✅ Password found: {plaintext!r}  — Time: {elapsed:.2f}s")
        return plaintext

    elapsed = time.time() - start_time
    print(f"❌ Password not found in rainbow table. Time: {elapsed:.2f}s")
    return None
