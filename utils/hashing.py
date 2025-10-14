# utils/hashing.py
import hashlib
import os
from typing import Optional, Tuple


def hash_password(password: str, algorithm: str) -> str:
    """
    Hash a password using the specified algorithm without salt.
    Supported algorithms: sha1, sha224, md5

    Returns:
        Hexadecimal digest string.
    Raises:
        ValueError for unsupported algorithms.
    """
    algo = algorithm.lower()
    if algo == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif algo == "sha224":
        return hashlib.sha224(password.encode()).hexdigest()
    elif algo == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")


def hash_password_with_salt(password: str, algorithm: str, salt: Optional[bytes] = None) -> Tuple[str, bytes]:
    """
    Hash a password with a salt using the specified algorithm.
    Supported algorithms: sha1, sha224, md5

    If `salt` is None a new random 16-byte salt is generated.
    Returns:
        (hex_digest, salt_bytes)
    Raises:
        ValueError for unsupported algorithms.
    """
    algo = algorithm.lower()
    if salt is None:
        salt = os.urandom(16)

    data = salt + password.encode()

    if algo == "sha1":
        hash_value = hashlib.sha1(data).hexdigest()
    elif algo == "sha224":
        hash_value = hashlib.sha224(data).hexdigest()
    elif algo == "md5":
        hash_value = hashlib.md5(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

    return hash_value, salt
