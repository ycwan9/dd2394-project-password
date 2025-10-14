# utils/password_check.py
import re
from pathlib import Path
from typing import Set

WORD_REGEXES = {
    "upper": re.compile(r"[A-Z]"),
    "lower": re.compile(r"[a-z]"),
    "digit": re.compile(r"\d"),
    "special": re.compile(r"[\W_]"),
}


def load_wordlist(path: str) -> Set[str]:
    """
    Return a set of lines from the given file (trimmed).
    If file missing, return empty set (no exception raised).
    """
    p = Path(path)
    if not p.is_file():
        print("Wordlist file not found. Skipping wordlist check.")
        return set()
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        return {line.strip() for line in f if line.strip()}


def check_password_strength(password: str, wordlist: Set[str]) -> str:
    """
    Same behaviour as before — returns one of:
      - "Weak Password: Password is too common. Avoid using passwords from known wordlists."
      - "Weak Password: Password is too short."
      - "Medium Password: Could be stronger by adding more characters and complexity."
      - "Strong Password: Password meets length and complexity requirements."
      - "Medium Password: Add more complexity (use a mix of upper/lowercase, digits, and special characters)."
      - fallback: "Weak Password: Needs more characters or complexity."
    """
    pw = password or ""
    length = len(pw)

    # wordlist check (exact match)
    if pw in wordlist:
        return "Weak Password: Password is too common. Avoid using passwords from known wordlists."

    # quick character class checks
    has_upper = bool(WORD_REGEXES["upper"].search(pw))
    has_lower = bool(WORD_REGEXES["lower"].search(pw))
    has_digit = bool(WORD_REGEXES["digit"].search(pw))
    has_special = bool(WORD_REGEXES["special"].search(pw))

    # rules identical to your original logic:
    if length < 6:
        return "Weak Password: Password is too short."

    if 6 <= length <= 10:
        # if it has *any* complexity, consider medium
        if any((has_upper, has_lower, has_digit, has_special)):
            return "Medium Password: Could be stronger by adding more characters and complexity."

    if length > 10 and all((has_upper, has_lower, has_digit, has_special)):
        return "Strong Password: Password meets length and complexity requirements."

    if length > 10:
        return "Medium Password: Add more complexity (use a mix of upper/lowercase, digits, and special characters)."

    return "Weak Password: Needs more characters or complexity."
