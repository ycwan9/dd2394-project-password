# main.py
import argparse
from attacks.brute_force_attack import (
    brute_force_hashed_with_salt,
    brute_force_hashed_no_salt,
    brute_force_plaintext,
)
from attacks.dictionary_attack import dictionary_attack
from attacks.rainbow_table_attacks import rainbow_table_attack, generate_rainbow_table
from utils.hashing import hash_password, hash_password_with_salt
from utils.password_complexity_check import check_password_strength


def safe_input(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled. Exiting.")
        exit()


def choose_from_menu(prompt: str, valid_choices: set):
    choice = safe_input(prompt).strip()
    if choice in valid_choices:
        return choice
    print("Invalid choice — please try again.\n")
    return None


# --- Menus / Handlers ---
def hashing_menu(with_salt: bool = False):
    header = "🔒 Hash the password (with salt)" if with_salt else "🔒 Hash the password"
    alg_menu = (
        """
Choose algorithm:
1️⃣ SHA-1
2️⃣ SHA-224
3️⃣ MD5
4️⃣ ❌ Exit
"""
    )
    print(header)
    print(alg_menu)

    alg_choice = choose_from_menu("Enter the number for your choice: ", {str(i) for i in range(1, 5)})
    if not alg_choice:
        return

    mapping = {
        "1": "sha1",
        "2": "sha224",
        "3": "md5",
    }

    if alg_choice == "4":
        print("Back to previous menu.\n")
        return

    algorithm = mapping[alg_choice]
    password = safe_input("Enter your password: ")

    if with_salt:
        hashed = hash_password_with_salt(password, algorithm)
        # hash_password_with_salt expected to return (hash, salt) or similar
        # adapt printing to the actual return format of your util
        if isinstance(hashed, (list, tuple)) and len(hashed) >= 1:
            print("Hash:", hashed[0])
            if len(hashed) > 1:
                print("Salt:", hashed[1])
        else:
            print("Result:", hashed)
    else:
        hashed = hash_password(password, algorithm)
        print("Hash:", hashed)

    print()


def password_storage_menu():
    menu = """
1️⃣ Hash the password
2️⃣ 🔐 Hash the password (with salt)
3️⃣ ⚠️ Store the password in plaintext (demo only)
4️⃣ ❌ Back
"""
    print(menu)
    choice = choose_from_menu("Enter the number for your choice: ", {"1", "2", "3", "4"})
    if not choice:
        return

    if choice == "1":
        hashing_menu(with_salt=False)
    elif choice == "2":
        hashing_menu(with_salt=True)
    elif choice == "3":
        pwd = safe_input("Enter your password (plaintext): ")
        print("Plaintext password (demo):", pwd)
        print()
    else:
        return


def attacks_menu():
    menu = """
Choose an attack method:
1️⃣ Brute Force Attack
2️⃣ Dictionary Attack
3️⃣ Rainbow Table Attack
4️⃣ ❌ Back
"""
    print(menu)
    choice = choose_from_menu("Enter the number for your choice: ", {"1", "2", "3", "4"})
    if not choice:
        return

    if choice == "1":
        brute_force_menu()
    elif choice == "2":
        print("Dictionary attack!")
        target_hash = safe_input("Enter the target hash: ")
        algorithm = safe_input("Enter the hashing algorithm: ")
        print("Started the attack...")
        result = dictionary_attack(target_hash, algorithm)
        print("Result:", result)
        print()
    elif choice == "3":
        print("Rainbow attack!")
        target_hash = safe_input("Enter the target hash: ")
        algorithm = safe_input("Enter the hashing algorithm: ")
        rainbow_table = generate_rainbow_table(algorithm)
        print("Generated the rainbow table")
        result = rainbow_table_attack(target_hash, rainbow_table)
        print("Result:", result)
        print()
    else:
        return


def brute_force_menu():
    menu = """
Brute force options:
1️⃣ Brute force with plaintext
2️⃣ Brute force (hashed, no salt)
3️⃣ Brute force (hashed, with salt)
4️⃣ ❌ Back
"""
    print(menu)
    choice = choose_from_menu("Enter the number for your choice: ", {"1", "2", "3", "4", "5"})
    if not choice:
        return

    if choice == "1":
        print("Brute force with plaintext!")
        target = safe_input("Enter the target password (plaintext): ")
        max_length = safe_input("Enter the maximum password length: ")
        try:
            max_length = int(max_length)
        except ValueError:
            print("Invalid number for max length.\n")
            return
        result = brute_force_plaintext(target, max_length)
        print("Result:", result)
        print()

    elif choice == "2":
        print("Brute force (hashed, no salt)!")
        target_hash = safe_input("Enter the target hash: ")
        max_length_str = safe_input("Enter the maximum password length: ")
        algorithm = safe_input("Enter the hashing algorithm: ")
        try:
            max_length = int(max_length_str)
        except ValueError:
            print("Invalid number for max length.\n")
            return
        result = brute_force_hashed_no_salt(target_hash, max_length, algorithm)
        print("Result:", result)
        print()

    elif choice == "3":
        print("Brute force (optimized)!")
        target_hash = safe_input("Enter the target hash: ")
        max_length_str = safe_input("Enter the maximum password length: ")
        algorithm = safe_input("Enter the hashing algorithm: ")
        try:
            max_length = int(max_length_str)
        except ValueError:
            print("Invalid number for max length.\n")
            return
        result = brute_force_hashed_no_salt(target_hash, max_length, algorithm)
        print("Result:", result)
        print()

    else:
        return


def protection_menu():
    print("Protection mechanisms!")
    password = safe_input("Enter your password to check its strength: ")
    feedback = check_password_strength(password, wordlist="wordlist.txt")
    print("Password feedback:")
    print(feedback)
    print()


# --- Main interactive loop ---
def interactive_terminal():
    main_menu = """
🔧 Choose an option:
1️⃣ Password
2️⃣ Attacks
3️⃣ Protection
4️⃣ ❌ Exit
"""
    while True:
        print(main_menu)
        choice = choose_from_menu("Choose what you want to test (1-4): ", {"1", "2", "3", "4"})
        if not choice:
            continue

        if choice == "1":
            password_storage_menu()
        elif choice == "2":
            attacks_menu()
        elif choice == "3":
            protection_menu()
        elif choice == "4":
            print("Exiting... Goodbye!\n")
            break


def main():
    parser = argparse.ArgumentParser(description="Password Cracking Program")
    parser.add_argument(
        "--password", type=str, help="The password to crack or hash (non-interactive)"
    )
    parser.add_argument("--hash", type=str, help="Hash value of the password (if provided)")
    parser.add_argument(
        "--attack",
        type=str,
        choices=["brute_force", "dictionary"],
        help="The attack method to use (non-interactive)",
    )
    parser.add_argument(
        "--hash_algo",
        type=str,
        choices=["sha1", "sha224", "md5"],
        default="sha1",
        help="Hashing algorithm to use (non-interactive)",
    )
    parser.add_argument(
        "--max_length", type=int, default=5, help="Maximum password length for brute force"
    )
    parser.add_argument("--salt", type=str, help="Salt value for hashing (if provided)")
    parser.add_argument("--dictionary", type=str, help="Path to the dictionary file")
    parser.add_argument(
        "--terminal",
        help="Start interactive terminal menu.",
        nargs="?",
        const=True,
    )

    args = parser.parse_args()

    if args.terminal:
        interactive_terminal()
    else:
        # Non-interactive / scriptable behavior:
        # If user supplied --attack use CLI flow, otherwise give help.
        if args.attack:
            if args.attack == "brute_force":
                print("Non-interactive brute force started (using CLI args)...")
                # minimal example: use brute_force_plaintext if password provided, else require hash
                if args.password:
                    res = brute_force_plaintext(args.password, args.max_length)
                    print(res)
                elif args.hash:
                    res = brute_force_hashed_no_salt(args.hash, args.max_length, args.hash_algo)
                    print(res)
                else:
                    print("Provide --password (plaintext) or --hash (hashed) for brute_force.")
            elif args.attack == "dictionary":
                if not args.hash:
                    print("Provide --hash for dictionary attack.")
                else:
                    res = dictionary_attack(args.hash, args.hash_algo)
                    print(res)
        else:
            print("No interactive terminal requested and no attack specified. Use --terminal to open menu or --help for CLI options.")


if __name__ == "__main__":
    main()
