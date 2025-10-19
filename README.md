# Password Cracking project

Group: [Group 4 / Bailin Lei | Yousra Al Mowahed | Yuchen Wang]


## Problem statement

Weak and improperly stored passwords remain a primary attack vector for account compromise. This project demonstrates common password-cracking techniques and simple protection mechanisms so students can:

• see how attackers recover weak passwords (brute-force, dictionary, rainbow-table),

• measure time–space tradeoffs (especially for rainbow tables),

• observe how simple defenses (unique salts, slow hashing) affect attack feasibility,

• and learn secure password-storage best practices by contrast.

The implementations are educational: they favor clarity and short runtimes (using fast hashes such as MD5/SHA-1/SHA-224) so experiments finish quickly. Do not use these fast hashes for real user passwords.

## References

Philippe Oechslin, “Making a Faster Cryptanalytic Time–Memory Trade-Off,” CRYPTO 2003.

K. Kelsey & B. Schneier, “Cryptanalytic attacks on pseudorandom number generators,” FSE 2002.

Online documentation:

[RFC 2898: PKCS #5 Password-Based Cryptography](https://datatracker.ietf.org/doc/html/rfc2898)

[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

Course materials: DD2394 KTH — (In)secure hash function Labs.

## Documentation of the Project
## Overview


This repository contains implementations of three password-cracking techniques and a benchmarking harness.

Main modules
```python
attacks/
 ├─ brute_force_attack.py         # brute-force attack
 ├─ dictionary_attack.py          # dictionary-based attack
 └─ rainbow_table/                # rainbow table demo and library
     ├─ __main__.py               # runnable CLI demo
     ├─ rainbow_table.py          # core chain/reduction logic
     ├─ base.py, random_seed.py   # utilities
utils/
 ├─ hashing.py                    # hash helpers (MD5, SHA1, etc.)
 ├─ password_complexity_check.py  # simple strength check
benchmark_rainbow.py              # benchmarking harness
requirements.txt
```

## Algorithms implemented

Brute-force attack: tries every candidate in a charset up to a maximum length. Complexity: 𝑂(∣𝐶∣ᶫ)

• Dictionary attack: reads candidate passwords from a file, optionally adding transformations.

• Rainbow-table attack: builds precomputed hash–reduction chains, stores endpoints, and later resolves target hashes through lookup.

## how to run

1.Clone and enter the repo:
```
git clone <repository_url>
cd dd2394-project-password
```

2.Create a virtual environment and install:
```
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
```

3.Run the main CLI (terminal mode):
```
python main.py --terminal
```

4.Run the rainbow-table demo directly:
```
python -m attacks.rainbow_table --help
python -m attacks.rainbow_table --charset abc --max-len 2 --chain-len 3 --random-seeds 3 --log-level INFO
```

5.Run benchmark :
```
python benchmark_rainbow.py --charset abc --max-len 2 --chain-len 3 --random-seeds 100 --cracking-me
```
## Notes

• If main.py raises import errors referencing attacks.rainbow_table_attacks, run the rainbow demo module directly (python -m attacks.rainbow_table ...) or add a small adapter module that re-exports functions from attacks.rainbow_table.

• The demo sometimes writes a pickle under a .json extension — treat saved files as untrusted and do not unpickle files from unknown sources.

## Implemented features (current prototype)

Brute-force (plaintext); brute-force (hashed, no salt)

Dictionary attack (with optional salt handling)

Rainbow-table building and lookup (small-space demo)

Hashes: MD5, SHA-1, SHA-224

Basic password strength checker (toy heuristic)

## Documentation on testing the project

This section describes both functional testing (correctness) and performance testing (benchmarks and interpretation).

## Functional testing (what to run to verify behavior)

Brute-force

• Create a trivial target (e.g., password ab with charset abc, max length 2) and confirm brute_force_attack finds it.

• Test both plaintext mode and hashed-no-salt mode: compute hash(password) with the same algorithm, then run the hashed brute-force.

Dictionary attack

• Prepare a small wordlist containing one or two known passwords; verify the attack finds them.

• Test with/without salts (salt prepended in this project).

Rainbow table

• Build a tiny rainbow table (charset abc, max-len 2, small chain length and few seeds), then run lookup against known hashes within that small space. Confirm found plaintexts match.

• Save and load the table (note the storage format — pickles are used in the prototype).

Salted hashing demo

• Generate salted hashes through utils/hashing.py and ensure brute-force/dictionary behavior matches expected difficulty changes.

## Performance testing (benchmarks)
Metrics to collect

• Build time — time to build the rainbow table (approx proportional to m * t).

• Crack time — per-target min/max/avg/stdev across sample targets.

• Success rate — fraction of sampled targets cracked by the table (empirical coverage).

• Table size on disk — stores the number of endpoints (≈ m entries).

• Merge ratio — empirical_coverage / theoretical_coverage (diagnostic for reduction function and chain merges).

Theoretical coverage estimate

For parameters:

• N = total password space (sum_{k=1..L} |C|^k)

• m = number of chains

• t = chain length

A first-order optimistic estimate:
```
coverage ≈ 1 - exp(-m * t / N)
```
This ignores merges and collisions; empirical coverage is typically lower.

## How to run benchmarks

Use benchmark_rainbow.py:

• --cracking-method all runs exhaustive tests (only feasible for small N).

• --cracking-method montecarlo performs random-sampling benchmarking (use for larger spaces).

Suggested workflow:

• Start with a tiny space (charset=abc, L=2) and verify correctness (exhaustive).

• Scale to Monte Carlo sampling for larger parameter sets.

• Vary m and t systematically; collect build time, success rate, and crack-time statistics.

## Example small benchmark command
```
python benchmark_rainbow.py \
  --charset abc \
  --max-len 2 \
  --chain-len 3 \
  --random-seeds 100 \
  --cracking-method montecarlo \
  --montecarlo-samples 1000
```

Interpreting results

• If empirical success rate is far below the theoretical estimate, chain merges or poor reduction design are likely causes — consider step-dependent reductions (classic rainbow approach).

• Build time should roughly scale with m * t. If not, check for logging or I/O overhead and optimize.

• For given m, increasing t has diminishing returns because chains start to overlap.

## Test artifacts and CI 

• Add unit tests (pytest) for:

• utils.hashing — hashing and salt handling.

• brute_force_attack — small-space known password recovery.

• dictionary_attack — wordlist handling, salt behavior.

• rainbow_table — round-trip build → lookup on a tiny space.

Add a GitHub Actions workflow to run tests on PRs and optionally run a tiny benchmark job nightly.

## Safety and security considerations in testing

• Never unpickle files from unknown sources in your tests or in CI.

• When demonstrating secure hashing (Argon2/bcrypt), do it in a separate secure-mode in code because these slow hashes are expensive for tests — use low-cost Argon2 parameters only in demo mode.

## Closing notes

This README is intended as the single required README per group submission. It contains the problem statement, references, documentation of the project, and testing instructions focused on algorithmic principles and performance testing as requested.
## Contributing

This repository was developed collaboratively as part of the KTH course DD2394 — Computer Security, focusing on the analysis and implementation of password-cracking algorithms.
The project demonstrates brute-force, dictionary, and rainbow-table attacks, along with basic password protection mechanisms such as salted hashing and strength evaluation.

The following sections describe each group member’s contribution in detail.

## Yousra Al Mowahed — Initial Development and System Design

Yousra created the initial version of the password-cracking toolkit, establishing the project’s folder structure and modular architecture. She implemented the first working versions of all main attack methods: brute-force (plaintext and hashed), dictionary attack, and rainbow-table attack.

She also added support for multiple hash algorithms (MD5, SHA-1, SHA-224) through Python’s hashlib, and implemented a basic password strength checker to demonstrate password evaluation. Her early prototype validated the project’s concept and ensured all algorithms interacted correctly.

Yousra’s work provided the foundation for later optimization, testing, and documentation. Her structured design and clean module separation made it easy for the team to expand the codebase efficiently.

## Yuchen Wang — Optimization and Rainbow Table Fixes

Yuchen rewrote and optimized the rainbow-table attack module, which was partially functional in the initial version. He redesigned the hash–reduction chain logic, fixed table generation errors, and ensured correct plaintext recovery through improved chain traversal.

He also enhanced benchmarking and performance testing, introducing both exhaustive and Monte Carlo modes for evaluating success rates and runtime efficiency. Yuchen improved code readability, parameter handling, and serialization safety for the rainbow-table module, making it robust and reproducible.

His technical contributions transformed the rainbow-table implementation into a correct, measurable, and optimized attack demonstration — the core analytical component of this project.

## Bailin Lei — Documentation, Testing, and Final Integration

Bailin authored the README and testing documentation, clearly describing the algorithms, their principles, and performance evaluation methods. He organized the project report into the required sections — Problem Statement, References, Documentation of Project, and Documentation on Testing.

He also set up a testing framework for verifying correctness and performance, covering brute-force, dictionary, and rainbow-table modules. Bailin coordinated the integration of Yousra’s and Yuchen’s contributions, ensuring consistent imports, formatting, and cross-platform compatibility, turning the technical implementation into a clear, reproducible, and well-documented academic submission.
## License

[MIT](https://choosealicense.com/licenses/mit/)




