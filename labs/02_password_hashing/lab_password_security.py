"""
Lab 02: Password Hashing, Salting & Brute-Force Resistance
Demonstrates why unsalted fast hashes (SHA-256) fail against dictionary attacks,
and how salted PBKDF2-HMAC-SHA256 protects stored credentials.
"""

import hashlib
import hmac
import secrets


def weak_hash(password: str) -> str:
    """BAD: Fast hash with no salt. Identical passwords produce identical hashes."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def strong_hash(password: str, iterations: int = 200_000) -> tuple[bytes, bytes, int]:
    """GOOD: Unique random salt + slow key derivation function (PBKDF2-HMAC-SHA256)."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return salt, dk, iterations


def verify_strong_password(
    candidate: str, salt: bytes, expected_dk: bytes, iterations: int
) -> bool:
    candidate_dk = hashlib.pbkdf2_hmac(
        "sha256", candidate.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(candidate_dk, expected_dk)


def run_demo() -> None:
    print("=== LAB 02: Password Hashing & Salting ===")
    leaked_pw = "welcome123"

    # 1. Weak unsalted SHA-256
    h1 = weak_hash(leaked_pw)
    h2 = weak_hash(leaked_pw)
    print(f"[Weak Hash User A] {h1[:24]}...")
    print(f"[Weak Hash User B] {h2[:24]}... (Identical! Leaks shared passwords)")
    assert h1 == h2

    # Tiny offline dictionary check
    wordlist = ["password", "12345678", "qwerty", "welcome123", "admin2026"]
    cracked = next((w for w in wordlist if weak_hash(w) == h1), None)
    print(f"[Dictionary Crack] Weak hash cracked immediately -> '{cracked}'")
    assert cracked == leaked_pw

    # 2. Strong salted PBKDF2-HMAC-SHA256
    salt_a, dk_a, iters = strong_hash(leaked_pw)
    salt_b, dk_b, _ = strong_hash(leaked_pw)
    print(f"[Strong Hash User A] salt={salt_a.hex()[:12]}... hash={dk_a.hex()[:24]}...")
    print(f"[Strong Hash User B] salt={salt_b.hex()[:12]}... hash={dk_b.hex()[:24]}... (Unique!)")
    assert dk_a != dk_b
    assert verify_strong_password(leaked_pw, salt_a, dk_a, iters) is True
    assert verify_strong_password("wrong_pass", salt_a, dk_a, iters) is False
    print("[Verification]     Constant-time PBKDF2 verification passed.")


if __name__ == "__main__":
    run_demo()
