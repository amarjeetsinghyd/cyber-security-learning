"""
Lab 05: JWT Tampering & Signature Verification
Pure-Python HS256 JWT demo showing why decoding a token without verifying its
cryptographic signature (or allowing alg=none) leads to privilege escalation.
"""

import base64
import hashlib
import hmac
import json

SECRET_KEY = b"local-demo-jwt-signing-key-do-not-hardcode-in-prod"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_jwt(payload: dict, secret: bytes = SECRET_KEY) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


def decode_jwt_vulnerable(token: str) -> dict:
    """BAD: Decodes Base64 payload without checking header algorithm or signature."""
    parts = token.split(".")
    return json.loads(b64url_decode(parts[1]))


def verify_jwt_secure(token: str, secret: bytes = SECRET_KEY) -> dict:
    """GOOD: Enforces strict HS256 algorithm and constant-time signature check."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT")
    h_b64, p_b64, sig_b64 = parts
    header = json.loads(b64url_decode(h_b64))
    if header.get("alg") != "HS256":
        raise ValueError(f"Rejected unsupported algorithm: {header.get('alg')}")

    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    provided_sig = b64url_decode(sig_b64)
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise ValueError("Invalid JWT signature (token tampered)")

    return json.loads(b64url_decode(p_b64))


def run_demo() -> None:
    print("=== LAB 05: JWT Tampering & Signature Verification ===")
    legit_token = create_jwt({"sub": "amarjeet", "role": "member"})

    # Attacker modifies payload role from "member" -> "admin" without knowing SECRET_KEY
    h_b64, _, sig_b64 = legit_token.split(".")
    forged_payload = b64url_encode(
        json.dumps({"sub": "amarjeet", "role": "admin"}, separators=(",", ":")).encode()
    )
    tampered_token = f"{h_b64}.{forged_payload}.{sig_b64}"

    vuln_claims = decode_jwt_vulnerable(tampered_token)
    print(f"[Vulnerable Decoder] Accepted tampered token! Role escalated to: {vuln_claims['role']}")
    assert vuln_claims["role"] == "admin"

    try:
        verify_jwt_secure(tampered_token)
        raise AssertionError("Tampered token should have been rejected!")
    except ValueError as exc:
        print(f"[Secure Verifier]    Tampered token rejected -> {exc}")

    valid_claims = verify_jwt_secure(legit_token)
    print(f"[Valid Token]        Verified cleanly -> {valid_claims}")
    assert valid_claims["role"] == "member"


if __name__ == "__main__":
    run_demo()
