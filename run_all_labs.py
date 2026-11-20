"""
Run all safe local cyber security labs and verify all defensive assertions pass.
"""

from pathlib import Path
import subprocess
import sys

LAB_SCRIPTS = [
    "labs/01_sql_injection/lab_sqli.py",
    "labs/02_password_hashing/lab_password_security.py",
    "labs/03_xss_and_sanitization/lab_xss.py",
    "labs/04_broken_access_control_idor/lab_idor.py",
    "labs/05_http_and_jwt_tampering/lab_jwt_security.py",
]


def main() -> int:
    root = Path(__file__).resolve().parent
    for rel_path in LAB_SCRIPTS:
        script = root / rel_path
        print(f"\n>>> Running {rel_path}")
        res = subprocess.run([sys.executable, str(script)], check=False)
        if res.returncode != 0:
            print(f"FAILED: {rel_path} (exit code {res.returncode})")
            return res.returncode
    print("\nAll 5 cyber security labs completed and verified successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
