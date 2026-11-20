"""
Lab 01: SQL Injection (Vulnerable vs. Secure Parameterized Query)
Runs 100% locally in an in-memory SQLite database for educational use.
"""

import sqlite3


def setup_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("admin", "Sup3rS3cretAdminPass!", "admin"),
            ("amarjeet", "UserPass2026!", "member"),
        ],
    )
    conn.commit()
    return conn


def vulnerable_login(conn: sqlite3.Connection, username: str, password: str):
    """BAD: Directly concatenating untrusted user input into SQL."""
    query = (
        f"SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchone(), query


def secure_login(conn: sqlite3.Connection, username: str, password: str):
    """GOOD: Using parameterized queries so input is strictly treated as data."""
    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    cur = conn.cursor()
    cur.execute(query, (username, password))
    return cur.fetchone(), query


def run_demo() -> None:
    print("=== LAB 01: SQL Injection (Vulnerable vs Secure) ===")
    conn = setup_db()

    attack_user = "admin' --"
    attack_pass = "anything"

    vuln_row, executed_query = vulnerable_login(conn, attack_user, attack_pass)
    print(f"[Vulnerable Query] {executed_query}")
    print(f"[Vulnerable Result] Login bypassed! Logged in as: {vuln_row}")
    assert vuln_row is not None and vuln_row[1] == "admin"

    sec_row, sec_query = secure_login(conn, attack_user, attack_pass)
    print(f"[Secure Query]     {sec_query}  with params=({attack_user!r}, {attack_pass!r})")
    print(f"[Secure Result]    Attack blocked! Result: {sec_row}")
    assert sec_row is None

    valid_row, _ = secure_login(conn, "amarjeet", "UserPass2026!")
    print(f"[Valid Login]      Legitimate user authenticated: {valid_row}")
    assert valid_row is not None and valid_row[1] == "amarjeet"
    conn.close()


if __name__ == "__main__":
    run_demo()
