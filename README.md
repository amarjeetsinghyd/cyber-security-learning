# Cyber Security Learning

A practical, hands-on **Ethical Hacking & Cyber Security** learning repository with a structured roadmap and **5 safe, local, zero-dependency Python labs** comparing **vulnerable code vs. secure fixes**.

> **Ethical & Legal Rule:** Every lab in this repository runs 100% locally in memory for defensive learning and security engineering practice. Never test any website, API, server, or network without explicit written authorization.

## Quick Start

Requires **Python 3.8+** (standard library only — no `pip install` needed).

```bash
# Run all 5 practical labs and security verification checks
python3 run_all_labs.py

# Or run any individual lab directly
python3 labs/01_sql_injection/lab_sqli.py
python3 labs/02_password_hashing/lab_password_security.py
python3 labs/03_xss_and_sanitization/lab_xss.py
python3 labs/04_broken_access_control_idor/lab_idor.py
python3 labs/05_http_and_jwt_tampering/lab_jwt_security.py
```

## Included Practical Labs

| # | Lab | Security Concept | Vulnerable Behavior | Defensive Fix |
|---|---|---|---|---|
| 01 | [`labs/01_sql_injection`](labs/01_sql_injection/lab_sqli.py) | SQL Injection (SQLi) | String-concatenated SQL query bypassed with `' OR '1'='1' --` | Parameterized queries (`?` placeholders) |
| 02 | [`labs/02_password_hashing`](labs/02_password_hashing/lab_password_security.py) | Password Storage | Plaintext / unsalted SHA-256 cracked via dictionary lookup | Per-user random salt + `PBKDF2-HMAC-SHA256` + `hmac.compare_digest` |
| 03 | [`labs/03_xss_and_sanitization`](labs/03_xss_and_sanitization/lab_xss.py) | Cross-Site Scripting (XSS) | Raw user input rendered into HTML `<script>` execution | Context-aware `html.escape()` + strict Content-Security-Policy |
| 04 | [`labs/04_broken_access_control_idor`](labs/04_broken_access_control_idor/lab_idor.py) | Broken Access Control / IDOR | Fetching another user's record by changing numeric ID | Object-level ownership & role authorization check |
| 05 | [`labs/05_http_and_jwt_tampering`](labs/05_http_and_jwt_tampering/lab_jwt_security.py) | JWT Tampering & Verification | Trusting decoded JWT payload without signature validation | Strict algorithm allowlist (`HS256`) + constant-time HMAC signature verification |

## Learning Roadmap & Trusted Platforms

Track your progress step-by-step in [`docs/01-roadmap-and-checklist.md`](docs/01-roadmap-and-checklist.md).

1. **Linux & Networking Foundations**
   - Practice Linux command-line fundamentals with [OverTheWire Bandit](https://overthewire.org/wargames/bandit/).
   - Build networking and OS basics with [TryHackMe Pre Security](https://tryhackme.com/path/outline/presecurity).
2. **Guided Hands-On Security Labs**
   - Follow [TryHackMe Cyber Security 101](https://tryhackme.com/path/outline/cybersecurity101) and then [TryHackMe Jr Penetration Tester](https://tryhackme.com/path/outline/jrpenetrationtester).
   - Set up [Kali Linux](https://www.kali.org/get-kali/) (via WSL on Windows or a lightweight VM) to practice standard security tools locally.
3. **Web Application & API Security**
   - Study the [OWASP Top 10](https://owasp.org/projects/top-ten) (including [OWASP Top 10:2025](https://top10.owasp.org/2025/en/)).
   - Complete interactive free web labs at [PortSwigger Web Security Academy](https://portswigger.net/web-security).
4. **Intermediate Labs, Bug Bounty & Certification**
   - Level up with role-based paths on [Hack The Box Academy](https://academy.hackthebox.com/catalogue/paths).
   - Practice responsible vulnerability disclosure on legal scopes via [HackerOne Bug Bounty Programs](https://www.hackerone.com/bug-bounty-programs).
   - Validate practical junior pentesting skills with [INE eJPT Certification](https://ine.com/security/certifications/ejpt-certification).
