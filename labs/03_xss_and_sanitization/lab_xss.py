"""
Lab 03: Cross-Site Scripting (XSS) & Safe HTML Output Encoding
Demonstrates how unescaped user input injects executable <script> tags,
and how context-aware escaping neutralizes the payload.
"""

import html


def render_comment_vulnerable(user_comment: str) -> str:
    """BAD: Inserts untrusted user input directly into HTML."""
    return f"<div class='comment'>{user_comment}</div>"


def render_comment_secure(user_comment: str) -> tuple[str, dict[str, str]]:
    """GOOD: Escapes HTML special characters and recommends a strict CSP header."""
    safe_text = html.escape(user_comment, quote=True)
    rendered = f"<div class='comment'>{safe_text}</div>"
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        "X-Content-Type-Options": "nosniff",
    }
    return rendered, headers


def run_demo() -> None:
    print("=== LAB 03: Cross-Site Scripting (XSS) & Output Encoding ===")
    payload = "<script>alert('XSS')</script>"

    vuln_html = render_comment_vulnerable(payload)
    print(f"[Vulnerable HTML] {vuln_html}")
    assert "<script>" in vuln_html

    safe_html, headers = render_comment_secure(payload)
    print(f"[Secure HTML]     {safe_html}")
    print(f"[Security Header] Content-Security-Policy: {headers['Content-Security-Policy']}")
    assert "<script>" not in safe_html
    assert "&lt;script&gt;" in safe_html


if __name__ == "__main__":
    run_demo()
