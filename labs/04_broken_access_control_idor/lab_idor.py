"""
Lab 04: Broken Access Control / IDOR (OWASP A01)
Demonstrates how missing object-level authorization lets User A read User B's
private invoice simply by changing an invoice ID, and how to fix it.
"""

INVOICES = {
    1001: {"owner": "alice", "amount_inr": 12500, "status": "paid"},
    1002: {"owner": "bob", "amount_inr": 48900, "status": "pending"},
}


def get_invoice_vulnerable(invoice_id: int, current_user: str):
    """BAD: Looks up resource by ID without checking if current_user owns it."""
    _ = current_user  # Unused!
    return INVOICES.get(invoice_id)


def get_invoice_secure(invoice_id: int, current_user: str, current_role: str = "user"):
    """GOOD: Enforces object-level ownership or explicit admin role."""
    record = INVOICES.get(invoice_id)
    if record is None:
        return None, 404
    if record["owner"] != current_user and current_role != "admin":
        return {"error": "403 Forbidden: Access denied"}, 403
    return record, 200


def run_demo() -> None:
    print("=== LAB 04: Broken Access Control / IDOR ===")
    # Alice tries to read Bob's invoice #1002
    leaked = get_invoice_vulnerable(invoice_id=1002, current_user="alice")
    print(f"[Vulnerable API] Alice requested invoice #1002 -> LEAKED: {leaked}")
    assert leaked is not None and leaked["owner"] == "bob"

    blocked_resp, status = get_invoice_secure(invoice_id=1002, current_user="alice")
    print(f"[Secure API]     Alice requested invoice #1002 -> HTTP {status}: {blocked_resp}")
    assert status == 403

    own_resp, own_status = get_invoice_secure(invoice_id=1001, current_user="alice")
    print(f"[Secure API]     Alice requested own invoice #1001 -> HTTP {own_status}: {own_resp}")
    assert own_status == 200 and own_resp["owner"] == "alice"


if __name__ == "__main__":
    run_demo()
