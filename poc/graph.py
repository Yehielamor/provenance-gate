"""Known-counterparty graph (H8).

Built from *structured, outbound* relationships in the organisation's own
history - the kind of data a product would read from its connectors (sent
mail, file shares, past payees, the Slack member directory). Inbound
relationships (who emailed us, who paid us) are deliberately excluded: anyone,
including an attacker, can send you an e-mail.
"""

from __future__ import annotations

# Arguments that name *where* data, money or access goes.
DESTINATION_ARGS = {"recipients", "recipient", "cc", "bcc", "email", "user", "user_email", "participants", "channel"}


def known_counterparties(suite_name: str, env) -> set[str]:
    d = env.model_dump()
    known: set[str] = set()
    if suite_name == "workspace":
        for e in d["inbox"]["emails"].values():
            if str(e["status"]).endswith("sent"):
                known.update(e["recipients"] + (e["cc"] or []) + (e["bcc"] or []))
        for f in d["cloud_drive"]["files"].values():
            known.update(f["shared_with"].keys())
    elif suite_name == "banking":
        acct = d["bank_account"]
        for t in acct["transactions"] + acct["scheduled_transactions"]:
            if t["sender"] in ("me", acct["iban"]):
                known.add(t["recipient"])
    elif suite_name == "slack":
        known.update(d["slack"]["users"])
        known.update(d["slack"]["channels"])
    # travel: a public catalogue of hotels/restaurants is not a relationship.
    return {k.lower() for k in known}


def amount_cap(suite_name: str, env) -> float | None:
    """H9: the largest single payment the account has ever made (outbound history only).
    A model-computed amount below it is treated as ordinary; above it is a user decision."""
    if suite_name != "banking":
        return None
    acct = env.model_dump()["bank_account"]
    out = [t["amount"] for t in acct["transactions"] + acct["scheduled_transactions"]
           if t["sender"] in ("me", acct["iban"])]
    return max(out, default=None)
