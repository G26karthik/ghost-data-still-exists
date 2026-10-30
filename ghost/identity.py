"""Resolve a request to current and historical person identifiers."""

import hashlib
import re
from typing import Any


EMAIL = re.compile(r"[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
USER = re.compile(r"\buser_\d+\b", re.I)
HASH = re.compile(r"\b[a-fA-F0-9]{64}\b")
PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")


def tokens(value: Any) -> set[str]:
    """Extract only explicit identifiers from a single record's values."""
    if isinstance(value, dict):
        return set().union(*(tokens(v) for v in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(tokens(v) for v in value)) if value else set()
    if not isinstance(value, str):
        return set()
    out = {x.lower() for x in EMAIL.findall(value)}
    out.update(x.lower() for x in USER.findall(value))
    out.update(x.lower() for x in HASH.findall(value))
    for phone in PHONE.findall(value):
        digits = re.sub(r"\D", "", phone)
        if 9 <= len(digits) <= 15:
            out.add(digits)
    return out


class IdentityIndex:
    def __init__(self, users: list[dict], audit: list[dict]) -> None:
        self.by_email = {}
        self.by_user = {}
        owner = {}
        for user in users:
            uid = user["user_id"].lower()
            self.by_user[uid] = user
            self.by_email[user["email"].lower()] = uid
            assert hashlib.sha256(user["email"].lower().encode()).hexdigest() == user["email_hash"].lower()
            values = {uid, user["email"].lower(), user["email_hash"].lower()}
            values |= tokens(user.get("phone", ""))
            user["_tokens"] = values
        for row in audit:
            uid = row["user_id"].lower()
            if uid not in self.by_user:
                continue
            values = set()
            for field in ("old_value", "new_value"):
                values |= tokens(row.get(field, ""))
            for email in [v for v in values if "@" in v]:
                values.add(hashlib.sha256(email.encode()).hexdigest())
                self.by_email[email] = uid
            self.by_user[uid]["_tokens"] |= values
        for uid, user in self.by_user.items():
            for token in user["_tokens"]:
                if token in owner and owner[token] != uid:
                    raise ValueError(f"Ambiguous identifier {token}: {owner[token]}, {uid}")
                owner[token] = uid
        self.owner = owner

    def resolve(self, email: str) -> tuple[str | None, set[str]]:
        uid = self.by_email.get(email.lower())
        if uid is None:
            return None, set()
        return uid, self.by_user[uid]["_tokens"]
