"""Apply the supplied category rules to one reconstructed resource state."""

from pathlib import Path

from .evidence import read_csv


RULE_ACTION = {
    "USER_PROFILE": "DELETE", "SECONDARY_IDENTIFIER": "DELETE", "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE", "SUPPORT_MESSAGE": "REDACT", "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE", "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE", "MARKETING_PROFILE": "DELETE", "EMAIL_DELIVERY_LOG": "REDACT",
    "SECURITY_AUDIT_LOG": "RETAIN", "LEGAL_HOLD_RECORD": "RETAIN",
    "BACKUP_ARCHIVE": "RETAIN", "ACCOUNT_TOMBSTONE": "REDACT", "DATA_FLOW": "DISABLE",
}


def load_rules(dataset: Path) -> dict[str, dict]:
    rows = read_csv(dataset / "deletion_rules.csv")
    for row in rows:
        expected = RULE_ACTION.get(row["data_category"])
        if expected != row["required_action"]:
            raise ValueError(f"Policy table differs for {row['data_category']}")
    return {row["data_category"]: row for row in rows}


def treatment(category: str, current: str, fields: dict, rules: dict[str, dict]) -> tuple[tuple[str, str] | None, tuple[str, str] | None, tuple[str, str] | None, str]:
    """Return finding, remediation, verification and an unresolved condition note."""
    if category != "DATA_FLOW" and category not in rules:
        return None, None, None, "category absent from policy"
    if current == "UNKNOWN":
        return None, None, None, "state unsupported"
    note = ""
    if category in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
                    "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE"}:
        if category == "SUPPORT_ATTACHMENT" and current != "ABSENT":
            note = "attachment sole ownership not explicitly established"
        return (("REPORT_REMAINING_RECORD", "PRESENT") if current != "ABSENT" else None,
                ("DELETE_RECORD", "ABSENT") if current != "ABSENT" else None,
                ("VERIFY_RECORD_ABSENT", "ABSENT"), note)
    if category in {"SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE", "EMAIL_DELIVERY_LOG"}:
        if current == "ABSENT":
            return None, None, ("VERIFY_RECORD_ABSENT", "ABSENT"), note
        if category == "SUPPORT_MESSAGE" and current == "IDENTIFIABLE":
            note = "shared context retention not explicit"
        if category == "ACCOUNT_TOMBSTONE" and current == "IDENTIFIABLE":
            note = "stable reference retention assumed from category"
        exposed = current not in ("REDACTED",)
        return (("REPORT_EXPOSED_PII", "PRESENT") if exposed else None,
                ("REDACT_RECORD", "REDACTED") if exposed else None,
                ("VERIFY_RECORD_REDACTED", "REDACTED"), note)
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if current == "ABSENT":
            return None, None, ("VERIFY_RECORD_ABSENT", "ABSENT"), note
        exposed = current not in ("ANONYMIZED", "ABSENT")
        return (("REPORT_EXPOSED_PII", "PRESENT") if exposed else None,
                ("ANONYMIZE_RECORD", "ANONYMIZED") if exposed else None,
                ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"), note)
    if category == "DATA_FLOW":
        active = current == "ACTIVE"
        return (("REPORT_ACTIVE_DATA_FLOW", "ACTIVE") if active else None,
                ("DISABLE_DATA_FLOW", "DISABLED") if active else None,
                ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"), note)
    if category == "BACKUP_ARCHIVE":
        active = current == "ACTIVE"
        if "restore_allowed" not in fields and "eligible" not in fields and "decision" not in fields:
            note = "restore control condition not explicit"
        return (("REPORT_RESTORE_RISK", "ACTIVE") if active else None,
                ("BLOCK_RESTORE", "BLOCKED") if active else None,
                ("VERIFY_RESTORE_BLOCKED", "BLOCKED"), note)
    if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
        if category == "SECURITY_AUDIT_LOG" and not any(k in fields for k in ("retain_until", "retention_until")):
            note = "retention period not explicit in record"
        if category == "LEGAL_HOLD_RECORD" and not any(k in fields for k in ("hold_active", "active")):
            note = "hold activity condition not explicit in record"
        return None, None, ("VERIFY_RECORD_PRESENT", "PRESENT"), note
    return None, None, None, "policy branch missing"
