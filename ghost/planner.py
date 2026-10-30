"""Build the one official decision row from linked, time-valid resources."""

import re

from .evidence import Observation
from .policy import treatment


OPERATIONS = {
    "FINDING": ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW",
                "REPORT_RESTORE_RISK"],
    "REMEDIATION": ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD",
                    "ANONYMIZE_RECORD"],
    "VERIFICATION": ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                     "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"],
}
RANK = {(phase, op): (phase_number, operation_number) for phase_number, (phase, operations) in
        enumerate(OPERATIONS.items()) for operation_number, op in enumerate(operations)}


def is_deletion_request(text: str) -> bool:
    """A deliberately narrow interim classifier; ambiguous language is reported separately."""
    value = text.casefold()
    negative = (r"\bdo not (?:delete|erase|close|remove)\b", r"\bdon't (?:delete|erase|close|remove)\b",
                r"\bnot (?:asking|a request) (?:for|to) (?:delet\w*|eras\w*)\b",
                r"\bwithout (?:removing|deleting|erasing)\b",
                r"\bremove me from (?:marketing|promotional|newsletter)\b",
                r"\b(?:access|download|export|correct|update|change|login|invoice|receipt) (?:my|the)\b",
                r"\b(?:marketing|newsletter) opt.out\b")
    if any(re.search(pattern, value) for pattern in negative):
        return False
    positive = ("delet", "eras", "remov", "close my account", "close the account", "close this account",
                "forget me", "elimin", "borr", "supprim", "löschen", "cancell", "purge", "wipe",
                "削除", "消去", "삭제", "exclusão", "gone", "suppression", "privacy request")
    return any(term in value for term in positive)


def plan(request: dict, resources: list[tuple[str, str, str, str, Observation]],
         rules: dict[str, dict], unresolved: tuple | list = (),
         authorized: bool | None = None) -> tuple[dict, list[tuple[str, str]]]:
    # ponytail: This cohesive function builds, orders, and numbers one official row.
    cid = request["case_id"]
    if not (is_deletion_request(request["request_text"]) if authorized is None else authorized):
        return {"case_id": cid, "deletion_status": "NOT_APPLICABLE", "steps_json": []}, []
    steps = []
    gaps = []
    for system, rid, category, current, obs in resources:
        finding, remediation, verification, note = treatment(category, current, obs.fields, rules)
        if note:
            gaps.append((rid, note))
        for phase, choice in (("FINDING", finding), ("REMEDIATION", remediation),
                              ("VERIFICATION", verification)):
            if choice is None:
                continue
            operation, target_state = choice
            steps.append({"step_no": 0, "phase": phase, "system_id": system, "resource_id": rid,
                          "operation": operation, "state": target_state,
                          "evidence_id": obs.file_id if phase == "FINDING" else ""})
    status = "INCOMPLETE" if any(x["phase"] == "FINDING" for x in steps) else "COMPLETE"
    if status == "INCOMPLETE":
        # A known resource still requires a future check even when its audit-time state is unresolved.
        for system, rid, category, _obs in unresolved:
            if any(x["resource_id"] == rid and x["system_id"] == system and x["phase"] == "VERIFICATION"
                   for x in steps):
                continue
            _finding, _remediation, verify, note = treatment(category, "ABSENT" if category in
                ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "USER_EXPORT", "SUPPORT_ATTACHMENT",
                 "MARKETING_PROFILE", "SECONDARY_IDENTIFIER", "CACHE_ENTRY") else
                "BLOCKED" if category == "BACKUP_ARCHIVE" else "DISABLED" if category == "DATA_FLOW" else
                "REDACTED" if category in ("SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE", "EMAIL_DELIVERY_LOG") else
                "ANONYMIZED" if category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY") else "PRESENT", {}, rules)
            if verify:
                steps.append({"step_no": 0, "phase": "VERIFICATION", "system_id": system,
                              "resource_id": rid, "operation": verify[0], "state": verify[1], "evidence_id": ""})
                gaps.append((rid, "verification obligation included; audit-time state unresolved"))
    if status == "COMPLETE":
        citation = {(system, rid): obs.file_id for system, rid, _cat, _state, obs in resources}
        for step in steps:
            step["evidence_id"] = citation[(step["system_id"], step["resource_id"])]
    steps.sort(key=lambda x: (*RANK[x["phase"], x["operation"]], x["system_id"], x["resource_id"]))
    for number, step in enumerate(steps, 1):
        step["step_no"] = number
    if not steps:
        gaps.append((cid, "deletion intent but no linked time-valid resource"))
    return {"case_id": cid, "deletion_status": status, "steps_json": steps}, gaps
