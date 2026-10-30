"""Classify linked resources using observations valid at the audit cutoff."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from .evidence import Observation


PREFIX_CATEGORY = {
    "account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY", "support": "SUPPORT_MESSAGE",
    "analytics": "ANALYTICS_PROFILE", "export": "USER_EXPORT", "data_flow": "DATA_FLOW",
    "backup": "BACKUP_ARCHIVE", "audit_record": "SECURITY_AUDIT_LOG", "tombstone": "ACCOUNT_TOMBSTONE",
    "marketing": "MARKETING_PROFILE", "object": "SUPPORT_ATTACHMENT", "legal_hold": "LEGAL_HOLD_RECORD",
    "cache": "CACHE_ENTRY", "email_log": "EMAIL_DELIVERY_LOG", "telemetry": "PRODUCT_TELEMETRY",
}
IDENTIFIER_FIELDS = {"email", "phone", "email_hash", "full_name", "name", "display_name", "requester_name",
                     "requester_email", "requester_phone", "owner_email", "owner_phone", "customer_email",
                     "user_id", "matched_value"}
ABSENT_RESULTS = {"NOT_FOUND", "ABSENT", "MISS", "DELETED"}


def time(value: str) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if str(value).lower() in ("true", "1", "yes", "allowed", "hit"):
        return True
    if str(value).lower() in ("false", "0", "no", "denied", "miss"):
        return False
    return None


def category(obs: Observation) -> str:
    fields = obs.fields
    declared = fields.get("record_type")
    if declared in PREFIX_CATEGORY.values():
        return declared
    rid = obs.resource_id
    prefix = rid.rsplit("_", 1)[0]
    result = PREFIX_CATEGORY.get(prefix, PREFIX_CATEGORY.get(rid.split("_")[0], ""))
    text = " ".join(str(fields.get(x, "")) for x in
                    ("event", "collection", "table", "file_name", "file", "source", "text")) .lower()
    if result == "SUPPORT_MESSAGE":
        if "contact" in text and "attachment" not in text:
            return "SECONDARY_IDENTIFIER"
        if any(x in text for x in ("attachment", "uploaded", "object_storage", ".pdf")):
            return "SUPPORT_ATTACHMENT"
    if result == "ANALYTICS_PROFILE" and ("contact" in text or "marketing" in text or
                                          "opt_in" in text or "email_opt_in" in fields):
        return "MARKETING_PROFILE"
    return result


def worker_operation_class(request: dict, system: str, resource_id: str,
                           activity: list[dict]) -> str | None:
    """Use a worker's attempted operation to classify a linked record, never its state."""
    classes = {
        ("support_platform", "DELETE_RECORD"): "SUPPORT_ATTACHMENT",
        ("support_platform", "REDACT_RECORD"): "SUPPORT_MESSAGE",
        ("analytics_platform", "DELETE_RECORD"): "MARKETING_PROFILE",
        ("analytics_platform", "ANONYMIZE_RECORD"): "ANALYTICS_PROFILE",
    }
    if system not in ("support_platform", "analytics_platform"):
        return None
    reported = time(request["reported_at"])
    choices = {classes.get((system, row["event_type"])) for row in activity
               if row.get("source_system") == "deletion_worker" and
               row.get("target_system") == system and row.get("resource_id") == resource_id and
               reported - timedelta(hours=2) <= time(row["event_time"]) <=
               reported + timedelta(hours=5)} - {None}
    return next(iter(choices)) if len(choices) == 1 else None


def record_from_action(request: dict, rid: str, observations: list[Observation]) -> tuple[tuple | None, tuple[str, str]]:
    """Resolve a uniquely timed target's state only from an independent readback."""
    audit = time(request["audit_at"])
    valid = [obs for obs in observations if obs.resource_id == rid and obs.kind == "record" and
             time(obs.file_captured_at) <= audit and time(obs.record_time) <= audit]
    if not valid:
        return None, (rid, "unique action target but no time-valid readback")
    obs = max(valid, key=lambda item: (item.record_time, item.file_captured_at))
    cat = category(obs)
    return ((obs.system, rid, cat, state(obs, cat), obs),
            (rid, "ownership inferred from unique near-report action; state from independent readback"))


def account_state_from_id(request: dict, rid: str,
                          observations: list[Observation]) -> tuple[tuple | None, tuple[str, str]]:
    """Read an assigned account or its omission from a later complete snapshot."""
    reported, audit = time(request["reported_at"]), time(request["audit_at"])
    existing = [obs for obs in observations if obs.resource_id == rid and obs.kind == "record" and
                time(obs.file_captured_at) <= audit and time(obs.record_time) <= audit]
    if existing:
        obs = max(existing, key=lambda item: (item.record_time, item.file_captured_at))
        cat = category(obs)
        return ((obs.system, rid, cat, state(obs, cat), obs),
                (rid, "ownership inferred from a unique near-report operation, not explicit subject link"))
    scopes = [obs for obs in observations if obs.kind == "scope" and obs.system == "account_service" and
              (obs.fields.get("full_copy") or obs.fields.get("table", "").startswith("customer_profiles") or
               obs.fields.get("collection") == "customer_profiles") and
              reported <= time(obs.file_captured_at) <= audit]
    if not scopes:
        return None, (rid, "unique account action but no subsequent full account snapshot")
    scope = max(scopes, key=lambda item: item.file_captured_at)
    obs = Observation(scope.file_id, scope.file_captured_at, scope.record_time, rid,
                      "account_service", {"resource_id": rid, "result": "NOT_FOUND",
                                          "inference": "omitted from full account snapshot"},
                      frozenset(), "record", scope.scope)
    return (("account_service", rid, "USER_PROFILE", "ABSENT", obs),
            (rid, "ownership inferred from a unique near-report operation; absence from full snapshot"))


def has_direct_identifiers(fields: dict) -> bool:
    direct = fields.get("direct_identifiers")
    if direct is not None:
        try:
            return int(direct) > 0
        except (ValueError, TypeError):
            pass
    for key, value in fields.items():
        if key in IDENTIFIER_FIELDS and value and str(value).upper() != "[REDACTED]":
            return True
    message = str(fields.get("message_text") or "")
    return "@" in message and message.upper() != "[REDACTED]"


def state(obs: Observation, cat: str) -> str:
    # ponytail: ordered category-specific rules map one source observation to one state.
    f = obs.fields
    result = str(f.get("result") or f.get("state") or "").upper()
    if result in ABSENT_RESULTS or f.get("status_code") == 404 or str(f.get("http_status")) == "404":
        return "ABSENT"
    if f.get("profile") is None and "profile" in f:
        return "ABSENT"
    if str(f.get("rows")) == "0" or (f.get("collection") == "index_queries" and
                                     (str(f.get("total")) == "0" or not f.get("hits", {}).get("documents", []))):
        return "ABSENT"
    if result in {"FOUND", "PRESENT", "IDENTIFIABLE", "ANONYMIZED", "REDACTED", "ACTIVE", "DISABLED", "BLOCKED"}:
        if result == "FOUND":
            return "PRESENT" if cat not in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
                                              "SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE", "EMAIL_DELIVERY_LOG") else \
                   ("IDENTIFIABLE" if has_direct_identifiers(f) else "ANONYMIZED" if cat in
                    ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY") else "REDACTED")
        return result
    if cat == "DATA_FLOW":
        for key in ("enabled", "delivering", "active"):
            if key in f:
                return "ACTIVE" if _bool(f[key]) else "DISABLED"
        return "UNKNOWN"
    if cat == "BACKUP_ARCHIVE":
        if str(f.get("decision", "")).lower() == "deny" or _bool(f.get("deletion_block")) is True:
            return "BLOCKED"
        for key in ("restore_allowed", "eligible"):
            if key in f:
                return "ACTIVE" if _bool(f[key]) else "BLOCKED"
        if f.get("image_archive_listed"):
            # A listed archive with no time-valid restore block remains a restoration risk.
            return "ACTIVE"
        return "UNKNOWN"
    if cat == "USER_EXPORT" and (f.get("download_available") is False or f.get("available") is False):
        return "ABSENT"
    if cat == "USER_PROFILE" and str(f.get("account_status", "")).upper() == "DELETED":
        return "ABSENT"
    if cat in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
        return "IDENTIFIABLE" if has_direct_identifiers(f) else "ANONYMIZED"
    if cat in ("SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE", "EMAIL_DELIVERY_LOG"):
        return "IDENTIFIABLE" if has_direct_identifiers(f) else "REDACTED"
    if cat:
        return "PRESENT"
    return "UNKNOWN"


def physical_scope(obs: Observation) -> str:
    """Group repeated snapshots of the same copy without merging replicas."""
    table = str(obs.fields.get("table") or "").lower()
    if "replica" in table:
        return f"sql:{table}"
    if "primary" in table:
        return f"sql:{table}"
    if obs.file_id.startswith("evidence_") and ":" in obs.scope:
        if "snapshot" in obs.scope or obs.fields.get("collection"):
            return f"{obs.system}:{obs.fields.get('collection','')}"
    return obs.scope or obs.file_id


def resources(request: dict, subject_tokens: set[str], observations: list[Observation],
              activity: tuple | list[dict] = ()) -> tuple[list[tuple], list[tuple[str, str]], list[tuple]]:
    # ponytail: one audit-cutoff pass selects the latest state for each physical copy.
    requested = time(request["requested_at"])
    audit = time(request["audit_at"])
    linked = defaultdict(list)
    for obs in observations:
        if not obs.resource_id or not (obs.link_tokens & subject_tokens):
            continue
        if not (requested - timedelta(days=30) <= time(obs.file_captured_at)
                <= audit + timedelta(days=7)):
            continue
        linked[(obs.system, obs.resource_id)].append(obs)
    decisions = []
    gaps = []
    unresolved = []
    for (system, rid), owned in sorted(linked.items()):
        # A link establishes ownership only; all state readbacks for that ID still need a valid time.
        valid = [o for o in observations if o.resource_id == rid and o.system == system and o.kind == "record"
                 and time(o.file_captured_at) <= audit and time(o.record_time) <= audit]
        if not valid:
            if (category(owned[0]) not in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD") and
                    all(time(o.file_captured_at) > audit for o in owned)):
                # A later export cannot add a resource to the audit-time plan by itself.
                continue
            gaps.append((rid, "linked resource has no time-valid state observation"))
            exemplar = next((o for o in owned if o.kind == "record"), owned[0])
            unresolved.append((system, rid, category(exemplar), exemplar))
            continue
        cats = [category(o) for o in valid]
        cat = next((x for x in ("SUPPORT_ATTACHMENT", "MARKETING_PROFILE", "SECONDARY_IDENTIFIER")
                    if x in cats), cats[-1] if cats else "")
        cat = worker_operation_class(request, system, rid, activity) or cat
        if not cat:
            gaps.append((rid, "unknown data category"))
            continue
        latest_by_scope = {}
        for obs in valid:
            key = physical_scope(obs)
            if key not in latest_by_scope or (time(obs.record_time), time(obs.file_captured_at)) > \
                    (time(latest_by_scope[key].record_time), time(latest_by_scope[key].file_captured_at)):
                latest_by_scope[key] = obs
        classified = [(o, state(o, cat)) for o in latest_by_scope.values()]
        good = [pair for pair in classified if pair[1] != "ABSENT"]
        chosen = max(good or classified, key=lambda pair: (time(pair[0].record_time), time(pair[0].file_captured_at)))
        if chosen[1] == "UNKNOWN":
            gaps.append((rid, "state unknown from supplied fields"))
        decisions.append((system, rid, cat, chosen[1], chosen[0]))
    return decisions, gaps, unresolved
