"""Correlate deletion-worker batches through timestamps, without treating actions as state proof."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from .evidence import Observation
from .identity import IdentityIndex
from .planner import is_deletion_request


STATUS_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}
FOLLOWUP = re.compile(
    r"Deletion worker received the final result|Active connector repopulated downstream resource|"
    r"Replication worker reported its final checkpoint", re.I)


def at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def second_distance(left: float, right: float) -> float:
    difference = (left - right) % 60
    return min(difference, 60 - difference)


def policy_offset(row: dict) -> float | None:
    if "Policy action completed for" not in row["details"]:
        return None
    operation, system = row["event_type"], row["target_system"]
    if (operation == "ANONYMIZE_RECORD" and system == "analytics_platform") or \
       (operation == "REDACT_RECORD" and system == "identity_service") or \
       (operation == "RETAIN_RECORD" and system == "legal_service"):
        return 19.5
    if operation == "REDACT_RECORD" and system == "support_platform":
        return 49.5
    if operation == "DISABLE_DATA_FLOW":
        return 20.5
    if operation == "BLOCK_RESTORE":
        return 50.5
    return None


def is_followup(row: dict) -> bool:
    return row["event_type"] in ("CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS") or \
        bool(FOLLOWUP.search(row["details"]))


def earliest_activity_tiebreak(candidates: list[dict]) -> dict:
    """Choose a reproducible unresolved target; this does not prove ownership."""
    return min(candidates, key=lambda row: (at(row["event_time"]), row["activity_id"]))


@dataclass
class Assignments:
    account: dict[str, dict]
    policy: dict[str, list[dict]]
    ambiguous: list[str]
    counts: Counter
    candidates: dict[str, list[dict]] | None = None


def unique_action_target(request: dict, requests: list[dict], found: list, activity: list[dict]) -> str | None:
    """Name a target only when a worker action is unique near a lone report."""
    report = at(request["reported_at"])
    if any(other["case_id"] != request["case_id"] and
           abs((at(other["reported_at"]) - report).total_seconds()) <= 900 for other in requests):
        return None
    candidates = [row for row in activity if row.get("source_system") == "deletion_worker" and
                  row.get("resource_id") and abs((at(row["event_time"]) - report).total_seconds()) <= 900]
    pending = {row["resource_id"] for row in candidates if all(
        item[1] != row["resource_id"] for item in found)}
    return next(iter(pending)) if len(pending) == 1 else None


def correlate(requests: list[dict], identities: IdentityIndex,
              observations: list[Observation], activity: list[dict]) -> Assignments:
    """Resolve batch targets from measured second offsets and independent identity links."""
    # ponytail: one fixed-point pass owns global account exclusivity and policy action claims.
    by_resource = defaultdict(list)
    for obs in observations:
        if obs.resource_id:
            by_resource[obs.resource_id].append(obs)
    action_by_resource = defaultdict(list)
    for row in activity:
        if row["resource_id"]:
            action_by_resource[row["resource_id"]].append(row)

    def follows_candidate(candidate: dict, item: dict) -> bool:
        """Check the first linked follow-up, including this account's own checkpoint."""
        report = at(item["request"]["reported_at"])
        checkpoints = [row for row in action_by_resource[candidate["resource_id"]] if
                       row["event_type"] == "SYNC_RECORD" and
                       "Replication worker reported its final checkpoint for account_" in row["details"] and
                       report - timedelta(hours=2) <= at(row["event_time"]) <= report + timedelta(hours=5)]
        followups = item["followups"] + checkpoints
        if not followups:
            return True
        first = min(followups, key=lambda row: at(row["event_time"]))
        expected = (at(first["event_time"]).second - 51.5) % 60
        return second_distance(at(candidate["event_time"]).second, expected) <= .75
    deletes = [row for row in activity if row["event_type"] == "DELETE_RECORD" and
               row["target_system"] == "account_service" and row["resource_id"].startswith("account_")]
    data = {}
    counts = Counter()

    for request in requests:
        if not is_deletion_request(request["request_text"]):
            continue
        cid = request["case_id"]
        uid, subject = identities.resolve(request["email"])
        report, requested, audit = at(request["reported_at"]), at(request["requested_at"]), at(request["audit_at"])
        owner_window = (requested - timedelta(days=30), audit + timedelta(days=7))
        linked = {(obs.system, obs.resource_id) for obs in observations if obs.resource_id and
                  obs.link_tokens & subject and owner_window[0] <= at(obs.file_captured_at) <= owner_window[1]}
        records = {rid for system, rid in linked if system != "account_service"}
        evidence_files = {obs.file_id for obs in observations if obs.resource_id in records and
                          obs.link_tokens & subject and obs.file_id.startswith("evidence_")}
        window = (report - timedelta(hours=2), report + timedelta(minutes=15))
        all_candidates = [row for row in deletes if window[0] <= at(row["event_time"]) <= window[1]]
        matching = [row for row in all_candidates if row["reported_result"] ==
                    STATUS_RESULT.get(request["reported_status"])]
        eligible = matching or all_candidates
        narrow = [row for row in eligible if report - timedelta(minutes=80) <=
                  at(row["event_time"]) <= report - timedelta(minutes=40)]
        candidates = narrow or eligible
        counts["cases"] += 1
        counts["status_filter_fallback"] += not bool(matching)
        counts["time_window_fallback"] += not bool(narrow)
        counts["initial_unique"] += len(candidates) == 1
        counts["initial_zero"] += not candidates

        associated = [row for rid in records for row in action_by_resource[rid] if
                      report - timedelta(hours=2) <= at(row["event_time"]) <=
                      report + timedelta(hours=5)]
        constraints = []
        for row in associated:
            k = policy_offset(row)
            if k is not None:
                constraints.append(((at(row["event_time"]).second + k) % 60, row["activity_id"]))
        followups = [row for row in associated if is_followup(row)]
        counts["cases_with_constraints"] += bool(constraints or followups)
        data[cid] = {"request": request, "uid": uid, "linked": linked, "evidence_files": evidence_files,
                     "candidates": candidates, "constraints": constraints, "followups": followups,
                     "owner_window": owner_window}

    def belongs_elsewhere(candidate: dict, item: dict) -> bool:
        owners = set()
        for obs in by_resource[candidate["resource_id"]]:
            if not (item["owner_window"][0] <= at(obs.file_captured_at) <= item["owner_window"][1]):
                continue
            owners.update(identities.owner[token] for token in obs.link_tokens if token in identities.owner)
        return len(owners) == 1 and item["uid"] not in owners

    assigned = {}
    used = set()
    pending = set(data)
    while True:
        changed = False
        for cid in sorted(pending, key=lambda key: (len(data[key]["candidates"]), key)):
            item = data[cid]
            open_candidates = [row for row in item["candidates"] if row["activity_id"] not in used and
                               not belongs_elsewhere(row, item)]
            identity_matches = [row for row in open_candidates if
                                ("account_service", row["resource_id"]) in item["linked"]]
            if len(identity_matches) == 1:
                survivors = identity_matches
                counts["assigned_identity"] += 1
            else:
                survivors = [row for row in open_candidates if all(
                    second_distance(at(row["event_time"]).second, expected) <= .75
                    for expected, _source in item["constraints"]) and follows_candidate(row, item)]
                if not survivors and len(open_candidates) == 1:
                    survivors = open_candidates
                    counts["constraint_override_single"] += 1
                if len(survivors) > 1 and item["evidence_files"]:
                    scores = {row["activity_id"]: len({obs.file_id for obs in by_resource[row["resource_id"]]}
                                                       & item["evidence_files"]) for row in survivors}
                    best = max(scores.values())
                    if best > 0 and sum(score == best for score in scores.values()) == 1:
                        survivors = [row for row in survivors if scores[row["activity_id"]] == best]
                        counts["assigned_same_file"] += 1
            if len(survivors) == 1:
                chosen = survivors[0]
                assigned[cid] = chosen
                used.add(chosen["activity_id"])
                pending.remove(cid)
                changed = True
                counts["assigned_unique"] += 1
        if not changed:
            break

    ambiguous = []
    for cid in sorted(pending):
        item = data[cid]
        remaining = [row for row in item["candidates"] if row["activity_id"] not in used and
                     not belongs_elsewhere(row, item)]
        ambiguous.append(cid)
        if remaining:
            chosen = earliest_activity_tiebreak(remaining)
            assigned[cid] = chosen
            used.add(chosen["activity_id"])
            counts["assigned_tiebreak"] += 1
        else:
            counts["unassigned"] += 1

    policy_proposals = defaultdict(list)
    for cid, delete in assigned.items():
        item = data[cid]
        report = at(item["request"]["reported_at"])
        second = at(delete["event_time"]).second
        for row in activity:
            k = policy_offset(row)
            if k is None or not (report - timedelta(minutes=40) <= at(row["event_time"]) <=
                                 report + timedelta(minutes=5)):
                continue
            if belongs_elsewhere(row, item):
                continue
            if any(system == row["target_system"] and rid != row["resource_id"]
                   for system, rid in item["linked"]):
                # An explicit subject link in this system outranks a batch-time link.
                continue
            distance = second_distance((at(row["event_time"]).second + k) % 60, second)
            if distance <= .75:
                policy_proposals[row["activity_id"]].append((distance, abs((at(row["event_time"]) - report).total_seconds()),
                                                               cid, row))
    policy = defaultdict(list)
    for proposals in policy_proposals.values():
        _distance, _time, cid, row = min(proposals)
        policy[cid].append(row)
        counts["policy_linked"] += 1
    counts["ambiguous_cases"] = len(ambiguous)
    return Assignments(assigned, dict(policy), ambiguous, counts,
                       {cid: item["candidates"] for cid, item in data.items()})
