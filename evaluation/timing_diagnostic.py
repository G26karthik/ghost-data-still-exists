"""Check worker timing on evaluation requests with independently linked accounts."""

import argparse
import sys
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost.activity import STATUS_RESULT, at, is_followup
from ghost.evidence import activity_links, load, read_csv
from ghost.identity import IdentityIndex
from ghost.vision import transcribe_all


POLICY_OFFSETS = {
    ("REDACT_RECORD", "support_platform"): {49, 50},
    ("BLOCK_RESTORE", "backup_service"): {50, 51},
    ("DISABLE_DATA_FLOW", "integration_service"): {20, 21},
    ("RETAIN_RECORD", "legal_service"): {19, 20},
    ("ANONYMIZE_RECORD", "analytics_platform"): {19, 20},
}


def diagnose(dataset: Path) -> tuple[dict, dict, dict]:
    # ponytail: independent source-linked timing checks are tallied in one source pass.
    manifest = read_csv(dataset / "evidence_files.csv")
    vision, _fresh = transcribe_all(dataset, manifest, Path("runs/final"), offline=True)
    observations, _coverage, _manifest = load(dataset, vision)
    observations.extend(activity_links(dataset))
    identities = IdentityIndex(read_csv(dataset / "user_identities.csv"),
                               read_csv(dataset / "user_audit_log.csv"))
    activity = read_csv(dataset / "system_activity.csv")
    by_resource = defaultdict(list)
    for row in activity:
        by_resource[row["resource_id"]].append(row)
    checks = defaultdict(lambda: [0, 0])
    offsets = defaultdict(Counter)
    exceptions = defaultdict(list)

    for request in read_csv(dataset / "deletion_requests.csv"):
        _uid, subject = identities.resolve(request["email"])
        report, requested, audit = (at(request[key]) for key in
                                    ("reported_at", "requested_at", "audit_at"))
        linked = {(obs.system, obs.resource_id) for obs in observations if obs.resource_id and
                  obs.link_tokens & subject and requested - timedelta(days=30) <=
                  at(obs.file_captured_at) <= audit + timedelta(days=7)}
        accounts = {rid for system, rid in linked if system == "account_service"}
        deletes = [row for rid in accounts for row in by_resource[rid] if
                   row["event_type"] == "DELETE_RECORD" and row["target_system"] == "account_service" and
                   report - timedelta(hours=2) <= at(row["event_time"]) <= report + timedelta(minutes=15)]
        if len(deletes) != 1:
            continue
        delete = deletes[0]
        lead = (report - at(delete["event_time"])).total_seconds() / 60
        for name, match in (("Account window", 40 <= lead <= 80),
                            ("Reported result", delete["reported_result"] ==
                             STATUS_RESULT.get(request["reported_status"]))):
            checks[name][0] += 1
            checks[name][1] += match
            if not match:
                exceptions[name].append(request["case_id"])

        associated = [row for system, rid in linked if system != "account_service"
                      for row in by_resource[rid] if report - timedelta(hours=2) <=
                      at(row["event_time"]) <= report + timedelta(hours=5)]
        own_checkpoints = [row for row in by_resource[delete["resource_id"]] if
                           row["event_type"] == "SYNC_RECORD" and
                           "Replication worker reported its final checkpoint for account_" in row["details"] and
                           report - timedelta(hours=2) <= at(row["event_time"]) <= report + timedelta(hours=5)]
        followups = [row for row in associated if is_followup(row)] + own_checkpoints
        if followups:
            first = min(followups, key=lambda row: at(row["event_time"]))
            offset = (at(first["event_time"]).second - at(delete["event_time"]).second) % 60
            offsets["First follow-up"][offset] += 1
            checks["First follow-up"][0] += 1
            checks["First follow-up"][1] += offset in (51, 52)
            if offset not in (51, 52):
                exceptions["First follow-up"].append(request["case_id"])

        linked_ids = {rid for system, rid in linked if system != "account_service"}
        for row in associated:
            key = (row["event_type"], row["target_system"])
            if key not in POLICY_OFFSETS or "Policy action completed for" not in row["details"] or \
                    row["resource_id"] not in linked_ids:
                continue
            name = f"{key[0]} / {key[1]}"
            offset = (at(delete["event_time"]).second - at(row["event_time"]).second) % 60
            offsets[name][offset] += 1
            checks[name][0] += 1
            checks[name][1] += offset in POLICY_OFFSETS[key]
            if offset not in POLICY_OFFSETS[key]:
                exceptions[name].append(request["case_id"])
    return dict(checks), dict(offsets), dict(exceptions)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("dataset"))
    args = parser.parse_args()
    rows, offsets, exceptions = diagnose(args.dataset)
    print("rule | checkable | agree | observed offsets | exceptions")
    for name, (total, agree) in rows.items():
        print(f"{name} | {total} | {agree} | {dict(sorted(offsets.get(name, {}).items()))} | "
              f"{exceptions.get(name, [])}")
