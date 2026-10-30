"""Mechanical output contract checks independent of planning."""

import argparse
import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

HEADER = ["case_id", "deletion_status", "steps_json"]
FIELDS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]
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
STATES = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}


def validate(rows: list[dict], requests: list[dict], manifest: list[dict],
             activity: tuple | list[dict] = ()) -> list[str]:
    errors = []
    expected = {x["case_id"] for x in requests}
    observed = [x["case_id"] for x in rows]
    if len(rows) != len(requests) or Counter(observed) != Counter(expected):
        errors.append("case coverage differs from requests")
    if observed != sorted(observed):
        errors.append("rows are not sorted by case_id")
    by_request = {x["case_id"]: x for x in requests}
    by_file = {x["file_id"]: x for x in manifest}
    by_file.update({x["activity_id"]: {"captured_at": x["event_time"]} for x in activity})
    for row in rows:
        cid = row["case_id"]
        status = row["deletion_status"]
        steps = row["steps_json"]
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            errors.append(f"{cid}: illegal status")
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json is not an array")
            continue
        if status == "NOT_APPLICABLE" and steps:
            errors.append(f"{cid}: non-deletion has steps")
        if status != "NOT_APPLICABLE" and not steps:
            errors.append(f"{cid}: deletion has no verifications")
        if status == "INCOMPLETE" and {x["phase"] for x in steps} != set(OPERATIONS):
            errors.append(f"{cid}: incomplete plan has missing phase")
        if status == "COMPLETE" and any(x["phase"] != "VERIFICATION" for x in steps):
            errors.append(f"{cid}: complete row has nonverification step")
        ordered = True
        for number, step in enumerate(steps, 1):
            if not isinstance(step, dict) or set(step) != set(FIELDS) or \
                    type(step["step_no"]) is not int or step["step_no"] != number or \
                    any(not isinstance(step[field], str) for field in FIELDS if field != "step_no"):
                errors.append(f"{cid}/{number}: step schema/number")
                ordered = False
                continue
            if (step["phase"], step["operation"]) not in RANK or STATES.get(step["operation"]) != step["state"]:
                errors.append(f"{cid}/{number}: operation/state")
                ordered = False
                continue
            citation = step["evidence_id"]
            needs = step["phase"] == "FINDING" or status == "COMPLETE"
            if bool(citation) != needs:
                errors.append(f"{cid}/{number}: citation presence")
            if citation and citation in by_file and cid in by_request:
                file_at = datetime.fromisoformat(by_file[citation]["captured_at"].replace("Z", "+00:00"))
                audit_at = datetime.fromisoformat(by_request[cid]["audit_at"].replace("Z", "+00:00"))
                if file_at > audit_at:
                    errors.append(f"{cid}/{number}: citation after cutoff")
            elif citation and citation not in by_file:
                errors.append(f"{cid}/{number}: unknown citation")
        if ordered and steps != sorted(steps, key=lambda x: (*RANK[x["phase"], x["operation"]],
                                                            x["system_id"], x["resource_id"])):
            errors.append(f"{cid}: noncanonical sequence")
    return errors


def main() -> bool:
    parser = argparse.ArgumentParser(description="Validate the final CSV against the participant input")
    parser.add_argument("output", type=Path, nargs="?", default=Path("output.csv"))
    parser.add_argument("--dataset", type=Path, default=Path("dataset"))
    args = parser.parse_args()

    def table(path: Path) -> list[dict]:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            return list(csv.DictReader(stream))

    with args.output.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != HEADER:
            raise ValueError(f"Wrong output header: {reader.fieldnames}")
        rows = [{**row, "steps_json": json.loads(row["steps_json"])} for row in reader]
    problems = validate(rows, table(args.dataset / "deletion_requests.csv"),
                        table(args.dataset / "evidence_files.csv"),
                        table(args.dataset / "system_activity.csv"))
    print(f"rows={len(rows)} errors={len(problems)}")
    for problem in problems:
        print(problem)
    return bool(problems)


if __name__ == "__main__":
    raise SystemExit(main())
