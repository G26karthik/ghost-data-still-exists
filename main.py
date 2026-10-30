"""Run the deterministic deletion audit against participant input files."""

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from ghost.evidence import Observation, activity_links, load, read_csv
from ghost.activity import correlate, unique_action_target
from ghost.intake import classify
from ghost.identity import IdentityIndex
from ghost.planner import plan
from ghost.policy import load_rules
from ghost.state import account_state_from_id, record_from_action, resources
from ghost.validate import HEADER, validate
from ghost.vision import transcribe_all
from ghost.agent import AgentConfig, AgentRuntime, AgentTransport
from ghost.agent_tools import AgentTools


def predict(dataset: Path, sample: bool = False, offline: bool = False,
            run_dir: Path = Path("runs/final"), ocr_crosscheck: bool = False,
            with_context: bool = False) -> tuple[Any, ...]:
    samples = read_csv(dataset / "sample_deletion_requests.csv")
    evaluation = read_csv(dataset / "deletion_requests.csv")
    requests = samples if sample else evaluation
    identities = IdentityIndex(read_csv(dataset / "user_identities.csv"),
                               read_csv(dataset / "user_audit_log.csv"))
    manifest = read_csv(dataset / "evidence_files.csv")
    vision_records, vision_fresh = transcribe_all(dataset, manifest, run_dir, offline)
    if sample:
        # Exposed sample scoring is free: the deterministic guard is the final authority.
        authorization, disagreements, bad_quotes = {}, [], []
    else:
        authorization, disagreements, bad_quotes = classify(requests, run_dir, offline)
    observations, coverage, manifest = load(dataset, vision_records, ocr_crosscheck)
    observations.extend(activity_links(dataset))
    activity = read_csv(dataset / "system_activity.csv")
    # Worker activities are shared across both supplied cohorts. Assign once,
    # then emit only the requested cohort so a target cannot be claimed twice.
    assignments = correlate(samples + evaluation, identities, observations, activity)
    rules = load_rules(dataset)
    rows = []
    gaps = []
    case_facts = {}
    for request in requests:
        uid, subject = identities.resolve(request["email"])
        if not uid:
            gaps.append((request["case_id"], "request email not resolved"))
        action_observations = [action_link(row, subject) for row in
                                            ([assignments.account[request["case_id"]]] if
                                             request["case_id"] in assignments.account else []) +
                                            assignments.policy.get(request["case_id"], [])]
        case_observations = observations + action_observations
        found, local, unresolved = resources(request, subject, case_observations, activity)
        assigned = assignments.account.get(request["case_id"])
        if assigned and not any(item[2] == "USER_PROFILE" for item in found):
            inferred, inference_gap = account_state_from_id(request, assigned["resource_id"], case_observations)
        else:
            inferred, inference_gap = None, None
        if inferred:
            found.append(inferred)
            unresolved = [item for item in unresolved if item[1] != inferred[1]]
        if inference_gap:
            local.append(inference_gap)
        if not assigned:
            rid = unique_action_target(request, requests, found, activity)
            if rid:
                action_fact, action_gap = record_from_action(request, rid, observations)
                if action_fact:
                    found.append(action_fact)
                if action_gap:
                    local.append(action_gap)
        row, plan_gaps = plan(request, found, rules, unresolved,
                              authorization.get(request["case_id"]) if not sample else None)
        rows.append(row)
        gaps.extend((request["case_id"], *gap) for gap in local + plan_gaps)
        if with_context:
            case_facts[request["case_id"]] = {"request": request, "uid": uid,
                "subject": subject, "found": found, "unresolved": unresolved,
                "action_observations": action_observations, "row": row,
                "gaps": local + plan_gaps,
                "authorized": authorization.get(request["case_id"]) if not sample else None}
    rows.sort(key=lambda x: x["case_id"])
    result = (rows, gaps, coverage, manifest, requests, assignments, disagreements, bad_quotes, vision_fresh)
    return result + ((case_facts, observations, identities, rules, activity),) if with_context else result


def action_link(action: dict, subject: set[str]) -> Observation:
    """An activity row establishes a correlated target ID, never its final state."""
    return Observation(action["activity_id"], action["event_time"], action["event_time"],
                       action["resource_id"], action["target_system"], action,
                       frozenset(subject), "link", "activity_batch")


def save(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row["case_id"], row["deletion_status"],
                             json.dumps(row["steps_json"], ensure_ascii=False, separators=(",", ":"))])
    os.replace(temp, path)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    started = time.perf_counter()
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", nargs="?", choices=["audit", "serve"])
    parser.add_argument("--offline", action="store_true", help="Use only supplied participant evidence")
    parser.add_argument("--sample", action="store_true")
    parser.add_argument("--dataset", type=Path, default=Path("dataset"))
    parser.add_argument("--run-dir", type=Path, default=Path("runs/final"))
    parser.add_argument("--ocr-crosscheck", action="store_true",
                        help="Optionally compare reviewed screenshot IDs with local OCR")
    parser.add_argument("--case", help="Known participant case ID for audit mode")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    result = predict(args.dataset, args.sample, args.offline, args.run_dir,
                     args.ocr_crosscheck, with_context=True)
    rows, gaps, coverage, manifest, requests, assignments, disagreements, bad_quotes, vision_fresh, context = result
    facts, observations, identities, rules, activity = context
    tools = AgentTools(facts, observations, identities, rules, activity, assignments, manifest)
    config = AgentConfig.environment()
    runtime = AgentRuntime(tools, AgentTransport(config, args.run_dir, args.offline), config, args.run_dir)
    if args.mode == "audit":
        if not args.case or args.case not in facts:
            parser.error("audit requires --case with a known case ID")
        row, trace = runtime.run_case(args.case)
        print(json.dumps({"row": row, "trace": trace if args.explain else
                          {"tools": [item["name"] for item in trace["tools"]],
                           "rationale": trace["rationale"], "fallback": trace["fallback"]}},
                         ensure_ascii=False, indent=2))
        return 0
    if args.mode == "serve":
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 4096:
                        raise ValueError("request size must be 1 to 4096 bytes")
                    payload = json.loads(self.rfile.read(size))
                    cid = payload["case_id"]
                    if cid not in facts or any(payload.get(key, facts[cid]["request"].get(key)) !=
                                               facts[cid]["request"].get(key) for key in
                                               ("request_text", "email", "audit_at")):
                        raise ValueError("unknown or changed participant request")
                    row, trace = runtime.run_case(cid)
                    body, status = {"row": row, "trace": trace}, 200
                except (ValueError, KeyError, TypeError) as exc:
                    body, status = {"error": str(exc)}, 400
                data = json.dumps(body, ensure_ascii=False, default=str).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        print(f"serving {len(facts)} indexed requests on port {args.port}")
        ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
        return 0
    rows, traces, summary = runtime.run_all([row["case_id"] for row in requests])
    errors = validate(rows, requests, manifest, read_csv(args.dataset / "system_activity.csv"))
    print("coverage", len(manifest), "files", sum(coverage.values()), "observations")
    print("file_id | observations | path")
    for item in manifest:
        count = coverage[item["file_id"]]
        print(item["file_id"], "|", count, "|", item["file_path"], "ZERO" if not count else "")
    print("statuses", dict(Counter(x["deletion_status"] for x in rows)))
    print("activity_assignments", dict(assignments.counts))
    print("activity_ambiguous", assignments.ambiguous)
    print("intake_disagreements", disagreements)
    print("intake_bad_quotes", bad_quotes)
    print("vision_fresh", vision_fresh)
    print("agent_summary", json.dumps(summary, sort_keys=True))
    if traces:
        counts = [len(trace["tools"]) for trace in traces.values()]
        print("agent_tool_calls_mean_max", round(sum(counts) / len(counts), 3), max(counts))
        comparisons = [trace["agreement_before_gate"] for trace in traces.values()
                       if trace["agreement_before_gate"] is not None]
        print("agent_agreement_before_gate", sum(comparisons), len(comparisons))
    print("gaps", len(gaps), "first", gaps[:15])
    print("contract_errors", len(errors), "first", errors[:20])
    if errors:
        print("elapsed_seconds", round(time.perf_counter() - started, 3))
        return 1
    path = args.run_dir / "sample_predictions.csv" if args.sample else Path("output.csv")
    save(rows, path)
    print("saved", path)
    print("elapsed_seconds", round(time.perf_counter() - started, 3))
    return 0


if __name__ == "__main__":
    sys.exit(main())
