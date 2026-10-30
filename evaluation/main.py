"""Offline comparison; sample answers are never imported by prediction code."""

import argparse
import csv
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path


KEYS = ("phase", "operation", "system_id", "resource_id", "state", "evidence_id")
FIELDS = ("step_no", *KEYS)


def read(path: Path) -> dict[str, dict]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return {row["case_id"]: {**row, "steps_json": json.loads(row["steps_json"])}
                for row in csv.DictReader(stream)}


def score(predictions: Path, answers: Path) -> dict:
    # ponytail: case, step, field, and sequence measures share one alignment pass.
    pred = read(predictions)
    gold = read(answers)
    if set(pred) != set(gold):
        raise ValueError("Prediction and answer case coverage differs")
    exact = status = tp = pp = gp = sequence = 0
    fields = {field: [0, 0] for field in FIELDS}
    causes = Counter()
    for cid in sorted(gold):
        a, b = pred[cid], gold[cid]
        equal_status = a["deletion_status"] == b["deletion_status"]
        status += equal_status
        a_steps, b_steps = a["steps_json"], b["steps_json"]
        exact += a == b
        sequence += [tuple(x[k] for k in KEYS) for x in a_steps] == [tuple(x[k] for k in KEYS) for x in b_steps]
        ap = Counter(tuple(x[k] for k in KEYS) for x in a_steps)
        bp = Counter(tuple(x[k] for k in KEYS) for x in b_steps)
        tp += sum((ap & bp).values())
        pp += sum(ap.values())
        gp += sum(bp.values())
        # Compare positions within each case; unmatched steps count in precision/recall.
        for predicted, expected in zip(a_steps, b_steps):
            for field in FIELDS:
                fields[field][0] += predicted[field] == expected[field]
                fields[field][1] += 1
        if a != b:
            missing = list((bp - ap).elements())
            extra = list((ap - bp).elements())
            if not equal_status:
                causes["status"] += 1
            if missing:
                causes["missing steps"] += 1
            if extra:
                causes["extra steps"] += 1
            print(cid, "status", a["deletion_status"], "expected", b["deletion_status"],
                  "missing", missing, "extra", extra)
    precision = tp / pp if pp else 0
    recall = tp / gp if gp else 0
    result = {"cases": len(gold), "exact_rows": exact, "status_correct": status,
              "steps_correct": tp, "steps_predicted": pp, "steps_expected": gp,
              "step_precision": precision, "step_recall": recall,
              "step_f1": 2 * precision * recall / (precision + recall) if precision + recall else 0,
              "sequence_correct": sequence, "fields": fields, "causes": dict(causes)}
    print("exact_rows", exact, "/", len(gold), "status_accuracy", status, "/", len(gold),
          "step_precision", round(precision, 4), "step_recall", round(recall, 4),
          "step_f1", round(result["step_f1"], 4), "sequence_accuracy", sequence, "/", len(gold))
    for field, (correct, total) in fields.items():
        print("field", field, correct, "/", total, round(correct / total, 4) if total else 0)
    print("causes", dict(causes))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("predictions", type=Path, nargs="?",
                        help="Sample CSV; omit to generate one offline from the supplied dataset")
    parser.add_argument("--dataset", type=Path, default=Path("dataset"))
    parser.add_argument("--answers", type=Path)
    args = parser.parse_args()
    answers = args.answers or args.dataset / "sample_output.csv"
    if args.predictions:
        score(args.predictions, answers)
    else:
        with tempfile.TemporaryDirectory() as run:
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / "main.py"),
                       "--offline", "--sample", "--dataset", str(args.dataset), "--run-dir", run]
            completed = subprocess.run(command, capture_output=True, text=True)
            if completed.returncode:
                raise RuntimeError(completed.stdout[-2000:] + completed.stderr[-2000:])
            score(Path(run) / "sample_predictions.csv", answers)
