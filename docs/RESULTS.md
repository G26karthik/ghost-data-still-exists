# Results and failures

All figures are from the final run on the 518-request challenge set, plus the 32 public samples. The dataset is not in this repository; see the README for where to get it.

## Final run

| Measurement | Result |
| --- | ---: |
| First decisions matching the engine after sorting and numbering | 503 / 518 (97.10%) |
| First deletion plans matching (508 deletion cases) | 493 / 508 |
| Cases accepted after a gate diff | 15 |
| Rejected submissions | 15 |
| Fallbacks to the engine | 0 |
| Cases that read states and called `policy_lookup` before submitting | 508 / 508 |
| Plans visible to the model before it submitted | 0 |
| Tool calls; maximum for one case | 5,211; 19 |
| Fresh model calls | 5,190 (+21 reused from probes) |
| Wall time, eight workers | 1,180.754 s |
| Input / output tokens, whole experiment | 13,734,621 / 354,814 |
| Estimated cost | USD 0.4747 (USD 0.0009 per request) |
| Verdicts | 355 `INCOMPLETE`, 153 `COMPLETE`, 10 `NOT_APPLICABLE` |
| Public samples | 32/32 statuses, 29/32 exact rows, 190/193 expected steps, 0 extra |

Model: `gpt-6-luna`, low reasoning, 2,600 output tokens, 120 s timeout. Prices used for the estimate are USD 0.10 per million input tokens, 0.01 cached, and 0.50 output; they are receipt estimates, not an invoice. All 508 deletion cases were assembled by the model. The ten non-deletion cases exit early after classification.

## How to read the agreement number

The 503/518 compares the model's first submission to the engine's private plan. It shows the agent can reach the engine's answer through read-only tools without being shown it. It is not an accuracy measure against the hidden answers, and the engine is not ground truth. The 32 public samples shaped development, so 29/32 is a fit. Twenty-nine evaluation requests have ambiguous worker-to-person links and use the documented timing tie-break.

## Why the gate earns its place

Fifteen submissions were rejected, and every one was repaired by the model inside two resubmissions. By reason: status wrong (12), citation wrong (15), an extra resource or operation (2), and contract validation (15); one rejection can have several reasons.

The clearest example: for a request with compliant readbacks and no findings, the model first proposed `INCOMPLETE` with empty verification citations. The gate returned that the status should be `COMPLETE` and that three verification steps needed a citation. The model resubmitted with `COMPLETE` and cited the readback file. Nothing about that was staged; it is a trace from the live run.

## What failed along the way

| Stage | Observation | What it taught |
| --- | --- | --- |
| Investigator with scripted observations | 0/24 exact on exposed development rows, 15/24 statuses | The model was given too little source evidence and let incomplete scope suppress actions. |
| Stronger model, revised retrieval | Still 0/24 exact, 16/24 statuses | A bigger model didn't fix a retrieval and admission problem. The paths differed in more than the model, so this is a comparison of architectures, not of models. |
| First deterministic engine | 18/32 exact | Anonymous ownership and some source types were still unlinked. |
| Worker-timing correlation | 29/32 exact, 190/193 steps, 0 extra | Batch behaviour supplied the missing links. |
| Follow-up timing check | 97/142 became 148/151 | The constraint ignored the candidate account's own replication checkpoint. |
| Worker operation on support records | 15 rows changed, samples unchanged | A worker's `DELETE_RECORD` on a support target classifies it as an attachment. It does not show the record is gone, so the plan now reports the remaining record and proposes delete plus an absence check. |
| Cache-miss lines in a log | 6 rows corrected | An infrastructure cache miss had been read as absence of the record. A genuine later 404 readback still counts. |
| Inactive fallbacks | 2 removed with 0 rows changed; a third moved into a narrower function after it changed one sample row | Ablation showed which guesses carried weight and which never fired. |

Ablations that changed nothing are reported because they are the reason those code paths were deleted.

## Evaluation scaffolding

`evaluation/main.py` scores case, step, field and sequence accuracy against an answer file. `evaluation/custom_cases/` holds five synthetic scenarios with expected answers, each testing one rule:

| Case | Rule it checks |
| --- | --- |
| `historical_replica` | A read replica still holds data under an old email after the primary shows `NOT_FOUND` |
| `after_audit` | A record recreated after `audit_at` does not make an earlier deletion false |
| `non_deletion` | A request that is not a deletion request returns `[]` |
| `tombstone_pii` | A tombstone may keep `user_id`, not name or email |
| `timed_analytics` | An anonymous analytics row is linked through worker timing |

`evaluation/timing_diagnostic.py` runs the worker-timing checks against the challenge data without reading any answer.
