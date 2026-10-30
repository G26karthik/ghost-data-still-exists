# How this was built

People keep asking what the approach was and how the submission was put together. This is that, in the order the thinking actually went. Numbers are from the saved reports; where something wasn't measured, it says so.

## 1. Read the contract as a spec

The grader is hidden, so the problem statement is the only description of what gets scored: status, identity resolution, discovered records and risks, cited evidence, policy decisions, and the completeness and order of the steps. Each of those became something I could check locally, and none of them was treated as "the model will probably get it".

One practical detail shaped the writing. The code judge reads Markdown and ignores `.csv`, `.json`, `.jsonl`, `.sql` and `.log`. The evaluation and usage reports therefore carry every number inline, as prose and tables, instead of pointing at data files.

## 2. Start with a model-first investigator, and measure it

The first design gave a model the evidence and tools and asked for the plan. On the exposed development rows it got **0/24 exact**. Swapping in a stronger model with revised retrieval still got **0/24**, with a few more statuses right.

Reading the failures, the model wasn't the bottleneck. It was being shown too little source evidence, and incomplete scope was suppressing actions it should have taken. A bigger model on the same retrieval wasn't going to fix that. (The two paths differed in more than the model, so this compares architectures, not models.)

## 3. Move the decisions the model shouldn't make into code

Identity, time, resource state and policy are rules, not judgement, so they became explicit code: an identity index over every current and historical identifier, a cutoff rule for what counts as evidence at `audit_at`, and a policy table the code refuses to load if it disagrees with itself. That took the samples to 18/32 exact.

The remaining misses were anonymous records: deleted accounts and anonymised analytics rows with no identity left to match. The worker log was the only link, so I studied its batch timing, measured the offsets per policy action, and assigned worker actions to requests exclusively across the whole batch. That reached **29/32 exact, 190 of 193 expected steps, none extra**.

Timing is a correlation, not proof, so ties stay ties. The plan says `undetermined` instead of picking a person.

## 4. Put the model back, behind a gate

A model that reads evidence well and an engine that applies rules the same way every time are both useful. The final design lets the model investigate with read-only tools and assemble the plan, and lets the engine audit it privately.

The rule that makes this honest is that the model never sees the engine's answer. The policy tool returns one `(category, state)` entry and no resources. The gate fixes ordering and numbering and nothing else; any content difference comes back as a diff, never a replacement row. Result on all 518 requests: 503 first decisions agreed, 15 were corrected by the model itself after a diff, zero needed a fallback.

## 5. Working rules that kept it honest

- **Samples are not a holdout.** Thirty-two public samples shaped development, so the reports call 29/32 a fit.
- **Fix by source property, never by case ID.** Every changed row in the evaluation report names the evidence cue that justified it.
- **Ablate before believing.** Three suspected fallbacks were removed one at a time. Two changed no rows and were deleted. The third changed one sample row, so it was kept, narrowed and renamed to say what it does.
- **Report uncertainty where it lives.** Twenty-nine ownership links rest on a timing tie-break. The reports list them by ID.
- **Never claim a score nobody published.** No hidden-set score was seen, so none is quoted.
- **Checks that can't fool themselves.** Agreement between the model and the engine is labelled as exactly that, not as accuracy.

## 6. Ponytail and the audits

I ran the build under Ponytail throughout: the smallest change that fully solves the problem, with deletion preferred over addition. Its audit pass asks what is risky without a test, what breaks under load, and what can be removed.

The `# ponytail:` comments in the source mark functions that deliberately own one job, such as the fixed-point worker assignment in `activity.py` and the single transaction that owns budget, usage and cache order in `agent.py`. Audits drove deletions: the inactive fallbacks above, OCR as a source of decision facts (zero rows changed without it), and cache entries that no replay reads.

## 7. Memory and resource use

None of this was profiled for peak RSS, so there is no memory figure to quote. The design choices, which are all visible in the code:

- **Parse once, share everywhere.** Evidence is turned into observations once, and the by-file, by-resource and by-scope indexes are built once and shared by every case, instead of re-reading sources per request.
- **One SQL snapshot at a time.** Each SQL evidence file is loaded into an in-memory SQLite database, queried, and closed before the next. The connection denies `ATTACH`, `DETACH`, extension loading and every function except `json_valid`.
- **Bounded model context.** A tool returns at most 20 quoted records per file and resource, and clips long fields at 500 characters. The loop has a hard tool allowance (24, or 26 for ambiguous cases) and a 2,600-token output cap, so a case's context can't grow without limit.
- **Bounded cache.** The request cache is append-only JSONL that tolerates a truncated last line. After tracing which entries a full replay actually reads, 419 unused ones were pruned, leaving 12,631.
- **Bounded spend.** Eight workers, a hard budget cap, a per-call timeout and a provider circuit breaker.

## 8. Packaging the zip

The archive was built from an explicit inclusion list rather than by zipping a folder: `README.md` and the code, with prompts, pinned dependencies and the two Markdown reports. It left out the dataset, environments, credentials and nested archives.

Then it was treated as a stranger would treat it. Extract the exact zip into an empty directory, install only the declared dependencies, run the documented command against the externally supplied dataset, and compare the regenerated CSV byte for byte with the frozen result. Run the validator, scan the archive and its members for credentials, and confirm no command depends on a file that wasn't shipped.

## What I'd challenge

The 29 ambiguous ownership links, a few policy conditions the data doesn't state outright, and the rule that a listed backup without an explicit restore block is a risk. Mechanical validity and sample fit say nothing about those. What would settle them is a first-party batch ID or a per-resource subject key in the worker log.
