# sentinel-fp-workflow: a KQL detection-engineering skill for Sentinel and Defender XDR

`sentinel-fp-workflow` is a Claude skill for people who write, review and tune KQL detections
and hunting queries on Microsoft Sentinel and Microsoft Defender XDR. Loaded, it changes how
Claude approaches a KQL task: instead of producing a plausible query from memory, it works
through a fixed set of quality gates, pulls in platform facts that are easy to get wrong, lints
its own output and leaves behind a rule document a reviewer can act on.

## What it does

The skill covers the full life of a detection:

- **Authoring.** Nine quality gates every rule must pass before deployment: a stated intent
  mapped to the behaviour the predicate asserts, entity-level alerting, windows that match the
  schedule, hoisted and explained tunables, a performance and semantics review, the platform
  contract (entity mappings for Sentinel; `Timestamp`, `ReportId`, `DeviceId` for XDR), unit
  tests with fixtures, a detection specification with blind spots, and a measured precision bar
  for anything wired to a response action.
- **Hunting.** A hunt is treated as a different artefact from a detection. The skill gives a
  hunt header template, a funnel method (population statistics, derived attribute, shortlist,
  enrichment, DFIR hand-off), a workflow for turning a threat report into a pack of narrow
  queries, a catalogue of reusable patterns (first-seen with a guard gap, two-tier prevalence,
  beaconing, two-stage anomaly, `scan` sequences, flow fingerprinting, threshold newly crossed,
  graph paths, threat-intelligence matching) and a checklist for promoting a hunt to a rule.
- **Scheduling and windows.** The most common silent failure in real rule repositories is a
  window that does not match how the platform runs the query. The skill prescribes the
  ingestion-delay form for Sentinel, explains that XDR evaluates its lookback on ingestion time,
  and covers baseline guard gaps, floors, poisoning and deduplication across runs.
- **False-positive triage.** A classification process (true positive, benign true positive,
  false positive), a fix-selection matrix that prefers data changes over rule redeploys, a
  seed taxonomy of known benign generators, and templates for change records and client reports.

## Components

The skill is a router plus references plus scripts, loaded progressively so only the relevant
part enters context.

| Component | Purpose |
|---|---|
| `SKILL.md` | Router and core workflows: quality gates, hunting workflow, FP triage, fix matrix, quick-reference patterns, validation checklist |
| `references/kql-performance.md` | Operator choice, filter order, join hygiene, command-line matching discipline, output shaping, review checklist |
| `references/kql-gotchas.md` | Operator semantics that produced real bugs, the XDR-versus-Sentinel delta table, telemetry facts (sampling, new ActionTypes), table and column churn |
| `references/rule-windows-and-baselines.md` | Rule contract in KQL, ingestion delay, per-table delay as data, baseline windows, dedup, time handling |
| `references/hunting-patterns.md` | Hunt-versus-detection contract, hunt header, methodologies, pattern catalogue, promotion checklist, IR query packs |
| `references/identity-email-patterns.md` | Entra result-code classification, flow fingerprints, token replay, audit-log parsing by name, MDO join discipline |
| `references/xdr-custom-detections.md` | Required columns, frequency and lookback pairs, the 150-alert cap, NRT restrictions, XDR-only functions, auditing the platform itself |
| `references/detection-as-code.md` | Repository layout, full Sentinel YAML contract, CI gates and lint list, fixture-based unit testing, watchlists, functions, summary rules |
| `references/documentation-templates.md` | Detection specification with mandatory blind spots, hunt header, report-pack page, change record, FP worksheet, watchlist schema |
| `scripts/kql_lint.py` | Static checks for the defect classes found most often in public rule repositories: bare `join`, unbounded `make_set`, short terms, positional indexing, platform column drift, self-inflicted window filters, placeholders, full-sample `has_all` |
| `scripts/kql_test_harness.py` | Builds unit-test queries by shadowing tables with inline `datatable` fixtures and pinning `now()`; emits or runs them |
| `scripts/kql_fp_patterns.py` | Generates 22 parameterised snippets: exclusions, ingestion windows, first-seen baselines, floors, flow fingerprints, TVM bridges, anomaly stages, tuning fences |
| `evals/` | Five test cases with prompts, input files and assertions for regression testing the skill (kept in the repository, not in the packaged skill) |

## Where the content comes from

The references were distilled from a review of roughly 5,000 hunting queries and detection
rules in 24 public repositories, including the Azure-Sentinel repository, FalconForce's Falcon
Friday, Cyb3r-Monk, ep3p, Bert-JanP, reprise99, HybridBrothers and SecurityAura. The review
counted defects as well as good patterns: a bare `join` appeared in about 130 official files, and
unbounded `make_set` in about 260, which is why both are hard checks in the lint script.
Platform facts about lookback, ingestion time, required columns and function support were
verified against Microsoft Learn.

## Does it help

In a five-task evaluation, each task run with the updated skill, the original skill and no skill
and graded blind against the same assertions, the updated skill passed 100% of assertions, the
original 92% and no skill 77%. The no-skill runs lost points on exactly the facts the skill
encodes: lookback semantics, ingestion-time windows, the alert cap, sensor sampling and
inline indicator lists. The cost is roughly 75% more tokens than an unassisted run, mostly from
reading references and running the lint and harness. One task, reviewing a deliberately flawed
query, did not separate the configurations at all; the base model already does that well.

## Limits

The lint is regex-based, not a parser; it is a cheap first gate, not a substitute for an offline
Kusto parse or a tenant run. Example thresholds are placeholders. The skill does not execute
queries or deploy anything; it writes rules, documents and tests for a human to validate.
