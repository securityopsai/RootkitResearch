# sentinel-fp-workflow, or: Why Your Detection Rule Doesn't Do What You Think It Does

Here's a thing nobody tells you about security detection rules. Most of them are not detecting
anything. They are *scheduled*. There's a difference. A rule that runs every hour and looks at
the last hour of data, on a platform that delivers data forty minutes late, is not a detection.
It's a ritual. Somebody wrote it, somebody deployed it, somebody put it in a slide, and the
attacker walked through the gap at minute forty-one. Everybody feels protected. Nobody is.

`sentinel-fp-workflow` is a Claude skill for the people who write KQL detections and hunting
queries on Microsoft Sentinel and Defender XDR, and who would prefer that the rules actually fire.
Load it, and Claude stops free-associating KQL from memory and starts behaving like the one
senior engineer on the team who has read the documentation, read it again, and keeps a list.

## What it actually does

**It refuses to let a rule out the door without passing nine gates.** State what attacker
behaviour this catches, in one sentence, mapped to the MITRE technique the *predicate* asserts.
Not "T1059 because it's a command line." That's not a mapping, that's a horoscope. Alert on the
entity the analyst investigates, not one alert per raw row, because an analyst with 400 alerts
for one laptop is not investigating, he's scrolling. Hoist every threshold into a `let` and say
what false positive it trades against. Make the query's windows match the schedule the platform
will actually run it on. Carry the columns the platform needs. Write the unit tests. Write the
blind spots. And if you wire the rule to isolate a machine, you'd better have a measured
precision rate, not a feeling.

**It treats hunting as a different animal.** A hunt is a question with a time picker. A
detection is a promise with a schedule. People keep confusing the two, which is how a 7-day
beaconing hunt ends up pasted into an hourly rule with a 4-hour lookback, where its "more than
12 hours of activity" condition can never be true. The skill has a catalogue of hunting patterns
that work (first-seen with a guard gap, two-tier prevalence, three beaconing algorithms, two-stage
anomaly, `scan` sequences, flow fingerprinting), a method for turning a threat report into a pack
of narrow queries, and a checklist for promoting a hunt into a rule without carrying the hunt's
bad habits along for the ride.

**It knows the things the platform won't tell you until it's too late.** Defender XDR evaluates
the lookback on ingestion time, so your helpful `Timestamp > ago(1h)` filter is quietly throwing
away the late events the platform just went to the trouble of keeping. A bare `join` in KQL is
`innerunique`, which deduplicates your left side and drops evidence, silently, which is the
worst kind of dropping. `has` on a two-character term isn't indexed. Entra spells "empty" three
different ways. `FileName == "net.exe"` misses `NET.EXE`. `TargetResources[2].displayName` works
right up until Microsoft reorders the array. None of this is secret. All of it is in the
documentation. Nobody reads the documentation. The skill read it for you.

**It handles false positives like a process instead of a mood.** Classify, root-cause, pick a fix
that doesn't require redeploying the rule when the fix is data, write it down, re-run the
true-positive fixture to prove you didn't just tune away the detection along with the noise.
There's a seed list of the usual benign suspects, because the MDI sensor has set off more SMB
alerts than any attacker in history.

## The parts

| Component | What it's for |
|---|---|
| `SKILL.md` | The router. Quality gates, hunting workflow, triage process, fix matrix, checklist. |
| `references/kql-performance.md` | Which operator, in which order, and why your join is slow and wrong. |
| `references/kql-gotchas.md` | Operator semantics that have bitten real people, XDR-versus-Sentinel deltas, telemetry facts, tables that got renamed while you weren't looking. |
| `references/rule-windows-and-baselines.md` | Ingestion delay, run windows, baseline guard gaps, floors, dedup across runs. The ritual-versus-detection chapter. |
| `references/hunting-patterns.md` | Hunt versus detection, the hunt funnel, threat report to hunt pack, the pattern catalogue, promotion checklist. |
| `references/identity-email-patterns.md` | Entra result codes that mean "the password was right, actually", flow fingerprints, token replay, parsing audit logs by name instead of by position. |
| `references/xdr-custom-detections.md` | Required columns, frequency and lookback pairs, the 150-alert cap, NRT restrictions, functions that only exist on one side of the fence. |
| `references/detection-as-code.md` | Repo layout, the full Sentinel YAML contract, the CI lint list, fixture tests, watchlists, summary rules. |
| `references/documentation-templates.md` | A detection specification where "blind spots" is mandatory and "None expected." has to be typed out loud. |
| `scripts/kql_lint.py` | Catches the defects that show up most in real repositories: bare joins, unbounded `make_set`, short terms, positional indexing, the wrong time column for the platform, placeholder strings somebody forgot to replace. |
| `scripts/kql_test_harness.py` | Shadows real tables with inline fixtures and pins the clock, so a detection can be tested like the pure function it is. |
| `scripts/kql_fp_patterns.py` | Twenty-two parameterised snippets for the things you keep retyping. |
| `evals/` | Five regression tests. Lives in the repo, not in the package. |

## Where it came from

Somebody read about 5,000 hunting queries and detection rules across 24 public repositories,
including Microsoft's own Azure-Sentinel repo, FalconForce's Falcon Friday, Cyb3r-Monk, ep3p,
Bert-JanP, reprise99, HybridBrothers and SecurityAura. The good patterns went into the
references. So did the bad ones, with counts. Bare `join` showed up in roughly 130 official
files. Unbounded `make_set` in roughly 260. That's not a style preference, that's a hard error
in the lint now. Platform facts were checked against Microsoft Learn, which is where they were
the whole time.

## Does it work

Five tasks, each run three ways: updated skill, original skill, no skill. Graded blind. Updated
skill passed 100% of the assertions, the original 92%, no skill 77%. The no-skill runs lost
points on exactly the stuff the skill encodes: lookback semantics, ingestion-time windows, the
alert cap, sensor sampling, indicators retyped inline. It costs about 75% more tokens than
winging it, because reading things costs tokens. One task didn't separate anybody: reviewing a
deliberately broken query. Turns out the model is already good at pointing at other people's
mistakes. Most of us are.

## What it won't do

The lint is regex, not a parser. It's a smoke detector, not a fire marshal. The example
thresholds are placeholders; your tenant is not the example. And it doesn't run queries or
deploy anything. It writes the rule, the tests and the document, and then a human has to do
the part where they find out if it's true.
