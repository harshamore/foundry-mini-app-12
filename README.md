# Foundry-mini — Streamlit showcase

An **agentic security scanner** that runs the Foundry Security Spec's finding
pipeline from the [Cisco Foundry Security Spec](https://github.com/CiscoDevNet/foundry-security-spec),
using real [CodeGuard](https://github.com/cosai-oasis/project-codeguard) rules —
wrapped in a guided Streamlit UI you can demo live.

Runs with **Anthropic**, **OpenAI**, or **fully offline** (deterministic engine,
no key, no network) so it never breaks in front of an audience.

This is a rewrite of an earlier prototype (`foundry-mini-app-11_1`) whose
Triager and Cartographer were staged: hardcoded to the exact four bugs planted
in the built-in sample, rather than reasoning about arbitrary code. Here,
every role that requires judgment is a real LLM call with its own
system/user prompt — see "What's actually real" below.

## What the audience sees

A four-step guided flow, then **one run that always compares both approaches**
on the same input:

- **Raw LLM:** one prompt to the model, taken at face value, producing a fast
  but *advisory* CISO report (explicitly marked low-assurance).
- **Foundry harness:** the full evidence-gated pipeline, producing an
  *authoritative* CISO report — plus two follow-on actions: authoring
  detection rules from new discoveries, and suggested patch code.

**The comparison table is the output.** The app doesn't show two separate
report sections and make you diff them yourself — the headline result is one
table, Raw LLM vs. Foundry harness, metric by metric, with the confirmed
findings, evidence, drafted rules, and suggested patches available underneath
for anyone who wants to dig in.

### The four capabilities

1. **CISO report without the harness.** The raw run yields an executive report
   that flags unverifiable findings and carries a clear "low assurance /
   advisory" banner — honest about what a single-pass LLM review can and
   cannot promise.
2. **CISO report with the harness.** The harnessed run yields a "high
   assurance / authoritative" report where every finding carries cited,
   verified evidence, plus a precision record (what was rejected) and a
   coverage claim.
3. **New discoveries → author & push rules.** When exploration confirms a
   class no CodeGuard rule covers, the app drafts a CodeGuard-format rule for
   it, lets you push it into the live corpus (so the next scan catches it
   systematically) and download the `.md` to commit to your own rule repo.
4. **Suggested patches.** For each confirmed finding, the app shows the
   corrected code side by side with the vulnerable code and explains why the
   fix works.

## What's actually real (and why no LangChain)

Every role below is a single structured-output LLM completion — a real
system/user prompt in, a real parsed JSON reply out — driven by a plain
Python orchestrator (`foundry_mini/pipeline.py`) that calls the roles in a
fixed sequence. There's no multi-step tool-use loop, no retrieval, no
cross-turn memory within a role — the things a framework like LangChain earns
its keep on. Adding it here would mean a heavier dependency tree on a
Streamlit Community Cloud free-tier deploy, an abstraction layer between the
prompt and the wire call (which fights this app's whole point — showing
exactly what was asked and why it fired), and no capability gained. Instead,
`foundry_mini/model.py` leans on each provider's own structured-output
feature (Anthropic forced tool-use, OpenAI JSON mode) so replies are reliably
parseable, and a parse failure is a loud, role-named error instead of a
silent empty result.

| Role | What it does | Real or deterministic? |
|---|---|---|
| **Indexer** | Python `ast` function inventory + call graph | Deterministic by design (FR-020 — never LLM-only) |
| **Cartographer** | Maps entry points / trust boundaries / sinks | Real LLM pass, with a heuristic scan as a non-empty floor (FR-036a) |
| **Detector — rule sweep** | Checks every function against the loaded CodeGuard rules | Real, one LLM call per function auditing all rules at once |
| **Detector — secret scan** | Regex for known secret formats | Deterministic (same approach real tools like gitleaks use) |
| **Detector — exploratory hunt** | Finds what no rule describes | Real LLM call reasoning over the whole target |
| **Triager** | Investigates each candidate, proposes cited evidence | Real LLM call per candidate — see below |
| **Evidence gate** | Decides true-positive vs. demoted | **Deterministic, non-negotiable.** Checks the model's citations mechanically; the model never grades itself (Principle I) |
| **Validator** | PoC narrative | Real LLM call; `exploited` always stays `false` — no live testbed, so no execution claim (Principle VII) |
| **Reporter** | Severity / title / business impact | Fast table for common CWEs, real LLM classification for anything else |

The Triager is the one that mattered most to fix: the previous build's
`_investigate()` was a 4-branch template keyed to the exact CWEs in the
sample, so anything outside that set got zero citations and was
auto-demoted regardless of whether it was real. Now the model gets the
candidate, the function's real source (numbered so its line citations are
directly checkable), its callers/callees, and the Cartographer's map, and is
told explicitly to **omit a leg it cannot honestly support rather than invent
a line number**. The evidence gate (`foundry_mini/finding.py`) is unchanged —
it still makes the actual pass/fail call by checking the required legs are
present and every citation resolves against the real source. The model
proposes; the gate decides. That split is what makes "the model does not get
to call itself right" true rather than aspirational.

## Observability (optional) — Splunk Agent Observability

Every role's real LLM call already passes through one seam, `Model.ask_json()`
(`foundry_mini/model.py`), so that's the one place optional tracing attaches
(`foundry_mini/observability.py`) — zero changes to any role's own logic, same
as every other design decision in this app.

Two GUI fields, both optional ("Observability" expander in the sidebar): a
**SAO API key** and a **SAO project name** (default `foundry-mini`, get-or-
created by name — nothing to set up in the console first). Leave the key
blank and `splunk_ao` is never imported and nothing is contacted — same
fails-soft, opt-in posture as the provider keys, just for tracing instead of
the scan itself. A bad key or the package not being installed degrades to "no
tracing" with a message in the terminal, never a failed run. Offline demo
mode never builds a tracer at all — there's no real model call to trace.

One tracer is shared by both models in a run (the raw baseline and the
harness pipeline), so a single "Run" click is **one SAO session** with **one
named trace per role's call** (`baseline`, `cartographer`, `detector.rule_sweep`,
`triager`, ...) inside it — not two disconnected sessions. A link back to the
run's Agent Stream appears above the comparison table once tracing activates;
a warning explains why not if a key was entered but it didn't.

Not a hard dependency — `splunk-ao` isn't in `requirements.txt`, matching the
same "own optional extra, not folded into the base install" reasoning used
for Galileo in the sibling LangChain-based harness this pattern is ported
from: `pip install splunk-ao` only if you intend to use this.

**Named limitation, not hidden**: `splunk_ao`'s context is a process-wide
singleton, so if this app ever serves multiple concurrent Streamlit sessions
with *different* SAO accounts from one process, the last `init()` wins for
all of them — fine for the single-user-at-a-time local/Streamlit-Cloud-demo
scope this app targets, not fine the moment that stops being true (the exact
same caveat this pattern's source repo already documents for its own
FastAPI backend).

## Run locally

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

## Deploy to Streamlit Community Cloud (free)

1. Push this folder to a GitHub repo.
2. Go to https://share.streamlit.io , "New app", point it at your repo and
   `streamlit_app.py`.
3. Deploy. No secrets required — users paste their own API key in the UI, or use
   offline demo mode.

That's it. Everything runs in-memory; there are no files written to disk at
runtime and no server-side keys, so it deploys cleanly on the free tier.

## The demo script (2 minutes)

1. Start in **offline mode**, load the **sample**, hit run. Narrate the stages.
2. Point at the **comparison table**: the raw LLM's count vs. the harness's
   confirmed count, and the demoted/unverifiable rows.
3. Point at the **demoted** candidate: "the model thought this was a bug; the
   evidence gate withheld it because it couldn't cite the three legs. That
   single control is what Cisco says moved their precision from unusable to
   trusted."
4. Point at the **rule gap**: "exploration found a class no rule caught. That
   gap becomes a CodeGuard rule — which then prevents the same bug in every
   developer's editor. That's the flywheel."
5. Switch to **Anthropic or OpenAI**, paste a key, run again on a real GitHub
   repo — and on a vulnerability class that isn't one of the four the sample
   plants, to see the Triager reason about something new instead of
   auto-demoting it.

## How it maps to the spec

| Spec role | Module |
|---|---|
| Indexer §5.2 — deterministic AST parser + call graph | `foundry_mini/index.py` |
| Cartographer §5.3 — attack surface, trust boundaries, data flow | `foundry_mini/cartographer.py` |
| Detector §5.4 — rule sweep + secret scan + exploratory + rule-gap loop | `foundry_mini/detector.py` |
| Triager §5.5 — investigation + evidence gate (§7.3) | `foundry_mini/triager.py` |
| Validator §5.6 | `foundry_mini/pipeline.py` (`stage_validate`) |
| Reporter §5.8 | `foundry_mini/reporter.py`, `foundry_mini/ciso_report.py` |
| Finding lifecycle §7 — states, verdicts, fingerprint, gate | `foundry_mini/finding.py` |
| Rule corpus FR-041 — CodeGuard loader | `foundry_mini/rules.py` |
| Provider layer §11.2 — Anthropic / OpenAI / mock, structured output | `foundry_mini/model.py` |

### Honored vs. deferred

**Honored** (a single process can): Evidence Over Assertion (I) — a
mechanical gate independent of the model's own say-so; Surface Only What
Survives (II); Fingerprints Stable Under Edit (VIII); Coverage Before Yield
(VI) — seeded from the actual rule corpus loaded that run, not a fixed list;
Exploited Means Demonstrated (VII).

**Deferred to the production build** (need a real fleet + runtime isolation):
heartbeat liveness (III), atomic mortal claims (IV), provider-as-rate-arbiter
(V), infrastructure sandbox (IX). This build also never executes fetched or
pasted code — running arbitrary untrusted code in a free-tier hosted app is a
real risk, not just a scope cut, so PoCs stay sketches by design. The UI says
so plainly — being honest about the gap is part of a credible demo.

To build the production system, run the spec through the `/speckit` workflow in
Claude Code as the Foundry README describes. This prototype makes the spec
tangible first.

---

_Detection rules: CodeGuard (CC-BY-4.0), see `foundry_mini/rules/ATTRIBUTION.md`.
Architecture: Cisco Foundry Security Spec. This is a prototype, not the
production system._
