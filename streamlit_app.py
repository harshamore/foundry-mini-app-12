"""
Foundry-mini — Streamlit showcase app.

An agentic security scanner derived from the Cisco Foundry Security Spec,
using real CodeGuard rules. Runs with Anthropic, OpenAI, or fully offline.

Run locally:   streamlit run streamlit_app.py
Deploy:        push to GitHub, point Streamlit Community Cloud at this file.
"""

import streamlit as st

from foundry_mini.model import Model, Budget, ModelError, DEFAULTS
from foundry_mini.pipeline import Pipeline
from foundry_mini.sample import SAMPLE_TARGET, build_markdown_report
from foundry_mini.github_fetch import fetch_sources
from foundry_mini.baseline import run_baseline
from foundry_mini.ciso_report import build_raw_ciso_report, build_harness_ciso_report
from foundry_mini.rule_authoring import draft_rule_from_gap, push_rule
from foundry_mini.remediator import suggest_patches
from foundry_mini.observability import build_sao_tracer, DEFAULT_PROJECT as SAO_DEFAULT_PROJECT

st.set_page_config(page_title="Foundry-mini — Agentic Security Scanner",
                   page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------- styling ----
st.markdown("""
<style>
  .block-container { padding-top: 2rem; max-width: 1150px; }
  .hero { font-size: 2.1rem; font-weight: 700; margin-bottom: .1rem; }
  .sub  { color: #6b7280; font-size: 1.02rem; margin-bottom: 1rem; }
  .pill { display:inline-block; padding:2px 10px; border-radius:999px;
          font-size:.72rem; font-weight:600; margin-right:6px; }
  .sev-critical { background:#fee2e2; color:#991b1b; }
  .sev-high     { background:#ffedd5; color:#9a3412; }
  .sev-medium   { background:#fef9c3; color:#854d0e; }
  .sev-low      { background:#e0e7ff; color:#3730a3; }
  .leg { font-family:ui-monospace,monospace; font-size:.82rem; color:#374151; }
  .stepbox { background:#f8fafc; border:1px solid #e5e7eb; border-radius:10px;
             padding:14px 16px; margin-bottom:10px; }
  .gate-ok  { color:#166534; font-weight:600; }
  .gate-bad { color:#b91c1c; font-weight:600; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="hero">🛡️ Foundry-mini</div>', unsafe_allow_html=True)
st.markdown('<div class="sub">An agentic security scanner — the Cisco Foundry '
            'Security Spec\'s pipeline, where every judgment-making role is a real '
            'LLM call, compared side by side against a raw one-shot prompt on the '
            'same code. Works with Anthropic, OpenAI, or fully offline.</div>',
            unsafe_allow_html=True)

with st.expander("What is this, and how does it work?  (read me first)", expanded=False):
    st.markdown("""
This runs a simplified version of the pipeline Cisco describes in the
[Foundry Security Spec](https://github.com/CiscoDevNet/foundry-security-spec),
next to a raw one-shot LLM prompt over the same code, so you can see what the
spec's controls actually buy you. Your code goes through:

1. **Indexer** — a deterministic parser (Python `ast`) builds a function
   inventory + call graph. Never LLM-only, by design (FR-020).
2. **Cartographer** — a real LLM pass maps entry points, trust boundaries, and
   sensitive data flows by reasoning about what each function actually does
   (not just literal parameter names), with a cheap deterministic heuristic
   scan underneath as a floor so the map is never empty.
3. **Detector** — sweeps every function against the loaded **CodeGuard rules**
   in one real LLM call per function, scans for secrets deterministically, and
   runs an **exploratory agent** that hunts for what no rule describes.
4. **Triager** — a real LLM call per candidate investigates it against the
   actual source (plus its callers/callees) and proposes cited evidence. The
   **evidence gate** — plain Python, not the model — then mechanically checks
   that the required legs (reachability, trust-boundary, impact) are present
   and every citation actually resolves to a real line. The model proposes;
   the gate decides. It cannot invent a citation its way past this.
5. **Validator** — no live testbed, so `exploited` always stays `false`; the
   model sketches a plausible proof-of-concept narrative instead of a claim.
6. **Reporter** — severity, title, and business impact — a fast table for
   common CWEs, a real LLM classification for anything else — rolled up only
   for findings that survived the gate.

Watch for: a rule false-alarm gets **demoted** by the evidence gate because it
can't cite all three legs, and the **flywheel** — the exploratory agent finds
a class no rule covered, which becomes a *rule gap* you can turn into a new
CodeGuard rule that catches the same bug in every developer's editor from then on.
    """)

# ------------------------------------------------------------- sidebar setup -
with st.sidebar:
    st.header("Setup")

    st.markdown("**Step 1 — Choose how to run**")
    run_mode = st.radio(
        "Provider",
        ["Offline demo (no key needed)", "Anthropic (Claude)", "OpenAI (GPT)"],
        label_visibility="collapsed",
    )

    provider = "mock"
    api_key = None
    model_name = None

    if run_mode == "Anthropic (Claude)":
        provider = "anthropic"
        st.markdown("**Step 2 — Paste your Anthropic API key**")
        api_key = st.text_input("Anthropic API key", type="password",
                                label_visibility="collapsed",
                                placeholder="sk-ant-...")
        model_name = st.text_input("Model", value=DEFAULTS["anthropic"],
                                   help="Editable — change if this model name is not "
                                        "available on your account.")
    elif run_mode == "OpenAI (GPT)":
        provider = "openai"
        st.markdown("**Step 2 — Paste your OpenAI API key**")
        api_key = st.text_input("OpenAI API key", type="password",
                                label_visibility="collapsed",
                                placeholder="sk-...")
        model_name = st.text_input("Model", value=DEFAULTS["openai"],
                                   help="Editable — e.g. gpt-4o, gpt-4o-mini.")
    else:
        st.caption("Offline mode uses a deterministic engine that reproduces the "
                   "model's judgments generically (pattern-driven, not hardcoded "
                   "to the built-in sample). No key, no network.")

    st.markdown("**Step 3 — Set a budget cap (USD)**")
    budget_cap = st.number_input("Budget cap", min_value=0.0, value=5.0, step=1.0,
                                 label_visibility="collapsed",
                                 help="Every role below now makes real LLM calls, so "
                                      "a run costs more than a single prompt would. "
                                      "The run halts as soon as either side crosses "
                                      "this cap (FR-112).")

    st.divider()
    with st.expander("Observability — Splunk Agent Observability (optional)"):
        st.caption("Both fields are optional. Leave the key blank and nothing "
                   "SAO-related is imported or contacted — same fails-soft, "
                   "opt-in behavior as the provider keys above, just for tracing "
                   "instead of the scan itself. Never used in Offline demo mode.")
        sao_api_key = st.text_input("SAO API key", type="password",
                                    placeholder="leave blank to disable tracing")
        sao_project = st.text_input("SAO project name", value=SAO_DEFAULT_PROJECT,
                                    help="Get-or-created by name — no manual setup "
                                         "needed in the SAO console first.")

    st.divider()
    st.caption("Rules: CodeGuard (CC-BY-4.0). Spec: Cisco Foundry Security Spec. "
               "This is a prototype, not the production system.")

# --------------------------------------------------------------- input pane --
st.markdown("### Step 4 — Give it something to scan")
tab_sample, tab_paste, tab_github = st.tabs(
    ["🧪 Use the sample app", "📝 Paste your code", "🔗 GitHub link"])

sources = None
with tab_sample:
    st.caption("A deliberately vulnerable Python service with four planted bugs. "
               "The fastest way to see the full pipeline fire.")
    with st.expander("Preview the sample code"):
        st.code(SAMPLE_TARGET, language="python")
    if st.button("Load sample", type="secondary"):
        st.session_state["sources"] = {"app.py": SAMPLE_TARGET}
        st.session_state["source_label"] = "built-in sample (app.py)"

with tab_paste:
    pasted = st.text_area("Paste Python code", height=240,
                          placeholder="# paste one or more Python functions here")
    fname = st.text_input("File name", value="pasted.py")
    if st.button("Use pasted code", type="secondary"):
        if pasted.strip():
            st.session_state["sources"] = {fname: pasted}
            st.session_state["source_label"] = f"pasted code ({fname})"
        else:
            st.warning("Paste some code first.")

with tab_github:
    st.caption("A single Python file URL, or a whole repo URL "
               "(github.com/owner/repo — Python files only, capped for demo).")
    gh_url = st.text_input("GitHub URL",
                           placeholder="https://github.com/owner/repo  or  .../blob/main/app.py")
    if st.button("Fetch from GitHub", type="secondary"):
        if gh_url.strip():
            try:
                with st.spinner("Fetching…"):
                    fetched = fetch_sources(gh_url)
                st.session_state["sources"] = fetched
                st.session_state["source_label"] = f"{gh_url} ({len(fetched)} file(s))"
                st.success(f"Fetched {len(fetched)} Python file(s).")
            except Exception as e:
                st.error(f"Could not fetch: {e}")
        else:
            st.warning("Enter a GitHub URL first.")

sources = st.session_state.get("sources")
if sources:
    st.info(f"Ready to scan: **{st.session_state.get('source_label','loaded source')}** "
            f"— {sum(len(s.splitlines()) for s in sources.values())} lines across "
            f"{len(sources)} file(s).")

# ------------------------------------------------------------------- run -----
st.markdown("### Step 5 — Run the comparison")
st.caption("Every run scans the same input two ways and puts the results side by "
           "side: a raw one-shot prompt, and the full evidence-gated harness.")

run = st.button("▶  Run: raw LLM vs. Foundry harness", type="primary",
                disabled=sources is None)


def _build_model(tracer=None):
    if provider in ("anthropic", "openai") and not api_key:
        st.error(f"Enter your {provider} API key in the sidebar, or switch to "
                 f"Offline demo mode.")
        st.stop()
    budget = Budget(budget_cap if budget_cap > 0 else None)
    try:
        return Model(provider, api_key, model_name, budget, tracer=tracer), budget
    except ModelError as e:
        st.error(str(e))
        st.stop()


def _run_pipeline(model, budget):
    mode_label = ("Offline (deterministic)" if provider == "mock"
                  else f"{provider} · {model.model}")
    st.caption(f"Mode: **{mode_label}**  |  Budget cap: {budget.usd_cap}")
    pipe = Pipeline(sources, model, budget)

    def _run_stage(status_label, fn):
        with st.status(status_label, expanded=False) as status:
            try:
                summary = fn()
            except ModelError as e:
                status.update(label=f"{status_label} — model error", state="error")
                st.error(f"{e}\n\nTip: check the model name, or switch to Offline "
                         f"demo mode to run without a provider.")
                st.stop()
            except Exception as e:
                status.update(label=f"{status_label} — failed", state="error")
                st.error(str(e))
                st.stop()
            status.update(label=status_label, state="complete")
            return summary

    idx = _run_stage("Indexer — building deterministic index (AST)…", pipe.stage_index)
    st.write(f"→ {idx['functions']} functions indexed, call graph built. "
             f"Index gate released (FR-003).")
    carto = _run_stage("Cartographer — mapping attack surface (LLM pass + heuristic floor)…",
                       pipe.stage_cartograph)
    aug = "live LLM pass" if carto["llm_augmented"] else "heuristic only (no live model)"
    st.write(f"→ {carto['entry_points']} entry points, {carto['trust_boundaries']} "
             f"trust boundaries, {carto['data_flows']} sensitive data flows. ({aug})")
    det = _run_stage("Detector — CodeGuard rule sweep + secret scan + exploratory hunt…",
                     pipe.stage_detect)
    st.write(f"→ {det['rule_candidates']} rule + {det['secret_candidates']} secret + "
             f"{det['exploratory_candidates']} exploratory candidates. "
             f"{det['rule_gaps']} rule gap(s) recorded.")
    if budget.exceeded():
        st.warning("Budget cap reached during detection — halting (FR-112).")
        st.stop()
    tri = _run_stage("Triager — LLM investigates each candidate; the gate decides…",
                     pipe.stage_triage)
    st.write(f"→ {tri['true_positives']} true-positive, {tri['demoted']} demoted to "
             f"needs-review by the gate.")
    if budget.exceeded():
        st.warning("Budget cap reached during triage — halting (FR-112).")
        st.stop()
    _run_stage("Validator — no testbed; the model sketches a PoC narrative…",
               pipe.stage_validate)
    return pipe.finalize()


def _run_raw(model):
    with st.status("Raw LLM — one prompt over the whole codebase…", expanded=False) as s:
        try:
            findings = run_baseline(sources, model)
        except ModelError as e:
            s.update(label="Raw LLM — model error", state="error")
            st.error(f"{e}\n\nTip: check the model name, or switch to Offline mode.")
            st.stop()
        s.update(label="Raw LLM — done (no verification applied)", state="complete")
    return findings


def _record_history():
    import datetime
    b = st.session_state.get("baseline")
    r = st.session_state.get("result")
    snap = {
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "source": st.session_state.get("source_label", "source"),
        "raw": None, "harness": None,
    }
    if b is not None:
        snap["raw"] = {
            "reported": len(b),
            "unverifiable": sum(1 for f in b if not f.get("_symbol_exists", True)),
        }
    if r is not None:
        snap["harness"] = {
            "tps": len(r.true_positives), "demoted": len(r.demotions),
            "gaps": len(r.rule_gaps), "coverage": r.coverage["complete"],
            "spend": r.budget["usd_spent"],
        }
    hist = st.session_state.get("history", [])
    hist.insert(0, snap)
    st.session_state["history"] = hist[:2]   # keep last 2


if run and sources:
    for k in ("result", "result_md", "baseline", "drafted_rules", "patches",
             "pushed_rules", "sao_urls", "sao_requested", "sao_activated"):
        st.session_state.pop(k, None)

    # One tracer, shared by both models below, so a run is one SAO session
    # with a named trace per role — not two disconnected sessions. Never
    # built in offline mode: there's no real model call to trace, so
    # attempting it would just be an unnecessary network round trip.
    tracer = None
    if provider != "mock" and sao_api_key:
        st.session_state["sao_requested"] = True
        tracer = build_sao_tracer(sao_api_key, sao_project)

    st.markdown("#### Running the raw LLM baseline")
    model_a, _ = _build_model(tracer)
    st.session_state["baseline"] = _run_raw(model_a)

    st.markdown("#### Running the Foundry pipeline")
    model_b, budget_b = _build_model(tracer)
    st.session_state["result"] = _run_pipeline(model_b, budget_b)
    st.session_state["result_md"] = build_markdown_report(st.session_state["result"])

    if tracer is not None:
        tracer.close()
        st.session_state["sao_activated"] = tracer.activated
        st.session_state["sao_urls"] = tracer.console_urls()

    _record_history()

# ============================ RESULTS (fragment) ============================
# The whole results area is a fragment: buttons inside it (downloads, draft
# rules, push, generate patches) rerun ONLY this fragment, so the page no longer
# scrolls to the top or re-renders on every click. Layout is two columns —
# results on the left, a persistent run-history panel on the right.

def _render_comparison_table(baseline, result):
    """The headline output: raw LLM vs. harness, one table, same run."""
    st.markdown("## Raw LLM vs. Foundry harness")
    raw_unverifiable = sum(1 for f in baseline if not f.get("_symbol_exists", True))
    rows = [
        {"Metric": "Findings reported / confirmed",
         "Raw LLM": str(len(baseline)), "Foundry harness": str(len(result.true_positives))},
        {"Metric": "Unverifiable / demoted",
         "Raw LLM": f"{raw_unverifiable} (never checked)",
         "Foundry harness": f"{len(result.demotions)} (checked & withheld)"},
        {"Metric": "Evidence backing",
         "Raw LLM": "none", "Foundry harness": "3-leg citations, mechanically resolved"},
        {"Metric": "Dedup identity",
         "Raw LLM": "none", "Foundry harness": "fingerprint (stable under edit)"},
        {"Metric": "Coverage claim",
         "Raw LLM": "none", "Foundry harness": str(result.coverage["complete"])},
        {"Metric": "New classes beyond the ruleset",
         "Raw LLM": "n/a", "Foundry harness": f"{len(result.rule_gaps)} rule gap(s)"},
        {"Metric": "Cost / calls",
         "Raw LLM": "1 call (unmetered)",
         "Foundry harness": f"${result.budget['usd_spent']} / {result.budget['calls']} calls "
                            f"(cap {result.budget['usd_cap']})"},
    ]
    st.table(rows)

    raw_symbols = {(f.get("symbol"), f.get("vuln_class")) for f in baseline}
    tp_symbols = {(f.symbol, f.vuln_class) for f in result.true_positives}
    only_pipeline = sorted(tp_symbols - raw_symbols)
    only_raw = sorted(raw_symbols - tp_symbols)
    if only_pipeline:
        st.markdown("**Found only by the harness** (systematic sweep / secret scan / "
                    "exploration caught what one glance missed): " +
                    ", ".join(f"`{s}` ({c})" for s, c in only_pipeline))
    if only_raw:
        st.markdown("**Claimed only by the raw LLM, not confirmed** (no evidence "
                    "could be assembled; withheld rather than reported): " +
                    ", ".join(f"`{s}` ({c})" for s, c in only_raw))
    if not only_pipeline and not only_raw:
        st.caption("Both found the same set on this input — but only the harness "
                   "can show cited, resolved evidence for each one.")

    d1, d2 = st.columns(2)
    d1.download_button("⬇  Raw LLM CISO report (advisory)",
                       data=build_raw_ciso_report(baseline),
                       file_name="ciso-report-no-harness.md", mime="text/markdown",
                       key="dl_raw_ciso")
    d2.download_button("⬇  Harness CISO report (authoritative)",
                       data=build_harness_ciso_report(result),
                       file_name="ciso-report-harnessed.md", mime="text/markdown",
                       key="dl_harness_ciso")


def _render_raw_detail(baseline):
    with st.expander("Raw LLM findings, as reported (unverified)"):
        st.caption("One prompt, one reply, taken at face value. Nothing here was "
                   "verified, deduplicated, or gated.")
        for f in baseline:
            exists = f.get("_symbol_exists", True)
            sev = (f.get("severity") or "medium").lower()
            sev = sev if sev in ("critical", "high", "medium", "low") else "medium"
            flag = "" if exists else "  ⚠️ unverifiable location"
            with st.container(border=True):
                st.markdown(f'<span class="pill sev-{sev}">{sev.upper()}</span> '
                            f'<b>{f.get("vuln_class","?")}</b> — '
                            f'<code>{f.get("symbol","?")}()</code>{flag}',
                            unsafe_allow_html=True)
                st.markdown(f"{f.get('why','')}")


def _render_harness_detail(result):
    with st.expander("Confirmed findings — evidence, PoC sketch, patches", expanded=True):
        st.caption("Only findings that survived the evidence gate appear here "
                   "(Principle II — Surface Only What Survives).")
        for f in result.true_positives:
            sev = f.severity
            with st.container(border=True):
                st.markdown(f'<span class="pill sev-{sev}">{sev.upper()}</span> '
                            f'<b>{f.title or f.vuln_class}</b> — '
                            f'<code>{f.symbol}()</code> · {f.weakness}',
                            unsafe_allow_html=True)
                st.markdown(f"**Location:** `{f.file}` → `{f.symbol}()`  \n"
                            f"**Fingerprint:** `{f.fingerprint()}` "
                            f"*(path + symbol + class — stable under edit)*  \n"
                            f"**Technique:** {f.technique}")
                st.markdown(f"**Investigation:** {f.investigation}")
                st.markdown("**Evidence — citations proposed by the model, "
                            "mechanically checked to resolve:**")
                for c in f.citations:
                    st.markdown(f'<span class="leg">• <b>{c.leg}</b> — '
                                f'{c.file}:{c.line} — {c.note}</span>',
                                unsafe_allow_html=True)
                st.markdown(f"**PoC sketch:** {f.poc}")
                st.markdown(f"**Exploited:** `{f.exploited}` "
                            f"*(no testbed — demonstrated ≠ argued, Principle VII)*")

        if result.demotions:
            st.markdown("#### Demoted to needs-review")
            st.caption("The model does not award itself true-positive — the evidence "
                       "gate does (Principle I). These candidates failed it and were "
                       "withheld:")
            for symbol, cls, why in result.demotions:
                st.markdown(f'<span class="gate-bad">✗</span> `{symbol}` ({cls}) — {why}',
                            unsafe_allow_html=True)

        with st.expander("Coverage & budget detail"):
            cov = result.coverage
            st.markdown(f"**Coverage-complete:** `{cov['complete']}`")
            for item, meta in cov["items"].items():
                mark = "✅" if meta["attempted"] else "⬜"
                techs = ", ".join(meta["techniques"]) or "—"
                st.markdown(f"{mark} {item} — *{techs}*")
            b = result.budget
            st.markdown(f"**Budget:** {b['calls']} model calls, ${b['usd_spent']} spent "
                        f"(cap {b['usd_cap']}), estimated fraction "
                        f"{b['estimated_fraction']}.")

        st.download_button("⬇  Full pipeline report (Markdown)",
                           data=st.session_state.get("result_md", ""),
                           file_name="foundry-mini-report.md", mime="text/markdown",
                           key="dl_full")


def _render_flywheel(result):
    if not result.rule_gaps:
        return
    st.divider()
    st.markdown("### New discoveries → author & push detection rules")
    st.caption("The harness confirmed vulnerability classes that no existing "
               "CodeGuard rule covers. Turn each into a rule so the next scan "
               "catches it systematically — and it becomes a prevention "
               "guardrail in developers' editors.")
    for i, g in enumerate(result.rule_gaps):
        st.markdown(f"**Discovery {i+1}: {g['vuln_class']}** in "
                    f"`{g['finding']}` — {g['pattern']}")
    if st.button("Draft CodeGuard rules from these discoveries", key="draft_rules"):
        model, _ = _build_model()
        st.session_state["drafted_rules"] = [
            draft_rule_from_gap(g, model) for g in result.rule_gaps]

    for i, dr in enumerate(st.session_state.get("drafted_rules", [])):
        with st.container(border=True):
            st.markdown(f"**Proposed rule:** `{dr['filename']}` "
                        f"(detects {dr['vuln_class']})")
            st.code(dr["markdown"], language="markdown")
            col1, col2 = st.columns(2)
            pushed = dr["filename"] in st.session_state.get("pushed_rules", set())
            if col1.button("✓ Push to live corpus" if not pushed else "✓ Pushed",
                          key=f"push_{i}", disabled=pushed):
                push_rule(dr)
                st.session_state.setdefault("pushed_rules", set()).add(dr["filename"])
                st.success(f"Pushed. Re-run the scan and {dr['vuln_class']} "
                          f"will be caught by this rule — the gap closes.")
            col2.download_button("⬇ Download .md rule", data=dr["markdown"],
                                 file_name=dr["filename"], mime="text/markdown",
                                 key=f"dlrule_{i}")


def _render_patches(result):
    st.divider()
    st.markdown("### Suggested patches for confirmed findings")
    st.caption("For each evidence-confirmed finding, the corrected code that "
               "closes it. Patches are suggestions — review, apply, and re-scan "
               "to verify.")
    if st.button("Generate suggested patches", key="gen_patches"):
        model, _ = _build_model()
        st.session_state["patches"] = suggest_patches(result.true_positives, model)

    for pt in st.session_state.get("patches", []):
        with st.container(border=True):
            st.markdown(f"**{pt['vuln_class']}** in `{pt['symbol']}()` — "
                        f"`{pt['file']}`")
            cbefore, cafter = st.columns(2)
            with cbefore:
                st.markdown("**Vulnerable**")
                st.code(pt["before"], language="python")
            with cafter:
                st.markdown("**Patched**")
                st.code(pt["after"], language="python")
            st.markdown(f"**Why this fixes it:** {pt['why']}")


def _render_sao_status():
    """Mirrors this app's own honesty pattern for Galileo tracing elsewhere in
    this codebase: confirm activation with a real link, or say plainly why it
    didn't, rather than leaving silence either way."""
    if not st.session_state.get("sao_requested"):
        return
    project_url, agent_stream_url = st.session_state.get("sao_urls", (None, None))
    if st.session_state.get("sao_activated") and agent_stream_url:
        st.markdown(f"🔭 [View this run in Splunk Agent Observability →]({agent_stream_url})")
    else:
        st.warning("SAO tracing was requested but did not activate for this run. "
                  "Check the terminal for a line starting with \"SAO tracing "
                  "unavailable\" or \"SAO API key is set but the `splunk-ao` "
                  "package isn't installed\" (pip install splunk-ao).")


def _render_history():
    st.markdown("#### 🕘 Run history")
    st.caption("Last 2 runs")
    hist = st.session_state.get("history", [])
    if not hist:
        st.caption("No runs yet — results appear here after you scan.")
        return
    for i, h in enumerate(hist):
        label = "Latest" if i == 0 else "Previous"
        with st.container(border=True):
            st.markdown(f"**{label}** · {h['time']}")
            st.caption(h["source"])
            if h["raw"]:
                extra = (f" · ⚠️{h['raw']['unverifiable']} unverifiable"
                        if h["raw"]["unverifiable"] else "")
                st.markdown(f"🟠 Raw: **{h['raw']['reported']}** found{extra}")
            if h["harness"]:
                hh = h["harness"]
                st.markdown(f"🔵 Harness: **{hh['tps']}** confirmed  \n"
                            f"{hh['demoted']} demoted · {hh['gaps']} gaps  \n"
                            f"cov {hh['coverage']} · ${hh['spend']}")


@st.fragment
def render_results_area():
    baseline = st.session_state.get("baseline")
    result = st.session_state.get("result")
    if baseline is None and result is None and not st.session_state.get("history"):
        return

    main_col, hist_col = st.columns([4, 1])
    with main_col:
        st.divider()
        _render_sao_status()
        if baseline is not None and result is not None:
            _render_comparison_table(baseline, result)
        if baseline is not None:
            _render_raw_detail(baseline)
        if result is not None:
            _render_harness_detail(result)
            _render_flywheel(result)
            _render_patches(result)
        with st.expander("What this prototype honors vs. defers (be honest in the demo)"):
            st.markdown("""
**Honored:** Evidence Over Assertion (I) — a mechanical gate independent of the
model's own say-so; Surface Only What Survives (II); Fingerprints Stable Under
Edit (VIII); Coverage Before Yield (VI) — seeded from the actual rule corpus
loaded this run; Exploited Means Demonstrated (VII) — `exploited` stays false
with no testbed.

**Deferred to a real multi-agent build** (need a real fleet + runtime
isolation, and faking them would violate the very principles): heartbeat
liveness (III), atomic mortal claims (IV), provider-as-rate-arbiter (V),
infrastructure sandbox (IX). This also does not execute any fetched or pasted
code — no live testbed means PoCs stay sketches, by design, not by omission.
            """)
    with hist_col:
        _render_history()


render_results_area()
