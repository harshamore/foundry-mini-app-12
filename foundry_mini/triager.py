"""
Triager — spec §5.5. Investigation + evidence gate.

This is the one role where the previous build was staged rather than real: it
had a 4-branch template keyed to the exact 4 CWEs planted in the built-in
sample, and never called the model. Anything outside those 4 classes got zero
citations and was auto-demoted — so on a real target the harness would
confirm nothing regardless of what was actually there.

Here the model does the investigation for real, for any vuln_class: given the
candidate, the function's real source (and its callers/callees, so it can
trace reachability across a short call chain), and the Cartographer's map, it
proposes citations. It is told explicitly to omit a leg it cannot honestly
support rather than invent a line number.

What does NOT change, and must not: evidence_gate() (finding.py) still makes
the actual pass/fail call by mechanically checking the required legs are
present and every citation's line resolves in real source. The model
proposes; the gate decides. That split is Principle I, and it's the only
thing that makes "the model does not get to call itself right" true.
"""

from __future__ import annotations

import re

from .finding import Verdict, State, Citation, evidence_gate, PRESENCE_IS_VULN
from .textutil import line_of_offset

TRIAGE_SYSTEM = (
    "You are a security triager investigating one candidate vulnerability. "
    "You do NOT get to declare it a true positive — a separate mechanical "
    "gate does that by checking your citations against the real source. "
    "Your job is to honestly assemble evidence, or admit you cannot.\n\n"
    "For most vulnerability classes, cite THREE legs, each a real line "
    "number from the numbered source given below:\n"
    "  - reachability: where attacker-controlled input enters the code path\n"
    "  - trust-boundary: where that untrusted value crosses into trusted "
    "processing without adequate validation or sanitization\n"
    "  - impact: the line where the dangerous operation actually executes\n"
    "For classes where mere PRESENCE in source is the vulnerability itself "
    "(e.g. a hardcoded credential, a broken/weak crypto primitive, sensitive "
    "data written to a log), cite only 'impact' — the line where the pattern "
    "appears — and say so in your narrative.\n\n"
    "Rules:\n"
    "- Every citation's line must be copied from the numbered source you "
    "were given. NEVER invent a line number.\n"
    "- If you cannot honestly find a real citation for a required leg, OMIT "
    "that leg rather than fabricate one. An incomplete citation set will "
    "correctly be rejected by the gate — that is the intended outcome, not a "
    "failure on your part.\n"
    "- If you conclude this candidate is not actually exploitable, say so in "
    "the narrative and only cite what evidence genuinely exists.\n\n"
    'Reply JSON: {"citations": [{"leg","file","line","note"}], "narrative": str}.'
)


def _cartographer_notes(security_map, symbol):
    lines = []
    for key in ("attack_surface", "trust_boundaries", "data_flows"):
        for e in security_map.get(key, []):
            if e.get("symbol") == symbol:
                lines.append(f"- {key}: {e}")
    return "\n".join(lines) or "(no cartographer entries reference this symbol)"


def _context_block(index, security_map, finding):
    meta = index.find_symbol(finding.symbol)
    callers = index.get_callers(finding.symbol) if meta else []
    callees = index.get_callees(finding.symbol) if meta else []
    files = index.context_files(finding.symbol)
    files_block = "\n\n".join(
        f"### FILE: {f}\n{index.numbered_file(f)}" for f in files)
    return (
        f"CANDIDATE: symbol={finding.symbol!r} file={finding.file!r} "
        f"vuln_class={finding.vuln_class}\n"
        f"Detector's note: {finding.description}\n"
        f"Detected via: {finding.technique}\n"
        f"Callers: {callers}  Callees: {callees}\n\n"
        f"Cartographer notes for this symbol:\n{_cartographer_notes(security_map, finding.symbol)}\n\n"
        f"{files_block}"
    )


# ------------------------------------------------------------- offline mock -
_GENERIC_ENTRY_RX = re.compile(r"\b(request|params|args|form|query)\b")
_GENERIC_BOUNDARY_RX = re.compile(r'["\']\s*\+\s*\w+|\w+\s*\+\s*["\']')
_GENERIC_SINK_RX = re.compile(
    r"\b(execute|system|call|Popen|eval|exec|pickle\.loads|yaml\.load|"
    r"os\.system|subprocess\.\w+)\s*\(")
_WEAK_CRYPTO_RX = re.compile(r"\b(md5|sha1|DES|ECB|RC4)\b", re.IGNORECASE)
_LOG_LEAK_RX = re.compile(
    r"log(ger|ging)?\.\w+\(.*(password|passwd|pwd|secret|token|api_?key)",
    re.IGNORECASE | re.DOTALL)


def _first_line(body, rx, start_line):
    m = rx.search(body)
    return line_of_offset(body, m.start(), start_line) if m else None


def _mock_investigate(index, finding):
    """
    Offline stand-in: locates evidence by GENERIC pattern (entry-hint words,
    string-concatenation-into-a-sink, a fixed sink-call list, weak-crypto
    keywords), never by the exact symbol names in the built-in sample — so
    this keeps working, without a key, on pasted code that isn't that sample.
    """
    meta = index.find_symbol(finding.symbol)
    body = index.get_function_body(finding.symbol) if meta else ""
    start = meta["line"] if meta else 1

    def fn(system, user):
        cites = []
        if finding.vuln_class in PRESENCE_IS_VULN:
            line = None
            if finding.vuln_class == "CWE-532":
                line = _first_line(body, _LOG_LEAK_RX, start)
            elif finding.vuln_class == "CWE-327":
                line = _first_line(body, _WEAK_CRYPTO_RX, start)
            if line is None:
                hits = index.full_text_search(finding.symbol)
                line = hits[0][1] if hits else None
            if line is not None:
                cites.append({"leg": "impact", "line": line,
                             "note": "matches the presence-is-vulnerability pattern"})
            narrative = ("Presence-is-vulnerability class: the pattern itself is "
                        "the finding, cited at its line.")
        else:
            entry = _first_line(body, _GENERIC_ENTRY_RX, start)
            boundary = _first_line(body, _GENERIC_BOUNDARY_RX, start)
            sink = _first_line(body, _GENERIC_SINK_RX, start)
            if entry:
                cites.append({"leg": "reachability", "line": entry,
                             "note": "request-derived input enters the function"})
            if boundary:
                cites.append({"leg": "trust-boundary", "line": boundary,
                             "note": "untrusted value concatenated without parameterization"})
            if sink:
                cites.append({"leg": "impact", "line": sink,
                             "note": "tainted value reaches a dangerous sink"})
            narrative = ("Generic pattern match: entry/boundary/sink located by "
                        "keyword search over the function body.")
        import json as _j
        return _j.dumps({"citations": cites, "narrative": narrative})
    return fn


# ------------------------------------------------------------- live agent ---
def _investigate(finding, index, security_map, model):
    user = _context_block(index, security_map, finding)
    data = model.ask_json("triager", TRIAGE_SYSTEM, user,
                          mock_fn=_mock_investigate(index, finding))
    cites = []
    for c in data.get("citations", []):
        leg, line = c.get("leg"), c.get("line")
        if leg not in ("reachability", "trust-boundary", "impact"):
            continue
        if not isinstance(line, int):
            continue
        cites.append(Citation(c.get("file") or finding.file, finding.symbol,
                              line, leg, c.get("note", "")))
    return cites, data.get("narrative", "")


def triage_all(store, index, sources, coverage, security_map, model):
    demotions = []
    for f in store.all():
        if f.verdict is not None:
            continue
        cites, narrative = _investigate(f, index, security_map, model)
        f.citations = cites
        ok, why = evidence_gate(f, sources)
        f.investigation = (narrative or "(model returned no narrative)") + f"  [gate: {why}]"
        coverage.record_attempt(f"triage:{f.vuln_class}", "llm-investigation")

        if ok:
            f.verdict = Verdict.TRUE_POSITIVE
            f.state = State.CONFIRMED
        else:
            f.verdict = Verdict.NEEDS_REVIEW
            f.state = State.VERDICT_ASSIGNED
            demotions.append((f.symbol, f.vuln_class, why))
    return demotions
