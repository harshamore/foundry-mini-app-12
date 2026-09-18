"""
Detector — spec §5.4. Rule sweep (FR-037) + secret scan (FR-039) +
exploratory hunt (FR-040) + rule-gap loop (FR-042). Candidates go to the
finding store only (FR-044).

Rule sweep asks one real question per function ("which of these rules does
this function's code exhibit, and where") instead of one question per
function-per-rule — same judgment, far fewer round trips, which matters once
the budget cap has to cover a real multi-file repo instead of one sample file.

Rule-gap detection is generic: any exploratory-confirmed vuln_class that isn't
in the loaded rule corpus is a gap, not a fixed set of classes — so the
flywheel (§ detection -> prevention) actually works for whatever an
exploratory hunt turns up, not just the one class this corpus happened to omit
on the demo target.
"""

from __future__ import annotations

import re

from .finding import Finding
from .textutil import line_of_offset


_SECRET_PATTERNS = [
    (r"sk_live_[A-Za-z0-9]{16,}", "Stripe live secret key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "private key"),
    (r"gh[pousr]_[A-Za-z0-9]{16,}", "GitHub token"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT"),
]


def secret_scan(index, store) -> int:
    added = 0
    for pattern, label in _SECRET_PATTERNS:
        rx = re.compile(pattern)
        for f, src in index.sources.items():
            for i, line in enumerate(src.splitlines(), start=1):
                if rx.search(line):
                    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
                    symbol = m.group(1) if m else f"secret_L{i}"
                    finding = Finding(file=f, symbol=symbol, vuln_class="CWE-798",
                                      description=f"hardcoded {label} in source",
                                      technique="secret-scan")
                    if store.add_candidate(finding):
                        added += 1
    return added


# ------------------------------------------------------------- rule sweep ---
RULE_SWEEP_SYSTEM = (
    "You are a security detector applying a fixed rule corpus to one "
    "function. For each rule below, decide whether the function's OWN code "
    "(not a hypothetical) exhibits that rule's vulnerability class. Cite the "
    "real line number (from the numbered text given) where the pattern "
    "appears. Reply JSON: {\"fires\": [{\"rule_id\",\"line\",\"why\"}]} — "
    "omit a rule entirely from the list if it does not fire on this function."
)


def _rule_by_id(corpus, rule_id):
    for r in corpus:
        if r.id == rule_id:
            return r
    return None


def _mock_rule_sweep(index, symbol, corpus):
    meta = index.find_symbol(symbol)
    body = index.get_function_body(symbol)

    def fn(system, user):
        fires = []
        for rule in corpus:
            m = re.search(rule.signal, body, re.IGNORECASE | re.DOTALL)
            if m:
                fires.append({"rule_id": rule.id,
                             "line": line_of_offset(body, m.start(), meta["line"]),
                             "why": f"matches {rule.vuln_class} pattern"})
        import json as _j
        return _j.dumps({"fires": fires})
    return fn


def rule_sweep(index, corpus, model, store) -> int:
    added = 0
    if not corpus:
        return added
    rules_block = "\n".join(
        f"- {r.id} ({r.vuln_class}): {r.description}" for r in corpus)
    for symbol in index.list_functions():
        meta = index.find_symbol(symbol)
        user = (f"RULES:\n{rules_block}\n\n"
                f"FUNCTION {symbol} in {meta['file']} "
                f"(callers: {index.get_callers(symbol)}), real line numbers:\n"
                f"{index.numbered_body(symbol)}")
        data = model.ask_json("detector.rule_sweep", RULE_SWEEP_SYSTEM, user,
                              mock_fn=_mock_rule_sweep(index, symbol, corpus))
        for hit in data.get("fires", []):
            rule = _rule_by_id(corpus, hit.get("rule_id"))
            if rule is None:
                continue
            f = Finding(file=meta["file"], symbol=symbol, vuln_class=rule.vuln_class,
                        description=hit.get("why", f"rule {rule.id} fired"),
                        technique=rule.id)
            if store.add_candidate(f):
                added += 1
    return added


# --------------------------------------------------------- exploratory hunt -
EXPLORATORY_SYSTEM = (
    "You are an exploratory security agent. Reason about THIS target's "
    "design and report vulnerabilities no generic rule would catch — logic "
    "flaws, sensitive data reaching an unexpected sink, missing "
    "authorization, unsafe deserialization, path traversal, SSRF, or "
    "anything else specific to how these functions are wired together. Cite "
    "a real line number from the function text given; use a CWE id for "
    "vuln_class when one applies. Reply JSON: {\"findings\": [{\"symbol\","
    "\"file\",\"vuln_class\",\"line\",\"why\"}]}. If you find nothing, "
    "return an empty list."
)


def _mock_exploratory(index):
    def fn(system, user):
        findings = []
        for symbol in index.list_functions():
            body = index.get_function_body(symbol)
            meta = index.find_symbol(symbol)
            m = re.search(r"log(ger|ging)?\.\w+\(.*(password|passwd|pwd|secret|token)",
                         body, re.IGNORECASE | re.DOTALL)
            if m:
                findings.append({"symbol": symbol, "file": meta["file"],
                                 "vuln_class": "CWE-532",
                                 "line": line_of_offset(body, m.start(), meta["line"]),
                                 "why": "plaintext credential reaches a log sink; "
                                        "exposed to anyone with log read access"})
        import json as _j
        return _j.dumps({"findings": findings})
    return fn


def exploratory_hunt(index, model, store, coverage, corpus):
    user = "Target functions, real line numbers:\n\n" + "\n\n".join(
        f"### {s} — {index.find_symbol(s)['file']}\n{index.numbered_body(s)}"
        for s in index.list_functions())
    data = model.ask_json("detector.exploratory", EXPLORATORY_SYSTEM, user,
                          mock_fn=_mock_exploratory(index))

    covered_classes = {r.vuln_class for r in corpus}
    added, gaps = 0, []
    for item in data.get("findings", []):
        f = Finding(file=item.get("file", ""), symbol=item.get("symbol", "?"),
                    vuln_class=item.get("vuln_class", "UNKNOWN"),
                    description=item.get("why", "exploratory finding"),
                    technique="exploratory")
        if store.add_candidate(f):
            added += 1
            coverage.record_attempt("exploratory-design-review", "exploratory")
            if f.vuln_class not in covered_classes:
                gaps.append({
                    "finding": f.symbol, "vuln_class": f.vuln_class,
                    "pattern": item.get("why", "pattern not covered by the rule corpus"),
                    "action": f"author a CodeGuard rule for {f.vuln_class} so the "
                             f"next sweep catches this class systematically",
                })
    return added, gaps
