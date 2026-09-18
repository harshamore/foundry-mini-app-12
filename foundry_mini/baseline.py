"""
Baseline scanner — the "raw LLM, no Foundry spec" comparison.

This is deliberately the naive approach a competent person would try first:
hand the whole code to the model, ask it to find vulnerabilities, and take the
answer at face value. There is NO indexer, NO security map, NO rule corpus, NO
evidence gate, NO fingerprinting, NO validation. Whatever the model says IS the
result.

The point is contrast. Running this next to the full pipeline on the same code
shows what the specification actually buys you:
  - the raw model may report bugs it cannot substantiate (no evidence gate),
  - it may miss things a systematic rule sweep would catch (no corpus),
  - it may hallucinate a location that does not exist (no citation check),
  - it offers no dedup identity, no coverage claim, no cost governance.

To keep the comparison fair this baseline is a GOOD-FAITH prompt, not a
strawman: it asks for structured output with locations and severity, exactly
what a sensible engineer would write.
"""

from __future__ import annotations

BASELINE_SYSTEM = (
    "You are a senior application security engineer. You will be given the full "
    "source of a program. Find the security vulnerabilities in it. For each one, "
    "report the file, the function or symbol, the vulnerability class (a CWE id "
    "if you can), a severity (critical/high/medium/low), and a one-sentence "
    "explanation. Respond ONLY with JSON of the form: "
    '{"findings": [{"file","symbol","vuln_class","severity","why"}]}. '
    "If you find nothing, return an empty list."
)


def _mock_baseline(sources):
    """
    Offline stand-in for the raw model, tuned to behave like a STRONG model
    would on this sample — because the offline demo must not contradict what a
    live GPT-5 or Claude actually does. A capable model in one shot will:
      - catch the obvious data-flow bugs (SQL injection, command injection),
      - catch a visible hardcoded key,
      - but plausibly MISS the subtlest issue (the password written to logs),
        which is exactly why the pipeline routes that class to exploration,
      - and ADD a confident, unsubstantiated finding — here a "weak crypto"
        claim pointing at a function that does not even exist in the code.

    That last item is the honest crux: the raw approach has no way to notice
    that its own citation is fabricated. The pipeline's evidence gate catches
    exactly this. So the contrast does not rest on the model being weak — it
    rests on the raw output being unverifiable and ungoverned.
    """
    import re

    def fn(system, user):
        findings = []
        joined = "\n".join(sources.values())
        if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*["\']\s*\+', joined, re.I) or \
           re.search(r'["\']\s*\+\s*\w+', joined):
            findings.append({"file": _file_of(sources, "execute") or list(sources)[0],
                             "symbol": "find_user_by_name", "vuln_class": "CWE-89",
                             "severity": "critical",
                             "why": "User input is concatenated directly into a SQL query."})
        if re.search(r'(system|call|Popen)\(', joined):
            findings.append({"file": _file_of(sources, "subprocess") or list(sources)[0],
                             "symbol": "export_report", "vuln_class": "CWE-78",
                             "severity": "critical",
                             "why": "User input is passed into a shell command."})
        if re.search(r'sk_live_|AKIA|api_?key\s*=', joined, re.I):
            findings.append({"file": _file_of(sources, "AKIA") or list(sources)[0],
                             "symbol": "AWS_ACCESS_KEY_ID", "vuln_class": "CWE-798",
                             "severity": "high",
                             "why": "A secret key appears hardcoded in the source."})
        # confident, unsubstantiated addition citing a function that isn't there:
        findings.append({"file": list(sources)[0], "symbol": "encrypt_payload",
                         "vuln_class": "CWE-327", "severity": "medium",
                         "why": "The encryption routine appears to use a weak cipher."})
        # NOTE: deliberately does NOT surface the log-leak (CWE-532) — the subtle
        # one a single glance tends to miss, and the one the pipeline catches via
        # exploration.
        import json as _j
        return _j.dumps({"findings": findings})
    return fn


def _file_of(sources, needle):
    for f, src in sources.items():
        if needle in src:
            return f
    return None


def run_baseline(sources, model):
    """
    One model call over the whole codebase. Returns a list of plain dict
    findings exactly as the model reported them — nothing verified, nothing
    filtered. This is the comparison point, not a role in the pipeline.
    """
    corpus_text = "\n\n".join(f"### FILE: {name}\n{src}" for name, src in sources.items())
    user = f"Here is the full source:\n\n{corpus_text}"
    data = model.ask_json("baseline", BASELINE_SYSTEM, user,
                          mock_fn=_mock_baseline(sources))
    findings = data.get("findings", [])
    # tag each with whether its cited symbol actually exists in the source —
    # we do NOT act on this (the raw approach has no gate); we only record it
    # so the UI can show how many claims are unverifiable.
    for f in findings:
        f["_symbol_exists"] = _symbol_present(sources, f.get("symbol", ""))
    return findings


def _symbol_present(sources, symbol):
    if not symbol:
        return False
    for src in sources.values():
        if symbol in src:
            return True
    return False
