"""
Rule authoring — closing the flywheel (feature 3).

When the harness's exploratory hunt confirms a vulnerability class that no rule
in the corpus covers, it records a "rule gap". This module turns a gap into a
real, CodeGuard-format rule the user can:
  - review,
  - push into the live corpus so the very next scan catches the class
    systematically (register_dynamic_rule), and
  - download as a .md file to commit to their own rule repository.

The rule body is drafted by the model (with a deterministic offline fallback).
For the classes this app's built-in corpus already knows about, the detection
signal is a fixed, hand-verified regex — we do not let the model invent the
regex that governs detection for a class we already understand well. For a
genuinely novel class (one an exploratory hunt found that isn't in that fixed
map), the model proposes a signal regex, which is validated by actually
compiling it before use; if it doesn't compile, a literal keyword pulled from
the gap's own pattern text is the fallback, so the flywheel still produces a
rule that fires rather than a decorative one.
"""

from __future__ import annotations

import re
from datetime import datetime

from .rules import Rule, register_dynamic_rule

# Deterministic detection signals per class, mirroring foundry_mini/rules.py.
# This is what makes an authored rule actually catch the class on the next scan.
_SIGNAL_FOR = {
    "CWE-532": r"""log(ger|ging)?\.(info|debug|warning|error)\s*\(.*(password|passwd|pwd|secret|token|api_?key)""",
    "CWE-89": r"""(SELECT|INSERT|UPDATE|DELETE).*["']\s*\+""",
    "CWE-78": r"""(os\.system|subprocess\.\w+)\s*\(.*\+""",
    "CWE-798": r"""(sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})""",
}

_CLASS_NAME = {
    "CWE-532": "sensitive-data-in-logs",
    "CWE-89": "sql-injection",
    "CWE-78": "os-command-injection",
    "CWE-798": "hardcoded-secret",
}


def _mock_rule_body(gap):
    cls = gap["vuln_class"]
    name = _CLASS_NAME.get(cls, cls.lower())
    def fn(system, user):
        import json as _j
        return _j.dumps({
            "title": f"Prevent {name.replace('-', ' ')}",
            "guidance": (
                f"Do not allow the pattern that leads to {cls}. "
                f"Specifically: {gap['pattern']}. "
                "Instead, keep sensitive values out of the dangerous sink: "
                "redact or omit secrets before logging; use parameterized APIs "
                "instead of string building; never place credentials in source."),
            "example_bad": "# risky: sensitive value flows into the sink unchanged",
            "example_good": "# safe: value is redacted / parameterized before the sink",
            "signal": "",
        })
    return fn


def _signal_for(cls: str, gap: dict, model) -> str:
    """A detection regex for `cls`. Known classes: fixed, hand-verified
    table. Novel classes: ask the model, but only use its answer if it
    actually compiles — otherwise fall back to a literal keyword pulled from
    the gap's own pattern text, so the authored rule still fires on
    SOMETHING rather than never matching."""
    if cls in _SIGNAL_FOR:
        return _SIGNAL_FOR[cls]
    system = ("You are a regex author for a security-rule engine. Given a "
             "vulnerability class and an observed pattern, propose a Python "
             'regex that would match it in source code. Reply JSON: {"signal": str}.')
    user = f"Vulnerability class: {cls}\nObserved pattern: {gap.get('pattern','')}"
    try:
        data = model.ask_json("rule_authoring.signal", system, user,
                              mock_fn=_mock_rule_body(gap))
        candidate = data.get("signal", "")
        if candidate:
            re.compile(candidate)   # validate before trusting it
            return candidate
    except Exception:
        pass
    return re.escape(gap.get("pattern", cls))


def draft_rule_from_gap(gap: dict, model) -> dict:
    """
    Produce a CodeGuard-format rule for a discovered gap.

    Returns a dict with:
      - filename : suggested .md filename
      - markdown : the full rule file content (frontmatter + body)
      - rule     : a Rule object ready for register_dynamic_rule()
    """
    cls = gap["vuln_class"]
    name = _CLASS_NAME.get(cls, cls.lower())
    signal = _signal_for(cls, gap, model)

    system = (
        "You are a secure-coding rule author. Given a vulnerability class and a "
        "described pattern, write concise prevention guidance. Reply JSON: "
        '{"title","guidance","example_bad","example_good"}.')
    user = (f"Vulnerability class: {cls}\nObserved pattern: {gap['pattern']}\n"
            f"Write a short prevention rule for developers.")
    drafted = model.ask_json("rule_authoring", system, user,
                             mock_fn=_mock_rule_body(gap))

    title = drafted.get("title", f"Prevent {name}")
    guidance = drafted.get("guidance", gap["pattern"])
    bad = drafted.get("example_bad", "")
    good = drafted.get("example_good", "")

    filename = f"codeguard-authored-{name}.md"
    markdown = (
        "---\n"
        f"description: {title}\n"
        "languages:\n  - python\n"
        "alwaysApply: true\n"
        f"authored: {datetime.utcnow().strftime('%Y-%m-%d')}\n"
        f"cwe: {cls}\n"
        "source: discovered by Foundry exploratory hunt (rule-gap flywheel)\n"
        "---\n\n"
        f"# {title}\n\n"
        f"{guidance}\n\n"
        "## Avoid\n\n"
        f"```python\n{bad}\n```\n\n"
        "## Prefer\n\n"
        f"```python\n{good}\n```\n"
    )

    rule = Rule(
        id=filename.replace(".md", ""),
        description=title,
        languages=["python"],
        body=markdown,
        vuln_class=cls,
        signal=signal,
    )
    return {"filename": filename, "markdown": markdown, "rule": rule,
            "vuln_class": cls}


def push_rule(drafted: dict) -> None:
    """Register the authored rule into the live corpus (feature 3 'push')."""
    register_dynamic_rule(drafted["rule"])
