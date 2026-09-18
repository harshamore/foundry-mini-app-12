"""
CodeGuard rule loader — spec FR-041. Reads bundled .md rules from the package
directory (Streamlit-Cloud safe: path is relative to this file, not the CWD).

The logging rule is intentionally NOT wired to a CWE, so no rule in the corpus
covers sensitive-data-in-logs — exploration catches that class and the rule-gap
loop records it (the flywheel). See detector.py.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

_RULE_META = {
    "codeguard-0-sql-injection-prevention.md": (
        "CWE-89",
        r"""execute\s*\(\s*["'].*?\+|["']\s*\+\s*\w+\s*\+?.*(SELECT|INSERT|UPDATE|DELETE)""",
    ),
    "codeguard-0-injection-prevention.md": (
        "CWE-89", r"""(SELECT|INSERT|UPDATE|DELETE).*["']\s*\+""",
    ),
    "codeguard-0-os-command-injection-defense.md": (
        "CWE-78",
        r"""(os\.system|subprocess\.(call|run|Popen))\s*\(.*\+.*shell\s*=\s*True|(os\.system|subprocess\.\w+)\s*\(\s*["'].*?\+""",
    ),
    "codeguard-0-password-storage.md": (
        "CWE-522", r"""pw\s*=|password\s*=.*request""",
    ),
}


@dataclass
class Rule:
    id: str
    description: str
    languages: list
    body: str
    vuln_class: str
    signal: str


def load_corpus(rules_dir: str = RULES_DIR) -> list:
    corpus = []
    if not os.path.isdir(rules_dir):
        return corpus
    for fname in sorted(os.listdir(rules_dir)):
        if not fname.endswith(".md"):
            continue
        meta = _RULE_META.get(fname)
        if meta is None:
            continue
        vuln_class, signal = meta
        with open(os.path.join(rules_dir, fname), "r", encoding="utf-8",
                  errors="replace") as fh:
            text = fh.read()
        desc = _field(text, "description") or fname
        corpus.append(Rule(
            id=fname.replace(".md", ""), description=desc,
            languages=_languages(text), body=_strip(text),
            vuln_class=vuln_class, signal=signal,
        ))
    corpus.extend(_DYNAMIC_RULES)   # runtime-authored rules join the sweep
    return corpus


# Rules authored during a session (feature 3). Appended to every load_corpus()
# call so a newly pushed rule is caught by the very next scan's rule sweep.
_DYNAMIC_RULES: list = []


def register_dynamic_rule(rule: "Rule") -> None:
    """Add an authored rule to the live corpus (dedup by id)."""
    if any(r.id == rule.id for r in _DYNAMIC_RULES):
        return
    _DYNAMIC_RULES.append(rule)


def dynamic_rules() -> list:
    return list(_DYNAMIC_RULES)


def clear_dynamic_rules() -> None:
    _DYNAMIC_RULES.clear()


def _strip(text):
    if text.startswith("---"):
        p = text.split("---", 2)
        if len(p) == 3:
            return p[2].strip()
    return text


def _field(text, key):
    m = re.search(rf"^{key}:\s*(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def _languages(text):
    block = text.split("---", 2)[1] if text.startswith("---") else ""
    langs, on = [], False
    for line in block.splitlines():
        if line.startswith("languages:"):
            on = True
            continue
        if on:
            if line.startswith("- "):
                langs.append(line[2:].strip())
            elif line.strip() and not line.startswith(" "):
                break
    return langs
