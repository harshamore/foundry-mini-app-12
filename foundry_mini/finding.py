"""
Finding lifecycle — spec §7. In-memory variant for the Streamlit app.

The only change from the CLI build is that the evidence gate resolves citations
against an in-memory source map (dict of path -> text) instead of files on disk,
so the whole pipeline runs on pasted code with no filesystem access — which is
what Streamlit Cloud needs.

Constitution honored here:
  I    Evidence Over Assertion  -> evidence_gate() (FR-087/088)
  VIII Fingerprints Stable Under Edit -> fingerprint() (FR-090)
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class State(str, Enum):
    CANDIDATE = "candidate"
    VERDICT_ASSIGNED = "verdict-assigned"
    CONFIRMED = "confirmed"
    PUBLISHED = "published"
    RECORDED = "recorded"


class Verdict(str, Enum):
    TRUE_POSITIVE = "true-positive"
    FALSE_POSITIVE = "false-positive"
    NEEDS_REVIEW = "needs-review"
    NOT_APPLICABLE = "not-applicable"
    CODE_QUALITY = "code-quality"


PRESENCE_IS_VULN = {"CWE-798", "CWE-259", "CWE-321", "CWE-327", "CWE-532"}


@dataclass
class Citation:
    file: str
    symbol: str
    line: int
    leg: str            # reachability | trust-boundary | impact
    note: str = ""

    def resolves(self, sources: dict) -> bool:
        src = sources.get(self.file)
        if src is None:
            return False
        n = len(src.splitlines())
        return 1 <= self.line <= n


@dataclass
class Finding:
    file: str
    symbol: str
    vuln_class: str
    description: str
    technique: str
    state: State = State.CANDIDATE
    verdict: Optional[Verdict] = None
    investigation: str = ""
    citations: list = field(default_factory=list)
    exploited: bool = False
    poc: str = ""
    severity: str = ""
    weakness: str = ""
    title: str = ""
    business_impact: str = ""

    def fingerprint(self) -> str:
        norm = os.path.normpath(self.file)
        basis = f"{norm}::{self.symbol}::{self.vuln_class}"
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        d["verdict"] = self.verdict.value if self.verdict else None
        d["fingerprint"] = self.fingerprint()
        d["citations"] = [asdict(c) for c in self.citations]
        return d


def evidence_gate(finding: Finding, sources: dict) -> tuple:
    """Three-leg gate + mechanical resolve check. See spec §7.3."""
    legs_needed = {"reachability", "trust-boundary", "impact"}
    present = {c.leg for c in finding.citations}

    if finding.vuln_class in PRESENCE_IS_VULN:
        if "impact" not in present:
            return False, "presence-is-vuln class missing required impact citation"
    else:
        missing = legs_needed - present
        if missing:
            return False, f"missing evidence leg(s): {sorted(missing)}"

    for c in finding.citations:
        if not c.resolves(sources):
            return False, f"citation does not resolve: {c.file}:{c.line} ({c.symbol})"

    return True, "all legs cited; all citations resolve on disk"
