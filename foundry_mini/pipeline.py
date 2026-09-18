"""
Substrate + Validator + Pipeline orchestrator.

The Pipeline class runs the roles in order and returns a structured Result the
Streamlit UI renders. Each stage method returns a short summary dict so the UI
can show progress live inside st.status blocks.
"""

from __future__ import annotations

from .finding import Verdict, State
from .index import build_index
from .cartographer import build_security_map
from .rules import load_corpus
from .model import ModelError
from . import detector, triager, reporter


class FindingStore:
    def __init__(self):
        self._by_fp = {}

    def add_candidate(self, finding) -> bool:
        fp = finding.fingerprint()
        if fp in self._by_fp:
            return False
        self._by_fp[fp] = finding
        return True

    def all(self):
        return list(self._by_fp.values())

    def with_verdict(self, verdict):
        return [f for f in self._by_fp.values() if f.verdict == verdict]


class CoverageChecklist:
    def __init__(self, goals):
        self.items = {g: {"attempted": False, "techniques": []} for g in goals}

    def ensure(self, goal):
        self.items.setdefault(goal, {"attempted": False, "techniques": []})

    def record_attempt(self, goal, technique):
        self.ensure(goal)
        self.items[goal]["attempted"] = True
        if technique not in self.items[goal]["techniques"]:
            self.items[goal]["techniques"].append(technique)

    def complete(self):
        return all(v["attempted"] for v in self.items.values())

    def report(self):
        return {"complete": self.complete(), "items": self.items}


def title_for(cls):
    """Back-compat thin wrapper — prefer reading Finding.title once the
    pipeline has run; this only covers the fast known-class table."""
    return reporter._TITLE.get(cls, cls)


def severity_for(cls):
    return reporter._SEVERITY.get(cls, "medium")


_VALIDATOR_SYSTEM = (
    "You are writing a short proof-of-concept SKETCH for a confirmed "
    "vulnerability finding: a paragraph of attacker-perspective narrative "
    "(what input you would send, what happens as a result), not runnable "
    "exploit code and not a claim that it was executed — no live testbed is "
    "configured for this run, so this is illustrative only. "
    'Reply JSON: {"poc": str}.'
)


def _mock_poc(finding):
    def fn(system, user):
        import json as _j
        return _j.dumps({
            "poc": f"An attacker exploiting {finding.vuln_class} at "
                  f"{finding.symbol}() would supply crafted input at the cited "
                  f"reachability point to trigger the cited impact.",
        })
    return fn


def _poc_sketch(finding, model):
    user = (f"Finding: {finding.vuln_class} in {finding.symbol} ({finding.file}).\n"
           f"Investigation: {finding.investigation}\nWrite the PoC sketch.")
    try:
        data = model.ask_json("validator", _VALIDATOR_SYSTEM, user,
                              mock_fn=_mock_poc(finding))
        return data.get("poc") or "(model returned no PoC narrative)"
    except ModelError:
        return "(PoC sketch unavailable — model call failed for this finding)"


class Result:
    def __init__(self):
        self.security_map = {}
        self.true_positives = []
        self.demotions = []
        self.rule_gaps = []
        self.coverage = {}
        self.budget = {}
        self.n_functions = 0
        self.n_rules = 0
        self.stages = []      # list of (name, detail)


class Pipeline:
    """Drives the eight roles. Call stages in order; each returns a summary."""

    def __init__(self, sources, model, budget):
        self.sources = sources
        self.model = model
        self.budget = budget
        self.store = FindingStore()
        # Only the always-present goal is seeded up front; stage_detect adds
        # one goal per loaded rule (+ secret-scan) once the corpus is known,
        # so "coverage complete" reflects what THIS run's corpus committed to
        # checking rather than a fixed list of the sample's four CWEs.
        self.coverage = CoverageChecklist(["exploratory-design-review"])
        self.index = None
        self.security_map = None
        self.corpus = []
        self.rule_gaps = []
        self.demotions = []

    def stage_index(self):
        self.index = build_index(self.sources)
        fns = self.index.list_functions()
        if not fns:
            raise RuntimeError("Index gate failed: no functions found (FR-003). "
                               "Is the input valid Python with function definitions?")
        return {"functions": len(fns), "names": fns}

    def stage_cartograph(self):
        self.security_map = build_security_map(self.index, self.model)
        return {"entry_points": len(self.security_map["attack_surface"]),
                "trust_boundaries": len(self.security_map["trust_boundaries"]),
                "data_flows": len(self.security_map["data_flows"]),
                "llm_augmented": self.security_map.get("llm_augmented", False)}

    def stage_detect(self):
        self.corpus = load_corpus()
        for r in self.corpus:
            self.coverage.ensure(f"triage:{r.vuln_class}")
        self.coverage.ensure("triage:CWE-798")   # secret-scan's class

        n_rule = detector.rule_sweep(self.index, self.corpus, self.model, self.store)
        n_secret = detector.secret_scan(self.index, self.store)
        n_expl, self.rule_gaps = detector.exploratory_hunt(
            self.index, self.model, self.store, self.coverage, self.corpus)
        self.coverage.record_attempt("triage:CWE-798", "secret-scan")
        return {"rules": len(self.corpus), "rule_candidates": n_rule,
                "secret_candidates": n_secret, "exploratory_candidates": n_expl,
                "rule_gaps": len(self.rule_gaps),
                "total_candidates": len(self.store.all())}

    def stage_triage(self):
        self.demotions = triager.triage_all(
            self.store, self.index, self.sources, self.coverage,
            self.security_map, self.model)
        tps = self.store.with_verdict(Verdict.TRUE_POSITIVE)
        return {"true_positives": len(tps), "demoted": len(self.demotions)}

    def stage_validate(self):
        tps = self.store.with_verdict(Verdict.TRUE_POSITIVE)
        for f in tps:
            f.poc = _poc_sketch(f, self.model)
            f.exploited = False   # Principle VII: no testbed -> no execution claim
        return {"poc_sketches": len(tps), "exploited": 0}

    def finalize(self) -> Result:
        r = Result()
        r.security_map = self.security_map
        r.n_functions = len(self.index.list_functions())
        r.n_rules = len(self.corpus)
        tps = self.store.with_verdict(Verdict.TRUE_POSITIVE)
        for f in tps:
            classified = reporter.classify(f.vuln_class, f.description, self.model)
            f.severity = classified["severity"]
            f.title = classified["title"]
            f.business_impact = classified["business_impact"]
            f.weakness = f.vuln_class
            f.state = State.PUBLISHED
        r.true_positives = sorted(
            tps, key=lambda x: ({"critical": 0, "high": 1, "medium": 2,
                                 "low": 3}.get(x.severity, 9), x.file))
        r.demotions = self.demotions
        r.rule_gaps = self.rule_gaps
        r.coverage = self.coverage.report()
        r.budget = self.budget.summary()
        return r
