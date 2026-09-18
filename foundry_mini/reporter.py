"""
Reporter — spec §5.8. Severity / title / business-impact classification for
the CISO report.

The known, common CWEs get a fast, free, deterministic table lookup — no
reason to spend a model call classifying "SQL injection" every run. Anything
else (a class an exploratory hunt surfaces that this app's small fixed rule
set doesn't name) gets one real, per-class-cached LLM classification instead
of silently falling back to "Unclassified" — so novel findings still get a
proper CISO write-up.
"""

from __future__ import annotations

from .model import ModelError

_SEVERITY = {"CWE-89": "critical", "CWE-78": "critical",
            "CWE-798": "high", "CWE-532": "medium", "CWE-522": "low"}
_TITLE = {"CWE-89": "SQL Injection", "CWE-78": "OS Command Injection",
         "CWE-798": "Hardcoded Credential in Source",
         "CWE-532": "Sensitive Data Written to Logs",
         "CWE-522": "Insufficiently Protected Credentials"}
_BUSINESS_IMPACT = {
    "CWE-89": "An attacker can read or modify arbitrary database records, including "
             "customer and account data — a direct data-breach and integrity risk.",
    "CWE-78": "An attacker can execute arbitrary commands on the host, leading to "
             "full server compromise and lateral movement.",
    "CWE-798": "A leaked production credential grants an attacker direct access to a "
              "third-party or internal system without needing to breach anything else.",
    "CWE-532": "Credentials or sensitive data in logs are exposed to anyone with log "
              "access, including downstream log-aggregation and support staff.",
    "CWE-522": "Weak credential protection lets an attacker who obtains the store "
              "recover usable passwords instead of only useless hashes.",
}

CLASSIFY_SYSTEM = (
    "You are a CISO report writer. Given a vulnerability class (a CWE id, or "
    "free text if no CWE applies) and a short technical note, produce a "
    "plain-English title, a severity, and a one-sentence business-impact "
    "statement a CISO would read. Reply JSON: {\"title\": str, "
    '"severity": "critical"|"high"|"medium"|"low", "business_impact": str}.'
)

_cache: dict = {}


def _mock_classify(cls, note):
    def fn(system, user):
        import json as _j
        return _j.dumps({
            "title": cls, "severity": "medium",
            "business_impact": f"Potential security impact from {cls}; requires "
                               f"review. ({note})",
        })
    return fn


def classify(vuln_class: str, note: str, model=None) -> dict:
    """{"title", "severity", "business_impact"} for any vuln_class."""
    if vuln_class in _TITLE:
        return {"title": _TITLE[vuln_class],
                "severity": _SEVERITY.get(vuln_class, "medium"),
                "business_impact": _BUSINESS_IMPACT.get(
                    vuln_class, "Potential security impact; requires review.")}
    if vuln_class in _cache:
        return _cache[vuln_class]

    result = {"title": vuln_class or "Unclassified", "severity": "medium",
             "business_impact": "Potential security impact; requires review."}
    if model is not None:
        try:
            data = model.ask_json("reporter", CLASSIFY_SYSTEM,
                                  f"Class: {vuln_class}\nNote: {note}",
                                  mock_fn=_mock_classify(vuln_class, note))
            sev = data.get("severity")
            result = {
                "title": data.get("title") or result["title"],
                "severity": sev if sev in ("critical", "high", "medium", "low") else "medium",
                "business_impact": data.get("business_impact") or result["business_impact"],
            }
        except ModelError:
            pass
    _cache[vuln_class] = result
    return result
