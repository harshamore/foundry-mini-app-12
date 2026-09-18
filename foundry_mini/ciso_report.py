"""
CISO-ready report builder.

Produces an executive-facing Markdown report for either kind of run:
  - build_raw_ciso_report(findings)      -> for the no-harness run (feature 1)
  - build_harness_ciso_report(result)    -> for the Foundry run   (feature 2)

The two reports intentionally differ in their assurance language, because the
whole point is that a CISO should read them differently. The raw report must
carry an explicit "these findings are unverified" caveat; the harness report
can state that every finding carries resolved evidence and that the run has a
coverage claim and a demotion (precision) record.
"""

from __future__ import annotations

from datetime import datetime

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_TITLE = {
    "CWE-89": "SQL Injection", "CWE-78": "OS Command Injection",
    "CWE-798": "Hardcoded Credential in Source",
    "CWE-532": "Sensitive Data Written to Logs",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
}
_BUSINESS_IMPACT = {
    "CWE-89": "An attacker can read or modify arbitrary database records, including "
              "customer and account data — a direct data-breach and integrity risk.",
    "CWE-78": "An attacker can execute arbitrary commands on the host, leading to "
              "full server compromise and lateral movement.",
    "CWE-798": "A leaked production credential grants an attacker direct access to a "
               "third-party or internal system without needing to breach anything else.",
    "CWE-532": "Credentials or sensitive data in logs are exposed to anyone with log "
               "access, including downstream log-aggregation and support staff.",
    "CWE-327": "Weak cryptography can be broken, undermining confidentiality guarantees "
               "relied upon for compliance.",
}


def _title(cls):
    return _TITLE.get(cls, cls or "Unclassified")


def _impact(cls):
    return _BUSINESS_IMPACT.get(cls, "Potential security impact; requires review.")


def _header(scope_label, assurance_line):
    return [
        "# Application Security Assessment",
        "## Executive Report for the CISO",
        "",
        f"_Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · "
        f"Scope: {scope_label}_",
        "",
        assurance_line,
        "",
    ]


def _severity_rollup(sev_counts):
    lines = ["## Risk posture at a glance", ""]
    total = sum(sev_counts.values())
    lines.append(f"- **Total findings: {total}**")
    for sev in ("critical", "high", "medium", "low"):
        if sev_counts.get(sev):
            lines.append(f"  - {sev.capitalize()}: **{sev_counts[sev]}**")
    lines.append("")
    return lines


# ----------------------------------------------------------- raw (feature 1) --
def build_raw_ciso_report(findings) -> str:
    sev_counts = {}
    for f in findings:
        s = (f.get("severity") or "medium").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    unverifiable = sum(1 for f in findings if not f.get("_symbol_exists", True))

    L = _header(
        "single-pass LLM review (no assurance harness)",
        "> **Assurance level: LOW / ADVISORY.** These findings come from a single "
        "language-model review of the code. They have **not** been independently "
        "verified, deduplicated, or coverage-checked. Treat this as a triage "
        "starting point, not an authoritative assessment. See the limitations "
        "section before acting.",
    )
    L += _severity_rollup(sev_counts)

    if unverifiable:
        L += [
            "## \u26a0 Reliability warning", "",
            f"- **{unverifiable} of {len(findings)} finding(s) reference a code "
            f"location that could not be confirmed to exist.** Without a "
            f"verification step, unverifiable claims are reported the same as real "
            f"ones. Each is flagged below.", "",
        ]

    L += ["## Findings", ""]
    for f in sorted(findings, key=lambda x: _SEV_ORDER.get((x.get("severity") or "medium").lower(), 9)):
        cls = f.get("vuln_class", "")
        exists = f.get("_symbol_exists", True)
        flag = "" if exists else "  \u26a0 **UNVERIFIED LOCATION**"
        L += [
            f"### [{(f.get('severity') or 'medium').upper()}] {_title(cls)}{flag}",
            "",
            f"- **Location (as reported):** `{f.get('file','?')}` \u2192 "
            f"`{f.get('symbol','?')}`",
            f"- **Weakness:** {cls}",
            f"- **Model's explanation:** {f.get('why','')}",
            f"- **Business impact:** {_impact(cls)}",
            "",
        ]

    L += [
        "## Assurance limitations (read before acting)", "",
        "- **No evidence.** Each finding is an assertion; none is backed by a "
        "verified chain from attacker input to impact.",
        "- **No verification.** A confident but incorrect finding is indistinguishable "
        "from a correct one here.",
        "- **No coverage guarantee.** There is no assurance the whole codebase was "
        "examined; the model may have focused on what caught its attention.",
        "- **Not repeatable.** A second run may return a different list.",
        "",
        "_To convert this into an authoritative assessment, re-run with the assurance "
        "harness enabled._",
        "",
    ]
    return "\n".join(L)


# ------------------------------------------------------- harness (feature 2) --
def build_harness_ciso_report(result) -> str:
    tps = result.true_positives
    sev_counts = {}
    for f in tps:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    L = _header(
        "assurance-harnessed evaluation (Foundry Security Spec)",
        "> **Assurance level: HIGH / AUTHORITATIVE.** Every finding below survived an "
        "evidence gate: it carries a cited, verified chain from attacker-controlled "
        "input to security impact. Claims that could not be substantiated were "
        "withheld. This run also records what it examined (coverage) and what it "
        "rejected (precision).",
    )
    L += _severity_rollup(sev_counts)

    L += [
        "## Assurance summary", "",
        f"- **Confirmed, evidence-backed findings: {len(tps)}**",
        f"- Candidates rejected as unprovable (withheld from this report): "
        f"**{len(result.demotions)}**",
        f"- Coverage of stated goals complete: **{result.coverage['complete']}**",
        f"- New weakness patterns discovered beyond the standard ruleset: "
        f"**{len(result.rule_gaps)}** (see remediation programme)",
        "",
        "## Confirmed findings", "",
    ]
    for f in tps:
        # title/business_impact come from the Reporter's classification
        # (pipeline.finalize -> reporter.classify), which handles both the
        # known-CWE fast table and, for anything else, a real LLM writeup \u2014
        # so this report doesn't need its own copy of that table.
        L += [
            f"### [{f.severity.upper()}] {f.title or f.vuln_class} \u2014 `{f.symbol}()`",
            "",
            f"- **Location:** `{f.file}` \u2192 `{f.symbol}()`",
            f"- **Weakness:** {f.vuln_class}",
            f"- **Business impact:** {f.business_impact or _impact(f.vuln_class)}",
            f"- **Verified evidence:**",
        ]
        for c in f.citations:
            L.append(f"  - _{c.leg}_ \u2014 `{f.file}:{c.line}` \u2014 {c.note}")
        L += [
            f"- **Tracking id (stable across scans):** `{f.fingerprint()}`",
            f"- **Proof-of-concept sketch:** {f.poc or '(none produced)'}",
            f"- **Demonstrated on a live testbed:** {f.exploited} "
            f"(no testbed configured in this run)",
            "",
        ]

    if result.demotions:
        L += [
            "## What was examined and rejected (precision record)", "",
            "_The following candidates were investigated and withheld because their "
            "evidence could not be verified. Shown for auditability:_", "",
        ]
        for symbol, cls, why in result.demotions:
            L.append(f"- `{symbol}` ({cls}) \u2014 {why}")
        L.append("")

    return "\n".join(L)
