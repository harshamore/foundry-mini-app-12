"""Bundled sample target + markdown report builder."""

SAMPLE_TARGET = '''"""
Acme Widgets — a deliberately vulnerable sample web service.
This is the TARGET of the evaluation. Every function below is intentionally
flawed so the scanner has something real to find. Do not deploy this.
"""

import os
import sqlite3
import logging
import subprocess

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("acme")

# --- planted vuln: hardcoded credential in source (CWE-798) ---
# (AWS's own long-standing published example key — a well-known placeholder,
# not a live credential — used here so secret-scan has real-shaped text to
# match without a real-looking secret ever landing in this repo)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def get_db():
    return sqlite3.connect("acme.db")


def find_user_by_name(request_params):
    """Look up a user. Entry point: HTTP query parameter 'name'."""
    name = request_params.get("name")            # attacker-controlled entry point
    conn = get_db()
    cur = conn.cursor()
    # --- planted vuln: SQL injection (CWE-89) ---
    query = "SELECT id, email FROM users WHERE name = '" + name + "'"
    cur.execute(query)
    return cur.fetchall()


def export_report(request_params):
    """Generate a report file. Entry point: HTTP query parameter 'filename'."""
    filename = request_params.get("filename")    # attacker-controlled entry point
    # --- planted vuln: OS command injection (CWE-78) ---
    subprocess.call("tar czf /tmp/" + filename + ".tgz /var/reports", shell=True)
    return "/tmp/" + filename + ".tgz"


def authenticate(request_params):
    """Authenticate a user. Entry point: HTTP form fields."""
    username = request_params.get("username")
    password = request_params.get("password")
    # --- planted vuln: sensitive data written to logs (CWE-532) ---
    log.info("Login attempt user=%s password=%s", username, password)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE name = ? AND pw = ?", (username, password))
    return cur.fetchone() is not None


def health_check():
    """Benign — the scanner should NOT flag this."""
    return {"status": "ok", "version": "1.4.2"}


def compute_discount(price, pct):
    """Benign — pure arithmetic, no untrusted sink."""
    return round(price * (1 - pct / 100.0), 2)
'''


def build_markdown_report(result) -> str:
    L = []
    L.append("# Foundry-mini — Security Evaluation Report")
    L.append("")
    L.append("_Agentic scanning pipeline derived from the Cisco Foundry Security "
             "Spec. Detection rules: CodeGuard (CC-BY-4.0)._")
    L.append("")
    L.append("## Rollup")
    L.append("")
    by_sev = {}
    for f in result.true_positives:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    L.append(f"- Confirmed true-positives: **{len(result.true_positives)}**")
    for sev in ("critical", "high", "medium", "low"):
        if by_sev.get(sev):
            L.append(f"  - {sev}: {by_sev[sev]}")
    L.append(f"- Demoted to needs-review by the evidence gate: {len(result.demotions)}")
    L.append(f"- Rule gaps recorded (flywheel): {len(result.rule_gaps)}")
    L.append("")
    L.append("## Confirmed findings")
    L.append("")
    for f in result.true_positives:
        L.append(f"### [{f.severity.upper()}] {f.title or f.vuln_class} "
                 f"— `{f.symbol}` ({f.weakness})")
        L.append("")
        L.append(f"- **Location:** `{f.file}` → `{f.symbol}()`")
        L.append(f"- **Fingerprint:** `{f.fingerprint()}` (path+symbol+class; "
                 f"stable under edit)")
        L.append(f"- **Technique:** {f.technique}")
        L.append(f"- **Investigation:** {f.investigation}")
        L.append(f"- **Proof-of-concept sketch:** {f.poc}")
        L.append("- **Evidence (all citations resolve):**")
        for c in f.citations:
            L.append(f"  - _{c.leg}_ — `{f.file}:{c.line}` — {c.note}")
        L.append(f"- **Exploited:** {f.exploited}")
        L.append("")
    if result.demotions:
        L.append("## Demoted to needs-review (NOT surfaced)")
        L.append("")
        for symbol, cls, why in result.demotions:
            L.append(f"- `{symbol}` ({cls}) — {why}")
        L.append("")
    if result.rule_gaps:
        L.append("## Rule gaps (detection → prevention flywheel)")
        L.append("")
        for g in result.rule_gaps:
            L.append(f"- **{g['vuln_class']}** in `{g['finding']}`: {g['pattern']}")
            L.append(f"  - Action: {g['action']}")
        L.append("")
    cov = result.coverage
    L.append("## Coverage")
    L.append("")
    L.append(f"- Coverage-complete: **{cov['complete']}**")
    for item, meta in cov["items"].items():
        mark = "x" if meta["attempted"] else " "
        techs = ", ".join(meta["techniques"]) or "—"
        L.append(f"  - [{mark}] {item} ({techs})")
    L.append("")
    b = result.budget
    L.append("## Budget")
    L.append("")
    L.append(f"- Model calls: {b['calls']}  |  Spend: ${b['usd_spent']} "
             f"(cap: {b['usd_cap']})  |  Estimated fraction: {b['estimated_fraction']}")
    L.append("")
    return "\n".join(L)
