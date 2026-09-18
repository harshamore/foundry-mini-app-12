"""
Remediator — suggested patches for confirmed findings (feature 4).

This is the spec's Remediator extension role, in prototype form. For each
harness-confirmed true-positive it produces a corrected version of the code.
The model drafts the fix (live mode); an offline fallback supplies the
canonical, known-correct fix per class so the feature works with no key and
never suggests something wrong on the sample.

Scope note: patches are SUGGESTIONS. The full spec role also re-runs detection
to verify the fix closes the finding; here we present the before/after and the
rationale, and leave applying and re-scanning to the user.
"""

from __future__ import annotations

# Canonical fixes for the classes the sample exercises. Used offline, and as a
# guaranteed-correct fallback if a live model returns something unusable.
_CANONICAL = {
    "CWE-89": {
        "before": 'query = "SELECT id, email FROM users WHERE name = \'" + name + "\'"\n'
                  'cur.execute(query)',
        "after": 'cur.execute("SELECT id, email FROM users WHERE name = ?", (name,))',
        "why": "Use a parameterized query. The database driver binds `name` as a "
               "value, so it can never be interpreted as SQL — the injection is "
               "structurally impossible, not just filtered.",
    },
    "CWE-78": {
        "before": 'subprocess.call("tar czf /tmp/" + filename + ".tgz /var/reports", '
                  'shell=True)',
        "after": 'subprocess.run(["tar", "czf", f"/tmp/{filename}.tgz", "/var/reports"], '
                 'shell=False, check=True)',
        "why": "Pass arguments as a list with shell=False. Without a shell, "
               "`filename` cannot inject extra commands. Ideally also validate "
               "`filename` against an allowlist of safe characters.",
    },
    "CWE-798": {
        "before": 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        "after": 'import os\nAWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]',
        "why": "Load secrets from the environment (or a secrets manager), never "
               "from source. Then rotate the exposed key immediately, since it "
               "must be treated as compromised once it has been committed.",
    },
    "CWE-532": {
        "before": 'log.info("Login attempt user=%s password=%s", username, password)',
        "after": 'log.info("Login attempt user=%s", username)  # never log credentials',
        "why": "Remove the credential from the log statement entirely. Log the "
               "non-sensitive context you need for auditing (the username, the "
               "outcome), never the secret itself.",
    },
    "CWE-522": {
        "before": "# password compared or stored without adequate protection",
        "after": "# store only a strong salted hash (e.g. bcrypt/argon2); compare hashes",
        "why": "Never store or compare plaintext credentials; use a slow salted "
               "password hash.",
    },
}


def _mock_patch(finding):
    canon = _CANONICAL.get(finding.vuln_class)
    def fn(system, user):
        import json as _j
        if canon:
            return _j.dumps(canon)
        return _j.dumps({"before": "", "after": "", "why": "No canonical fix available."})
    return fn


def suggest_patches(true_positives, model) -> list:
    """
    For each confirmed finding, return a dict:
      {symbol, file, vuln_class, before, after, why}
    """
    patches = []
    for f in true_positives:
        body = f.investigation
        system = (
            "You are a secure-coding remediation assistant. Given a vulnerability "
            "and the vulnerable code, produce a minimal corrected version. Reply "
            'JSON: {"before","after","why"} where before/after are code snippets.')
        user = (f"Vulnerability: {f.vuln_class} in function {f.symbol} "
                f"(file {f.file}).\nContext: {body}\nProvide the fix.")
        data = model.ask_json("remediator", system, user, mock_fn=_mock_patch(f))
        canon = _CANONICAL.get(f.vuln_class, {})
        patches.append({
            "symbol": f.symbol,
            "file": f.file,
            "vuln_class": f.vuln_class,
            "before": data.get("before") or canon.get("before", ""),
            "after": data.get("after") or canon.get("after", ""),
            "why": data.get("why") or canon.get("why", ""),
        })
    return patches
