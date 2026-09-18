"""
Fetch Python source from GitHub for the demo. Two shapes:
  - a single file URL  (github.com/.../blob/... or raw.githubusercontent.com/...)
  - a repository URL    (github.com/owner/repo) -> downloads the default-branch
    tarball and extracts Python files, capped for demo safety.

Defensive by design: clear errors, size caps, and a file-count limit so a demo
never hangs on a huge repo.
"""

from __future__ import annotations

import io
import re
import tarfile

import requests

MAX_FILES = 40
MAX_BYTES_PER_FILE = 200_000
TIMEOUT = 20


def fetch_sources(url: str) -> dict:
    url = url.strip()
    if not url:
        raise ValueError("empty URL")

    # single file: blob or raw
    if "/blob/" in url or "raw.githubusercontent.com" in url:
        return _fetch_single_file(url)

    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/?$", url)
    if m:
        return _fetch_repo(m.group(1), m.group(2).replace(".git", ""))

    # a bare raw URL or anything else: try as a single file
    return _fetch_single_file(url)


def _to_raw(url: str) -> str:
    if "raw.githubusercontent.com" in url:
        return url
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/blob/(.+)", url)
    if m:
        owner, repo, rest = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{rest}"
    return url


def _fetch_single_file(url: str) -> dict:
    raw = _to_raw(url)
    resp = requests.get(raw, timeout=TIMEOUT)
    resp.raise_for_status()
    text = resp.text[:MAX_BYTES_PER_FILE]
    name = raw.rsplit("/", 1)[-1] or "fetched.py"
    if not name.endswith(".py"):
        raise ValueError("that URL is not a .py file; paste a Python file or a repo URL")
    return {name: text}


def _fetch_repo(owner: str, repo: str) -> dict:
    # try main then master
    last_err = None
    for branch in ("main", "master"):
        url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}"
        try:
            resp = requests.get(url, timeout=TIMEOUT)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            return _extract_python(resp.content)
        except Exception as e:  # noqa
            last_err = e
    raise ValueError(f"could not download repo {owner}/{repo} "
                     f"(tried main and master): {last_err}")


def _extract_python(tar_bytes: bytes) -> dict:
    sources = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile() or not member.name.endswith(".py"):
                continue
            if len(sources) >= MAX_FILES:
                break
            f = tf.extractfile(member)
            if f is None:
                continue
            data = f.read(MAX_BYTES_PER_FILE)
            # strip the top-level tarball dir from the path for readability
            rel = member.name.split("/", 1)[-1]
            try:
                sources[rel] = data.decode("utf-8", errors="replace")
            except Exception:
                continue
    if not sources:
        raise ValueError("no Python files found in that repository")
    return sources
