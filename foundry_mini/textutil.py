"""Tiny text helper shared by the offline mock paths in detector.py/triager.py."""

from __future__ import annotations


def line_of_offset(body: str, offset: int, start_line: int) -> int:
    """Real file line number of a character offset into `body`, given the
    real line number `body`'s first line starts at."""
    return start_line + body[:offset].count("\n")
