"""
Cartographer — spec §5.3.

Builds the security map every other role reasons against: attack surface,
trust boundaries, data-flow for sensitive classes.

Two layers:
  - a heuristic substring scan (entry points inferred from parameter-name-like
    hints, sinks from a fixed call-name list) that is cheap, deterministic,
    and — per FR-036a, "an empty map is a failure, not graceful degradation" —
    guaranteed non-empty on any target with functions;
  - a real LLM pass over the whole target that reasons about entry points by
    what they actually do (any externally-controlled input mechanism, not
    just a literal `request`/`params` parameter name), trust boundaries, and
    sinks, each cited to a real symbol/file/line.

The LLM pass is the map's primary source of truth when a live model is
available; the heuristic is the floor under it, not a replacement for it — if
the LLM call fails or a live model isn't configured, the heuristic alone still
satisfies FR-036a.
"""

from __future__ import annotations

from .model import ModelError

ENTRY_HINTS = ("request", "params", "args", "form", "query")
SINK_HINTS = {
    "execute": "database query (SQL sink)",
    "system": "shell execution (command sink)",
    "call": "shell execution (command sink)",
    "Popen": "shell execution (command sink)",
    "info": "log sink",
    "debug": "log sink",
}

CARTOGRAPHER_SYSTEM = (
    "You are a security architect mapping a codebase's attack surface. You "
    "are given every file in the target, with real line numbers. Identify:\n"
    "1. entry_points - functions/handlers that receive externally-controlled "
    "input, via ANY mechanism: HTTP route/decorator, CLI argument, "
    "environment variable, file read, queue/message consumer, "
    "deserialization, form field. Do not limit yourself to functions with "
    "request-like parameter names.\n"
    "2. trust_boundaries - for each entry point, the specific line where "
    "untrusted data starts being treated as trusted (used in a query, a "
    "command, a path, a template, etc. without validation).\n"
    "3. data_flows - lines where a value reaches a sensitive sink: database "
    "query, shell/process exec, filesystem write, network call, logging "
    "call, deserialization, template render, or crypto routine.\n"
    "Cite every item to a real symbol, file, and line number taken from the "
    "text you were given. Never invent a line number. Reply JSON: "
    '{"entry_points": [{"symbol","file","line","note"}], '
    '"trust_boundaries": [{"symbol","file","line","note"}], '
    '"data_flows": [{"symbol","file","line","sink"}]}.'
)


def _heuristic_map(index) -> dict:
    entry_points, trust_boundaries, data_flows = [], [], []
    for symbol in index.list_functions():
        body = index.get_function_body(symbol)
        meta = index.find_symbol(symbol)
        if any(h in body for h in ENTRY_HINTS):
            entry_points.append({
                "symbol": symbol, "file": meta["file"], "line": meta["line"],
                "note": "accepts request-derived input (heuristic: parameter-like name)",
            })
            trust_boundaries.append({
                "symbol": symbol, "file": meta["file"], "line": meta["line"],
                "note": "untrusted request data enters trusted processing here",
            })
        for needle, kind in SINK_HINTS.items():
            if needle + "(" in body or "." + needle in body:
                data_flows.append({"symbol": symbol, "file": meta["file"], "sink": kind})
    return {
        "architecture": f"{len(index.list_functions())} functions indexed in target",
        "attack_surface": entry_points,
        "trust_boundaries": trust_boundaries,
        "data_flows": data_flows,
    }


def _valid_entry(e, index, line_key="line"):
    f = e.get("file")
    if f not in index.sources:
        return False
    line = e.get(line_key)
    if not isinstance(line, int):
        return False
    return 1 <= line <= len(index.sources[f].splitlines())


def _llm_map(index, model) -> dict:
    files_block = "\n\n".join(
        f"### FILE: {f}\n{index.numbered_file(f)}" for f in index.sources)
    user = (f"Functions defined in this target: {index.list_functions()}\n\n"
            f"{files_block}")
    data = model.ask_json("cartographer", CARTOGRAPHER_SYSTEM, user)
    entries = [e for e in data.get("entry_points", []) if _valid_entry(e, index)]
    bounds = [e for e in data.get("trust_boundaries", []) if _valid_entry(e, index)]
    flows = [e for e in data.get("data_flows", []) if e.get("file") in index.sources]
    return {"attack_surface": entries, "trust_boundaries": bounds, "data_flows": flows}


def _dedup(items, key):
    seen, out = set(), []
    for it in items:
        k = key(it)
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
    return out


def _merge(heuristic, llm) -> dict:
    return {
        "architecture": heuristic["architecture"],
        "attack_surface": _dedup(
            heuristic["attack_surface"] + llm["attack_surface"],
            key=lambda e: (e.get("symbol"), e.get("file"), e.get("line"))),
        "trust_boundaries": _dedup(
            heuristic["trust_boundaries"] + llm["trust_boundaries"],
            key=lambda e: (e.get("symbol"), e.get("file"), e.get("line"))),
        "data_flows": _dedup(
            heuristic["data_flows"] + llm["data_flows"],
            key=lambda e: (e.get("symbol"), e.get("file"), e.get("sink"))),
        "llm_augmented": True,
    }


def build_security_map(index, model=None) -> dict:
    heuristic = _heuristic_map(index)
    if model is None or not model.is_live:
        heuristic["llm_augmented"] = False
        return heuristic
    try:
        llm = _llm_map(index, model)
    except ModelError:
        heuristic["llm_augmented"] = False
        return heuristic
    return _merge(heuristic, llm)
