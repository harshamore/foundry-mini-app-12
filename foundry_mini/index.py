"""
Indexer — spec §5.2. In-memory: builds the index from a sources dict.

FR-020: deterministic parser (Python `ast`), never LLM-only. Exposes the
query interface FR-022 requires.
"""

from __future__ import annotations

import ast
import warnings


class Index:
    def __init__(self):
        self.functions = {}      # symbol -> {file, line, end_line, body}
        self.callers = {}
        self.callees = {}
        self._source = {}        # file -> text

    def get_function_body(self, symbol: str) -> str:
        return self.functions.get(symbol, {}).get("body", "")

    def get_callers(self, symbol: str) -> list:
        return sorted(self.callers.get(symbol, set()))

    def get_callees(self, symbol: str) -> list:
        return sorted(self.callees.get(symbol, set()))

    def find_symbol(self, name: str):
        return self.functions.get(name)

    def full_text_search(self, needle: str) -> list:
        hits = []
        for f, src in self._source.items():
            for i, line in enumerate(src.splitlines(), start=1):
                if needle in line:
                    hits.append((f, i, line.strip()))
        return hits

    def list_functions(self) -> list:
        return sorted(self.functions.keys())

    @property
    def sources(self) -> dict:
        return self._source

    def numbered_body(self, symbol: str) -> str:
        """Just this function's lines, numbered with their REAL file line
        numbers (offset by where the function starts) — cheaper than
        numbered_file() for roles that only need one function's text, while
        staying directly checkable by evidence_gate()."""
        meta = self.functions.get(symbol)
        if not meta:
            return ""
        start = meta["line"]
        return "\n".join(f"{start + i}: {line}"
                         for i, line in enumerate(meta["body"].splitlines()))

    def numbered_file(self, file: str, max_lines: int = 400) -> str:
        """
        Whole file, one real line number per line (`1: ...`). Agents cite
        against these exact numbers, and evidence_gate() checks a citation's
        line against the same whole-file text — using real file line numbers
        end to end means a cited line is either genuinely in range or it
        isn't, with no offset arithmetic on either side to get wrong.
        """
        src = self._source.get(file, "")
        lines = src.splitlines()[:max_lines]
        return "\n".join(f"{i}: {line}" for i, line in enumerate(lines, start=1))

    def context_files(self, symbol: str, max_related: int = 3) -> list:
        """
        The file a symbol lives in, plus the files of its direct callers and
        callees (deduped) — enough for an agent to trace reachability across
        a short call chain without dumping an entire multi-file repo into one
        prompt. Falls back to every loaded file if `symbol` isn't a parsed
        function (e.g. a module-level constant a secret-scan candidate names).
        """
        meta = self.find_symbol(symbol)
        if meta is None:
            return list(self._source.keys())
        files = [meta["file"]]
        related = (self.get_callers(symbol) + self.get_callees(symbol))[:max_related]
        for r in related:
            rmeta = self.find_symbol(r)
            if rmeta and rmeta["file"] not in files:
                files.append(rmeta["file"])
        return files


def build_index(sources: dict) -> Index:
    idx = Index()
    defined = set()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        _build(sources, idx, defined)
    return idx


def _build(sources, idx, defined):
    # pass 1: deterministic function inventory (FR-020)
    for rel, src in sources.items():
        idx._source[rel] = src
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        lines = src.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = getattr(node, "end_lineno", node.lineno)
                body = "\n".join(lines[node.lineno - 1:end])
                idx.functions[node.name] = {
                    "file": rel, "line": node.lineno, "end_line": end, "body": body,
                }
                defined.add(node.name)

    # pass 2: call graph (FR-021, direct static calls)
    for symbol in idx.functions:
        idx.callees.setdefault(symbol, set())
        idx.callers.setdefault(symbol, set())
    for rel, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        _extract_calls(tree, idx, defined)


def _extract_calls(tree, idx, defined):
    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.stack = []

        def visit_FunctionDef(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            callee = None
            if isinstance(node.func, ast.Name):
                callee = node.func.id
            elif isinstance(node.func, ast.Attribute):
                callee = node.func.attr
            if callee in defined and self.stack:
                caller = self.stack[-1]
                idx.callees[caller].add(callee)
                idx.callers.setdefault(callee, set()).add(caller)
            self.generic_visit(node)

    Visitor().visit(tree)
