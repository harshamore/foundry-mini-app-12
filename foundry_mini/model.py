"""
Model layer — spec §11.2 + budget §9.3.

Three modes behind one interface:
  - anthropic : real Claude calls via the anthropic SDK
  - openai    : real GPT calls via the openai SDK
  - mock      : deterministic offline judgments, so the app runs with no key
                and never breaks in front of an audience.

The call sites in the roles are identical across all three. The mock is not a
toy: it reproduces the judgments a real model reaches on the sample target, so
the pipeline (gate, fingerprint, flywheel) is fully exercised offline.

`ask_json()` is the one entry point every role uses for structured output. No
LangChain here on purpose: every role is a single structured-output completion
driven by a plain Python orchestrator (pipeline.py) — there's no multi-step
tool-use loop, retrieval, or cross-turn memory for a framework to earn its keep
on. Instead this file leans on each provider's own structured-output feature
(Anthropic forced tool-use, OpenAI JSON mode) so replies are reliably parseable
JSON without regex-scraping free text, and a parse failure is a loud
`ModelError` naming the role that failed rather than a silent empty dict —
silent failures are exactly what made the previous build hard to trust.

Being the one seam every role's LLM call passes through also makes this the
one place optional Splunk Agent Observability (SAO) tracing attaches
(observability.py's SAOTracer, passed in as `tracer=`) — one named trace per
role's real call, with zero changes to any role's own code. Mock/offline
calls are never traced: there's no real model behavior to observe.
"""

from __future__ import annotations

import re
import json
import time

DEFAULTS = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
}

# Illustrative rates for cost estimation when the provider doesn't return cost.
_RATE = {
    "anthropic": (0.003 / 1000, 0.015 / 1000),
    "openai": (0.0025 / 1000, 0.010 / 1000),
    "mock": (0.003 / 1000, 0.015 / 1000),
}


class Budget:
    def __init__(self, usd_cap=None):
        self.usd_cap = usd_cap
        self.spent = 0.0
        self.estimated = 0.0
        self.calls = 0

    def charge(self, in_tok, out_tok, provider, estimated):
        rin, rout = _RATE.get(provider, _RATE["mock"])
        cost = in_tok * rin + out_tok * rout
        self.spent += cost
        if estimated:
            self.estimated += cost
        self.calls += 1

    def exceeded(self):
        return self.usd_cap is not None and self.spent >= self.usd_cap

    def summary(self):
        frac = (self.estimated / self.spent) if self.spent else 0.0
        return {
            "usd_spent": round(self.spent, 4),
            "usd_cap": self.usd_cap,
            "calls": self.calls,
            "estimated_fraction": round(frac, 2),
        }


class ModelError(Exception):
    pass


_TOOL_NAME = "emit_result"


class Model:
    def __init__(self, provider, api_key, model_name, budget, tracer=None):
        self.provider = provider          # "anthropic" | "openai" | "mock"
        self.model = model_name or DEFAULTS.get(provider, "")
        self.budget = budget
        self.tracer = tracer              # optional observability.SAOTracer
        self._client = None
        self._last_usage = (0, 0)         # (in_tok, out_tok) from the last live call
        if provider in ("anthropic", "openai") and api_key:
            self._init_client(api_key)

    def _init_client(self, api_key):
        try:
            if self.provider == "anthropic":
                import anthropic
                self._client = anthropic.Anthropic(api_key=api_key)
            elif self.provider == "openai":
                import openai
                self._client = openai.OpenAI(api_key=api_key)
        except Exception as e:
            raise ModelError(f"could not initialize {self.provider} client: {e}")

    @property
    def is_live(self):
        return self._client is not None

    def ask(self, system, user, mock_fn=None):
        """Free-text call. Prefer ask_json() for anything a role will parse."""
        return self._call(system, user, mock_fn, json_mode=False, role="call")

    def ask_json(self, role: str, system: str, user: str, mock_fn=None) -> dict:
        """
        Structured call every role uses. Live calls request the provider's
        native structured-output mode; mock calls run mock_fn exactly as
        ask() does. Either way the reply is parsed to a dict — a parse
        failure raises ModelError naming `role` rather than degrading to {}.
        """
        reply = self._call(system, user, mock_fn, json_mode=True, role=role)
        try:
            return extract_json(reply)
        except ValueError as e:
            raise ModelError(f"{role}: {self.provider} returned an unparseable "
                              f"reply ({e})")

    def _call(self, system, user, mock_fn, json_mode, role):
        if self.is_live:
            start = time.time()
            try:
                reply = self._ask_live(system, user, json_mode)
            except ModelError:
                raise
            except Exception as e:
                raise ModelError(f"{role}: {self.provider} call failed: {e}")
            if self.tracer is not None:
                in_tok, out_tok = self._last_usage
                self.tracer.trace_call(role, system, user, self.model, reply,
                                       in_tok, out_tok, (time.time() - start) * 1e9)
            return reply
        # mock
        answer = mock_fn(system, user) if mock_fn else "{}"
        in_tok = max(1, len(system) + len(user)) // 4
        out_tok = max(1, len(answer)) // 4
        self.budget.charge(in_tok, out_tok, "mock", estimated=True)
        return answer

    def _ask_live(self, system, user, json_mode):
        if self.provider == "anthropic":
            return self._ask_anthropic(system, user, json_mode)
        return self._ask_openai(system, user, json_mode)

    def _ask_anthropic(self, system, user, json_mode):
        kwargs = dict(
            model=self.model, max_tokens=2048, system=system,
            messages=[{"role": "user", "content": user}],
        )
        if json_mode:
            # Forced tool-use: the model must emit a JSON object as tool
            # input rather than free text, so no fence-stripping / regex
            # recovery is needed on the way back. The schema is deliberately
            # permissive — each role's own prompt defines the shape it wants;
            # this only guarantees "valid JSON object", not a specific shape.
            kwargs["tools"] = [{
                "name": _TOOL_NAME,
                "description": "Return the structured result for this analysis.",
                "input_schema": {"type": "object"},
            }]
            kwargs["tool_choice"] = {"type": "tool", "name": _TOOL_NAME}
        resp = self._client.messages.create(**kwargs)
        self.budget.charge(resp.usage.input_tokens, resp.usage.output_tokens,
                           "anthropic", estimated=False)
        self._last_usage = (resp.usage.input_tokens, resp.usage.output_tokens)
        if json_mode:
            for block in resp.content:
                if block.type == "tool_use":
                    return json.dumps(block.input)
            raise ModelError("anthropic call did not return a tool_use block")
        return "".join(b.text for b in resp.content if b.type == "text")

    def _ask_openai(self, system, user, json_mode):
        resp = self._openai_create(system, user, json_mode)
        u = resp.usage
        self.budget.charge(u.prompt_tokens, u.completion_tokens,
                           "openai", estimated=False)
        self._last_usage = (u.prompt_tokens, u.completion_tokens)
        return resp.choices[0].message.content or ""

    def _openai_create(self, system, user, json_mode):
        """
        Call OpenAI, self-healing across the max_tokens rename.

        Older models (gpt-4o and earlier) use `max_tokens`. Newer models
        (the gpt-5 family and o-series reasoning models) reject it and require
        `max_completion_tokens`. Rather than maintain a model-name list, we try
        the old parameter and, only if the API rejects it with that specific
        error, retry once with the new one. The cap is generous because
        reasoning models spend tokens internally before the visible answer.

        json_mode requests `response_format={"type":"json_object"}` — OpenAI
        requires the word "json" to appear in the prompt for this to be
        accepted, which every structured-output system prompt in this app
        already satisfies (each one says "Reply JSON: ...").
        """
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": user}]
        cap = 4096
        extra = {"response_format": {"type": "json_object"}} if json_mode else {}
        try:
            return self._client.chat.completions.create(
                model=self.model, max_tokens=cap, messages=messages, **extra)
        except Exception as e:
            msg = str(e).lower()
            if "max_tokens" in msg and "max_completion_tokens" in msg:
                return self._client.chat.completions.create(
                    model=self.model, max_completion_tokens=cap, messages=messages,
                    **extra)
            raise


def extract_json(text: str) -> dict:
    """Parse JSON out of a model reply, tolerating code fences. Raises
    ValueError (not a silent {}) when no JSON object can be recovered, so
    callers can surface which role actually failed."""
    cleaned = re.sub(r"```(json)?", "", text or "").strip()
    try:
        return json.loads(cleaned)
    except Exception:
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
    raise ValueError(f"no parseable JSON in reply: {(text or '')[:200]!r}")
