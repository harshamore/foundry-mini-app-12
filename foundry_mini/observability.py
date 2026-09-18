"""
Optional Splunk Agent Observability (SAO) tracing.

Automatic-only scope, same shape as the Galileo integration this pattern is
ported from: one trace per role's real LLM call, wired at the single seam
every role already calls through (Model._call() in model.py), touching no
role's own logic. Strictly opt-in and fails soft: build_sao_tracer() returns
None whenever no API key is supplied — no import of `splunk_ao` is even
attempted — and any failure once a key IS set (bad key, unreachable console,
package not installed) is caught and reported, never raised. Tracing is
peripheral instrumentation, not core harness function: a broken SAO account
must never abort a scan.

Manual spans, not the `splunk_ao.openai` wrapper client: the wrapper only
covers OpenAI (no Anthropic equivalent), and its auto-created traces have no
shown way to name themselves per role — so both providers here go through
one uniform `add_llm_span()` call instead, keeping every trace named after
the role that produced it regardless of provider.
"""

from __future__ import annotations

import os
from typing import Any

DEFAULT_PROJECT = "foundry-mini"
DEFAULT_AGENT_STREAM = "streamlit"
DEFAULT_CONSOLE_URL = "https://console.multitenant.galileocloud.io"


class SAOTracer:
    """One of these per Streamlit run, shared by both the raw-baseline Model
    and the harness-pipeline Model, so a single run shows up as one session
    with every role's call as its own named trace inside it — not two
    disconnected sessions for the two sides of the comparison."""

    def __init__(self, logger: Any, console_url: str):
        self._logger = logger
        self._console_url = console_url
        self._session_started = False
        self.activated = False   # flips true on the first successful span

    def start_session(self) -> None:
        if self._session_started:
            return
        self._logger.start_session()
        self._session_started = True

    def trace_call(self, role: str, system: str, user: str, model_name: str,
                   reply: str, in_tok: int, out_tok: int, duration_ns: float) -> None:
        """One trace + one LLM span for a single Model._call(). Never raises —
        a bad SAO account degrades to 'no tracing', not a failed scan."""
        try:
            self._logger.start_trace(name=role, input=user)
            self._logger.add_llm_span(
                input=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
                output=reply, model=model_name,
                num_input_tokens=in_tok, num_output_tokens=out_tok,
                total_tokens=in_tok + out_tok, duration_ns=duration_ns,
            )
            self._logger.conclude(output=reply)
            self.activated = True
        except Exception as e:  # noqa: BLE001 -- a trace-logging failure must not break a run
            print(f"SAO trace_call({role!r}) failed ({type(e).__name__}: {e}) "
                 f"-- continuing without it.")

    def console_urls(self) -> tuple[str | None, str | None]:
        """(project_url, agent_stream_url), or (None, None) if the logger
        never got far enough to have real ids (e.g. every trace_call failed)."""
        try:
            project_id = self._logger.project_id
            agent_stream_id = self._logger.agent_stream_id
            if not (project_id and agent_stream_id):
                return None, None
            project_url = f"{self._console_url.rstrip('/')}/project/{project_id}"
            return project_url, f"{project_url}/agent-streams/{agent_stream_id}"
        except Exception:
            return None, None

    def close(self) -> None:
        try:
            self._logger.flush()
        except Exception:
            pass


def build_sao_tracer(api_key: str | None, project: str | None) -> SAOTracer | None:
    """A ready-to-use SAOTracer, or None if tracing isn't configured/reachable.

    Known, named limitation (same one already accepted for Galileo in the
    sibling harness's FastAPI backend): splunk_ao_context is a process-wide
    singleton, so if this Streamlit app ever serves multiple concurrent
    browser sessions with different SAO accounts from one process, the last
    init() wins for all of them. Fine for the single-user-at-a-time local/
    Streamlit-Cloud-demo scope this app targets; worth revisiting the moment
    that stops being true.
    """
    if not api_key:
        return None

    os.environ["SPLUNK_AO_API_KEY"] = api_key
    os.environ.setdefault("SPLUNK_AO_CONSOLE_URL", DEFAULT_CONSOLE_URL)

    try:
        from splunk_ao import splunk_ao_context
        from splunk_ao.config import SplunkAOConfig
    except ImportError:
        print("SAO API key is set but the `splunk-ao` package isn't installed "
             "(pip install splunk-ao) -- continuing without tracing.")
        return None

    try:
        splunk_ao_context.init(project=project or DEFAULT_PROJECT,
                               agent_stream=DEFAULT_AGENT_STREAM)
        logger = splunk_ao_context.get_logger_instance()
        console_url = SplunkAOConfig.get().console_url or DEFAULT_CONSOLE_URL
        tracer = SAOTracer(logger, console_url)
        tracer.start_session()
        return tracer
    except Exception as e:  # noqa: BLE001 -- init/network failure must not break a run
        print(f"SAO tracing unavailable ({type(e).__name__}: {e}) -- continuing without it.")
        return None
