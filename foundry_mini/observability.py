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

project and agent_stream are both exposed as GUI fields (both optional,
both blank-default) rather than just project — Splunk's own sample scripts
always pass both explicitly to splunk_ao_context.init() as meaningful,
memorable names (e.g. project="Foundry", agent_stream="foundry-trace"), not
just the project.

Important, learned by reading the SDK's own source rather than assumed:
start_trace() / add_llm_span() / conclude() / flush() do NOT raise on
failure. They're wrapped in the SDK's own `warn_catch_exception` decorator,
which catches the error and routes it to Python's `logging` module
(`logging.getLogger("splunk_ao.logger").warning(...)`) instead of
propagating it — by design, so one bad span never crashes the caller's
app. That means try/except around these specific calls (kept below anyway,
as a second line of defense for anything that DOES still raise) cannot see
most real failures — this is why a project/Agent Stream can exist (that
call path raises normally, so build_sao_tracer's try/except catches it)
while individual traces silently never arrive. _WarningCollector attaches
a handler to the "splunk_ao" logger to surface exactly these otherwise-
invisible warnings in the app itself.
"""

from __future__ import annotations

import logging
import os
from typing import Any


class _WarningCollector(logging.Handler):
    """Captures splunk_ao's own internally-swallowed warnings (see module
    docstring) so the app can show them instead of them vanishing into
    Python logging with no visible handler configured."""

    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(self.format(record))

DEFAULT_PROJECT = "foundry-mini"
DEFAULT_AGENT_STREAM = "streamlit"
DEFAULT_CONSOLE_URL = "https://console.multitenant.galileocloud.io"


class SAOTracer:
    """One of these lives for as long as one SAO session does — built for the
    main "Run" click, then reused (via st.session_state) by the two later
    follow-on buttons (draft rules, generate patches) too, so *every* real
    LLM call in a session gets a trace, not just the ones inside the main
    comparison. A brand-new "Run" click replaces it with a fresh tracer
    (fresh session, fresh warning collector) — detach() tears down the old
    one's logging handler at that point so handlers don't pile up on the
    shared "splunk_ao" logger across many runs in one long-lived process."""

    def __init__(self, logger: Any, console_url: str):
        self._logger = logger
        self._console_url = console_url
        self._session_started = False
        self.activated = False   # flips true on the first successful span
        self.pending_before_flush = 0   # trace count seen just before the last flush()
        self._warnings = _WarningCollector()
        logging.getLogger("splunk_ao").addHandler(self._warnings)

    @property
    def session_id(self) -> str | None:
        return getattr(self._logger, "session_id", None)

    @property
    def sdk_warnings(self) -> list[str]:
        """Warnings the SDK logged internally instead of raising (see module
        docstring) — non-empty here is the real signal something didn't
        actually reach SAO, even when activated is True."""
        return self._warnings.records

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

    def flush(self) -> None:
        """Push whatever's been logged so far. Safe to call repeatedly — once
        after the main run, again after each later follow-on action — unlike
        the old close(), this does NOT tear down the warning handler, since
        this same tracer is reused for those later calls too.

        Records pending_before_flush = how many trace objects the logger
        actually held locally right before this call — the one number that
        tells apart "nothing was ever built" (0: the problem is in
        start_trace/add_llm_span/conclude) from "something was built but
        never sent" (>0: the problem is in flush()/delivery, i.e. network,
        auth scope on ingestion, or a server-side rejection)."""
        self.pending_before_flush = len(getattr(self._logger, "traces", None) or [])
        try:
            self._logger.flush()   # on_error deliberately omitted -- letting
                                   # a flush failure fall through to its
                                   # default logging.warning() path, same
                                   # channel _WarningCollector already
                                   # watches, keeps one uniform mechanism
                                   # for every SDK-swallowed failure.
        except Exception:
            pass

    def detach(self) -> None:
        """Remove this tracer's warning handler from the shared 'splunk_ao'
        logger. Call only when replacing this tracer with a new one (a fresh
        "Run" click) — not after every flush, since this tracer keeps getting
        reused by later follow-on actions in the same session."""
        logging.getLogger("splunk_ao").removeHandler(self._warnings)


def build_sao_tracer(api_key: str | None, project: str | None,
                     agent_stream: str | None = None) -> SAOTracer | None:
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
                               agent_stream=agent_stream or DEFAULT_AGENT_STREAM)
        logger = splunk_ao_context.get_logger_instance()
        console_url = SplunkAOConfig.get().console_url or DEFAULT_CONSOLE_URL
        tracer = SAOTracer(logger, console_url)
        tracer.start_session()
        return tracer
    except Exception as e:  # noqa: BLE001 -- init/network failure must not break a run
        print(f"SAO tracing unavailable ({type(e).__name__}: {e}) -- continuing without it.")
        return None
