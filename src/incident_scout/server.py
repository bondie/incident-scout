"""A local page for deciding on ticket proposals.

The Teams card links here, so it only works on the machine that runs the monitor. Every link
carries the proposal's random token, so a page elsewhere cannot approve anything by guessing ids.
"""

from __future__ import annotations

import hmac
import json
import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from .investigator import Diagnosis
from .models import Event
from .proposal import Proposal
from .state import Store
from .teams import labels

_ROUTE = re.compile(r"^/incidents/(\d+)(?:/(approve|reject))?$")
DECISIONS: dict[str, Literal["approved", "rejected"]] = {
    "approve": "approved",
    "reject": "rejected",
}


def links(base: str, incident_id: int, token: str) -> dict[str, str]:
    root = f"{base.rstrip('/')}/incidents/{incident_id}"
    return {
        "detail": f"{root}?t={token}",
        "approve": f"{root}/approve?t={token}",
        "reject": f"{root}/reject?t={token}",
    }


def decide(store: Store, incident: sqlite3.Row, action: str, now: datetime) -> None:
    decision = DECISIONS[action]
    store.decide(incident["id"], decision, now)
    store.record(
        [
            Event(
                decision,
                "info",
                f"proposal {decision}",
                Proposal.from_json(incident["proposal"]).title,
                group=incident["fingerprint"],
                incident_id=incident["id"],
            )
        ],
        now,
    )


def handler(state_path: Path, language: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            match = _ROUTE.match(parts.path)
            if match is None:
                self._reply(HTTPStatus.NOT_FOUND, "<p>Not found</p>")
                return
            token = parse_qs(parts.query).get("t", [""])[0]
            store = Store(state_path)
            try:
                incident = store.incident(int(match.group(1)))
                if incident is None or not incident["proposal"]:
                    self._reply(HTTPStatus.NOT_FOUND, "<p>No such proposal</p>")
                    return
                if not hmac.compare_digest(token, incident["proposal_token"] or ""):
                    self._reply(HTTPStatus.FORBIDDEN, "<p>Invalid link</p>")
                    return
                if match.group(2):
                    decide(store, incident, match.group(2), datetime.now(UTC))
                    incident = store.incident(incident["id"])
                if incident is not None:
                    port = getattr(self.server, "server_port", 0)
                    base = f"http://127.0.0.1:{port}"
                    self._reply(HTTPStatus.OK, page(incident, language, base))
            finally:
                store.close()

        def log_message(self, format: str, *args: object) -> None:
            return None

        def _reply(self, status: HTTPStatus, body: str) -> None:
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

    return Handler


def serve(
    state_path: Path,
    language: str,
    port: int,
    host: str = "127.0.0.1",
    ready: Callable[[ThreadingHTTPServer], None] | None = None,
) -> None:
    server = ThreadingHTTPServer((host, port), handler(state_path, language))
    if ready:
        ready(server)
    with server:
        server.serve_forever()


def page(incident: sqlite3.Row, language: str, base: str) -> str:
    text = labels(language)
    proposal = Proposal.from_json(incident["proposal"])
    status = text.get(incident["decision"] or "pending", text["pending"])
    links_ = links(base, incident["id"], incident["proposal_token"])
    heading = text[proposal.recommendation]
    if proposal.existing_ticket:
        heading = f"{heading}: {proposal.existing_ticket}"
    diagnosis = ""
    if incident["diagnosis"]:
        found = Diagnosis(**json.loads(incident["diagnosis"]))
        diagnosis = (
            f"<h2>{escape(text['diagnosis'])}</h2><p>{escape(found.summary)}</p>"
            f"<p><b>{escape(text['cause'])}:</b> {escape(found.likely_cause)}</p>"
        )
    ticket_text = f"{proposal.title}\n\n{proposal.description}"
    tone = {"approved": "ok", "rejected": "no"}.get(incident["decision"] or "", "accent")
    return f"""<!doctype html>
<html lang="{"cs" if language == "Czech" else "en"}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>#{incident["id"]} {escape(proposal.title)}</title>
<style>
:root {{ --bg: #fff; --fg: #1b1b1f; --muted: #5f6368; --line: #d9dbe0; --accent: #4f52b2;
  --ok: #1e7b34; --no: #a4262c; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg: #1b1b1f; --fg: #ececf1;
  --muted: #a0a3ab; --line: #3a3b40; --accent: #a5a7f5; --ok: #6ccb85; --no: #f1707b; }} }}
body {{ background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, sans-serif;
  margin: 0 auto; max-width: 860px; padding: 24px 16px; }}
h1 {{ font-size: 1.3rem; margin: .2rem 0 1rem; }} h2 {{ font-size: 1rem; margin-top: 1.6rem; }}
.status {{ font-weight: 600; color: var(--{tone}); }}
.muted {{ color: var(--muted); }}
textarea {{ width: 100%; min-height: 320px; box-sizing: border-box; font: 13px/1.45 ui-monospace,
  monospace; background: transparent; color: var(--fg); border: 1px solid var(--line);
  border-radius: 6px; padding: 10px; }}
a.button, button {{ display: inline-block; margin: 8px 8px 0 0; padding: 7px 14px;
  border-radius: 6px; border: 1px solid var(--line); background: transparent; color: var(--fg);
  font: inherit; text-decoration: none; cursor: pointer; }}
</style></head><body>
<p class="status">{escape(status)}</p>
<h1>{escape(heading)}</h1>
<p><b>{escape(proposal.title)}</b></p>
<p class="muted">{escape(incident["rule"])} #{incident["id"]} · {escape(incident["summary"])} ·
{escape(text["priority"])}: {escape(proposal.priority)}</p>
<h2>{escape(text["reason"])}</h2><p>{escape(proposal.reason)}</p>
{diagnosis}
<h2>{escape(text["description"])}</h2>
<textarea id="ticket" readonly>{escape(ticket_text)}</textarea>
<button id="copy" type="button">{escape(text["copy"])}</button>
<a class="button" href="{escape(links_["approve"])}">{escape(text["approve"])}</a>
<a class="button" href="{escape(links_["reject"])}">{escape(text["reject"])}</a>
<script>
document.getElementById("copy").addEventListener("click", async (event) => {{
  await navigator.clipboard.writeText(document.getElementById("ticket").value);
  event.target.textContent = {json.dumps(text["copied"])};
}});
</script>
</body></html>"""
