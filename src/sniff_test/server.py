"""`sniff-test serve`: the add-on's ingress panel. Stdlib only, one scan at a time.

Behind HA ingress, HA does the login and the Supervisor (172.30.32.2) is the only
client the panel ever sees, so every other address is refused. Forms carry a
per-process token so another page can't make the panel start scans.

Everything shown from a report (repo names, refs, file names, evidence, hosts) came
from scanned repos and is escaped. The JSON view is served as `application/json`
with `nosniff`, and the CSP allows no scripts at all.
"""

from __future__ import annotations

import html
import json
import os
import queue
import re
import secrets
import threading
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from sniff_test import __version__
from sniff_test.diff import HEADLINE_MAX, HEADLINE_RANK
from sniff_test.diff import diff as diff_reports
from sniff_test.report.json_report import sanitize_untrusted
from sniff_test.scoring import VERDICTS
from sniff_test.store import Store, StoreError

SUPERVISOR_IP = "172.30.32.2"
_INGRESS_PATH = re.compile(r"^/api/hassio_ingress/[A-Za-z0-9_-]+$")
_REPO = re.compile(r"^(?:https://github\.com/)?([A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100})/?$")
_REF = re.compile(r"^[A-Za-z0-9_.+/-]{1,100}$")
_EMOJI = {v.key: v.emoji for _, v in VERDICTS}
_SEV_CLASS = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "low"}
_JOBS_KEPT = 20
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'self'"
)


def e(text: Any, limit: int = 300) -> str:
    """Escape for HTML text and attribute values (untrusted text is also truncated)."""
    return html.escape(sanitize_untrusted(str(text), limit) if text is not None else "")


# --- jobs ------------------------------------------------------------------------------


@dataclass
class Job:
    id: int
    kind: str  # scan | update
    repo: str
    ref: str | None
    state: str = "queued"  # queued | running | done | failed
    message: str = ""
    scan_ids: list[int] = field(default_factory=list)
    created: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))


ScanFn = Callable[[str, str | None], dict[str, Any]]


class Worker:
    """Runs scans one at a time (Semgrep is the memory hog; never run two at once)."""

    def __init__(self, store: Store, scan_fn: ScanFn, tool_version: str = __version__):
        self.store = store
        self.scan_fn = scan_fn
        self.tool_version = tool_version
        self.jobs: list[Job] = []
        self._q: queue.Queue[Job] = queue.Queue()
        self._lock = threading.Lock()
        self._next = 1
        self._thread = threading.Thread(target=self._run, name="sniff-worker", daemon=True)
        self._thread.start()

    def submit(self, kind: str, repo: str, ref: str | None) -> Job:
        with self._lock:
            job = Job(self._next, kind, repo, ref)
            self._next += 1
            self.jobs.insert(0, job)
            del self.jobs[_JOBS_KEPT:]
        self._q.put(job)
        return job

    def wait(self) -> None:
        """Block until the queue is empty (tests)."""
        self._q.join()

    def _stored_or_scan(self, repo: str, ref: str | None, exposure: str, ha: str | None) -> int:
        if ref:
            hit = self.store.find(
                repo, ref, exposure=exposure, tool_version=self.tool_version, ha_version=ha
            )
            if hit:
                return hit.id
        return self.store.save(self.scan_fn(repo, ref))

    def _run(self) -> None:
        while True:
            job = self._q.get()
            job.state = "running"
            try:
                if job.kind == "scan":
                    job.scan_ids = [self.store.save(self.scan_fn(job.repo, job.ref))]
                    job.message = "scanned"
                else:  # update: stored scan of the installed ref vs what HACS installs now
                    new = self.store.save(self.scan_fn(job.repo, None))
                    row = self.store.get(new)
                    assert row is not None  # noqa: S101 - just saved
                    old = self._stored_or_scan(job.repo, job.ref, row.exposure, row.ha_version)
                    job.scan_ids = [old, new]
                    job.message = f"{job.ref} → {row.ref}"
                job.state = "done"
            except Exception as ex:
                job.state = "failed"
                job.message = f"{type(ex).__name__}: {ex}"
            finally:
                self._q.task_done()


# --- HTML ------------------------------------------------------------------------------

_STYLE = """
:root { --bg:#fff; --fg:#1c1c1c; --muted:#666; --line:#e3e3e3; --card:#f7f7f7;
  --crit:#b3261e; --high:#c4540a; --med:#9a6b00; --low:#4b6b88; --ok:#2e7d32; }
@media (prefers-color-scheme: dark) { :root { --bg:#111; --fg:#e8e8e8; --muted:#9a9a9a;
  --line:#2a2a2a; --card:#1a1a1a; --crit:#ff7b72; --high:#ffa657; --med:#e3b341;
  --low:#8bb4d9; --ok:#7ee787; } }
body { background:var(--bg); color:var(--fg); font:15px/1.45 system-ui,sans-serif;
  margin:0 auto; max-width:960px; padding:16px; }
a { color:inherit; } h1 { font-size:1.4em; } h2 { font-size:1.1em; margin-top:1.6em; }
table { border-collapse:collapse; width:100%; } td, th { text-align:left; padding:6px 8px;
  border-bottom:1px solid var(--line); vertical-align:top; overflow-wrap:anywhere; }
.muted { color:var(--muted); } .card { background:var(--card); padding:12px; border-radius:8px; }
.crit { color:var(--crit); font-weight:600; } .high { color:var(--high); font-weight:600; }
.med { color:var(--med); } .low { color:var(--low); } .ok { color:var(--ok); }
form { display:flex; gap:8px; flex-wrap:wrap; margin:8px 0; }
input { padding:6px; min-width:0; flex:1 1 180px; } button { padding:6px 12px; }
code { overflow-wrap:anywhere; }
"""


def _page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{e(title)}</title><style>{_STYLE}</style></head><body>"
        f"{body}</body></html>"
    ).encode()


def _verdict(score: int, key: str) -> str:
    cls = {"good_boy": "ok", "kinda_sus": "med", "very_sus": "high", "bork": "crit"}.get(key, "")
    return f'<span class="{cls}">{score} {_EMOJI.get(key, "")}</span>'


def render_index(base: str, store: Store, jobs: list[Job], token: str) -> bytes:
    rows = store.history(limit=100)
    out = [
        "<h1>🐕 Sniff Test</h1>",
        '<p class="muted">Scans run one at a time. Scores never come from an AI.</p>',
        f'<div class="card"><form method=post action="{base}/scan">'
        f'<input type=hidden name=token value="{token}">'
        '<input name=repo placeholder="owner/repo" required>'
        '<input name=ref placeholder="tag (default: what HACS installs)">'
        "<button>Sniff it</button></form>"
        f'<form method=post action="{base}/update">'
        f'<input type=hidden name=token value="{token}">'
        '<input name=repo placeholder="owner/repo" required>'
        '<input name=ref placeholder="installed tag" required>'
        "<button>What would updating change?</button></form></div>",
    ]
    if jobs:
        out.append("<h2>Jobs</h2><table>")
        for j in jobs:
            links = " ".join(f'<a href="{base}/scan/{i}">@{i}</a>' for i in j.scan_ids)
            if j.kind == "update" and len(j.scan_ids) == 2:
                old, new = j.scan_ids
                links += f' · <a href="{base}/diff?old={old}&amp;new={new}">diff</a>'
            out.append(
                f"<tr><td>{e(j.kind)}</td><td>{e(j.repo)}{'@' + e(j.ref) if j.ref else ''}"
                f"</td><td>{e(j.state)}</td><td>{e(j.message)} {links}</td></tr>"
            )
        out.append("</table>")
    out.append("<h2>Stored scans</h2>")
    if not rows:
        out.append('<p class="muted">No scans yet.</p>')
    else:
        out.append("<table><tr><th>#</th><th>score</th><th>repo</th><th>when</th></tr>")
        for r in rows:
            extra = r.kind + (f" · HA {r.ha_version}" if r.ha_version else "")
            if not r.complete:
                extra += " · incomplete"
            out.append(
                f'<tr><td><a href="{base}/scan/{r.id}">@{r.id}</a></td>'
                f"<td>{_verdict(r.score, r.verdict)}</td>"
                f"<td>{e(r.repo or r.source, 100)}@{e(r.ref or '?', 60)}"
                f'<br><span class="muted">{e(extra)}</span></td>'
                f"<td>{e(r.scanned_at[:16].replace('T', ' '))}</td></tr>"
            )
        out.append("</table>")
    return _page("Sniff Test", "".join(out))


def render_scan(base: str, sid: int, report: dict[str, Any], store: Store) -> bytes:
    t = report["target"]
    name = f"{t.get('repo') or t.get('input')}@{t.get('ref') or '?'}"
    findings = report.get("findings", [])
    out = [
        f'<p><a href="{base}/">← all scans</a></p>',
        f"<h1>@{sid} {e(name, 160)}</h1>",
        f'<p class="card">{_verdict(report["score"], report["verdict"]["key"])} '
        f"{e(report['verdict']['label'])}"
        f"{'' if report.get('complete') else ' · <b>incomplete scan</b> (capped at 89)'}"
        f'<br><span class="muted">{e(t.get("kind"))} · {e(t.get("install_source"))} · '
        f"commit {e((t.get('commit_sha') or '')[:12])}"
        f"{' · HA ' + e(report['ha_version']) if report.get('ha_version') else ''}</span></p>",
    ]
    older = [r for r in store.history(t.get("repo")) if r.id != sid] if t.get("repo") else []
    if older:
        out.append("<p>Compare with: ")
        out.append(
            " ".join(
                f'<a href="{base}/diff?old={r.id}&amp;new={sid}">@{r.id} {e(r.ref or "?", 40)}</a>'
                for r in older[:8]
            )
        )
        out.append("</p>")
    out.append(f"<h2>Findings ({len(findings)})</h2>")
    if findings:
        out.append("<table>")
        for f in findings:
            loc = f.get("file") or ""
            if loc and f.get("line"):
                loc += f":{f['line']}"
            out.append(
                f'<tr><td class="{_SEV_CLASS.get(f["severity"], "")}">{e(f["severity"])}</td>'
                f"<td><b>{e(f['title'])}</b> <span class=muted>{e(f['rule_id'])}</span>"
                f"<br>{e(f.get('message'), 600)}"
                f"{'<br><code>' + e(loc, 200) + '</code>' if loc else ''}"
                f"{'<br><code>' + e(ev, 200) + '</code>' if (ev := f.get('evidence')) else ''}"
                "</td></tr>"
            )
        out.append("</table>")
    else:
        out.append('<p class="ok">Nothing smelled off. 🦴</p>')
    out.append(f'<p><a href="{base}/scan/{sid}.json">raw JSON report</a></p>')
    return _page(f"Sniff Test @{sid}", "".join(out))


def render_diff(base: str, old: int, new: int, d: dict[str, Any]) -> bytes:
    frm, to = d["from"], d["to"]
    changes = d.get("changes", [])
    head = [c for c in changes if c["rank"] >= HEADLINE_RANK][:HEADLINE_MAX]
    rest = [c for c in changes if c not in head]
    out = [
        f'<p><a href="{base}/">← all scans</a></p>',
        f"<h1>What changes: {e(frm.get('repo'), 100)}</h1>",
        f'<p class="card"><a href="{base}/scan/{old}">@{old}</a> {e(frm.get("ref"), 60)} → '
        f'<a href="{base}/scan/{new}">@{new}</a> {e(to.get("ref"), 60)}<br>'
        f'<span class="muted">score {e(d["score"].get("from"))} → {e(d["score"].get("to"))} '
        "(each side's own score; the diff never scores)</span></p>",
    ]
    for w in d.get("warnings", []):
        out.append(f'<p class="med">⚠ {e(w, 400)}</p>')
    if not head:
        out.append("<p>Nothing important changed. 🦴</p>")
    else:
        out.append("<table>")
        for c in head:
            cls = _SEV_CLASS.get(c.get("severity") or "", "")
            out.append(
                f'<tr><td class="{cls}">{e(c["sign"])}</td><td>{e(c["text"], 400)}</td></tr>'
            )
        out.append("</table>")
    if rest:
        out.append(f"<h2>Also changed ({len(rest)})</h2><table>")
        for c in rest:
            out.append(
                f"<tr><td class=muted>{e(c['sign'])}</td><td class=muted>{e(c['text'], 300)}"
                "</td></tr>"
            )
        out.append("</table>")
    return _page("Sniff Test diff", "".join(out))


# --- HTTP ------------------------------------------------------------------------------


class Panel:
    def __init__(self, store: Store, worker: Worker, allow: set[str]):
        self.store = store
        self.worker = worker
        self.allow = allow
        self.token = secrets.token_urlsafe(24)

    def handler(self) -> type[BaseHTTPRequestHandler]:
        panel = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "sniff-test"
            sys_version = ""

            def log_message(self, fmt: str, *args: Any) -> None:  # quiet, no request lines
                pass

            def _base(self) -> str:
                path = self.headers.get("X-Ingress-Path", "")
                return path if _INGRESS_PATH.match(path) else ""

            def _send(self, status: int, body: bytes, ctype: str = "text/html") -> None:
                self.send_response(status)
                self.send_header("Content-Type", f"{ctype}; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Security-Policy", _CSP)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _text(self, status: int, msg: str) -> None:
                self._send(status, _page("Sniff Test", f"<p>🐕 {e(msg)}</p>"))

            def _redirect(self, to: str) -> None:
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", to or "/")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _allowed(self) -> bool:
                if self.client_address[0] in panel.allow:
                    return True
                self._text(HTTPStatus.FORBIDDEN, "only reachable through Home Assistant")
                return False

            def do_GET(self) -> None:
                if not self._allowed():
                    return
                url = urllib.parse.urlsplit(self.path)
                base = self._base()
                try:
                    if url.path in ("", "/"):
                        jobs = list(panel.worker.jobs)
                        return self._send(200, render_index(base, panel.store, jobs, panel.token))
                    if m := re.fullmatch(r"/scan/(\d+)(\.json)?", url.path):
                        sid = int(m[1])
                        report = panel.store.report(sid)
                        if m[2]:
                            body = json.dumps(report, indent=2).encode()
                            return self._send(200, body, "application/json")
                        return self._send(200, render_scan(base, sid, report, panel.store))
                    if url.path == "/diff":
                        q = urllib.parse.parse_qs(url.query)
                        old, new = int(q["old"][0]), int(q["new"][0])
                        d = diff_reports(panel.store.report(old), panel.store.report(new))
                        return self._send(200, render_diff(base, old, new, d))
                except StoreError as ex:
                    return self._text(HTTPStatus.NOT_FOUND, str(ex))
                except (KeyError, ValueError):
                    return self._text(HTTPStatus.BAD_REQUEST, "bad request")
                self._text(HTTPStatus.NOT_FOUND, "nothing to sniff here")

            def do_POST(self) -> None:
                if not self._allowed():
                    return
                size = int(self.headers.get("Content-Length") or 0)
                if size > 4096:
                    return self._text(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too large")
                form = urllib.parse.parse_qs(self.rfile.read(size).decode("utf-8", "replace"))
                get = lambda k: (form.get(k) or [""])[0].strip()  # noqa: E731
                if not secrets.compare_digest(get("token"), panel.token):
                    return self._text(HTTPStatus.FORBIDDEN, "stale form; reload the page")
                path = urllib.parse.urlsplit(self.path).path
                if path not in ("/scan", "/update"):
                    return self._text(HTTPStatus.NOT_FOUND, "nothing to sniff here")
                m = _REPO.match(get("repo"))
                ref = get("ref") or None
                if not m or (ref and not _REF.match(ref)) or (path == "/update" and not ref):
                    return self._text(HTTPStatus.BAD_REQUEST, "want owner/repo and a tag")
                panel.worker.submit(path.lstrip("/"), m[1], ref)
                self._redirect(f"{self._base()}/")

        return Handler


def supervisor_ha_version(token: str | None = None) -> str | None:
    """The installed HA version, via the Supervisor's Core API proxy (add-on only)."""
    token = token or os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        return None
    req = urllib.request.Request("http://supervisor/core/api/config")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 - fixed URL
            version = json.load(r).get("version")
    except (OSError, ValueError):
        return None
    return version if isinstance(version, str) else None


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    panel: Panel


def serve(store: Store, scan_fn: ScanFn, host: str, port: int, allow: set[str]) -> PanelServer:
    """Build the server (caller runs `serve_forever`); `.panel.worker` runs the scans."""
    panel = Panel(store, Worker(store, scan_fn), allow)
    httpd = PanelServer((host, port), panel.handler())
    httpd.panel = panel
    return httpd
