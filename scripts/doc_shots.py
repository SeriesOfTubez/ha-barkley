"""Screenshots for the README and the wiki, made from Barkley's own made-up test apps
(tests/fixtures), never from a real project.

    uv run python scripts/doc_shots.py --reports DIR --answers docs/screenshots/ai-answers.json
    uv run --with playwright python scripts/doc_shots.py ... --shots --out docs/images

`--reports` holds `sniff-test scan tests/fixtures/<name> --json --offline` reports, one
file per fixture name. The AI text comes from `--answers`: real answers to Barkley's own
requests for those apps, written by the model named in that file (a stand-in for the
user's AI Task entity), and every answer goes through the same checks as on a real box
(report.ai.accept, ai_words.accept, ai_context.accept), so only what passes is shown.
Nothing here touches the real store, the box or the network (the fonts are served from
the package)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sniff_test import readings, server, settings, supervisor
from sniff_test.diff import diff as diff_reports
from sniff_test.report import ai as report_ai
from sniff_test.report import ai_context, ai_words
from sniff_test.store import Store

TOKEN = "t0k3n"  # noqa: S105  (a form token for static pages; nothing is served)
FONTS = Path(__file__).resolve().parent.parent / "src" / "sniff_test" / "assets" / "fonts"
# The test apps' folder names say what they test; on the pages they get plain example names.
NAMES = {
    "evil_integration": ("Example: token thief", "integration"),
    "evil_card": ("Example: card that leaks its token", "card"),
    "hidden_card": ("Example: card hiding its calls", "card"),
    "clean_integration": ("Example: weather station", "integration"),
    "oauth_redirects": ("Example: cloud sign-in", "integration"),
}
SIZE = 12000  # Settings → AI answers, the default


def build(reports_dir: Path, answers_file: Path, out: Path) -> dict[str, bytes]:
    out.mkdir(parents=True, exist_ok=True)
    for p in out.glob("doc-shots.db*"):
        p.unlink()
    store = Store(out / "doc-shots.db")
    answers = json.loads(answers_file.read_text())
    entity = answers["entity"]
    reports = {p.stem: json.loads(p.read_text()) for p in sorted(reports_dir.glob("*.json"))}
    for key, r in reports.items():  # the page shows this instead of the local test folder
        r.setdefault("target", {})["input"] = f"examples/{key.replace('_', '-')}"
    ids = {k: store.save(r) for k, r in reports.items()}

    # item readings first: an app explanation older than them offers "Ask again"
    order = sorted(answers["answers"].items(), key=lambda kv: not kv[0].endswith("--item"))
    for key, a in order:
        app, kind = key.split("--")
        rep, sid = reports[app], ids[app]
        if kind == "app":
            acc = report_ai.accept(rep, a["data"], {})
            words = answers["answers"].get(f"{app}--words")
            if words:
                acc["words"] = ai_words.accept(rep, words["data"], SIZE)
            store.save_explanation(sid, entity, acc)
        elif kind == "item":
            acc = ai_context.accept(rep, a["item"], a["data"])
            store.save_item_explanation(sid, a["item"], entity, acc)

    # the list: every test app as an installed one, the second weather version offered
    rows, names, by_key = [], {}, {}
    for key, (name, kind) in NAMES.items():
        repo = f"example/{key.replace('_', '-')}"
        offered = "v2.0.0" if key == "clean_integration" else "v1.0.0"
        it = supervisor.Installed(repo=repo, kind=kind, name=name, installed="v1.0.0",
                                  available=offered, custom=False)  # fmt: skip
        rd = readings.compute(reports[key])
        group = "attention" if rd.threat_level != "none" else (
            "unchecked" if it.update else "current")  # fmt: skip
        scan = store.get(ids[key])
        scan = replace(scan, readings=rd.to_dict()) if scan else None
        row = server.Row(it, group, scan, None, [])
        row.ai = key == "oauth_redirects"  # the one the status strip says the AI is answering
        rows.append(row)
        by_key[key] = row
        names[repo] = name
    st = server.InstalledState(items=[r.item for r in rows], other={"theme": 2},
                               fetched=time.time() - 120)  # fmt: skip

    def shown(sid: int) -> dict:  # the report as the panel shows it: with its readings
        rep = store.report(sid)
        return {**rep, "readings": readings.compute(rep).to_dict()}

    installed = server.render_installed("", st, rows, TOKEN, shown)
    now = time.time()
    status = server.status_html(
        "", [], names, "", now=now,
        ai=[server.AiRun(ids["oauth_redirects"], "", now - 48, "example/oauth-redirects")],
    )  # fmt: skip
    pages = {
        "list": server.render_index("", store, [], TOKEN, installed, None, "", "2026.11.1", 2,
                                    True, status, "view=cards", ai_busy=True),
        "settings": server.render_settings("", settings.Settings(), TOKEN, ai_entity=entity,
                                           ai_choices=[(entity, "Claude Sonnet")]),
    }  # fmt: skip
    for key in ("evil_integration", "oauth_redirects", "evil_card"):
        pages[f"app-{key}"] = server.render_scan(
            "", ids[key], store.report(ids[key]), store, by_key[key], TOKEN, ai_entity=entity,
            ai_choices=[(entity, "Claude Sonnet")], ai_mode="deep",
        )  # fmt: skip
    old, new = reports["clean_integration"], reports["clean_integration_v2"]
    pages["update"] = server.render_diff(
        "", ids["clean_integration"], ids["clean_integration_v2"], diff_reports(old, new),
        name=NAMES["clean_integration"][0],
        readings_of=(readings.compute(old).to_dict(), readings.compute(new).to_dict()),
    )  # fmt: skip
    for name, body in pages.items():
        (out / f"{name}.html").write_bytes(body)
    (out / "items.json").write_text(
        json.dumps({k: a.get("item", "") for k, a in answers["answers"].items() if a.get("item")})
    )
    return pages


# (file stem, page, width, what): what is "page" (the first screen), "full", "sheet" (the
# item's AI reading open), or the heading of the one section to capture
SHOTS = (
    ("list", "list", 1100, "full"),
    ("list-phone", "list", 390, "page"),
    ("app", "app-evil_integration", 1100, "page"),
    ("ai-reading", "app-evil_integration", 1100, "sheet"),
    ("picture", "app-evil_integration", 1100, "What it touches"),
    ("developer-says", "app-oauth_redirects", 1100, "In short"),
    ("update", "update", 1100, "main"),
    ("settings-ai", "settings", 1100, "AI answers"),
)


def shoot(out: Path, chromium: str | None) -> list[Path]:
    """Two pictures per SHOTS line (light and dark), at twice the pixels for sharp text."""
    from playwright.sync_api import sync_playwright

    items = json.loads((out / "items.json").read_text())
    made: list[Path] = []
    with sync_playwright() as p:
        b = p.chromium.launch(**({"executable_path": chromium} if chromium else {}))
        for scheme in ("light", "dark"):
            for stem, page_name, width, what in SHOTS:
                ctx = b.new_context(viewport={"width": width, "height": 900},
                                    color_scheme=scheme, device_scale_factor=2)  # fmt: skip
                ctx.route("**/fonts/*", lambda r: r.fulfill(
                    path=str(FONTS / r.request.url.rsplit("/", 1)[-1])))  # fmt: skip
                page = ctx.new_page()
                url = (out / f"{page_name}.html").as_uri()
                if what == "sheet":
                    url += f"#ai-{items['evil_integration--item']}"
                page.goto(url)
                page.wait_for_timeout(400)
                dest = out / f"{stem}-{scheme}.png"
                if what == "main":  # the page's content, without the empty screen below it
                    page.locator("main").screenshot(path=str(dest), animations="disabled")
                elif what in ("page", "sheet", "full"):
                    page.screenshot(path=str(dest), full_page=what == "full",
                                    animations="disabled")  # fmt: skip
                elif stem == "settings-ai":  # the two AI answers rows together
                    rows = page.locator(".setrow", has_text=what)
                    top = rows.first.bounding_box()
                    last = page.locator(".setrow", has_text="AI time limit").first.bounding_box()
                    tall = last["y"] + last["height"] - top["y"] + 16
                    clip = {"x": 0, "y": top["y"] - 8, "width": width, "height": tall}
                    page.screenshot(path=str(dest), full_page=True, animations="disabled",
                                    clip=clip)  # fmt: skip
                else:
                    head = page.locator("section.box h2", has_text=what).first
                    head.locator("xpath=ancestor::section[1]").screenshot(
                        path=str(dest), animations="disabled")  # fmt: skip
                made.append(dest)
                ctx.close()
        b.close()
    return made


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", type=Path, required=True)
    ap.add_argument("--answers", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--shots", action="store_true")
    ap.add_argument("--chromium", default=None)
    a = ap.parse_args()
    print("pages:", ", ".join(build(a.reports, a.answers, a.out)))
    if a.shots:
        for f in shoot(a.out, a.chromium):
            print(f.name)


if __name__ == "__main__":
    main()
