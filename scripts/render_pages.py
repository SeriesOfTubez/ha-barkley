"""Render every Barkley panel page from real stored reports into static HTML, then (with
Playwright) screenshot them light/dark at desktop and phone width and measure what the
browser computes (text sizes, radii, borders, paddings, gaps). No Supervisor needed.

    uv run --with playwright python scripts/render_pages.py --reports DIR [DIR...] --out DIR

`--reports` folders hold `*.json` reports from `sniff-test scan --json`; the keys below
pick which ones stand in for the installed list (any that are missing are skipped).
`--no-shots` writes only the HTML. Playwright's cached headless Chromium is used; pass
`--chromium PATH` for another one. Nothing here touches the real store or the box."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sniff_test import diff as diffmod
from sniff_test import doctor, server, supervisor, ui
from sniff_test.report import ai_context
from sniff_test.store import Store

TOKEN = "t0k3n"  # noqa: S105  (a form token for static pages; nothing is served)
BASE = ""
CHROMIUM = str(
    Path(
        "~/Library/Caches/ms-playwright/chromium_headless_shell-1248/"
        "chrome-headless-shell-mac-arm64/chrome-headless-shell"
    ).expanduser()
)

# (report key, kind, shown name, installed version, available version, group, reasons, busy)
GRID = [
    ("greghesp_ha-bambulab", "integration", "Bambu Lab", None, "v2.4.1", "attention",
     ["Update: 1 new undeclared site (makerworld.com)"], ""),
    ("aradlein_hass-agent-llm", "integration", "hass-agent-llm", None, None, "current", [], ""),
    ("AlexxIT_WebRTC", "integration", "WebRTC Camera", "v3.6.1", None, "current", [], ""),
    ("custom-components_alexa_media_player", "integration", "Alexa Media Player", "5.0.0",
     "5.6.1", "unchecked", [], ""),
    ("hacs_integration", "integration", "HACS", "2.0.5", None, "current", [], ""),
    ("kalkih_mini-graph-card", "card", "Mini Graph Card", "v0.13.0", None, "current", [], ""),
    ("piitaya_lovelace-mushroom", "card", "Mushroom", None, None, "current", [], "running"),
    ("thomasloven_lovelace-card-mod", "card", "card-mod", "v4.2.1", None, "current", [], ""),
    (None, "integration", "Body Mi Scale", "2026.11.0", None, "current", [], ""),
    (None, "integration", "Tigo Energy", "1.4.2", None, "current", [], "queued"),
]  # fmt: skip
REPOS = {  # report key -> Marketplace repo for the items without a report
    "Body Mi Scale": "dckiller51/bodymiscale",
    "Tigo Energy": "Tigo-Energy/ha-tigo",
}
MEASURE_JS = """
() => {
  const fs = {}, radii = {}, borders = {}, pads = {}, gaps = {};
  const colors = new Set(), fonts = new Set();
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none') continue;
    const hasText = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (hasText) {
      const k = cs.fontSize; fs[k] = (fs[k] || 0) + 1;
      fonts.add(cs.fontFamily.split(',')[0]); colors.add(cs.color);
    }
    const r = cs.borderTopLeftRadius; if (r && r !== '0px') radii[r] = (radii[r] || 0) + 1;
    const bw = cs.borderTopWidth;
    if (bw && bw !== '0px' && cs.borderTopStyle !== 'none') {
      const k = bw + ' ' + cs.borderTopStyle; borders[k] = (borders[k] || 0) + 1; }
    for (const p of ['paddingTop', 'paddingLeft']) {
      const v = cs[p]; if (v !== '0px') pads[v] = (pads[v] || 0) + 1; }
    const g = cs.gap; if (g && g !== 'normal' && g !== '0px') gaps[g] = (gaps[g] || 0) + 1;
  }
  return {fontSizes: fs, radii, borders, pads, gaps, textColors: colors.size, fonts: [...fonts],
          height: document.documentElement.scrollHeight,
          hscroll: document.documentElement.scrollWidth > document.documentElement.clientWidth};
}
"""


def load(dirs: list[Path], store: Store) -> tuple[dict[str, dict], dict[str, int]]:
    reports: dict[str, dict] = {}
    ids: dict[str, int] = {}
    when = datetime.now(UTC) - timedelta(days=9)
    for d in dirs:
        for f in sorted(d.glob("*.json")):
            rep = json.loads(f.read_text())
            if "score" not in rep or "target" not in rep:
                continue
            reports[f.stem] = rep
            ids[f.stem] = store.save(rep, when)
            when += timedelta(hours=7)
    return reports, ids


def render(dirs: list[Path], out: Path) -> dict[str, bytes]:
    out.mkdir(parents=True, exist_ok=True)
    db = out / "render.db"
    for p in out.glob("render.db*"):
        p.unlink()
    store = Store(db)
    reports, ids = load(dirs, store)
    print("reports:", ", ".join(sorted(reports)))

    def row_for(key: str):
        return store.get(ids[key])

    rows: list[server.Row] = []
    cards: list[ui.Card] = []
    names: dict[str, str] = {}
    for key, kind, name, inst, avail, group, reasons, busy in GRID:
        if key and key not in reports:
            continue
        rep = reports.get(key) if key else None
        repo = (rep or {}).get("target", {}).get("repo") or REPOS.get(name, name)
        inst = inst or (rep or {}).get("target", {}).get("ref") or "main"
        it = supervisor.Installed(repo=repo, kind=kind, name=name, installed=inst,
                                  available=avail or inst, custom=False)  # fmt: skip
        scan = row_for(key) if key else None
        row = server.Row(it, group, scan, None, reasons, busy)
        rows.append(row)
        names[repo.lower()] = name
        cards.append(ui.Card(
            repo=repo, name=name, kind=kind, installed=inst,
            available=avail if it.update else None, scan=scan, report=rep, group=group,
            reasons=reasons, busy=busy, diff_link="",
            action=server._action(BASE, row, TOKEN, "view=cards"),
        ))  # fmt: skip

    jobs = [
        server.Job(1, "installed", "piitaya/lovelace-mushroom", "v5.2.3", state="running"),
        server.Job(2, "installed", "Tigo-Energy/ha-tigo", "1.4.2", state="queued"),
        server.Job(3, "auto", "kalkih/mini-graph-card", "v0.13.0", prev="v0.12.1",
                   state="done", message="done",
                   scan_ids=[ids["kalkih_mini-graph-card"]] * 2, finished=time.time() - 90),
    ]  # fmt: skip
    status = server.status_html(BASE, jobs, names, "view=cards")

    class FakeWatcher:
        enabled = True
        notify_target = "mobile_app_pixel_9"
        last_test = ""
        age_out_days = 7.0

        def targets(self, refresh=False):
            return (["mobile_app_pixel_9", "persistent_notification"], "")

        def diagnostics(self):
            return (True, "Auto-sniff on; watching the Marketplace (snapshot of 16 items, "
                    "4 min ago); notifications: bell + notify.mobile_app_pixel_9")  # fmt: skip

        def log(self):
            return [
                {"when": "2026-11-11T00:28:00", "repo": "henriquekraemer/intellikeep",
                 "version": "v2.1.1", "score": 92, "verdict": "good_boy",
                 "scan_ids": [ids["hacs_integration"]], "complete": True},
                {"when": "2026-11-11T00:07:00", "repo": "flixlix/power-flow-card-plus",
                 "version": "v0.6.1", "previous": "v0.6.0", "score": 100, "verdict": "good_boy",
                 "changes": "nothing important changed",
                 "scan_ids": [ids["thomasloven_lovelace-card-mod"]] * 2, "complete": True},
            ]  # fmt: skip

    auto = server.render_auto(BASE, FakeWatcher(), TOKEN)

    def installed_html(view: str) -> str:
        v = ui.View(view=view)
        st = server.InstalledState(items=[r.item for r in rows], other={"theme": 2},
                                   fetched=time.time() - 240)  # fmt: skip
        html = server.render_installed(BASE, st, rows, TOKEN, lambda i: store.report(i), v)
        extra = []
        for key in ("tests_fixtures_evil_card", "evil_integration_full",
                    "tests_fixtures_clean_integration_v2"):  # fmt: skip
            if key not in reports:
                continue
            r = row_for(key)
            nm = key.replace("tests_fixtures_", "").replace("_full", "").replace("_", " ")
            extra.append(ui.Card(repo=key, name=nm, kind=reports[key]["target"].get("kind",
                         "integration"), installed=r.ref or "main", available=None, scan=r,
                         report=reports[key]))  # fmt: skip
        return html + server.not_installed_cards_html(BASE, extra)

    out_pages: dict[str, bytes] = {}
    for view in ("cards", "table"):
        out_pages[f"index-{view}"] = server.render_index(
            BASE, store, jobs, TOKEN, installed_html(view), None, "", "2026.11.1", 2, True,
            status, f"view={view}", auto,
        )  # fmt: skip

    # Detail pages. The main one gets a believable AI summary and one deep reading so the
    # AI surfaces render; the user's own "Very Sus" find gets its real context items.
    detail_key = (
        "greghesp_ha-bambulab" if "greghesp_ha-bambulab" in reports else "evil_integration_full"
    )
    choices = [("ai_task.glm_5_3_flash", "GLM 5.3 Flash"), ("ai_task.glm_5_3", "GLM 5.3")]
    deep_item = None
    if detail_key in reports:
        rep, sid = reports[detail_key], ids[detail_key]
        fids = [f["id"] for f in rep.get("findings", [])]
        store.save_explanation(sid, "ai_task.glm_5_3_flash", {
            "summary": "This integration talks to the printer on your own network over MQTT "
            "and to Bambu's cloud for account features. The findings are about how it reads "
            "your Home Assistant access token to reach its own API, which is normal for a "
            "card-backed integration but worth knowing. Nothing here sends your data anywhere "
            "unexpected.",
            "findings": {fids[0]: "The code reads the access token so its dashboard card can "
                         "call the integration's own API on the same Home Assistant. That is "
                         "the usual way a card and integration talk; the token never leaves "
                         "your box in this code."} if fids else {},
            "readings": [], "dropped": 0,
        })  # fmt: skip
        for k in (rep.get("context") or {}).get("items") or {}:
            snip = ai_context.snippet_of(rep, k)
            if snip and snip.get("segments"):
                seg = snip["segments"][0]
                deep_item = k
                store.save_item_explanation(sid, k, "ai_task.glm_5_3_flash", {
                    "claims": [
                        {"text": "These lines build the request from a constant base address "
                         "and attach the saved token as a bearer header.",
                         "cites": [[seg["file"], seg["start"], seg["start"] + 2]]},
                        {"text": "The address is a relative path on the same Home Assistant, "
                         "so the token goes back to your own server, not to the internet.",
                         "cites": [[seg["file"], seg["start"], seg["start"]]]},
                    ],
                    "questions": [{"text": "Does any other code path reuse this header for a "
                                   "cloud address?", "cites": [[seg["file"], seg["start"],
                                   seg["start"]]]}],
                    "dropped": ["dismissal"], "entity_id": "ai_task.glm_5_3_flash",
                    "created": "2026-11-11T09:12:00",
                })  # fmt: skip
                break

    def detail(key: str, row=None, mode="deep", entity="ai_task.glm_5_3_flash") -> bytes:
        return server.render_scan(BASE, ids[key], reports[key], store, row=row, token=TOKEN,
                                  ai_entity=entity, ai_choices=choices, ai_mode=mode)  # fmt: skip

    main_row = next((r for r in rows if r.item.repo == "greghesp/ha-bambulab"), None)
    if detail_key in reports:
        out_pages["detail-main"] = detail(detail_key, main_row)
    for key, name, mode, entity in (
        ("aradlein_hass-agent-llm", "detail-verysus", "deep", "ai_task.glm_5_3_flash"),
        ("evil_integration_full", "detail-evil", "summary", ""),
        ("tests_fixtures_clean_integration", "detail-clean", "summary", ""),
        ("piitaya_lovelace-mushroom", "detail-mushroom", "summary", "ai_task.glm_5_3_flash"),
    ):
        if key in reports:
            out_pages[name] = detail(key, None, mode, entity)

    cat = [
        supervisor.CatalogItem("greghesp/ha-bambulab", "integration", "Bambu Lab",
                               "Home Assistant integration for Bambu Lab 3D printers (X1, P1, "
                               "A1 series) over local MQTT and the cloud.", 2140, 48213, True, ()),
        supervisor.CatalogItem("sjsadowski/bambu-ha-card", "card", "Bambu Lab Printer Card",
                               "A dashboard card showing printer status, bed temperature and "
                               "AMS trays.", 318, 9721, False, ()),
        supervisor.CatalogItem("piitaya/lovelace-mushroom", "card", "Mushroom",
                               "Build a beautiful dashboard easily.", 4821, 391004, True, ()),
    ]  # fmt: skip
    scans_by_repo = {}
    for key in ("greghesp_ha-bambulab", "piitaya_lovelace-mushroom"):
        if key in reports:
            scans_by_repo[reports[key]["target"]["repo"]] = row_for(key)
    out_pages["search"] = server.render_search(BASE, "bambu", "", cat, scans_by_repo,
                                               {"sjsadowski/bambu-ha-card": "queued"}, TOKEN,
                                               "", 3271)  # fmt: skip
    rels = [
        SimpleNamespace(tag="v2.4.1", prerelease=False, publisher="greghesp", bot=False,
                        published_at="2026-11-02T10:04:00Z"),
        SimpleNamespace(tag="v2.4.1-beta.2", prerelease=True, publisher="AdrianGarside",
                        bot=False, published_at="2026-10-28T19:40:00Z"),
        SimpleNamespace(tag="v2.4.0", prerelease=False, publisher="greghesp", bot=False,
                        published_at="2026-10-11T08:12:00Z"),
        SimpleNamespace(tag="v2.3.0", prerelease=False, publisher="greghesp", bot=False,
                        published_at="2026-09-20T17:33:00Z"),
        SimpleNamespace(tag="v2.2.25", prerelease=False, publisher="github-actions[bot]",
                        bot=True, published_at="2026-09-03T06:10:00Z"),
    ]  # fmt: skip
    vs = {"v2.4.0": row_for("greghesp_ha-bambulab")} if "greghesp_ha-bambulab" in reports else {}
    out_pages["versions"] = server.render_versions(BASE, "greghesp/ha-bambulab", "Bambu Lab",
                                                   rels, "v2.4.1", "v2.4.0", vs,
                                                   {"v2.4.1": "running"}, TOKEN)  # fmt: skip
    a, b = "tests_fixtures_clean_integration", "tests_fixtures_clean_integration_v2"
    if a in reports and b in reports:
        d = diffmod.diff(reports[a], reports[b])
        out_pages["diff"] = server.render_diff(BASE, ids[a], ids[b], d)
    out_pages["doctor"] = server.render_doctor(BASE, doctor.run_checks(addon=False))

    for name, body in out_pages.items():
        (out / f"{name}.html").write_bytes(body)
    (out / "meta.json").write_text(json.dumps({"deep_item": deep_item, "detail_key": detail_key}))
    print("pages:", ", ".join(sorted(out_pages)))
    return out_pages


def shoot(out: Path, chromium: str) -> None:
    from playwright.sync_api import sync_playwright

    meta = json.loads((out / "meta.json").read_text())
    pages = sorted(p.stem for p in out.glob("*.html"))
    results: dict[str, dict] = {}
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=chromium)
        for scheme in ("light", "dark"):
            for width, tag in ((1100, "desktop"), (390, "phone")):
                ctx = b.new_context(viewport={"width": width, "height": 900},
                                    color_scheme=scheme, device_scale_factor=1)  # fmt: skip
                page = ctx.new_page()
                for name in pages:
                    page.goto((out / f"{name}.html").as_uri())
                    page.wait_for_timeout(80)
                    page.screenshot(path=str(out / f"shot-{name}-{tag}-{scheme}.png"),
                                    full_page=True)  # fmt: skip
                    if scheme == "light":
                        m = page.evaluate(MEASURE_JS)
                        results.setdefault(name, {})[tag] = m
                if meta.get("deep_item") and tag == "desktop" and "detail-main" in pages:
                    page.goto((out / "detail-main.html").as_uri() + f"#ai-{meta['deep_item']}")
                    page.wait_for_timeout(300)
                    page.screenshot(path=str(out / f"shot-detail-sheet-{tag}-{scheme}.png"))
                ctx.close()
        b.close()
    (out / "measure.json").write_text(json.dumps(results, indent=1))
    agg: Counter[str] = Counter()
    for r in results.values():
        for k, v in r["desktop"]["fontSizes"].items():
            agg[k] += v
    print("text sizes on all pages (desktop):")
    for k, v in sorted(agg.items(), key=lambda kv: float(kv[0][:-2])):
        print(f"  {k:>8}  {v}")
    for name, r in results.items():
        d, ph = r["desktop"], r["phone"]
        print(f"\n{name}: {d['height']} px tall; sideways scroll desktop {d['hscroll']}, "
              f"phone {ph['hscroll']}; fonts {d['fonts']}")  # fmt: skip
        print("  radii:", dict(sorted(d["radii"].items(), key=lambda kv: float(kv[0][:-2]))))
        print("  borders:", d["borders"])
        print("  pads:", dict(sorted(d["pads"].items(), key=lambda kv: float(kv[0][:-2]))))
        print("  gaps:", d["gaps"])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--reports", nargs="+", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--chromium", default=CHROMIUM)
    ap.add_argument("--no-shots", action="store_true")
    a = ap.parse_args()
    render(a.reports, a.out)
    if not a.no_shots:
        shoot(a.out, a.chromium)


if __name__ == "__main__":
    main()
