"""`sniff-test diff`: what an update changes, from two JSON reports. Never scores.

Signal first: every change gets a rank, and the human view shows the few that matter
(new findings, new data flows, evidence upgrades, new publishers, new unexplained
hosts) before a one-line count of everything else.

Matching is built for real version pairs, where most bytes move without meaning:
- Graph edges are keyed by (source, relation, target) with the scanned item's own node
  replaced by `@subject`, so a renamed domain doesn't make every edge "new".
- Findings are matched on rule + file + evidence with line numbers dropped and version
  strings and build hashes blanked (HACS's frontend chunks are renamed on every build:
  `2831.f1b6e847444f5d27.js`). Leftovers pair on rule + file + leading token (the
  package name for dependency findings), then rule + file. A pair whose severity moved
  is a severity change, not a new finding.
- Findings linked to a new graph edge (a secrets read, a possible flow) are folded into
  that edge's line instead of being listed twice.
- Publishers come from `provenance`: someone who published the new release but none of
  the releases up to the old one.

Labels, file names and hosts in the output come from the scanned repos (untrusted).
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

DIFF_VERSION = 1
SUBJECT = "@subject"
_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_EVIDENCE = {"declared": 1, "possible": 2, "proven": 3, "observed": 4}
_NEW_FINDING_RANK = {4: 100, 3: 90, 2: 60, 1: 20, 0: 5}
_RESOLVED_RANK = {4: 70, 3: 60, 2: 30, 1: 10, 0: 2}
_HOST_RANK = {
    "exfil_service": 90,
    "public_ip": 90,
    "undeclared": 70,
    "developer_hosted": 70,
    "messaging": 60,
}
_UNEXPLAINED = set(_HOST_RANK)
# Tie-break between equal ranks: the line that explains the others first.
_GROUP_ORDER = {"flows": 0, "repo": 1, "findings": 2, "data": 3, "hosts": 4, "coverage": 5}
_REPO_RELATIONS = {"published_by", "formerly_at"}  # handled from provenance
_INBOUND_KINDS = {"http_view", "webhook", "http_static", "ws_command", "inbound"}
HEADLINE_RANK = 40
HEADLINE_MAX = 12
_VERSION = re.compile(r"v?\d+(?:\.\d+){1,3}(?:[-+.][0-9A-Za-z.]+)?")
_HASH = re.compile(r"[0-9a-f]{8,}")
_NUM = re.compile(r"(?<![A-Za-z])\d+(?![A-Za-z])")
_LEAD = re.compile(r"[A-Za-z0-9@][\w.@/-]*")


@dataclass
class Change:
    kind: str
    rank: int
    group: str  # summary bucket: findings, flows, data, hosts, packages, hooks, repo, coverage
    text: str  # plain, built from report fields (may contain untrusted labels)
    sign: str = "+"  # + added, - removed, ~ changed
    severity: str | None = None
    finding_ids: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = {
            "kind": self.kind,
            "rank": self.rank,
            "group": self.group,
            "sign": self.sign,
            "text": self.text,
            "severity": self.severity,
            "finding_ids": self.finding_ids,
        }
        if self.detail:
            out["detail"] = self.detail
        return out


# --- findings --------------------------------------------------------------------------


def _norm_file(path: str | None) -> str:
    return _NUM.sub("<n>", _HASH.sub("<h>", path or ""))


def _norm_evidence(text: str | None) -> str:
    text = " ".join((text or "").split())
    return _NUM.sub("<n>", _HASH.sub("<h>", _VERSION.sub("<v>", text)))


def _lead(text: str | None) -> str:
    m = _LEAD.match((text or "").strip())
    return _VERSION.sub("", m[0]).rstrip("@=") if m else ""


def match_findings(
    old: list[dict[str, Any]], new: list[dict[str, Any]]
) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """(pairs, added, removed), pairing the most specific keys first."""
    keys = (
        lambda f: (f["rule_id"], _norm_file(f["file"]), _norm_evidence(f["evidence"])),
        lambda f: (f["rule_id"], _norm_file(f["file"]), _lead(f["evidence"])),
        lambda f: (f["rule_id"], _norm_file(f["file"])),
    )
    left, right = list(old), list(new)
    pairs: list[tuple[dict, dict]] = []
    for key in keys:
        pool: dict[Any, list[dict]] = defaultdict(list)
        for f in left:
            pool[key(f)].append(f)
        rest = []
        for f in right:
            if pool.get(key(f)):
                pairs.append((pool[key(f)].pop(0), f))
            else:
                rest.append(f)
        right = rest
        left = [f for fs in pool.values() for f in fs]
    return pairs, right, left


def _where(f: dict[str, Any]) -> str:
    return f" ({f['file']})" if f.get("file") else ""


def _finding_changes(old: dict, new: dict) -> tuple[list[Change], dict[str, dict]]:
    pairs, added, removed = match_findings(old["findings"], new["findings"])
    out = []
    for f in added:
        sev = _SEV[f["severity"]]
        out.append(
            Change(
                "new_finding",
                _NEW_FINDING_RANK[sev],
                "findings",
                f"{f['title']}{_where(f)}",
                severity=f["severity"],
                finding_ids=[f["id"]],
                detail={"rule_id": f["rule_id"], "evidence": f["evidence"]},
            )
        )
    for f in removed:
        out.append(
            Change(
                "resolved_finding",
                _RESOLVED_RANK[_SEV[f["severity"]]],
                "findings",
                f"{f['title']}{_where(f)}",
                sign="-",
                severity=f["severity"],
                finding_ids=[f["id"]],
                detail={"rule_id": f["rule_id"]},
            )
        )
    for a, b in pairs:
        sa, sb = _SEV[a["severity"]], _SEV[b["severity"]]
        if sa == sb:
            continue
        up = sb > sa
        out.append(
            Change(
                "severity_up" if up else "severity_down",
                (80 if sb >= 3 else 50) if up else 25,
                "findings",
                f"{b['title']}{_where(b)}: {a['severity']} → {b['severity']}",
                sign="~",
                severity=b["severity"],
                finding_ids=[b["id"]],
                detail={"rule_id": b["rule_id"], "from": a["severity"]},
            )
        )
    new_by_id = {f["id"]: f for f in added}
    return out, new_by_id


# --- graph -----------------------------------------------------------------------------


@dataclass
class _Graph:
    nodes: dict[str, dict[str, Any]]
    edges: dict[tuple[str, str, str], dict[str, Any]]


def _graph(report: dict[str, Any]) -> _Graph:
    g = report.get("graph") or {"nodes": [], "edges": [], "subject": ""}
    subject = g.get("subject", "")
    nodes = {n["id"]: n for n in g["nodes"]}
    if subject in nodes:
        nodes[SUBJECT] = nodes[subject]

    def norm(nid: str) -> str:
        return SUBJECT if nid == subject else nid

    edges = {}
    for e in g["edges"]:
        if e["relation"] in _REPO_RELATIONS:
            continue
        edges[(norm(e["source"]), e["relation"], norm(e["target"]))] = e
    return _Graph(nodes, edges)


def _label(g: _Graph, nid: str) -> str:
    n = g.nodes.get(nid)
    return n["label"] if n else nid.split(":", 1)[-1]


def _kind(g: _Graph, nid: str) -> str:
    n = g.nodes.get(nid)
    return n["kind"] if n else nid.split(":", 1)[0]


def _sample(e: dict[str, Any]) -> str:
    s = (e.get("samples") or [None])[0]
    if not s:
        return ""
    return f" ({s['file']}{':' + str(s['line']) if s.get('line') else ''})"


def _findings_note(ids: list[str], new_findings: dict[str, dict]) -> tuple[str, int, str | None]:
    """Text, rank and severity of the new findings an edge carries."""
    fs = [new_findings[i] for i in ids if i in new_findings]
    if not fs:
        return "", 0, None
    top = max(fs, key=lambda f: _SEV[f["severity"]])
    rules = ", ".join(sorted({f["rule_id"] for f in fs}))
    return (
        f" · {rules}",
        _NEW_FINDING_RANK[_SEV[top["severity"]]],
        top["severity"],
    )


def _edge_changes(
    old: _Graph, new: _Graph, new_findings: dict[str, dict], unresolved: set[str]
) -> tuple[list[Change], set[str]]:
    """`unresolved`: package names the old scan couldn't resolve (dep-unresolvable)."""
    out: list[Change] = []
    absorbed: set[str] = set()
    added = [k for k in new.edges if k not in old.edges]
    removed = [k for k in old.edges if k not in new.edges]

    # New flows, grouped by (source, evidence) so one new read toward 13 hosts is one line.
    flows: dict[tuple[str, str], list[tuple[str, str, str]]] = defaultdict(list)
    for k in added:
        if k[1] == "flows_to":
            flows[(k[0], new.edges[k]["evidence"])].append(k)
    for (src, ev), ks in flows.items():
        targets = sorted(_label(new, k[2]) for k in ks)
        ids = sorted({i for k in ks for i in new.edges[k]["finding_ids"]})
        note, frank, fsev = _findings_note(ids, new_findings)
        absorbed.update(ids)
        shown = ", ".join(targets[:3]) + (
            f" and {len(targets) - 3} more" if len(targets) > 3 else ""
        )
        out.append(
            Change(
                "new_flow",
                max(100 if ev == "proven" else 85, frank),
                "flows",
                f"{ev}: {_label(new, src)} → {shown}{note}",
                severity=fsev,
                finding_ids=ids,
                detail={"source": src, "targets": [k[2] for k in ks], "evidence": ev},
            )
        )

    hosts: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for k in added:
        e = new.edges[k]
        src, rel, tgt = k
        kind = _kind(new, tgt)
        if rel == "flows_to":
            continue
        if rel == "connects_to":
            hosts[str(e["attrs"].get("class", "undeclared"))].append(k)
            absorbed.update(e["finding_ids"])
            continue
        note, frank, fsev = _findings_note(e["finding_ids"], new_findings)
        absorbed.update(e["finding_ids"])
        if rel == "reads" and kind in ("data", "auth"):
            out.append(
                Change(
                    "new_read",
                    max(75, frank),
                    "data",
                    f"{_label(new, tgt)}{_sample(e)}{note}",
                    severity=fsev,
                    finding_ids=e["finding_ids"],
                    detail={"target": tgt, "evidence": e["evidence"]},
                )
            )
        elif rel in ("depends_on", "bundles") and kind == "package":
            a = e["attrs"]
            rank = 5 if a.get("ha_provided") else 45 if a.get("direct", True) else 25
            ver = a.get("version") or a.get("spec") or a.get("requirement") or ""
            text = f"{rel.replace('_', ' ')} {_label(new, tgt)} {ver}".rstrip()
            if _label(new, tgt).split("/", 1)[-1] in unresolved:
                # Declared before too; the old version just couldn't be installed.
                rank, text = 10, f"{_label(new, tgt)} {ver} now resolves (it didn't before)"
            out.append(
                Change(
                    "new_package",
                    max(rank, frank),
                    "packages",
                    text + note,
                    severity=fsev,
                    finding_ids=e["finding_ids"],
                    detail={"target": tgt, "attrs": a},
                )
            )
        elif rel == "exposes" or (rel == "registers" and kind in _INBOUND_KINDS):
            out.append(
                Change(
                    "new_inbound",
                    max(55 if rel == "exposes" else 35, frank),
                    "hooks",
                    f"{rel} {kind.replace('_', ' ')} {_label(new, tgt)}{_sample(e)}{note}",
                    severity=fsev,
                    finding_ids=e["finding_ids"],
                    detail={"target": tgt},
                )
            )
        else:
            out.append(
                Change(
                    "new_hook",
                    max(15, frank),
                    "hooks",
                    f"{rel.replace('_', ' ')} {kind.replace('_', ' ')} {_label(new, tgt)}{note}",
                    severity=fsev,
                    finding_ids=e["finding_ids"],
                    detail={"target": tgt, "relation": rel},
                )
            )

    out = _group_packages(out)

    for cls, ks in sorted(hosts.items()):
        rank = _HOST_RANK.get(cls, 10)
        ids = sorted({i for k in ks for i in new.edges[k]["finding_ids"]})
        note, frank, fsev = _findings_note(ids, new_findings)
        if len(ks) <= 3 or (rank >= HEADLINE_RANK and len(ks) <= 5):
            for k in sorted(ks):
                e = new.edges[k]
                n2, r2, s2 = _findings_note(e["finding_ids"], new_findings)
                out.append(
                    Change(
                        "new_host",
                        max(rank, r2),
                        "hosts",
                        f"{cls.replace('_', ' ')}: {_label(new, k[2])}{_sample(e)}{n2}",
                        severity=s2,
                        finding_ids=e["finding_ids"],
                        detail={"target": k[2], "class": cls},
                    )
                )
        else:
            labels = sorted(_label(new, k[2]) for k in ks)
            out.append(
                Change(
                    "new_host",
                    max(rank, frank),
                    "hosts",
                    f"{len(ks)} {cls.replace('_', ' ')}: {', '.join(labels[:4])}, …{note}",
                    severity=fsev,
                    finding_ids=ids,
                    detail={"targets": [k[2] for k in ks], "class": cls},
                )
            )

    for k in removed:
        e = old.edges[k]
        rel, tgt = k[1], k[2]
        kind = _kind(old, tgt)
        group = {
            "flows_to": "flows",
            "connects_to": "hosts",
            "depends_on": "packages",
            "bundles": "packages",
        }.get(rel, "data" if rel == "reads" and kind in ("data", "auth") else "hooks")
        text = {
            "flows": f"{e['evidence']}: {_label(old, k[0])} → {_label(old, tgt)}",
            "hosts": f"{e['attrs'].get('class', 'undeclared')}: {_label(old, tgt)}",
            "data": _label(old, tgt),
            "packages": _label(old, tgt),
        }.get(group, f"{rel.replace('_', ' ')} {kind.replace('_', ' ')} {_label(old, tgt)}")
        out.append(
            Change(
                f"removed_{group.rstrip('s')}",
                20 if rel in ("flows_to",) or group == "data" else 3,
                group,
                text,
                sign="-",
                detail={"target": tgt, "relation": rel},
            )
        )

    for k in new.edges.keys() & old.edges.keys():
        a, b = old.edges[k], new.edges[k]
        ea, eb = _EVIDENCE.get(a["evidence"], 0), _EVIDENCE.get(b["evidence"], 0)
        what = f"{k[1].replace('_', ' ')} {_label(new, k[2])}"
        if k[0] != SUBJECT:
            what = f"{_label(new, k[0])} → {_label(new, k[2])}"
        if eb != ea:
            important = k[1] in ("flows_to", "reads") and eb > ea
            out.append(
                Change(
                    "evidence_up" if eb > ea else "evidence_down",
                    (90 if important else 40) if eb > ea else 15,
                    "flows" if k[1] == "flows_to" else "data" if k[1] == "reads" else "hooks",
                    f"{what}: {a['evidence']} → {b['evidence']}",
                    sign="~",
                    finding_ids=b["finding_ids"],
                    detail={"edge": list(k), "from": a["evidence"], "to": b["evidence"]},
                )
            )
        if k[1] == "connects_to":
            ca, cb = a["attrs"].get("class"), b["attrs"].get("class")
            if ca != cb:
                out.append(
                    Change(
                        "host_class",
                        _HOST_RANK.get(str(cb), 10) - 20 if cb in _UNEXPLAINED else 5,
                        "hosts",
                        f"{_label(new, k[2])}: {ca} → {cb}",
                        sign="~",
                        detail={"target": k[2], "from": ca, "to": cb},
                    )
                )
        if k[1] in ("depends_on", "bundles"):
            va = a["attrs"].get("version") or a["attrs"].get("spec")
            vb = b["attrs"].get("version") or b["attrs"].get("spec")
            if va != vb:
                out.append(
                    Change(
                        "package_version",
                        8 if not b["attrs"].get("ha_provided") else 2,
                        "packages",
                        f"{_label(new, k[2])} {va} → {vb}",
                        sign="~",
                        detail={"target": k[2], "from": va, "to": vb},
                    )
                )
    return out, absorbed


def _group_packages(changes: list[Change]) -> list[Change]:
    """More than 3 new packages without findings, same relation: one line."""
    plain: dict[str, list[Change]] = defaultdict(list)
    for c in changes:
        if c.kind == "new_package" and not c.finding_ids and c.rank >= 25:
            plain[c.text.split(" ", 2)[0]].append(c)
    grouped = [cs for cs in plain.values() if len(cs) > 3]
    drop = {id(c) for cs in grouped for c in cs}
    out = [c for c in changes if id(c) not in drop]
    for cs in grouped:
        names = sorted(c.detail["target"].split("/", 1)[-1] for c in cs)
        what = "bundled packages" if cs[0].text.startswith("bundles") else "dependencies"
        out.append(
            Change(
                "new_package",
                max(c.rank for c in cs),
                "packages",
                f"{len(cs)} new {what}: {', '.join(names[:4])}" + (", …" if len(names) > 4 else ""),
                detail={"targets": [c.detail["target"] for c in cs]},
            )
        )
    return out


# --- provenance and coverage -----------------------------------------------------------


def _when(s: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None
    except ValueError:
        return None


def publisher_changes(old: dict, new: dict) -> list[Change]:
    po, pn = old.get("provenance"), new.get("provenance")
    if not po or not pn:
        return []
    out = []
    same = po.get("repo_id") and po.get("repo_id") == pn.get("repo_id")
    if same and po.get("full_name") != pn.get("full_name"):
        out.append(
            Change(
                "repo_moved",
                85,
                "repo",
                f"repository moved: {po.get('full_name')} → {pn.get('full_name')}",
                sign="~",
            )
        )
    releases = pn.get("releases") or po.get("releases") or []
    by_tag = {r["tag"]: r for r in releases}
    old_tag, new_tag = old["target"].get("ref"), new["target"].get("ref")
    rel_old, rel_new = by_tag.get(old_tag), by_tag.get(new_tag)
    if not rel_new or not rel_old or not (t_old := _when(rel_old.get("published_at"))):
        return out
    upto = [r for r in releases if (w := _when(r.get("published_at"))) and w <= t_old]
    seen = Counter(r["publisher"] for r in upto if r.get("publisher"))
    for r in upto:
        for u in r.get("asset_uploaders") or []:
            seen.setdefault(u, 0)
    who = [rel_new.get("publisher")] + [
        u for u in rel_new.get("asset_uploaders") or [] if not u.endswith("[bot]")
    ]
    for login in dict.fromkeys(w for w in who if w):
        if login in seen:
            continue
        role = "published" if login == rel_new.get("publisher") else "uploaded assets for"
        prev = ", ".join(f"{p} {n}" for p, n in seen.most_common(3))
        out.append(
            Change(
                "new_publisher",
                88,
                "repo",
                f"{login} {role} {new_tag}, and published none of the {len(upto)} "
                f"release(s) up to {old_tag} ({prev})",
                detail={"login": login, "role": role, "previous": dict(seen)},
            )
        )
    if not out and rel_new.get("publisher") != rel_old.get("publisher"):
        out.append(
            Change(
                "publisher_changed",
                15,
                "repo",
                f"{new_tag} published by {rel_new.get('publisher')} "
                f"({old_tag}: {rel_old.get('publisher')}, who had published here before)",
                sign="~",
            )
        )
    return out


def coverage_changes(old: dict, new: dict) -> list[Change]:
    out = []
    before = {a["name"]: a["state"] for a in old.get("analyzers", [])}
    for a in new.get("analyzers", []):
        was = before.get(a["name"])
        if a["state"] in ("error", "skipped") and was not in ("error", "skipped"):
            out.append(
                Change(
                    "coverage_lost",
                    50,
                    "coverage",
                    f"{a['name']} did not complete in the new scan ({a['detail']}): changes "
                    "it would find are missing",
                    sign="~",
                )
            )
    t_old, t_new = old["target"], new["target"]
    if t_old.get("install_source") != t_new.get("install_source"):
        out.append(
            Change(
                "install_source",
                30,
                "coverage",
                f"installed from {t_old.get('install_source')} → {t_new.get('install_source')}",
                sign="~",
            )
        )
    return out


# --- entry point -----------------------------------------------------------------------


def _side(r: dict[str, Any]) -> dict[str, Any]:
    t = r["target"]
    return {
        "repo": t.get("repo") or t.get("input"),
        "ref": t.get("ref"),
        "commit_sha": t.get("commit_sha"),
        "kind": t.get("kind"),
        "score": r["score"],
        "verdict": r["verdict"],
        "complete": r["complete"],
        "exposure": r.get("exposure"),
        "ha_version": r.get("ha_version"),
    }


def same_item(old: dict[str, Any], new: dict[str, Any]) -> bool:
    """Same repo (or the same GitHub repo id after a move), or the same graph subject."""
    a, b = old["target"], new["target"]
    if a.get("repo") and b.get("repo") and a["repo"].lower() == b["repo"].lower():
        return True
    po, pn = old.get("provenance") or {}, new.get("provenance") or {}
    if po.get("repo_id") and po.get("repo_id") == pn.get("repo_id"):
        return True
    ga, gb = old.get("graph") or {}, new.get("graph") or {}
    return bool(ga.get("subject")) and ga.get("subject") == gb.get("subject")


def diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    warnings = []
    if old.get("schema_version") != new.get("schema_version"):
        warnings.append("the reports use different schema versions")
    if old.get("exposure") != new.get("exposure"):
        warnings.append("the scans used different --exposure settings")
    a, b = _side(old), _side(new)
    if a["ha_version"] and b["ha_version"] and a["ha_version"] != b["ha_version"]:
        warnings.append(
            f"dependencies were resolved against different HA releases "
            f"({a['ha_version']} and {b['ha_version']})"
        )
    if not same_item(old, new):
        warnings.append(f"comparing two different items: {a['repo']} and {b['repo']}")

    fchanges, new_findings = _finding_changes(old, new)
    unresolved = {
        re.sub(r"[-_.]+", "-", _lead(f["evidence"]).rstrip(":")).lower()
        for f in old["findings"]
        if f["rule_id"] == "dep-unresolvable"
    }
    echanges, absorbed = _edge_changes(_graph(old), _graph(new), new_findings, unresolved)
    fchanges = [
        c for c in fchanges if not (c.kind == "new_finding" and set(c.finding_ids) <= absorbed)
    ]
    repo = publisher_changes(old, new)
    folded = [
        c
        for c in fchanges
        if repo
        and c.kind == "new_finding"
        and c.detail["rule_id"] in ("repo-new-maintainer-release", "repo-transferred")
    ]
    if folded:  # the scan's own repo findings say the same thing as the publisher line
        top = max(folded, key=lambda c: _SEV[c.severity or "info"])
        repo[0].text += " · " + ", ".join(sorted({c.detail["rule_id"] for c in folded}))
        repo[0].severity = top.severity
        repo[0].finding_ids += [i for c in folded for i in c.finding_ids]
        fchanges = [c for c in fchanges if c not in folded]
    changes = fchanges + echanges + repo + coverage_changes(old, new)
    changes.sort(key=lambda c: (-c.rank, _GROUP_ORDER.get(c.group, 9), c.text))
    summary: dict[str, dict[str, int]] = {}
    for c in changes:
        s = summary.setdefault(c.group, {"+": 0, "-": 0, "~": 0})
        s[c.sign] += 1
    return {
        "diff_version": DIFF_VERSION,
        "from": a,
        "to": b,
        "score": {"from": a["score"], "to": b["score"], "delta": b["score"] - a["score"]},
        "warnings": warnings,
        "headline_rank": HEADLINE_RANK,
        "untrusted_fields": ["changes[].text", "changes[].detail"],
        "summary": summary,
        "changes": [c.to_dict() for c in changes],
    }
