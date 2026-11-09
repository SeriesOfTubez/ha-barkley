"""The `graph` section: what the scanned item hooks into, never scored.

Built from inventory facts (Semgrep inventory rules, endpoint extraction, repo
signals), sensitive-access / exfil findings, and the dependency resolution.

Designed for the future add-on's SQLite store and update diffs:
- **Node ids are content-derived** (`<kind>:<key>`, e.g. `host:api.vendor.com`,
  `data:secrets.yaml`, `package:pypi/aiohttp`), so the same node from two integrations
  or two versions has the same id. A home-wide union is a plain merge on node id.
- **Edge ids hash (source, relation, target)**, so a version diff is a set difference
  on edge ids plus a comparison of `evidence` (e.g. possible -> proven).
- **Per-item details live on edges**, not nodes (a host is "declared" by one
  integration and undeclared for another). Nodes carry only intrinsic facts.
- One edge per (source, relation, target), with a `count` and up to three `samples`;
  never one edge per call site.
- `samples`, node keys and `values` come from the scanned code: untrusted text.

Suggested tables: nodes(scan_id, id, kind, ring, label), edges(scan_id, id, source,
target, relation, evidence, count, attrs_json), edge_findings(scan_id, edge_id,
finding_id).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sniff_test.analyzers.correlate import PROVEN_RULES, SENSITIVE_NODES, explained_by_taint
from sniff_test.analyzers.endpoints import UNEXPLAINED
from sniff_test.models import Category, Evidence, Fact, Finding, Ring, Severity, TargetKind

if TYPE_CHECKING:
    from sniff_test.report.json_report import ScanResult

GRAPH_VERSION = 1
_KEY_MAX = 200
_SAMPLES = 3
_VALUES_MAX = 25
_CONTROL = re.compile(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩]")
_DEP_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:==|@| )")
OFF_BOX = ("network", "off-box (destination not visible statically)")

_RING_OF_KIND = {
    "data": Ring.DATA,
    "auth": Ring.DATA,
    "host": Ring.NETWORK,
    "ip": Ring.NETWORK,
    "network": Ring.NETWORK,
    "package": Ring.PACKAGES,
    "ha_component": Ring.HA,
    "inbound": Ring.HA,
    "account": Ring.REPO,
    "repo": Ring.REPO,
}


def _clean(text: str) -> str:
    return _CONTROL.sub("", text)[:_KEY_MAX]


def node_id(kind: str, key: str) -> str:
    return f"{kind}:{_clean(key)}"


def edge_id(source: str, relation: str, target: str) -> str:
    return hashlib.sha256(f"{source}\0{relation}\0{target}".encode()).hexdigest()[:16]


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class _Edge:
    source: str
    target: str
    relation: str
    evidence: Evidence
    count: int = 0
    samples: list[dict[str, Any]] = field(default_factory=list)
    finding_ids: set[str] = field(default_factory=set)
    attrs: dict[str, Any] = field(default_factory=dict)


class GraphBuilder:
    def __init__(self, subject_kind: str, subject_key: str, subject_attrs: dict[str, Any]):
        self.subject = node_id(subject_kind, subject_key)
        self.nodes: dict[str, dict[str, Any]] = {
            self.subject: {
                "id": self.subject,
                "kind": subject_kind,
                "ring": "subject",
                "label": _clean(subject_key),
                "attrs": subject_attrs,
            }
        }
        self.edges: dict[str, _Edge] = {}

    def node(self, kind: str, key: str, ring: Ring | None = None, **attrs: Any) -> str:
        nid = node_id(kind, key)
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id": nid,
                "kind": kind,
                "ring": str(ring or _RING_OF_KIND.get(kind, Ring.HA)),
                "label": _clean(key),
                "attrs": {},
            }
        self.nodes[nid]["attrs"].update(attrs)
        return nid

    def edge(
        self,
        source: str,
        relation: str,
        target: str,
        evidence: Evidence,
        file: str | None = None,
        line: int | None = None,
        finding_id: str | None = None,
        attrs: dict[str, Any] | None = None,
    ) -> None:
        eid = edge_id(source, relation, target)
        e = self.edges.get(eid)
        if e is None:
            e = self.edges[eid] = _Edge(source, target, relation, evidence)
        e.evidence = max(e.evidence, evidence)
        e.count += 1
        if file and len(e.samples) < _SAMPLES:
            sample = {"file": _clean(file), "line": line}
            if sample not in e.samples:
                e.samples.append(sample)
        if finding_id:
            e.finding_ids.add(finding_id)
        for k, v in (attrs or {}).items():
            if isinstance(v, list):
                merged = e.attrs.setdefault(k, [])
                for item in v:
                    item = _clean(item) if isinstance(item, str) else item
                    if item not in merged and len(merged) < _VALUES_MAX:
                        merged.append(item)
            else:
                e.attrs[k] = v

    def to_dict(self) -> dict[str, Any]:
        edges = [
            {
                "id": eid,
                "source": e.source,
                "target": e.target,
                "relation": e.relation,
                "evidence": str(e.evidence),
                "count": e.count,
                "samples": e.samples,
                "finding_ids": sorted(e.finding_ids),
                "attrs": {
                    k: (sorted(v, key=str) if isinstance(v, list) else v)
                    for k, v in sorted(e.attrs.items())
                },
            }
            for eid, e in self.edges.items()
        ]
        edges.sort(key=lambda e: (e["source"] != self.subject, e["relation"], e["target"]))
        nodes = sorted(
            self.nodes.values(), key=lambda n: (n["id"] != self.subject, n["ring"], n["id"])
        )
        rings: dict[str, int] = {}
        for n in nodes[1:]:
            rings[n["ring"]] = rings.get(n["ring"], 0) + 1
        return {
            "graph_version": GRAPH_VERSION,
            "subject": self.subject,
            "evidence_levels": [str(e) for e in Evidence],
            "untrusted_fields": [
                "nodes[].label",
                "nodes[].id",
                "edges[].samples",
                "edges[].attrs.values",
            ],
            "summary": {"nodes_by_ring": rings, "edges": len(edges)},
            "nodes": nodes,
            "edges": edges,
        }


# --- sources ---------------------------------------------------------------------------


def _add_fact(g: GraphBuilder, f: Fact) -> None:
    attrs = dict(f.attrs)
    attrs.pop("outbound", None)
    target = g.node(f.kind, f.key, f.ring)
    if f.kind in ("host", "ip") and attrs.get("class") in (
        "local",
        "exfil_service",
        "developer_hosted",
        "messaging",
        "resolver",
    ):
        g.nodes[target]["attrs"]["class"] = attrs["class"]  # intrinsic
    g.edge(g.subject, f.relation, target, f.evidence, f.file, f.line, attrs=attrs)


def _add_findings(
    g: GraphBuilder, findings: list[Finding], root: Any, destinations: list[str]
) -> None:
    by_id = {f.id: f for f in findings}
    explained = explained_by_taint(findings, root) if root is not None else {}
    for f in findings:
        if f.rule_id in SENSITIVE_NODES:
            kind, key = SENSITIVE_NODES[f.rule_id]
            g.edge(g.subject, "reads", g.node(kind, key), Evidence.POSSIBLE, f.file, f.line, f.id)
        elif f.category is Category.INBOUND:
            g.edge(
                g.subject,
                "exposes",
                g.node("inbound", f.title),
                Evidence.POSSIBLE,
                f.file,
                f.line,
                f.id,
            )
    # Proven flows: sources sharing a function with a taint sink.
    for src_id, sink in explained.items():
        src = by_id[src_id]
        kind, key = SENSITIVE_NODES[src.rule_id]
        g.edge(
            g.node(kind, key),
            "flows_to",
            g.node(*OFF_BOX),
            Evidence.PROVEN,
            sink.file,
            sink.line,
            sink.id,
        )
    for f in findings:
        if f.rule_id in PROVEN_RULES and f.id not in {s.id for s in explained.values()}:
            g.edge(
                g.node("data", "sensitive data (source not attributed)"),
                "flows_to",
                g.node(*OFF_BOX),
                Evidence.PROVEN,
                f.file,
                f.line,
                f.id,
            )
    # Possible flows from the correlation: each unexplained source to each unexplained
    # destination the correlation weighed.
    for f in findings:
        if f.rule_id != "possible-exfil":
            continue
        srcs = [
            s
            for s in findings
            if s.rule_id in SENSITIVE_NODES
            and s.id not in explained
            and s.severity >= Severity.HIGH
        ]
        for s in srcs:
            kind, key = SENSITIVE_NODES[s.rule_id]
            for d in destinations:
                g.edge(g.node(kind, key), "flows_to", d, Evidence.POSSIBLE, f.file, f.line, f.id)


def _dep_findings(findings: list[Finding]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for f in findings:
        if f.category is Category.DEPENDENCY and f.evidence and (m := _DEP_NAME.match(f.evidence)):
            out.setdefault(_pep503(m[1]), []).append(f.id)
    return out


def _add_packages(g: GraphBuilder, scan: ScanResult) -> None:
    t = scan.target
    deps = _dep_findings(scan.findings)
    if t.kind is TargetKind.INTEGRATION:
        manifest = _read_json(t.root / "manifest.json")
        for key in ("dependencies", "after_dependencies"):
            for comp in manifest.get(key) or []:
                if isinstance(comp, str):
                    g.edge(
                        g.subject,
                        "depends_on" if key == "dependencies" else "loads_after",
                        g.node("ha_component", comp),
                        Evidence.DECLARED,
                    )
        res = scan.resolution
        if res and res.packages:
            for pkg in res.packages.values():
                name = _pep503(pkg.name)
                g.edge(
                    g.subject,
                    "depends_on",
                    g.node("package", f"pypi/{name}"),
                    Evidence.DECLARED,
                    attrs={
                        "version": pkg.version,
                        "direct": pkg.direct,
                        "ha_provided": pkg.ha_provided,
                        "platforms": sorted(pkg.platforms),
                    },
                )
                for fid in deps.get(name, []):
                    g.edges[
                        edge_id(g.subject, "depends_on", node_id("package", f"pypi/{name}"))
                    ].finding_ids.add(fid)
        else:  # unresolved (offline): what the manifest asks for
            for req in manifest.get("requirements") or []:
                if isinstance(req, str) and (
                    m := re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req)
                ):
                    name = _pep503(m[1])
                    g.edge(
                        g.subject,
                        "depends_on",
                        g.node("package", f"pypi/{name}"),
                        Evidence.DECLARED,
                        attrs={"requirement": _clean(req), "direct": True},
                    )
                    for fid in deps.get(name, []):
                        g.edges[
                            edge_id(g.subject, "depends_on", node_id("package", f"pypi/{name}"))
                        ].finding_ids.add(fid)
    elif t.source_root is not None:
        pkg = _read_json(t.source_root / "package.json")
        for name, spec in (pkg.get("dependencies") or {}).items():
            if isinstance(name, str):
                g.edge(
                    g.subject,
                    "bundles",
                    g.node("package", f"npm/{name}"),
                    Evidence.DECLARED,
                    attrs={"spec": _clean(str(spec))},
                )
                for fid in deps.get(_pep503(name), []):
                    g.edges[
                        edge_id(g.subject, "bundles", node_id("package", f"npm/{name}"))
                    ].finding_ids.add(fid)


def _read_json(path: Any) -> dict[str, Any]:
    import json

    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def build(scan: ScanResult) -> dict[str, Any]:
    t = scan.target
    if t.kind is TargetKind.INTEGRATION:
        subject = ("integration", t.domain or (t.repo or t.source).rsplit("/", 1)[-1])
    else:
        subject = ("card", (t.repo or t.source).rsplit("/", 1)[-1])
    g = GraphBuilder(
        *subject,
        {k: v for k, v in (("repo", t.repo), ("ref", t.ref), ("commit_sha", t.commit_sha)) if v},
    )
    for f in scan.facts:
        _add_fact(g, f)
    destinations = sorted(
        {
            node_id(f.kind, f.key)
            for f in scan.facts
            if f.kind in ("host", "ip") and f.attrs.get("class") in UNEXPLAINED
        }
    )
    _add_findings(g, scan.findings, t.root, destinations)
    _add_packages(g, scan)
    return g.to_dict()
