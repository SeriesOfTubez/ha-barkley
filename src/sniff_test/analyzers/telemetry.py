"""(0.14.0) Usage reporting ("telemetry") in an integration's Python: when, gated, disclosed.

User decision 2026-11-17: telemetry is a privacy matter, worst when it's sent on its own,
without an option to turn it off and without telling the user ("shadow telemetry"). It is
scored only when all three are certain; anything uncertain is an unscored note that says
what Barkley could and couldn't tell. Parse only (py_resolve): nothing here runs the code.

A send is an HTTP call (`.post/.get/.put/.patch/.request`, `urlopen`) whose URL starts
with a fixed `http(s)://` address on the internet and whose fixed text says it collects
usage (telemetry, analytics, ping, beacon, usage, heartbeat; on a call that sends data,
also metrics, stats and track).

- Automatic: a chain of plain calls (`f()`, `self.m()`, functions imported from the app's
  own modules, tasks made from those) leads to it from setup (`async_setup`,
  `async_setup_entry`, …), a timer (`async_track_time_interval`, `async_call_later`, …),
  a startup listener or a coordinator update. A user action is a service, a config-flow
  step, a button press, a websocket command or an entity action. A chain broken by a call
  we can't follow (another object's method) proves nothing.
- Gated: any `if` around a call on that chain, or an early `return` before it. When the
  test reads an option whose default the code fixes, the default says opt-in or opt-out.
- Disclosed: the README, info.md, strings.json or English translation mentions telemetry,
  analytics or usage statistics.

`telemetry-shadow` (medium): automatic, nothing gates it, not disclosed.
`telemetry-opt-out` (low): automatic, but on by default behind an option, or disclosed.
`telemetry-usage` (info): anything else, with what we could and couldn't tell.
"""

from __future__ import annotations

import ast
import itertools
import re
from dataclasses import dataclass, field
from pathlib import Path

from sniff_test.analyzers.py_resolve import Resolver
from sniff_test.models import AnalyzerResult, AnalyzerState, Category, Finding, Severity, Target

NAME = "telemetry"
MARKER = re.compile(
    r"(?i)telemetry|analytic|usage|heartbeat|(?:^|[./_?&=-])(?:ping|beacon)(?:$|[./_?&=-])"
)
# (0.15, batch 2026-11-21) Words that also name what an app reads: an integration GETting
# `https://<game api>/v2/stats/…` fetches the player's statistics it shows; a parcel
# API's `/track/` reads a delivery. They mark usage reporting only on a call that sends
# data (POST, PUT, PATCH).
WEAK_MARKER = re.compile(r"(?i)metric|(?:^|[./_?&=-])(?:stats?|track)(?:$|[./_?&=-])")
_SENDS_DATA = frozenset({"post", "put", "patch"})
_HTTP = frozenset({"post", "get", "put", "patch", "request", "urlopen"})
_LOCAL = re.compile(
    r"^(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[?::1|[^.]+$|.*\.local$)"
)
_AUTO_ROOTS = frozenset(
    {"async_setup", "async_setup_entry", "setup", "setup_entry", "async_migrate_entry",
     "_async_update_data", "async_added_to_hass"}
)  # fmt: skip
_TIMERS = frozenset(
    {"async_track_time_interval", "async_call_later", "async_track_point_in_time",
     "async_track_point_in_utc_time", "async_track_time_change", "async_track_utc_time_change",
     "track_time_interval", "call_later", "async_at_started", "async_at_start",
     "async_listen_once"}
)  # fmt: skip
_TASKS = frozenset(
    {"async_create_task", "create_task", "async_create_background_task", "ensure_future",
     "async_add_executor_job", "async_add_job", "run_coroutine_threadsafe"}
)  # fmt: skip
_USER_PREFIXES = ("async_step_", "async_press", "async_turn_", "async_set_", "async_select_",
                  "async_handle_", "websocket_", "ws_")  # fmt: skip
_DISCLOSE = re.compile(
    r"(?i)\btelemetry\b|\banalytics\b|usage (?:statistics|stats|data|reporting)|"
    r"anonymous(?:ly)? (?:usage|statistics|data)"
)
_DOCS = ("README.md", "README.rst", "README", "info.md")
_MAX_DEPTH = 8

Fn = tuple[str, str]  # (file, qualified name: "f" or "Class.m")


@dataclass
class _Graph:
    callers: dict[Fn, set[Fn]] = field(default_factory=dict)
    auto: set[Fn] = field(default_factory=set)
    user: set[Fn] = field(default_factory=set)
    defs: dict[Fn, ast.AST] = field(default_factory=dict)
    # the statement in the caller's body that calls the callee: for gate checks
    sites: dict[tuple[Fn, Fn], list[ast.AST]] = field(default_factory=dict)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _functions(tree: ast.Module) -> list[tuple[str, ast.AST, str | None]]:
    out: list[tuple[str, ast.AST, str | None]] = []
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((n.name, n, None))
        elif isinstance(n, ast.ClassDef):
            for m in n.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.append((f"{n.name}.{m.name}", m, n.name))
    return out


def _target(res: Resolver, rel: str, cls: str | None, node: ast.AST, names: set[str]) -> Fn | None:
    """The function a callee expression names: `f`, `self.m`, or an imported `f`."""
    if isinstance(node, ast.Name):
        if node.id in names:
            return (rel, node.id)
        imp = res.imports(rel).get(node.id)
        if imp and imp[0].startswith("."):
            level = len(imp[0]) - len(imp[0].lstrip("."))
            mod = imp[0].lstrip(".") or None
            f = res._module_file(rel, level, mod)
            if f:
                return (f, imp[1])
        return None
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and cls
        and f"{cls}.{node.attr}" in names
    ):
        return (rel, f"{cls}.{node.attr}")
    return None


def _graph(res: Resolver, files: list[str]) -> _Graph:
    g = _Graph()
    for rel in files:
        tree = res.tree(rel)
        if tree is None:
            continue
        fns = _functions(tree)
        names = {q for q, _, _ in fns}
        for qual, node, cls in fns:
            me = (rel, qual)
            g.defs[me] = node
            short = qual.rsplit(".", 1)[-1]
            if short in _AUTO_ROOTS and (
                cls is None or short in ("_async_update_data", "async_added_to_hass")
            ):
                g.auto.add(me)
            if short.startswith(_USER_PREFIXES):
                g.user.add(me)
            for dec in getattr(node, "decorator_list", []):
                if "websocket" in _dotted(dec.func if isinstance(dec, ast.Call) else dec):
                    g.user.add(me)
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                fname = _dotted(sub.func).rsplit(".", 1)[-1]
                refs: list[tuple[ast.AST, str]] = [(sub.func, "call")]
                if fname in _TIMERS or fname in _TASKS:
                    refs += [(a, "auto" if fname in _TIMERS else "call") for a in sub.args]
                    refs += [(a.func, "call") for a in sub.args if isinstance(a, ast.Call)]
                if fname == "async_register" and len(sub.args) >= 3:
                    refs.append((sub.args[2], "user"))
                if fname == "DataUpdateCoordinator":
                    refs += [(k.value, "auto") for k in sub.keywords if k.arg == "update_method"]
                for expr, how in refs:
                    t = _target(res, rel, cls, expr, names)
                    if t is None:
                        continue
                    if how == "auto":
                        g.auto.add(t)
                    elif how == "user":
                        g.user.add(t)
                    else:
                        g.callers.setdefault(t, set()).add(me)
                        g.sites.setdefault((me, t), []).append(sub)
    return g


def _conditional(fn: ast.AST, call: ast.AST) -> list[ast.expr]:
    """Tests that decide whether `call` runs inside `fn`: enclosing `if`s (and ternaries),
    and `if …: return` statements before it in an enclosing block."""
    tests: list[ast.expr] = []

    def visit(node: ast.AST, guards: list[ast.expr]) -> bool:
        if node is call:
            tests.extend(guards)
            return True
        body_lists = [getattr(node, k) for k in ("body", "orelse", "finalbody", "handlers")
                      if isinstance(getattr(node, k, None), list)]  # fmt: skip
        loops = (ast.If, ast.IfExp, ast.While)
        inner = [*guards, node.test] if isinstance(node, loops) else guards
        for block in body_lists:
            early: list[ast.expr] = []
            for st in block:
                if visit(st, inner + early):
                    return True
                if isinstance(st, ast.If) and any(
                    isinstance(x, (ast.Return, ast.Raise)) for x in st.body
                ):
                    early.append(st.test)
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.stmt, ast.ExceptHandler)) and visit(child, inner):
                return True
        return False

    visit(fn, [])
    return tests


def _default(res: Resolver, rel: str, test: ast.expr) -> bool | None:
    """Whether the report is on by default, when the test reads an option whose fixed
    default is a boolean: `.get(CONF_X, True)`, `.get(CONF_X, DEFAULT_X)` with
    DEFAULT_X = True. An option named "disable…", "opt_out…" or "no_…" is read the other
    way round. None when there's no such option."""
    for n in ast.walk(test):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
            continue
        if n.func.attr != "get" or len(n.args) < 2:
            continue
        value: bool | None = None
        d = n.args[1]
        if isinstance(d, ast.Constant) and isinstance(d.value, bool):
            value = d.value
        elif isinstance(d, ast.Name):
            node = _const_node(res, rel, d.id)
            if isinstance(node, ast.Constant) and isinstance(node.value, bool):
                value = node.value
        if value is None:
            continue
        key = n.args[0]
        name = (res.value(rel, key) or "") + " " + (key.id if isinstance(key, ast.Name) else "")
        if re.search(r"(?i)disable|opt_?out|(?:^|_)no_", name):
            value = not value
        return value
    return None


def _const_node(res: Resolver, rel: str, name: str, depth: int = 0) -> ast.expr | None:
    tree = res.tree(rel)
    if tree is None or depth > 3:
        return None
    hits = [
        st.value
        for st in tree.body
        if isinstance(st, ast.Assign)
        and len(st.targets) == 1
        and isinstance(st.targets[0], ast.Name)
        and st.targets[0].id == name
    ]
    if len(hits) == 1:
        return hits[0]
    imp = res.imports(rel).get(name)
    if imp and imp[0].startswith("."):
        level = len(imp[0]) - len(imp[0].lstrip("."))
        f = res._module_file(rel, level, imp[0].lstrip(".") or None)
        if f:
            return _const_node(res, f, imp[1], depth + 1)
    return None


def _url_text(res: Resolver, rel: str, node: ast.expr) -> tuple[str, str]:
    """(certain prefix, all fixed text) of a URL expression."""
    from sniff_test.analyzers.py_precision import _prefix

    prefix = _prefix(res, rel, node)
    fixed = [prefix]
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            fixed.append(n.value)
        elif isinstance(n, ast.Name) and (v := res.constant(rel, n.id)) is not None:
            fixed.append(v)
    return prefix, " ".join(fixed)


@dataclass
class Send:
    fn: Fn
    call: ast.Call
    host: str
    line: int


def _sends(res: Resolver, files: list[str], g: _Graph) -> list[Send]:
    out: list[Send] = []
    for (rel, qual), node in g.defs.items():
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            verb = _dotted(sub.func).rsplit(".", 1)[-1]
            if verb not in _HTTP:
                continue
            args = list(sub.args)
            if verb == "request" and args and isinstance(args[0], ast.Constant):
                verb = str(args.pop(0).value).lower()  # session.request("POST", url)
            elif verb == "request":
                method = next((k.value for k in sub.keywords if k.arg == "method"), None)
                if isinstance(method, ast.Constant):
                    verb = str(method.value).lower()
            elif verb == "urlopen":  # a Request with data= or a data argument sends data
                verb = (
                    "post" if len(args) > 1 or any(k.arg == "data" for k in sub.keywords) else "get"
                )
            url = (
                args[0]
                if args
                else next((k.value for k in sub.keywords if k.arg in ("url", "str_or_url")), None)
            )
            if url is None:
                continue
            prefix, fixed = _url_text(res, rel, url)
            m = re.match(r"^https?://([^/:?#]+)", prefix)
            if not m or _LOCAL.match(m.group(1).lower()):
                continue
            path_text = prefix[m.end() :] + " " + fixed.replace(prefix, "", 1)
            marks = (MARKER,) + ((WEAK_MARKER,) if verb in _SENDS_DATA else ())
            if not any(x.search(m.group(1)) or x.search(path_text) for x in marks):
                continue
            out.append(Send((rel, qual), sub, m.group(1).lower(), sub.lineno))
    return out


def _paths(g: _Graph, start: Fn) -> tuple[list[list[Fn]], bool]:
    """Call chains from automatic roots down to `start`, and whether a user-action root
    reaches it."""
    autos: list[list[Fn]] = []
    user = False
    stack: list[list[Fn]] = [[start]]
    seen: set[Fn] = set()
    while stack:
        path = stack.pop()
        fn = path[-1]
        if fn in g.auto:
            autos.append(list(reversed(path)))
        if fn in g.user:
            user = True
        if fn in seen or len(path) > _MAX_DEPTH:
            continue
        seen.add(fn)
        for caller in g.callers.get(fn, ()):
            if caller not in path:
                stack.append([*path, caller])
    return autos, user


def _disclosed(target: Target) -> bool:
    texts: list[Path] = []
    for base in {target.root, target.source_root or target.root}:
        texts += [base / d for d in _DOCS]
    texts += [target.root / "strings.json", target.root / "translations" / "en.json"]
    for p in texts:
        try:
            if (
                p.is_file()
                and not p.is_symlink()
                and _DISCLOSE.search(p.read_text("utf-8", "replace")[:2_000_000])
            ):
                return True
        except OSError:
            continue
    return False


def run(target: Target) -> AnalyzerResult:
    res = Resolver(target.root)
    files = sorted(
        p.relative_to(res.root).as_posix()
        for p in res.root.rglob("*.py")
        if p.is_file() and not p.is_symlink()
    )[:3000]
    g = _graph(res, files)
    sends = _sends(res, files, g)
    if not sends:
        return AnalyzerResult(NAME, AnalyzerState.OK, detail="no usage reporting found")
    disclosed = _disclosed(target)
    findings: list[Finding] = []
    for s in sends:
        autos, user = _paths(g, s.fn)
        findings.append(_judge(res, g, s, autos, user, disclosed))
    return AnalyzerResult(NAME, AnalyzerState.OK, findings, detail=f"{len(sends)} usage reports")


def _judge(
    res: Resolver, g: _Graph, s: Send, autos: list[list[Fn]], user: bool, disclosed: bool
) -> Finding:
    if not autos:
        how = (
            "It runs when you use the app (a service, a setup step or a button)"
            if user
            else "Barkley couldn't tell when it runs"
        )
        return _finding("telemetry-usage", Severity.INFO, s, f"{how}.", disclosed)
    gates: list[tuple[str, ast.expr]] = []
    for path in autos:
        mine: list[tuple[str, ast.expr]] = []
        for caller, callee in itertools.pairwise(path):
            sites = g.sites.get((caller, callee), [])
            # a caller with several call sites: gated only if every one is
            per_site = [_conditional(g.defs[caller], site) for site in sites]
            if per_site and all(per_site):
                mine += [(caller[0], t) for ts in per_site for t in ts]
        mine += [(s.fn[0], t) for t in _conditional(g.defs[s.fn], s.call)]
        gates += mine
        if not mine:
            if disclosed:
                return _finding("telemetry-opt-out", Severity.LOW, s,
                                "It's sent automatically with no option around it, but the "
                                "app's description mentions it.", disclosed)  # fmt: skip
            chain = " → ".join(q for _, q in path)
            return _finding(
                "telemetry-shadow",
                Severity.MEDIUM,
                s,
                f"It's sent automatically ({chain}), nothing in the code lets you turn it "
                "off, and the app's description doesn't mention it.",
                disclosed,
            )
    defaults = {_default(res, rel, t) for rel, t in gates}
    if defaults == {True}:
        return _finding("telemetry-opt-out", Severity.LOW, s,
                        "It's sent automatically behind an option that is on unless you "
                        "turn it off.", disclosed)  # fmt: skip
    if defaults == {False}:
        return _finding("telemetry-usage", Severity.INFO, s,
                        "It's sent only after you switch on an option that is off by "
                        "default.", disclosed)  # fmt: skip
    return _finding(
        "telemetry-usage",
        Severity.INFO,
        s,
        "It can run on its own, but a condition in the code decides whether it does, and "
        "Barkley couldn't tell from the code whether that's an option you control.",
        disclosed,
    )


def _finding(rule: str, sev: Severity, s: Send, how: str, disclosed: bool) -> Finding:
    told = "The app's description mentions it." if disclosed else ""
    title = {
        "telemetry-shadow": "Sends usage data on its own, without telling you",
        "telemetry-opt-out": "Sends usage data unless you turn it off",
        "telemetry-usage": "Can send usage data",
    }[rule]
    return Finding(
        rule_id=rule,
        title=title,
        severity=sev,
        category=Category.ENDPOINT,
        # (0.15) said once: some reasons already say the description mentions it
        message=f"Sends what looks like usage reporting to {s.host}. {how}"
        + ("" if "description mentions it" in how else f" {told}").rstrip(),
        file=s.fn[0],
        line=s.line,
        evidence=f"{s.host} from {s.fn[1]}",
        analyzer=NAME,
    )
