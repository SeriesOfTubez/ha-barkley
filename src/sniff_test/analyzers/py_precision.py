"""(0.14.0) Parse-only checks that make three Python rules precise after Semgrep.

Semgrep sees a name's text, not what it holds; these checks read the integration's own
files with `ast` (py_resolve: never run, never imported) and decide:

- `ha-foreign-entry-data` / `-options`: whose config entries a loop reads. The
  integration's own (`async_entries(DOMAIN, include_ignore=False)`, the manifest domain
  as a literal, any constant holding it) is no finding. A foreign entry read only for a
  non-secret field (`entry.data.get(CONF_HOST)`, `entry.data["mac"]`) is no finding.
  Anything else stays. A `DOMAIN` imported from another package is another
  integration's domain (that used to pass as "own").
- `ha-raw-storage-access`: a path into `.storage` in three levels. Into the app's own
  file or folder (starts with its domain) is `ha-own-storage-path` (info, not
  scored); into `auth*`, `core.config_entries` or `onboarding` through a constant is
  `ha-read-auth-storage` (high); anything else, or anything we can't resolve, stays
  medium.
- `py-runtime-pip`: an install whose packages are all fixed in the code (a literal list
  of plain requirements, no options or URLs) is `py-runtime-pip-listed` (low), and those
  packages are scanned like the manifest's (Target.runtime_requirements). Anything
  computed (a user's own requirements file, a variable) stays high.

Every check keeps the original finding when it can't parse or resolve something.
"""

from __future__ import annotations

import ast
import dataclasses
import functools
import json
import re
from collections.abc import Callable
from importlib import resources
from pathlib import Path

from sniff_test.analyzers.py_resolve import Resolver, parents
from sniff_test.deps import reqs
from sniff_test.models import Finding, Severity

ENTRY_RULES = ("ha-foreign-entry-data", "ha-foreign-entry-options")
SAFE_KEYS = frozenset({"host", "mac", "name", "unique_id"})
AUTH_FILES = re.compile(r"^(auth|core\.config_entries|onboarding)")
_SPAN = (ast.For, ast.AsyncFor, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


# --- whose config entries ------------------------------------------------------------


def _entries_loop(tree: ast.AST, line: int) -> tuple[ast.Call, str] | None:
    """The innermost loop/comprehension over `….config_entries.async_entries(…)` around
    `line`, as (the call, the loop variable)."""
    best: tuple[int, ast.Call, str] | None = None
    for n in ast.walk(tree):
        if not isinstance(n, _SPAN) or not (n.lineno <= line <= (n.end_lineno or n.lineno)):
            continue
        gens = (
            [(n.iter, n.target)]
            if isinstance(n, ast.For | ast.AsyncFor)
            else [(g.iter, g.target) for g in n.generators]
        )
        for it, target in gens:
            if (
                isinstance(it, ast.Call)
                and isinstance(it.func, ast.Attribute)
                and it.func.attr == "async_entries"
                and _dotted(it.func.value).endswith("config_entries")
                and isinstance(target, ast.Name)
            ):
                size = (n.end_lineno or n.lineno) - n.lineno
                if best is None or size < best[0]:
                    best = (size, it, target.id)
    return (best[1], best[2]) if best else None


def _own_domain(res: Resolver, rel: str, call: ast.Call, domain: str | None) -> bool:
    arg = (
        call.args[0]
        if call.args
        else next((k.value for k in call.keywords if k.arg == "domain"), None)
    )
    if arg is None:
        return False  # every integration's entries
    value = res.value(rel, arg)
    if value is not None:
        return value in own_domains(res, domain)
    if isinstance(arg, ast.Name) and arg.id == "DOMAIN":
        imported = res.imports(rel).get("DOMAIN")
        # from homeassistant.components.<x> import DOMAIN is another integration's
        return imported is None or imported[0].startswith(".")
    return False


def own_domains(res: Resolver, domain: str | None) -> frozenset[str]:
    """The manifest's domain, plus the domain of every manifest.json inside the app's
    folder whose domain starts with the app's own (`<domain>_inverse`): an app can ship
    sub-integrations of its own (a real one ships three), whose entries are its own too."""
    if res.domains is None:
        found: set[str] = set()
        for m in sorted(res.root.rglob("manifest.json"))[:50]:
            if m.is_symlink() or not m.is_file():
                continue
            try:
                d = json.loads(m.read_text(encoding="utf-8", errors="replace")).get("domain")
            except (OSError, ValueError, AttributeError):
                continue
            if isinstance(d, str) and d:
                found.add(d)
        res.domains = frozenset(found)
    if not domain:
        return frozenset()
    # Only names under the app's own (`<domain>_x`): a nested manifest claiming another
    # domain ("mqtt") must not make that integration's entries look like the app's. And
    # never one of HA's built-in domains: an app `google` shipping a nested
    # `google_assistant` manifest doesn't make Google Assistant's entries its own.
    builtin = ha_domains()
    return frozenset(
        {domain} | {d for d in res.domains if d.startswith(f"{domain}_") and d not in builtin}
    )


@functools.cache
def ha_domains() -> frozenset[str]:
    """Home Assistant's built-in integration domains (data/ha_domains.txt, made by
    scripts/ha_domains.py from HA's source tree)."""
    text = (resources.files("sniff_test") / "data" / "ha_domains.txt").read_text("utf-8")
    return frozenset(ln for ln in text.splitlines() if ln and not ln.startswith("#"))


def _safe_key(res: Resolver, rel: str, node: ast.expr) -> bool:
    key = res.value(rel, node) or res.ha_const(rel, node)
    return key in SAFE_KEYS


def _only_safe_fields(res: Resolver, rel: str, tree: ast.AST, line: int, var: str) -> bool:
    """Every `<var>.data` on `line` is `.get(<safe key>[, default])` or `[<safe key>]`."""
    up = parents(tree)
    uses = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute)
        and n.attr == "data"
        and n.lineno == line
        and isinstance(n.value, ast.Name)
        and n.value.id == var
    ]
    if not uses:
        return False
    for n in uses:
        p = up.get(n)
        if isinstance(p, ast.Subscript) and p.value is n:
            if not _safe_key(res, rel, p.slice):
                return False
        elif isinstance(p, ast.Attribute) and p.attr == "get":
            call = up.get(p)
            if not (
                isinstance(call, ast.Call)
                and call.func is p
                and call.args
                and len(call.args) <= 2
                and not call.keywords
                and _safe_key(res, rel, call.args[0])
            ):
                return False
        else:
            return False
    return True


def entry_finding_dropped(f: Finding, res: Resolver, domain: str | None) -> bool:
    if f.rule_id not in ENTRY_RULES or not f.file or not f.line:
        return False
    tree = res.tree(f.file)
    if tree is None:
        return False
    found = _entries_loop(tree, f.line)
    if found is None:
        return False
    call, var = found
    if _own_domain(res, f.file, call, domain):
        return True
    return f.rule_id == "ha-foreign-entry-data" and _only_safe_fields(
        res, f.file, tree, f.line, var
    )


# --- .storage in three levels --------------------------------------------------------


def _prefix(res: Resolver, rel: str, node: ast.expr) -> str:
    """As much of the string's start as is certain ("" when nothing is)."""
    if (v := res.value(rel, node)) is not None:
        return v
    if isinstance(node, ast.JoinedStr):
        out = ""
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                out += part.value
            elif isinstance(part, ast.FormattedValue) and (
                (s := res.value(rel, part.value)) is not None
            ):
                out += s
            else:
                break
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _prefix(res, rel, node.left)
        if (v := res.value(rel, node.left)) is not None:
            return v + _prefix(res, rel, node.right)
        return left
    return ""


def _storage_names(res: Resolver, rel: str, tree: ast.AST, line: int) -> list[str | None]:
    """What follows `.storage` in each path built on `line`: the certain start of the
    name ("" when unknown), or None for the bare folder."""
    out: list[str | None] = []
    up = parents(tree)
    for n in ast.walk(tree):
        if getattr(n, "lineno", None) != line:
            continue
        if isinstance(n, ast.Call):
            args = n.args
            for i, a in enumerate(args):
                if res.value(rel, a) in (".storage", "/config/.storage"):
                    out.append(_prefix(res, rel, args[i + 1]) if i + 1 < len(args) else None)
        elif (
            isinstance(n, ast.BinOp)
            and isinstance(n.op, ast.Div)
            and (
                res.value(rel, n.left) == ".storage"
                or _prefix(res, rel, n.left).endswith("/.storage")
            )
        ):
            out.append(_prefix(res, rel, n.right))
        if isinstance(n, ast.Constant | ast.JoinedStr) and not isinstance(
            up.get(n), ast.JoinedStr | ast.FormattedValue
        ):
            text = _prefix(res, rel, n)  # type: ignore[arg-type]
            m = re.match(r"^(?:/config/)?\.storage[\\/](.*)$", text, re.S)
            if m:
                out.append(m[1])
    return out


def _is_own(name: str, domain: str | None) -> bool:
    if not domain or not name.startswith(domain):
        return False
    rest = name[len(domain) :]
    return rest == "" or rest[0] in "._-/"


def storage_level(f: Finding, res: Resolver, domain: str | None) -> Finding | None:
    """A replacement for an `ha-raw-storage-access` finding, or None to keep it."""
    if f.rule_id != "ha-raw-storage-access" or not f.file or not f.line:
        return None
    tree = res.tree(f.file)
    if tree is None:
        return None
    names = _storage_names(res, f.file, tree, f.line)
    if not names or any(n is None or n == "" for n in names):
        return None  # the whole folder, or a name we can't read: medium
    if any(AUTH_FILES.match(n) for n in names):  # type: ignore[arg-type]
        return dataclasses.replace(
            f,
            rule_id="ha-read-auth-storage",
            title="Reads HA auth/credential storage",
            severity=Severity.HIGH,
            message=(
                "Builds a path to Home Assistant's auth or config-entry storage files. "
                "These hold password hashes, refresh tokens, and every integration's "
                "credentials."
            ),
        )
    if all(_is_own(n, domain) for n in names):  # type: ignore[arg-type]
        return own_storage(f)
    return None


def own_storage(f: Finding) -> Finding:
    """Info, not scored (user decision 2026-11-17): HA has no developer page for the
    `Store` helper and no rule against writing into `.storage`, so this is a description
    of what the code does, not a practice finding."""
    return dataclasses.replace(
        f,
        rule_id="ha-own-storage-path",
        title="Builds its own .storage path by hand",
        severity=Severity.INFO,
        message=(
            "Builds a path to its own file in Home Assistant's .storage folder itself, "
            "instead of going through the homeassistant.helpers.storage.Store helper."
        ),
    )


# --- packages installed while running ------------------------------------------------


_INSTALLERS = frozenset(
    {
        "async_process_requirements",
        "install_package",
        "run",
        "call",
        "check_call",
        "check_output",
        "Popen",
        "create_subprocess_exec",
        "main",
    }
)


def _strings(res: Resolver, rel: str, node: ast.expr) -> list[str] | None:
    if not isinstance(node, ast.List | ast.Tuple):
        return None
    out = [res.value(rel, e) for e in node.elts]
    return None if any(v is None for v in out) else out  # type: ignore[return-value]


def _plain(specs: list[str]) -> bool:
    return bool(specs) and all(reqs.parse(s).kind is reqs.ReqKind.PLAIN for s in specs)


def _listed_packages(res: Resolver, rel: str, call: ast.Call) -> list[str] | None:
    name = _dotted(call.func).rsplit(".", 1)[-1]
    if name == "async_process_requirements":
        arg = (
            call.args[2]
            if len(call.args) > 2
            else next((k.value for k in call.keywords if k.arg == "requirements"), None)
        )
        specs = _strings(res, rel, arg) if arg is not None else None
        return specs if specs is not None and _plain(specs) else None
    if name == "install_package":
        spec = res.value(rel, call.args[0]) if call.args else None
        return [spec] if spec is not None and _plain([spec]) else None
    if call.args and isinstance(call.args[0], ast.List | ast.Tuple):  # subprocess argv
        argv = call.args[0].elts
    elif name == "create_subprocess_exec":
        argv = call.args
    else:
        return None
    words: list[str] = []
    for e in argv:
        if _dotted(e) == "sys.executable":
            words.append("python")
        elif (v := res.value(rel, e)) is not None:
            words.append(v)
        else:
            return None
    if "install" not in words or not ({"pip", "pip3"} & set(words)):
        return None
    specs = words[words.index("install") + 1 :]
    if any(s.startswith("-") for s in specs):
        return None  # options (an index URL, a requirements file): not just names
    return specs if _plain(specs) else None


def pip_listed(f: Finding, res: Resolver) -> tuple[Finding, list[str]] | None:
    if f.rule_id != "py-runtime-pip" or not f.file or not f.line:
        return None
    tree = res.tree(f.file)
    if tree is None:
        return None
    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and n.lineno == f.line
        and _dotted(n.func).rsplit(".", 1)[-1] in _INSTALLERS
    ]
    found = [p for c in calls if (p := _listed_packages(res, f.file, c)) is not None]
    if len(calls) != 1 or len(found) != 1:
        return None  # several installers on the line, or one we can't read: keep it high
    packages = found[0]
    shown = ", ".join(packages[:6]) + (" …" if len(packages) > 6 else "")
    return (
        dataclasses.replace(
            f,
            rule_id="py-runtime-pip-listed",
            title="Installs named packages at runtime",
            severity=Severity.LOW,
            message=(
                "Installs Python packages while running instead of declaring them in "
                f"manifest.json. The packages are fixed in the code ({shown}), so Barkley "
                "checked them like the declared ones."
            ),
        ),
        packages,
    )


# --- secrets.yaml: HA's file, or text and the app's own copy (issue #15) ---------------

_SECRETS = re.compile(r"secrets\.yaml")
_LOG_CALLS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)
_BLOCKS = (
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.For, ast.AsyncFor,
    ast.While, ast.With, ast.AsyncWith, ast.Try, ast.Match,
)  # fmt: skip


def _hops(node: ast.expr) -> int | None:
    """How many folders up from the file a path expression built from `__file__` is
    (`Path(__file__)` 0, `.parent` 1, `.parents[1]` 2, `os.path.dirname` 1, a `/ "x"`
    one down, `/ ".."` one up), or None when it isn't plainly built from `__file__`."""
    if isinstance(node, ast.Name):
        return 0 if node.id == "__file__" else None
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        h = _hops(node.value)
        return None if h is None else h + 1
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "parents"
        and isinstance(node.slice, ast.Constant)
        and type(node.slice.value) is int
        and node.slice.value >= 0
    ):
        h = _hops(node.value.value)
        return None if h is None else h + node.slice.value + 1
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        h = _hops(node.left)
        step = _step(node.right)
        return None if h is None or step is None else h + step
    if isinstance(node, ast.Call):
        name = _dotted(node.func)
        if name.endswith(("resolve", "absolute")) and isinstance(node.func, ast.Attribute):
            return _hops(node.func.value) if not node.args else None
        if len(node.args) != 1 or node.keywords:
            if name in ("os.path.join", "path.join", "join") and node.args:
                return _joined(node.args)
            return None
        arg = node.args[0]
        if name in ("Path", "pathlib.Path", "PurePath", "os.path.abspath", "os.path.realpath",
                    "abspath", "realpath"):  # fmt: skip
            return _hops(arg)
        if name in ("os.path.dirname", "dirname", "path.dirname"):
            h = _hops(arg)
            return None if h is None else h + 1
    return None


def _step(node: ast.expr) -> int | None:
    """A fixed path part: ".." one up (+1), a plain name one down (-1)."""
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return None
    total = 0
    for part in node.value.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        total += 1 if part == ".." else -1
    if node.value.startswith(("/", "\\")) or ":" in node.value:
        return None  # an absolute path: not relative to the file any more
    return total


def _joined(args: list[ast.expr]) -> int | None:
    h = _hops(args[0])
    if h is None:
        return None
    for a in args[1:-1]:
        step = _step(a)
        if step is None:
            return None
        h += step
    return h


def _own_copy(const: ast.Constant, up: dict[ast.AST, ast.AST], depth: int) -> bool:
    """`const` ("secrets.yaml") is the last part of a path built from `__file__` that stays
    inside the app's folder: `depth` is how many folders the file sits below it. HA's
    real secrets.yaml is above the app (config/custom_components/<domain>/), so a path
    that climbs out of the app keeps the finding."""
    parent = up.get(const)
    if isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Div) and parent.right is const:
        h = _hops(parent.left)
    elif (
        isinstance(parent, ast.Call)
        and _dotted(parent.func) in ("os.path.join", "path.join", "join")
        and parent.args
        and parent.args[-1] is const
        and len(parent.args) >= 2
    ):
        h = _joined(parent.args)
    else:
        return False
    if h is None or _step(const) is None or const.value.replace("\\", "/") != "secrets.yaml":
        return False
    return h - 1 <= depth  # h = 1 is the file's own folder


def _prose(const: ast.Constant, up: dict[ast.AST, ast.AST]) -> bool:
    """Text about secrets.yaml, not a path to it: a message (it has spaces), or a string
    passed straight to a log call or a raised exception. Passing through any other call
    on the way up (`_LOGGER.info("%s", open("/config/secrets.yaml").read())`) keeps it."""
    if any(ch.isspace() for ch in const.value):
        return True
    node: ast.AST = const
    while True:
        parent = up.get(node)
        if isinstance(parent, (ast.JoinedStr, ast.FormattedValue, ast.Tuple, ast.keyword)):
            node = parent
            continue
        if isinstance(parent, ast.BinOp) and isinstance(parent.op, (ast.Mod, ast.Add)):
            node = parent
            continue
        if isinstance(parent, ast.Call) and node is not parent.func:
            if isinstance(parent.func, ast.Attribute) and parent.func.attr in _LOG_CALLS:
                return True
            return isinstance(up.get(parent), ast.Raise)  # raise SomeError("…secrets.yaml")
        return False


_AUTH_TEXT = re.compile(
    r"\.storage[\\/](?:auth|core\.config_entries|onboarding)|auth_provider\.homeassistant"
)


def secrets_dropped(f: Finding, res: Resolver) -> bool:
    """`ha-read-secrets` where every `secrets.yaml` string in the matched statement is
    message text, or the path is the app's own copy next to its code (issue #15: a test
    script's `Path(__file__).resolve().parent / "secrets.yaml"`); `ha-read-auth-storage`
    where every matching string is message text (a docstring, a log line, an error).
    Anything we can't read plainly keeps the finding."""
    if f.rule_id == "ha-read-secrets":
        rx, own_copy = _SECRETS, True
    elif f.rule_id == "ha-read-auth-storage" and f.analyzer == "semgrep":
        rx, own_copy = _AUTH_TEXT, False
    else:
        return False
    if not f.file or not f.line:
        return False
    tree = res.tree(f.file)
    if tree is None:
        return False
    stmts = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.stmt)
        and not isinstance(n, _BLOCKS)
        and n.lineno <= f.line <= (n.end_lineno or n.lineno)
    ]
    if not stmts:
        return False
    stmt = min(stmts, key=lambda n: (n.end_lineno or n.lineno) - n.lineno)
    up = parents(tree)
    hits = [
        n
        for n in ast.walk(stmt)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and rx.search(n.value)
    ]
    if not hits:
        return False  # the name came through a constant: keep
    depth = len(Path(f.file).parts) - 1
    return all(_prose(c, up) or (own_copy and _own_copy(c, up, depth)) for c in hits)


# --- test code no runtime module imports ---------------------------------------------

_TEST_DIRS = frozenset({"test", "tests", "testing"})


def _looks_like_test(rel: str) -> bool:
    p = Path(rel)
    name = p.name
    return (
        bool(_TEST_DIRS & set(p.parts[:-1]))
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


_SCRIPT_DIRS = frozenset({"scripts", "script", "tools", "examples", "example", "dev"})


def looks_like_a_script(rel: str) -> bool:
    """(0.15) A developer's own helper: a file in a scripts/tools/examples folder, or
    named like a test without the underscore (`TestLogin.py`)."""
    p = Path(rel)
    return bool(_SCRIPT_DIRS & set(p.parts[:-1])) or p.name.lower().startswith("test")


def test_only_files(res: Resolver, also: Callable[[str], bool] | None = None) -> frozenset[str]:
    """`also`: a wider test for "looks like a test" (the requests list also sets
    developer scripts aside; findings keep the narrow test).
    Python files that look like tests (a test folder, test_*.py, conftest.py) and that
    no other module of the app imports or names. Home Assistant imports an integration's
    package and its platforms; a test file nothing imports is never loaded by it."""
    files = sorted(
        p.relative_to(res.root).as_posix()
        for p in res.root.rglob("*.py")
        if p.is_file() and not p.is_symlink()
    )[:5000]
    tests = {r for r in files if _looks_like_test(r) or (also is not None and also(r))}
    if not tests:
        return frozenset()
    used: set[str] = set()
    for rel in files:
        if rel in tests:
            continue
        tree = res.tree(rel)
        if tree is None:
            return frozenset()  # can't tell what an unreadable module imports
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom):
                target = res._module_file(rel, n.level, n.module)
                if target:
                    used.add(target)
                for a in n.names:  # from . import tests  /  from .tests import helper
                    mod = f"{n.module}.{a.name}" if n.module else a.name
                    sub = res._module_file(rel, n.level, mod)
                    if sub:
                        used.add(sub)
            elif isinstance(n, ast.Import):
                for a in n.names:
                    segs = a.name.split(".")
                    if any(seg in _TEST_DIRS or seg.startswith("test_") for seg in segs):
                        return frozenset()  # an absolute import of a test module: unsure
            elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                for t in tests:  # import_module("…tests…") or a path string
                    stem = Path(t).with_suffix("").as_posix()
                    if stem.replace("/", ".") in n.value or stem in n.value:
                        used.add(t)
    return frozenset(tests - used)


# --- the Supervisor token: read, or only checked for ----------------------------------


def _env_read(node: ast.AST) -> bool:
    if not isinstance(node, (ast.Call, ast.Subscript)):
        return False
    text = _dotted(node.func if isinstance(node, ast.Call) else node.value)
    return text in ("os.environ.get", "os.getenv", "getenv", "environ.get", "os.environ", "environ")


def supervisor_presence_only(f: Finding, res: Resolver) -> bool:
    """`ha-supervisor-token` where every read of the variable on that line is only a
    test of whether it is set (`if os.environ.get("SUPERVISOR_TOKEN"):`, `bool(…)`,
    `… is None`, `not …`): the token's value is never kept or sent."""
    if f.rule_id != "ha-supervisor-token" or not f.file or not f.line:
        return False
    tree = res.tree(f.file)
    if tree is None:
        return False
    up = parents(tree)
    reads = [
        n
        for n in ast.walk(tree)
        if _env_read(n)
        and getattr(n, "lineno", 0) <= f.line <= (getattr(n, "end_lineno", 0) or 0)
        and any(
            isinstance(c, ast.Constant) and c.value in ("SUPERVISOR_TOKEN", "HASSIO_TOKEN")
            for c in ast.walk(n)
        )
    ]
    if not reads:
        return False

    def tested(n: ast.AST) -> bool:
        p = up.get(n)
        while isinstance(p, ast.BoolOp) or (
            isinstance(p, ast.UnaryOp) and isinstance(p.op, ast.Not)
        ):
            if isinstance(p, ast.BoolOp):
                q = up.get(p)
                # `a or b` as a value passes a token on; only inside a test is it a check
                if (
                    not (isinstance(q, (ast.If, ast.While, ast.IfExp, ast.Assert)) and q.test is p)
                    and not (isinstance(q, ast.UnaryOp) and isinstance(q.op, ast.Not))
                    and not (isinstance(q, ast.Call) and _dotted(q.func) == "bool")
                ):
                    return False
            n, p = p, up.get(p)
        if isinstance(p, (ast.If, ast.While, ast.IfExp, ast.Assert)) and p.test is n:
            return True
        if isinstance(p, ast.UnaryOp) and isinstance(p.op, ast.Not):
            return True
        if isinstance(p, ast.Call) and _dotted(p.func) == "bool" and p.args == [n]:
            return True
        if isinstance(p, ast.Compare) and all(isinstance(o, (ast.Is, ast.IsNot)) for o in p.ops):
            return all(isinstance(c, ast.Constant) and c.value is None for c in p.comparators)
        return False

    return all(tested(n) for n in reads)


# --- (0.15) sent to the Supervisor on this box, not off it --------------------------------

# The methods `ha-exfil-taint` counts as sending (rules/python/exfil-taint.yaml)
_SEND = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "request", "ws_connect", "urlopen"}
)
# The Supervisor's own name inside Home Assistant's network, and its old one. The slash
# makes the host certain: "http://supervisor.example/" must not pass.
_SUPERVISOR_URL = re.compile(r"^http://(supervisor|hassio)/")


def supervisor_only(f: Finding, res: Resolver) -> str | None:
    """`ha-exfil-taint` whose every sending call on that line names the Supervisor as a
    literal address (`session.get("http://supervisor/addons", headers=…)`): the data
    goes to the Supervisor on the same box, the party the Supervisor's key is meant for,
    so nothing leaves the box. Returns the certain start of the address, else None. An
    address held in a variable Barkley can't resolve keeps the finding."""
    if f.rule_id != "ha-exfil-taint" or not f.file or not f.line:
        return None
    tree = res.tree(f.file)
    if tree is None:
        return None
    urls: list[str] = []
    for n in ast.walk(tree):
        if not (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in _SEND
            and n.lineno <= f.line <= (n.end_lineno or n.lineno)
        ):
            continue
        start = _to_supervisor(res, f.file, n)
        if not start:
            return None
        urls.append(start)
    return urls[0] if urls else None


LOCAL_RULE = "ha-supervisor-token-local"


def _to_supervisor(res: Resolver, rel: str, call: ast.Call) -> str:
    """The certain start of a sending call's address when it names the Supervisor."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr in _SEND):
        return ""
    addr = next((k.value for k in call.keywords if k.arg == "url"), None)
    if addr is None and call.args:
        addr = call.args[1] if call.func.attr == "request" and len(call.args) > 1 else call.args[0]
    start = _prefix(res, rel, addr) if addr is not None else ""
    return start if _SUPERVISOR_URL.match(start) else ""


def supervisor_token_stays(f: Finding, res: Resolver) -> str | None:
    """`ha-supervisor-token` whose value never leaves the function that reads it, except
    to the Supervisor: it is kept in one local name, and every use of that name is a test
    of whether it is set, or sits inside a sending call whose literal address is the
    Supervisor. Returns that address, else None (returned, stored, passed to another
    function or sent anywhere else: None)."""
    if f.rule_id != "ha-supervisor-token" or not f.file or not f.line:
        return None
    tree = res.tree(f.file)
    if tree is None:
        return None
    up = parents(tree)
    stmts = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Assign) and n.lineno <= f.line <= (n.end_lineno or n.lineno)
        and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
        and any(_env_read(c) for c in ast.walk(n.value))
    ]  # fmt: skip
    if len(stmts) != 1 or (func := _enclosing(stmts[0], up)) is None:
        return None
    name = stmts[0].targets[0].id  # type: ignore[attr-defined]
    stores = [n for n in ast.walk(func) if isinstance(n, ast.Name) and n.id == name
              and not isinstance(n.ctx, ast.Load)]  # fmt: skip
    if len(stores) != 1:
        return None  # assigned again somewhere: not certain what it holds
    url = ""
    for n in ast.walk(func):
        if not (isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)):
            continue
        if _none_test(n, up):
            continue
        p, hit = up.get(n), ""
        while p is not None and p is not func and not hit:
            if isinstance(p, ast.Call):
                hit = _to_supervisor(res, f.file, p)
                if not hit and not (isinstance(p.func, ast.Name) and p.func.id in ("str", "dict")):
                    return None  # handed to some other call
            p = up.get(p)
        if not hit:
            return None
        url = url or hit
    return url or None


def sent_to_supervisor(f: Finding, url: str) -> Finding:
    """The Supervisor's key, used only to ask the Supervisor on the same box."""
    return dataclasses.replace(
        f,
        rule_id=LOCAL_RULE,
        title="Asks the Supervisor with the Supervisor's key",
        message=(
            "Reads the Supervisor API token from the environment and sends it to the "
            f"Supervisor on this box ({url}), which is who the key is for. In the function "
            "that reads it, Barkley saw it go nowhere else."
        ),
    )


# --- (0.14.1, #21) checking a login token sent to the app --------------------------------

CHECK_RULE = "ha-auth-token-check"
_CHECK_CALLS = frozenset({"async_validate_access_token", "async_get_refresh_token"})
# What a check may read from the token it found: whose it is, nothing secret (.token and
# .jwt_key are the token itself and the key that signs its access tokens)
_CHECK_ATTRS = frozenset({"user", "id", "user_id"})


def _none_test(node: ast.AST, up: dict[ast.AST, ast.AST]) -> bool:
    """`node` is only tested: `node is None`, `node is not None`, `not node`, `if node:`."""
    p = up.get(node)
    if isinstance(p, ast.Compare) and len(p.ops) == 1 and isinstance(p.ops[0], (ast.Is, ast.IsNot)):
        other = p.comparators[0] if p.left is node else p.left
        return isinstance(other, ast.Constant) and other.value is None
    if isinstance(p, ast.UnaryOp) and isinstance(p.op, ast.Not):
        return True
    return isinstance(p, (ast.If, ast.While, ast.IfExp, ast.Assert)) and p.test is node


def _enclosing(node: ast.AST, up: dict[ast.AST, ast.AST]) -> ast.AST | None:
    while node in up:
        node = up[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


def token_check_only(f: Finding, res: Resolver) -> Finding | None:
    """An `ha-auth-internals` hit that only checks a token sent to the app becomes
    `ha-auth-token-check` (low, never paired with a destination): the call's result is
    only tested for None, or kept in one name that is only tested or read for `.user`,
    `.id` or `.user_id`, as Home Assistant's own signed-link check does. Anything else
    (the token itself, its signing key, the object passed on) stays as it is."""
    if f.rule_id != "ha-auth-internals" or not f.file or not f.line:
        return None
    tree = res.tree(f.file)
    if tree is None:
        return None
    up = parents(tree)
    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr in _CHECK_CALLS
        and n.func.lineno == f.line
        and isinstance(n.func.value, ast.Attribute)
        and n.func.value.attr == "auth"
    ]
    if len(calls) != 1:
        return None
    call = calls[0]
    node: ast.AST = call
    if isinstance(up.get(node), ast.Await):
        node = up[node]
    if _none_test(node, up):
        return _token_check(f)
    target = up.get(node)
    if isinstance(target, ast.Assign) and len(target.targets) == 1:
        name = target.targets[0]
    elif isinstance(target, ast.NamedExpr):
        name = target.target
    else:
        return None
    if not isinstance(name, ast.Name):
        return None
    scope = _enclosing(call, up)
    if scope is None:
        return None
    stores = [
        n for n in ast.walk(scope)
        if isinstance(n, ast.Name) and n.id == name.id and isinstance(n.ctx, ast.Store)
    ]  # fmt: skip
    if len(stores) != 1:
        return None
    for n in ast.walk(scope):
        if not (isinstance(n, ast.Name) and n.id == name.id and isinstance(n.ctx, ast.Load)):
            continue
        p = up.get(n)
        if _none_test(n, up):
            continue
        if isinstance(p, ast.Attribute) and p.value is n and p.attr in _CHECK_ATTRS:
            continue
        return None
    return _token_check(f)


def _token_check(f: Finding) -> Finding:
    return dataclasses.replace(
        f,
        rule_id=CHECK_RULE,
        title="Checks login tokens sent to it",
        severity=Severity.LOW,
        message=(
            "Checks whether a login token or a signed link someone sent to the app is "
            "valid, and whose it is, the way Home Assistant's own login check does. Only "
            "that is used: the token itself and the key that signs it aren't read."
        ),
    )
