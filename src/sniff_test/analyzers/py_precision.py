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
  file or folder (starts with its domain) is `ha-own-storage-path` (low, a practice
  note); into `auth*`, `core.config_entries` or `onboarding` through a constant is
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
import json
import re

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
    # domain ("mqtt") must not make that integration's entries look like the app's.
    return frozenset({domain} | {d for d in res.domains if d.startswith(f"{domain}_")})


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
    return dataclasses.replace(
        f,
        rule_id="ha-own-storage-path",
        title="Builds its own .storage path by hand",
        severity=Severity.LOW,
        message=(
            "Builds a path to its own file in HA's .storage folder instead of using the "
            "homeassistant.helpers.storage.Store helper. Poor practice, not a risk."
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
