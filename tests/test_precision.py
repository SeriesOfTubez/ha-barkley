"""(0.14.0) Part 2 of the feedback plan: rule precision, each change on a synthetic case.

All names are made up. Hosts use .invalid / .example. Nothing here runs scanned code:
the analyzers parse it.
"""

from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path

import pytest

from sniff_test.analyzers import correlate, osv, py_precision, repo_signals, semgrep
from sniff_test.analyzers.endpoints import Declared
from sniff_test.analyzers.py_resolve import Resolver
from sniff_test.models import Category, Evidence, Fact, Finding, Ring, Severity, Target, TargetKind

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")


def _integration(tmp_path: Path, files: dict[str, str], domain: str = "acme_power") -> Target:
    root = tmp_path / "custom_components" / domain
    root.mkdir(parents=True)
    (root / "manifest.json").write_text(json.dumps({"domain": domain, "name": "Acme"}))
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return Target(source=str(root), kind=TargetKind.INTEGRATION, root=root, domain=domain)


def _run(tmp_path: Path, files: dict[str, str], domain: str = "acme_power"):
    target = _integration(tmp_path, files, domain)
    work = tmp_path / "work"
    work.mkdir()
    return semgrep.run(target, work), target


def _hits(result, rule: str) -> list[int]:
    return sorted(f.line for f in result.findings if f.rule_id == rule)


# --- bug 1a: the integration's own entries -------------------------------------------

OWN_ENTRIES = {
    "const.py": 'DOMAIN = "acme_power"\nKIND = "kind"\n',
    "__init__.py": """\
        from .const import DOMAIN, KIND


        def own(hass):
            for entry in hass.config_entries.async_entries(DOMAIN, include_ignore=False):
                print(entry.data[KIND])
            a = [e.data for e in hass.config_entries.async_entries(DOMAIN, include_disabled=False)]
            b = {e.data["k"] for e in hass.config_entries.async_entries(DOMAIN, False)}
            c = [e.data for e in hass.config_entries.async_entries("acme_power")]
            return a, b, c
        """,
}


@needs_semgrep
def test_own_entries_with_extra_arguments_are_no_finding(tmp_path):
    result, _ = _run(tmp_path, OWN_ENTRIES)
    assert _hits(result, "ha-foreign-entry-data") == []


FOREIGN_DOMAIN = {
    "__init__.py": """\
        from homeassistant.components.mqtt import DOMAIN
        from .const import OTHER

        WRONG = "someone_else"


        def foreign(hass):
            for entry in hass.config_entries.async_entries(DOMAIN):
                print(entry.data)
            x = [e.data for e in hass.config_entries.async_entries(OTHER, include_ignore=False)]
            y = [e.data for e in hass.config_entries.async_entries(WRONG)]
            z = [e.data for e in hass.config_entries.async_entries()]
            return x, y, z
        """,
    "const.py": 'OTHER = "tplink"\n',
}


@needs_semgrep
def test_a_domain_constant_that_is_another_integrations_stays(tmp_path):
    result, _ = _run(tmp_path, FOREIGN_DOMAIN)
    # DOMAIN imported from another integration, a constant holding another domain, a
    # literal that isn't the manifest's, and every entry: all foreign
    assert _hits(result, "ha-foreign-entry-data") == [9, 10, 11, 12]


@needs_semgrep
def test_a_sub_integration_shipped_inside_the_app_is_its_own(tmp_path):
    result, _ = _run(
        tmp_path,
        {
            "integrations/acme_power_inverse/manifest.json": '{"domain": "acme_power_inverse"}',
            "integrations/acme_power_inverse/const.py": 'DOMAIN = "acme_power_inverse"\n',
            "integrations/acme_power_inverse/__init__.py": """\
                from .const import DOMAIN


                def others(hass):
                    return [e.options for e in hass.config_entries.async_entries(DOMAIN)]
                """,
        },
    )
    assert _hits(result, "ha-foreign-entry-options") == []


@needs_semgrep
def test_a_nested_manifest_cannot_claim_another_domain(tmp_path):
    result, _ = _run(
        tmp_path,
        {
            "shim/manifest.json": '{"domain": "mqtt"}',
            "__init__.py": """\
                def grab(hass):
                    return [e.data for e in hass.config_entries.async_entries("mqtt")]
                """,
        },
    )
    assert _hits(result, "ha-foreign-entry-data") == [2]


# --- bug 1b: a foreign entry read for a non-secret field ------------------------------

SAFE_FIELDS = {
    "__init__.py": """\
        from homeassistant.const import CONF_HOST, CONF_MAC, CONF_PASSWORD

        CONF_NAME = "password"


        def used_by_other(hass, host):
            for entry in hass.config_entries.async_entries("tplink", include_ignore=False):
                if entry.data.get(CONF_HOST) != host:
                    continue
                mac = entry.data[CONF_MAC]
                label = entry.data.get("unique_id", "")
                secret = entry.data.get(CONF_PASSWORD)
                fake = entry.data.get(CONF_NAME)
                everything = dict(entry.data)
                for key in entry.data:
                    print(key)
            return mac, label, secret, fake, everything
        """,
}


@needs_semgrep
def test_only_non_secret_fields_of_a_foreign_entry_are_no_finding(tmp_path):
    result, _ = _run(tmp_path, SAFE_FIELDS)
    # host / mac / unique_id pass; a password, a local CONF_NAME that holds "password",
    # the whole data and iterating it stay high
    assert _hits(result, "ha-foreign-entry-data") == [12, 13, 14, 15]


# --- change 8: other integrations' options are medium ---------------------------------


@needs_semgrep
def test_foreign_options_are_medium_and_own_options_nothing(tmp_path):
    result, _ = _run(
        tmp_path,
        {
            "__init__.py": """\
                DOMAIN = "acme_power"


                def check(hass):
                    theirs = [e.options for e in hass.config_entries.async_entries("template")]
                    mine = [e.options for e in hass.config_entries.async_entries(DOMAIN)]
                    return theirs, mine
                """
        },
    )
    hits = [f for f in result.findings if f.rule_id == "ha-foreign-entry-options"]
    assert [(f.line, f.severity) for f in hits] == [(5, Severity.MEDIUM)]
    assert _hits(result, "ha-foreign-entry-data") == []


# --- change 7: auth internals in three rules ------------------------------------------


@needs_semgrep
def test_auth_split(tmp_path):
    result, _ = _run(
        tmp_path,
        {
            "__init__.py": """\
                async def users(hass, user):
                    people = await hass.auth.async_get_users()
                    await hass.auth.async_update_user(user, is_active=False)
                    token = await hass.auth.async_create_refresh_token(user)
                    return people, token
                """
        },
    )
    sev = {f.rule_id: (f.line, f.severity) for f in result.findings}
    assert sev["ha-auth-list-users"] == (2, Severity.MEDIUM)
    assert sev["ha-auth-change-users"] == (3, Severity.HIGH)
    assert sev["ha-auth-internals"] == (4, Severity.HIGH)


# --- .storage in three levels ---------------------------------------------------------

STORAGE = {
    "const.py": 'DOMAIN = "acme_power"\n',
    "store.py": """\
        from pathlib import Path

        from .const import DOMAIN

        RENDERS = f"{DOMAIN}_renders"
        AUTH = "auth"


        def paths(hass, name):
            a = hass.config.path(".storage", RENDERS)
            b = hass.config.path(f".storage/{DOMAIN}.{name}.json")
            c = hass.config.path(".storage", AUTH)
            d = hass.config.path(".storage", "someone_else.data")
            e = hass.config.path(".storage")
            f = hass.config.path(".storage", name)
            g = hass.config.path(".storage", "acme_powerful.data")
            return a, b, c, d, e, f, g
        """,
}


@needs_semgrep
def test_storage_levels(tmp_path):
    result, _ = _run(tmp_path, STORAGE)
    got = {(f.line, f.rule_id, f.severity) for f in result.findings if "storage" in f.rule_id}
    assert got == {
        (10, "ha-own-storage-path", Severity.LOW),  # its own folder through a constant
        (11, "ha-own-storage-path", Severity.LOW),  # its own file in an f-string
        (12, "ha-read-auth-storage", Severity.HIGH),  # auth through a constant
        (13, "ha-raw-storage-access", Severity.MEDIUM),  # someone else's file
        (14, "ha-raw-storage-access", Severity.MEDIUM),  # the whole folder
        (15, "ha-raw-storage-access", Severity.MEDIUM),  # can't tell
        (16, "ha-raw-storage-access", Severity.MEDIUM),  # a longer name, not its own
    }


# --- change 9: runtime installs from a fixed list -------------------------------------

PIP = {
    "__init__.py": """\
        import subprocess
        import sys

        from homeassistant.requirements import async_process_requirements

        DOMAIN = "acme_power"
        RADIO = "acme-radio==1.2.0"


        async def setup(hass, user_list):
            await async_process_requirements(hass, DOMAIN, [RADIO, "acme-serial>=3.5"])
            await async_process_requirements(hass, DOMAIN, user_list)
            subprocess.run([sys.executable, "-m", "pip", "install", "acme-extra==2.0"])
            subprocess.run(["pip", "install", "--index-url", "https://pkgs.invalid", "x"])
            await async_process_requirements(hass, DOMAIN, ["git+https://code.invalid/x"])
        """,
}


@needs_semgrep
def test_fixed_package_lists_are_low_and_get_scanned(tmp_path):
    result, target = _run(tmp_path, PIP)
    got = sorted((f.line, f.rule_id) for f in result.findings if "pip" in f.rule_id)
    assert got == [
        (11, "py-runtime-pip-listed"),
        (12, "py-runtime-pip"),  # a variable: stays high
        (13, "py-runtime-pip-listed"),
        (14, "py-runtime-pip"),  # an index URL: stays high
        (15, "py-runtime-pip"),  # a URL requirement: stays high
    ]
    assert target.runtime_requirements == [
        "acme-radio==1.2.0",
        "acme-serial>=3.5",
        "acme-extra==2.0",
    ]


def test_runtime_requirements_join_the_manifests(tmp_path, monkeypatch):
    from sniff_test.analyzers import python_deps

    target = _integration(tmp_path, {})
    (target.root / "manifest.json").write_text(
        json.dumps({"domain": "acme_power", "requirements": ["acme-api==1.0"]})
    )
    target.runtime_requirements = ["acme-radio==1.2.0", "acme-api==1.0"]
    monkeypatch.setattr(python_deps.uv, "exe", lambda: None)  # stop before resolving
    _, resolution = python_deps.run(target, tmp_path, None)
    assert [r.raw for r in resolution.requirements] == ["acme-api==1.0", "acme-radio==1.2.0"]


def test_pip_listed_needs_a_parse(tmp_path):
    target = _integration(tmp_path, {"broken.py": "def (:\n"})
    f = Finding("py-runtime-pip", "t", Severity.HIGH, Category.CODE_EXEC, "m", "broken.py", 1)
    assert py_precision.pip_listed(f, Resolver(target.root)) is None


# --- the resolver ---------------------------------------------------------------------


def test_resolver_follows_relative_imports_and_refuses_doubt(tmp_path):
    target = _integration(
        tmp_path,
        {
            "const.py": 'DOMAIN = "acme_power"\nTWICE = "a"\nTWICE = "b"\n',
            "sub/__init__.py": "",
            "sub/mod.py": "from ..const import DOMAIN, TWICE\nNAME = f'{DOMAIN}_x'\n",
            "py314.py": "try:\n    pass\nexcept ValueError, TypeError:\n    pass\nK = 'v'\n",
        },
    )
    res = Resolver(target.root)
    assert res.constant("sub/mod.py", "NAME") == "acme_power_x"
    assert res.constant("sub/mod.py", "TWICE") is None  # assigned twice: not certain
    assert res.constant("py314.py", "K") == "v"  # Python 3.14 except syntax parses


# --- bug 2: a name that spans the top-level domain -------------------------------------


def test_declared_name_spanning_the_tld():
    d = Declared(hosts=set(), names={"acmeenergy"})
    assert d.matches("api.backend.acme.energy")
    assert d.matches("acme.energy")
    assert not d.matches("acme.example")  # no prefix matching
    assert not d.matches("acmeenergy-cdn.invalid.example")
    assert Declared(hosts=set(), names={"acme"}).matches("api.acme.example")  # as before


# --- bug 3: yarn.lock and pnpm-lock.yaml runtime closure -------------------------------

PACKAGE_JSON = {
    "dependencies": {"widget": "^3.3.0", "@acme/util": "^1.0.0"},
    "devDependencies": {"bundler": "^4.0.0"},
}

YARN_V1 = """\
# yarn lockfile v1


"@acme/util@^1.0.0":
  version "1.0.2"
  resolved "https://registry.invalid/u.tgz"

bundler@^4.0.0:
  version "4.5.9"
  dependencies:
    esparse "^0.18.0"
    "@acme/util" "^1.0.0"

esparse@^0.18.0:
  version "0.18.20"

widget@^3.3.0:
  version "3.3.0"
  dependencies:
    widget-core "^2.1.0"

widget-core@^2.1.0, widget-core@^2.0.0:
  version "2.1.0"
"""

YARN_BERRY = """\
__metadata:
  version: 8
  cacheKey: 10

"@acme/util@npm:^1.0.0":
  version: 1.0.2
  resolution: "@acme/util@npm:1.0.2"
  languageName: node

"bundler@npm:^4.0.0":
  version: 4.5.9
  dependencies:
    esparse: "npm:^0.18.0"
  languageName: node

"esparse@npm:^0.18.0":
  version: 0.18.20
  languageName: node

"card@workspace:.":
  version: 0.0.0-use.local
  dependencies:
    bundler: "npm:^4.0.0"
    widget: "npm:^3.3.0"

"widget@npm:^3.3.0":
  version: 3.3.0
  dependencies:
    "widget-core": "npm:^2.1.0"

"widget-core@npm:^2.1.0":
  version: 2.1.0
"""

PNPM_V9 = """\
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@acme/util':
        specifier: ^1.0.0
        version: 1.0.2
      widget:
        specifier: ^3.3.0
        version: 3.3.0
    devDependencies:
      bundler:
        specifier: ^4.0.0
        version: 4.5.9(@types/node@20.0.0)

packages:

  '@acme/util@1.0.2':
    resolution: {integrity: sha512-x}

snapshots:

  '@acme/util@1.0.2': {}

  bundler@4.5.9(@types/node@20.0.0):
    dependencies:
      esparse: 0.18.20

  esparse@0.18.20: {}

  widget-core@2.1.0: {}

  widget@3.3.0:
    dependencies:
      widget-core: 2.1.0
"""

PNPM_V6 = """\
lockfileVersion: '6.0'

dependencies:
  widget:
    specifier: ^3.3.0
    version: 3.3.0

devDependencies:
  bundler:
    specifier: ^4.0.0
    version: 4.5.9

packages:

  /bundler@4.5.9:
    resolution: {integrity: sha512-x}
    dependencies:
      esparse: 0.18.20
    dev: true

  /esparse@0.18.20:
    dev: true

  /widget-core@2.1.0:
    dev: false

  /widget@3.3.0:
    dependencies:
      widget-core: 2.1.0
    dev: false
"""

DEV = {("bundler", "4.5.9"), ("esparse", "0.18.20")}


@pytest.mark.parametrize(
    "name,text", [("yarn.lock", YARN_V1), ("yarn.lock", YARN_BERRY), ("pnpm-lock.yaml", PNPM_V9)]
)
def test_lockfile_runtime_closure(tmp_path, name, text):
    (tmp_path / "package.json").write_text(json.dumps(PACKAGE_JSON))
    (tmp_path / name).write_text(text)
    assert osv.npm_dev_only(tmp_path / name) == DEV


def test_pnpm_v6(tmp_path):
    pkg = {"dependencies": {"widget": "^3.3.0"}, "devDependencies": {"bundler": "^4.0.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    (tmp_path / "pnpm-lock.yaml").write_text(PNPM_V6)
    assert osv.npm_dev_only(tmp_path / "pnpm-lock.yaml") == DEV


def test_a_package_reached_from_both_sides_is_bundled(tmp_path):
    # @acme/util is a dev tool's dependency AND a runtime one: it ships
    (tmp_path / "package.json").write_text(json.dumps(PACKAGE_JSON))
    (tmp_path / "yarn.lock").write_text(YARN_V1)
    assert ("@acme/util", "1.0.2") not in osv.npm_dev_only(tmp_path / "yarn.lock")


@pytest.mark.parametrize("name", ["yarn.lock", "pnpm-lock.yaml"])
def test_lockfile_walk_falls_back_to_bundled(tmp_path, name):
    if name == "yarn.lock":  # yarn needs package.json to know the roots (pnpm doesn't)
        (tmp_path / name).write_text(YARN_V1)
        assert osv.npm_dev_only(tmp_path / name) == set()
    (tmp_path / "package.json").write_text(json.dumps(PACKAGE_JSON))
    (tmp_path / name).write_text("garbage: [\n")
    assert osv.npm_dev_only(tmp_path / name) == set()


# --- minor A: a release that only fills in a constant ---------------------------------


def _pair(tmp_path: Path, tagged: str, released: str) -> tuple[Path, Path]:
    a, b = tmp_path / "zip", tmp_path / "tag"
    for root, text in ((a, released), (b, tagged)):
        root.mkdir()
        (root / "keys.py").write_text(textwrap.dedent(text))
        (root / "manifest.json").write_text('{"domain": "acme_power"}')
    return a, b


def test_release_that_fills_in_a_constant_is_medium(tmp_path):
    a, b = _pair(tmp_path, 'PROJECT_KEY = ""\nX = 1\n', 'PROJECT_KEY = "k-123abc"\nX = 1\n')
    out = repo_signals.compare_integration_asset(a, b)
    assert [(f.rule_id, f.severity) for f in out] == [
        ("repo-release-fills-constant", Severity.MEDIUM)
    ]
    assert "PROJECT_KEY" in out[0].evidence and "k-123abc" not in out[0].evidence


@pytest.mark.parametrize(
    "tagged,released",
    [
        ('KEY = ""\n', 'KEY = "https://collect.invalid/x"\n'),  # an address
        ('KEY = ""\n', 'KEY = "203.0.113.9"\n'),  # an IP
        ('KEY = ""\n', 'KEY = "collect.example.com"\n'),  # a host
        ('KEY = "old"\n', 'KEY = "new"\n'),  # not empty at the tag
        ('KEY = ""\n', 'KEY = "k"\nimport os\n'),  # more than the constant
        ('KEY = ""\n', 'KEY = "k" + "j"\n'),  # not a literal
    ],
)
def test_anything_more_stays_high(tmp_path, tagged, released):
    a, b = _pair(tmp_path, tagged, released)
    out = repo_signals.compare_integration_asset(a, b)
    assert [(f.rule_id, f.severity) for f in out] == [
        ("repo-release-source-mismatch", Severity.HIGH)
    ]


# --- change 11: only credential sources pair into possible-exfil ----------------------


def _corr(tmp_path: Path, rule: str) -> list[Finding]:
    src = Finding(rule, "t", Severity.HIGH, Category.SENSITIVE_ACCESS, "m", "ws.py", 3)
    facts = [
        Fact(
            Ring.NETWORK,
            "host",
            "store.invalid",
            "connects_to",
            Evidence.POSSIBLE,
            attrs={"class": "undeclared"},
        ),
        Fact(
            Ring.NETWORK,
            "http_client",
            "aiohttp",
            "uses",
            Evidence.POSSIBLE,
            attrs={"outbound": True},
        ),
    ]
    return correlate.correlate([src], facts, tmp_path)


def test_listing_or_changing_users_no_longer_pairs_with_a_host(tmp_path):
    assert _corr(tmp_path, "ha-auth-change-users") == []
    assert [f.rule_id for f in _corr(tmp_path, "ha-foreign-entry-data")] == ["possible-exfil"]
    assert [f.rule_id for f in _corr(tmp_path, "ha-auth-internals")] == ["possible-exfil"]
