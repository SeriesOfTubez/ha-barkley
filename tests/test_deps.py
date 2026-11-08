"""Dependency analysis: unit tests with mocked uv / OSV / GuardDog / PyPI output."""

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sniff_test.analyzers import guarddog, osv, pypi_meta, python_deps
from sniff_test.deps import reqs
from sniff_test.deps.ha_env import HAEnv
from sniff_test.deps.uv import Artifact, parse_pylock
from sniff_test.models import AnalyzerState, Severity, Tag, Target, TargetKind

# --- requirement parsing ------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "name", "pinned"),
    [
        ("requests==2.31.0", "requests", "2.31.0"),
        ("Py_Foo.Bar>=1.0,<2", "py-foo-bar", None),
        ("aiohttp[speedups]==3.9.1", "aiohttp", "3.9.1"),
        ('pyserial==3.5; python_version >= "3.8"', "pyserial", "3.5"),
        ("dictor>=0.1.12,<0.2", "dictor", None),
        ("wrapt", "wrapt", None),
    ],
)
def test_plain_requirements(raw, name, pinned):
    r = reqs.parse(raw)
    assert (r.kind, r.name, r.pinned) == (reqs.ReqKind.PLAIN, name, pinned)


@pytest.mark.parametrize(
    "raw",
    [
        "git+https://github.com/x/y.git@main#egg=y",
        "foo @ https://example.invalid/foo-1.0.tar.gz",
        "foo@git+https://example.invalid/foo",
        "file:///tmp/foo",
        "./vendor/foo",
        "https://example.invalid/foo.whl",
    ],
)
def test_url_requirements(raw):
    assert reqs.parse(raw).kind is reqs.ReqKind.URL


@pytest.mark.parametrize(
    "raw",
    [
        "-e git+https://example.invalid/x",
        "--index-url=https://evil.invalid/simple",
        "-r /etc/passwd",
        "requests==2.31.0\n--extra-index-url https://evil.invalid",
        "requests===",
        42,
        None,
    ],
)
def test_option_like_or_malformed_requirements_are_invalid(raw):
    assert reqs.parse(raw).kind is reqs.ReqKind.INVALID


def test_constraint_names():
    text = "# c\n-c other.txt\naiohttp==3.14.5\nurllib3>=2.0\npycrypto==1000000000.0.0 # ban\n"
    assert reqs.constraint_names(text) == {
        "aiohttp": "3.14.5",
        "urllib3": None,
        "pycrypto": "1000000000.0.0",
    }


# --- typosquats (offline) ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("reqeusts", "requests"),
        ("urlib3", "urllib3"),
        ("colourama", "colorama"),
        ("pythondateutil", "python-dateutil"),
        ("python-dateutill", "python-dateutil"),
    ],
)
def test_typosquat_detected(name, target):
    assert pypi_meta.typosquat_target(name) == target


@pytest.mark.parametrize("name", ["requests", "urllib3", "aiohttp", "pyyaml", "alexapy"])
def test_popular_or_unrelated_names_are_not_typosquats(name):
    assert pypi_meta.typosquat_target(name) is None


def test_ha_known_names_are_never_typosquats():
    # pysml is a real HA library one edit from pyaml (in the top-1000 list)
    assert pypi_meta.typosquat_target("pysml", known=frozenset({"pysml"})) is None


def test_ha_constraint_names_are_squat_targets():
    assert pypi_meta.typosquat_target("hass-nabucasaa", extra_targets=("hass-nabucasa",)) == (
        "hass-nabucasa"
    )


# --- fake HA env --------------------------------------------------------------------------


def _env(tmp_path: Path, shipped=frozenset(), constraints=None) -> HAEnv:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "package_constraints.txt").write_text("aiohttp==3.14.5\n")
    env = HAEnv(
        version="2026.11.0",
        python_version="3.14.10",
        dir=tmp_path,
        constraints=constraints or {"aiohttp": "3.14.5"},
        core_names=frozenset({"aiohttp"}),
    )
    env._shipped = {"x86_64": shipped, "aarch64": shipped}
    return env


def test_ha_provided_requires_exact_version_on_every_platform(tmp_path):
    env = _env(tmp_path, shipped=frozenset({("idna", "3.20")}))
    assert env.is_ha_provided("idna", "3.20", {"x86_64", "aarch64"})
    assert not env.is_ha_provided("idna", "3.19", {"x86_64"})
    assert not env.is_ha_provided("alexapy", "1.0", {"x86_64"})
    env._shipped["aarch64"] = frozenset()
    assert not env.is_ha_provided("idna", "3.20", {"x86_64", "aarch64"})


# --- uv output handling -------------------------------------------------------------------

PYLOCK = """
lock-version = "1.0"
created-by = "uv"

[[packages]]
name = "Some_Pkg"
version = "1.2.3"
wheels = [
  { url = "https://h.invalid/some_pkg-1.2.3-cp314-musllinux_1_2_x86_64.whl", hashes = {} },
  { url = "https://h.invalid/some_pkg-1.2.3-py3-none-any.whl", hashes = { sha256 = "bb" } },
]
"""


def test_parse_pylock(tmp_path):
    p = tmp_path / "pylock.toml"
    p.write_text(PYLOCK)
    [(name, version, arts)] = parse_pylock(p)
    assert (name, version) == ("some-pkg", "1.2.3")
    assert [a.sha256 for a in arts] == [None, "bb"]
    assert arts[1].filename == "some_pkg-1.2.3-py3-none-any.whl"


@pytest.mark.parametrize(
    ("stderr", "name", "reason", "version"),
    [
        (
            "  cause: Because reqeusts was not found in the package registry and you require "
            "reqeusts==2.31.0, we can conclude that your requirements are unsatisfiable.",
            "reqeusts",
            "not_found",
            None,
        ),
        (
            "  cause: Because docopt==0.6.2 has no usable wheels and you require docopt==0.6.2, "
            "...\n\nhint: Wheels are required for `docopt` because building from source is "
            "disabled for all packages (i.e., with `--no-build`)",
            "docopt",
            "sdist_only",
            "0.6.2",
        ),
        (
            "  cause: Because you require numpy==1.21.0 and numpy==2.3.2, we can conclude ...",
            "numpy",
            "conflict",
            None,
        ),
    ],
)
def test_find_culprit(stderr, name, reason, version):
    c = python_deps.find_culprit("error: No solution found\n" + stderr)
    assert (c.name, c.reason, c.version) == (name, reason, version)


def test_find_culprit_unknown_error():
    assert python_deps.find_culprit("error: Failed to fetch: connection reset") is None


def test_static_requires_reads_pkg_info_without_running_anything(tmp_path):
    root = tmp_path / "foo-1.0"
    root.mkdir()
    (root / "PKG-INFO").write_text(
        "Metadata-Version: 2.2\nName: foo\nVersion: 1.0\nRequires-Dist: requests>=2\n"
        'Requires-Dist: pytest; extra == "test"\n\nlong description\n'
    )
    (root / "setup.py").write_text("raise SystemExit('must never run')\n")
    assert python_deps.static_requires(tmp_path) == ["requests>=2"]


def _integration(tmp_path, requirements) -> Target:
    root = tmp_path / "cc" / "x"
    root.mkdir(parents=True)
    (root / "manifest.json").write_text(json.dumps({"domain": "x", "requirements": requirements}))
    return Target(source="x", kind=TargetKind.INTEGRATION, root=root)


def test_resolver_excludes_culprit_and_resolves_the_rest(tmp_path, monkeypatch):
    calls = []

    def fake_compile(exe, req_file, out, *, excludes=None, platform, **kw):
        calls.append((platform, req_file.read_text(), excludes.read_text()))
        if "reqeusts" not in excludes.read_text():
            return subprocess.CompletedProcess(
                [], 1, "", "  cause: Because reqeusts was not found in the package registry"
            )
        out.write_text(PYLOCK)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(python_deps.uv, "exe", lambda: "/bin/uv")
    monkeypatch.setattr(python_deps.uv, "compile_lock", fake_compile)
    monkeypatch.setattr(python_deps, "uv_version", lambda: "0.13.7")
    target = _integration(tmp_path, ["reqeusts==2.31.0", "some-pkg", "-e git+x"])
    ws = tmp_path / "ws"
    ws.mkdir()
    result, resolution = python_deps.run(target, ws, _env(tmp_path / "env"))
    assert result.state is AnalyzerState.OK
    assert "-e" not in calls[0][1]  # invalid lines never reach uv
    [f] = result.findings
    assert f.rule_id == "dep-unresolvable"
    assert f.platforms == {"x86_64", "aarch64"}
    [pkg] = resolution.third_party()
    assert pkg.name == "some-pkg" and pkg.platforms == {"x86_64", "aarch64"}
    assert set(resolution.lockfiles) == {"x86_64", "aarch64"}


def test_resolver_unknown_failure_marks_scan_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(python_deps.uv, "exe", lambda: "/bin/uv")
    monkeypatch.setattr(
        python_deps.uv,
        "compile_lock",
        lambda *a, **k: subprocess.CompletedProcess([], 2, "", "error: network down"),
    )
    monkeypatch.setattr(python_deps, "uv_version", lambda: "0.13.7")
    target = _integration(tmp_path, ["foo==1.0"])
    ws = tmp_path / "ws"
    ws.mkdir()
    result, _ = python_deps.run(target, ws, _env(tmp_path / "env"))
    assert result.state is AnalyzerState.ERROR


def test_resolver_without_ha_env_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(python_deps.uv, "exe", lambda: "/bin/uv")
    monkeypatch.setattr(python_deps, "uv_version", lambda: "0.13.7")
    result, resolution = python_deps.run(_integration(tmp_path, ["foo"]), tmp_path, None)
    assert result.state is AnalyzerState.SKIPPED
    assert resolution.requirements[0].name == "foo"


# --- package metadata -----------------------------------------------------------------


def test_meta_flags_url_and_option_requirements_offline():
    parsed = [reqs.parse(r) for r in ["git+https://x.invalid/y", "--index-url=https://e.invalid"]]
    result = pypi_meta.run(parsed, None, None, online=False)
    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["dep-vcs-or-url-requirement"].severity is Severity.HIGH
    assert by_rule["dep-invalid-requirement"].severity is Severity.HIGH


def test_meta_very_new_package(tmp_path, monkeypatch):
    now = datetime(2026, 11, 8, tzinfo=UTC)
    uploads = {
        "fresh": now - timedelta(days=3),
        "old": now - timedelta(days=900),
    }

    def fake_get_json(url):
        name = url.split("/")[-2]
        if name == "ha-only":
            raise pypi_meta.http.NotFoundError(url)
        t = uploads[name].isoformat().replace("+00:00", "Z")
        return {"releases": {"1.0": [{"upload_time_iso_8601": t}]}}

    monkeypatch.setattr(pypi_meta.http, "get_json", fake_get_json)
    res = python_deps.Resolution(requirements=[reqs.parse("fresh"), reqs.parse("old")])
    for n in ("fresh", "old", "ha-only"):
        res.packages[(n, "1.0")] = python_deps.ResolvedPackage(n, "1.0", {"x86_64"})
    result = pypi_meta.run(res.requirements, res, _env(tmp_path), now=now)
    assert [f.rule_id for f in result.findings] == ["dep-very-new-package"]
    assert "fresh" in result.findings[0].evidence
    assert result.state is AnalyzerState.OK


# --- OSV ----------------------------------------------------------------------------------


def _pkg(name, vulns, groups, ecosystem="PyPI"):
    return osv._Pkg(name, "1.0", ecosystem, {v["id"]: v for v in vulns}, groups)


def test_osv_mal_advisory_is_critical_malware():
    p = _pkg("flatmap-stream", [{"id": "MAL-2025-20690"}], [{"ids": ["MAL-2025-20690"]}], "npm")
    [f] = osv.to_findings([p], "package-lock.json", set())
    assert f.rule_id == "dep-malicious" and f.severity is Severity.CRITICAL
    assert Tag.MALWARE in f.tags


def test_osv_github_malware_cwe_counts_as_malicious():
    v = {"id": "GHSA-mh6f-8j2x-4483", "database_specific": {"cwe_ids": ["CWE-506"]}}
    [f] = osv.to_findings([_pkg("event-stream", [v], [{"ids": [v["id"]]}])], None, set())
    assert f.rule_id == "dep-malicious"


def test_osv_vulns_aggregate_per_package_with_cvss_severity_and_inbound_tag():
    vulns = [
        {"id": "A", "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]},
        {"id": "B", "severity": [{"score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}]},
    ]
    groups = [{"ids": ["A"], "max_severity": "7.5"}, {"ids": ["B"], "max_severity": "3.1"}]
    [f] = osv.to_findings([_pkg("idna", vulns, groups)], "manifest.json", set())
    assert f.rule_id == "dep-vuln" and f.severity is Severity.HIGH
    assert Tag.INBOUND in f.tags
    assert "A, B" in f.evidence


def test_osv_vulns_in_ha_provided_packages_are_dropped_but_malware_is_not():
    vuln = _pkg("aiohttp", [{"id": "X"}], [{"ids": ["X"], "max_severity": "5.0"}])
    mal = _pkg("aiohttp", [{"id": "MAL-1"}], [{"ids": ["MAL-1"]}])
    assert osv.to_findings([vuln], None, {"aiohttp"}) == []
    assert osv.to_findings([mal], None, {"aiohttp"})[0].rule_id == "dep-malicious"


def test_osv_ghsa_label_used_when_no_cvss():
    v = {"id": "G", "database_specific": {"severity": "MODERATE"}}
    [f] = osv.to_findings([_pkg("x", [v], [{"ids": ["G"], "max_severity": ""}])], None, set())
    assert f.severity is Severity.MEDIUM


def _card(tmp_path, package_json=None) -> Target:
    src = tmp_path / "src"
    src.mkdir()
    if package_json is not None:
        (src / "package.json").write_text(json.dumps(package_json))
    return Target(source="x", kind=TargetKind.PLUGIN, root=src, source_root=src)


def test_card_without_lockfile_gets_low_finding(tmp_path):
    result = osv.run_npm(_card(tmp_path, {"dependencies": {"lit": "^3"}}), tmp_path)
    assert [f.rule_id for f in result.findings] == ["dep-npm-no-lockfile"]


def test_card_without_npm_deps_is_not_applicable(tmp_path):
    assert osv.run_npm(_card(tmp_path), tmp_path).state is AnalyzerState.NOT_APPLICABLE


# --- GuardDog -------------------------------------------------------------------------------


def test_guarddog_mapping_keeps_threats_only():
    data = {
        "results": {
            "capability-network-outbound": [{"location": "a.py:1", "match": "requests.post"}],
            "threat-runtime-environment-read": [{"location": "a.py:2", "match": "os.environ"}],
            "threat-network-exfil-messenger": [
                {"location": "a.py:3", "match": "discord.com/api/webhooks/1/", "message": "m"},
                {"location": "b.py:9", "match": "discord.com/api/webhooks/2/"},
            ],
            "threat-runtime-obfuscation-base64exec": [{"location": "a.py:4", "match": "b64"}],
            "threat-brand-new-rule": [{"location": "a.py:5", "match": "?"}],
            "threat-filesystem-read": {},
        }
    }
    pkg = python_deps.ResolvedPackage("evil", "1.0", {"x86_64", "aarch64"})
    art = Artifact("https://x", "evil-1.0-cp314-cp314-musllinux_1_2_x86_64.whl", None, "wheel")
    found = {f.rule_id: f for f in guarddog.to_findings(data, pkg, art)}
    assert set(found) == {
        "dep-guarddog-network-exfil-messenger",
        "dep-guarddog-runtime-obfuscation-base64exec",
        "dep-guarddog-brand-new-rule",
    }
    exfil = found["dep-guarddog-network-exfil-messenger"]
    assert exfil.severity is Severity.HIGH and Tag.POSSIBLE in exfil.tags
    assert exfil.platforms == {"x86_64"}  # arch-specific wheel
    assert "and 1 more" in exfil.message
    assert found["dep-guarddog-brand-new-rule"].severity is Severity.LOW
    assert all(f.severity < Severity.CRITICAL for f in found.values())


def test_guarddog_skips_ha_provided_packages(tmp_path):
    res = python_deps.Resolution()
    res.packages[("aiohttp", "3.14.5")] = python_deps.ResolvedPackage(
        "aiohttp", "3.14.5", {"x86_64"}, ha_provided=True
    )
    assert guarddog.run(res, tmp_path).state is AnalyzerState.NOT_APPLICABLE
