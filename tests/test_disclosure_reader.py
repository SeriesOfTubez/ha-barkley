"""(0.15) Reading a scanned repo's disclosure.yaml: hostile input, version 1 only.

tests/data holds copies of the published version 1 schema and sample (CC0 1.0, from
https://ha-barkley.github.io/disclosure/v1/). The sample is a made-up app; its hosts use
the reserved .example domain.
"""

import json
import time
from pathlib import Path

import pytest

from sniff_test.analyzers import disclosure as d

DATA = Path(__file__).parent / "data"
SAMPLE = (DATA / "disclosure-v1.sample.yaml").read_text()


def _read(tmp_path: Path, text: str | bytes):
    p = tmp_path / "disclosure.yaml"
    p.write_bytes(text.encode() if isinstance(text, str) else text)
    return d.read(tmp_path)


def test_the_published_sample_is_read(tmp_path):
    r = _read(tmp_path, SAMPLE)
    assert r["state"] == "read"
    data = r["data"]
    assert data["home_assistant_access"] == []  # an empty list says "none"
    assert data["connections"][0]["destination"] == "api.petalgarden.example"
    assert data["telemetry"][0]["on_by_default"] is False


def test_no_file_and_a_missing_section(tmp_path):
    assert d.read(tmp_path) is None
    assert d.read(None) is None
    r = _read(tmp_path, "version: 1\ntelemetry: []\n")
    assert r == {"state": "read", "data": {"telemetry": []}}  # connections: not stated


@pytest.mark.parametrize(
    ("text", "why"),
    [
        # a "billion laughs": aliases are refused before anything is built
        ("version: 1\na: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\n", "anchors or aliases"),
        ("version: 1\nx-a: *nowhere\n", "anchors or aliases"),
        ("version: !!int 1\n", "tags"),
        ("version: 1\nx-a: !!python/object/apply:os.system [echo]\n", "tags"),
        ("version: 1\nconnections: []\nconnections: []\n", "the key connections twice"),
        ("version: 1\nx-a: {<<: {b: 1}}\n", "merge key"),
        ("version: 1\n---\nversion: 1\n", "more than one YAML document"),
        ("version: 1\nx-a: " + "[" * 20 + "]" * 20 + "\n", "nested too deeply"),
        ("version: 1\n? [a]\n: b\n", "a key that isn't text"),
        ("version: 1\nx-a: [" + "1," * 25_000 + "]\n", "too large"),
        ("\tversion: 1\n", "isn't valid YAML"),
    ],
)
def test_hostile_yaml_is_refused(tmp_path, text, why):
    r = _read(tmp_path, text)
    assert r["state"] == "ignored" and "data" not in r
    assert why in r["problems"][0], r


def test_size_encoding_and_links(tmp_path):
    big = "version: 1\n# " + "x" * d.MAX_BYTES + "\n"
    assert "larger than 64 KB" in _read(tmp_path, big)["problems"][0]
    assert "UTF-8" in _read(tmp_path, b"version: 1\nx-a: \xff\n")["problems"][0]
    (tmp_path / "disclosure.yaml").unlink()
    (tmp_path / "secret").write_text("version: 1\n")
    (tmp_path / "disclosure.yaml").symlink_to(tmp_path / "secret")
    assert _read_link(tmp_path)["problems"] == ["The file isn't a plain file."]
    (tmp_path / "disclosure.yaml").unlink()
    (tmp_path / "disclosure.yaml").symlink_to(tmp_path / "gone")  # dangling
    assert _read_link(tmp_path)["problems"] == ["The file isn't a plain file."]
    (tmp_path / "disclosure.yaml").unlink()
    (tmp_path / "disclosure.yaml").mkdir()
    assert d.read(tmp_path)["state"] == "ignored"


def _read_link(root):
    return d.read(root)


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("connections: []\n", "version: missing"),
        ("version: 2\n", "version: Barkley reads version 1"),
        ("version: true\n", "version: Barkley reads version 1"),
        ("version: 1\nsecrets: []\n", "secrets: not a section of version 1"),
        ("version: 1\ntelemetry: {}\n", "telemetry: should be a list"),
        ("version: 1\npages: [{path: x, protection: none, purpose: p}]\n",
         "pages[0].path: should start with /"),
        ("version: 1\nconnections: [{source: browser, purpose: p, when: always}]\n",
         "connections[0]: needs destination or destination_set_by"),
        ("version: 1\nconnections: [{destination: a.example, source: browser, purpose: p,"
         " when: setting}]\n", "connections[0].setting: missing (needed when when is setting)"),
        # YAML 1.1 reads a bare "on" as true: the spec says to quote it
        ("version: 1\nconnections: [{destination: a.example, source: browser, purpose: p,"
         " when: setting, setting: on}]\n", "connections[0].setting: should be text"),
        ("version: 1\nconnections: [{destination: 'a..example', source: browser,"
         " purpose: p, when: always}]\n", "connections[0].destination: should be a host"),
        ("version: 1\nconnections: [{destination: a.example, source: browser, purpose: p,"
         " when: always, sends: [ip_address, ip_address]}]\n", "each of its values once"),
        ("version: 1\ntelemetry: [{destination: s.example, type: usage_stats,"
         " contents: c}]\n", "telemetry[0].on_by_default: missing"),
        ("version: 1\nlogin_tokens: [{kind: refresh, purpose: p, lifetime: forever}]\n",
         'lifetime: should read like "30 minutes"'),
        ("version: 1\nhome_assistant_access: [{uses: actions, purpose: p}]\n",
         ".actions: missing (needed when uses is actions)"),
        ("version: 1\nlinks: [{host: a.example, color: red}]\n", "links[0].color: not a field"),
    ],
)  # fmt: skip
def test_a_file_that_doesnt_follow_version_1_is_ignored(tmp_path, text, problem):
    r = _read(tmp_path, text)
    assert r["state"] == "ignored" and "data" not in r
    assert any(problem in p for p in r["problems"]), r["problems"]


def test_only_version_1_fields_are_kept_and_text_is_clipped(tmp_path):
    long = "y" * 1000
    r = _read(
        tmp_path,
        "version: 1\nx-tool: {anything: [1]}\n"
        f'links: [{{host: a.example, purpose: "a\\u0007b {long}", x-extra: 1}}]\n',
    )
    link = r["data"]["links"][0]
    assert set(link) == {"host", "purpose"} and "x-tool" not in r["data"]
    assert "\x07" not in link["purpose"] and len(link["purpose"]) == d.TEXT_MAX + 1  # + "…"
    many = "version: 1\ngenerated_files:\n" + "".join(f"  - path: f{i}\n" for i in range(150))
    r = _read(tmp_path, many)
    assert len(r["data"]["generated_files"]) == d.MAX_ENTRIES
    assert r["data"]["_clipped"] == ["generated_files"]


def test_problems_are_capped_and_hostile_keys_are_clipped(tmp_path):
    keys = "".join(f"k{i}{'z' * 200}: 1\n" for i in range(20))
    r = _read(tmp_path, "version: 1\n" + keys)
    assert len(r["problems"]) == d.MAX_PROBLEMS
    assert all(len(p) < 80 for p in r["problems"])


def test_hosts_without_backtracking():
    assert d.is_host("*.tile.openmaps.example") and d.is_host("192.0.2.1")
    assert d.is_host("2001:db8::1") and not d.is_host("a." * 200)
    for bad in ("a" * 70 + ".example", "-a.example", "a.example.", "*.", "a b.example", ""):
        assert not d.is_host(bad), bad
    for run in (":" * 30_000 + "x", "a-" * 30_000, "a." * 30_000 + "!", "*." * 30_000):
        t = time.perf_counter()
        d.is_host(run)
        assert time.perf_counter() - t < 0.2


def test_long_hostile_files_read_quickly(tmp_path):
    runs = [
        "version: 1\nx-a: '" + "a" * 60_000 + "'\n",
        "version: 1\nx-a: " + "a " * 30_000 + "\n",
        "version: 1\nx-a:\n" + "  - a\n" * 9_000,
        "version: 1\n" + "#" * 60_000 + "\n",
        'version: 1\nx-a: "' + "\\\\" * 30_000 + '"\n',
        "version: 1\nconnections:\n" + "  - {destination: a.example}\n" * 2_000,
    ]
    for text in runs:
        t = time.perf_counter()
        _read(tmp_path, text)
        assert time.perf_counter() - t < 5, text[:30]


def test_the_checks_match_the_published_schema():
    """Every section, field, required field and listed value of version 1, both ways."""
    schema = json.loads((DATA / "disclosure-v1.schema.json").read_text())
    defs = schema["$defs"]
    props = {k: v for k, v in schema["properties"].items() if k != "version"}
    assert set(props) == set(d.SECTIONS)
    for section, spec in d.SECTIONS.items():
        entry = defs[props[section]["items"]["$ref"].rsplit("/", 1)[-1]]
        assert set(entry["properties"]) == set(spec.fields), section
        assert tuple(entry.get("required", ())) == spec.required, section
        any_of = tuple(r["required"][0] for r in entry.get("anyOf", []))
        assert any_of == spec.any_of, section
        when = tuple(
            (next(iter(c["if"]["properties"])), next(iter(c["if"]["properties"].values()))["const"],
             c["then"]["required"][0])
            for c in entry.get("allOf", [])
        )  # fmt: skip
        assert when == spec.when, section
        for field, fs in entry["properties"].items():
            values = fs.get("enum") or defs.get(fs.get("$ref", "").rsplit("/", 1)[-1], {}).get(
                "enum"
            )
            if values:
                check = spec.fields[field]
                assert all(check(v) is None for v in values), (section, field)
                assert check("not-a-value") is not None, (section, field)
    sends = defs["sends"]["items"]["enum"]
    assert tuple(sends) == d.SENDS
    assert tuple(defs["run_by"]["enum"]) == d.RUN_BY
    assert tuple(defs["destination_set_by"]["enum"]) == d.SET_BY
