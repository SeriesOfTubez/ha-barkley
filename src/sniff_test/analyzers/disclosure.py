"""(0.15, his decision 2026-11-26) The developer's `disclosure.yaml`, version 1.

The file is the developer's own account of what the app connects to and handles
(https://ha-barkley.github.io/disclosure/). It never changes a finding, a score or a
reading: the panel shows it beside what the scan found and says where the two don't
match (report/disclosed.py).

The file comes from the scanned repository, so it's hostile input:
- one file only, `disclosure.yaml` at the repository's root; a link (symlink) or anything
  other than a plain file is refused, and at most MAX_BYTES are read;
- YAML is parsed by PyYAML's safe loader after a pass over its events that refuses
  anchors and aliases (no "billion laughs"), tags, merge keys, duplicate keys, keys that
  aren't text, more than one document, nesting deeper than MAX_DEPTH and more than
  MAX_EVENTS events. The event pass is a generator, so it stops at the first problem;
- the result is checked against version 1 by hand (no schema library), field by field,
  with the schema's types, values and required fields. Host names are checked label by
  label and IP addresses with `ipaddress`, never with a pattern that can backtrack;
- a file that doesn't follow version 1 is ignored, and the panel says why (the first
  MAX_PROBLEMS problems). Nothing from such a file is kept;
- from a file that does, only the fields version 1 defines are kept (`x-` keys are
  dropped), text is clipped to TEXT_MAX characters with control characters removed, and
  each section to MAX_ENTRIES entries. Everything is escaped where it's shown, and none
  of it is ever sent to the AI.
"""

from __future__ import annotations

import ipaddress
import os
import re
import stat
from pathlib import Path
from typing import Any

import yaml

from sniff_test.report.json_report import sanitize_untrusted

NAME = "disclosure.yaml"
SPEC = "https://ha-barkley.github.io/disclosure/"
MAX_BYTES = 64 * 1024
MAX_DEPTH = 8
MAX_EVENTS = 20_000
MAX_ENTRIES = 100
MAX_PROBLEMS = 5
TEXT_MAX = 300

# --- the version 1 schema, field by field ------------------------------------------------

_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_ACTION = re.compile(r"[a-z0-9_]{1,100}\.[a-z0-9_]{1,100}")
_LIFETIME = re.compile(r"[1-9][0-9]{0,5} (?:minutes?|hours?|days?)")

SENDS = ("ip_address", "physical_location", "map_area", "entity_states", "credentials",
         "device_ids", "ha_address", "media", "personal_details", "versions")  # fmt: skip
RUN_BY = ("developer", "vendor", "third_party", "user")
SET_BY = ("setup", "setting", "server_reply")


def is_host(v: Any) -> bool:
    """A host name (optionally `*.` for any subdomain) or an IP address."""
    if not isinstance(v, str) or not v or len(v) > 253:
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        pass
    name = v[2:] if v.startswith("*.") else v
    return all(_LABEL.fullmatch(label) for label in name.split("."))


def _is_url(v: Any) -> bool:
    return (
        isinstance(v, str)
        and len(v) <= 2000
        and v.startswith(("http://", "https://"))
        and len(v) > v.index("//") + 2
        and not any(c.isspace() for c in v)
    )


# Each check returns None when the value is fine, else what's wrong, in plain words.
def _text(v: Any) -> str | None:
    return None if isinstance(v, str) and v else "should be text"


def _bool(v: Any) -> str | None:
    return None if isinstance(v, bool) else "should be true or false"


def _one_of(*values: str):
    def check(v: Any) -> str | None:
        ok = isinstance(v, str) and v in values
        return None if ok else f"should be one of {', '.join(values)}"

    return check


def _host(v: Any) -> str | None:
    return None if is_host(v) else "should be a host name or an IP address"


def _destination(v: Any) -> str | None:
    if isinstance(v, list):
        if not v:
            return "should list at least one host"
        if len(v) != len({str(x) for x in v}):
            return "lists a host twice"
        return None if all(is_host(x) for x in v) else "should list host names or IP addresses"
    return _host(v)


def _list_of(item, *, at_least: int = 0, what: str = "values"):
    def check(v: Any) -> str | None:
        if not isinstance(v, list):
            return "should be a list"
        if len(v) < at_least:
            return f"should list at least {at_least}"
        if any(not isinstance(x, (str, int, bool)) for x in v) or len(v) != len(
            {repr(x) for x in v}
        ):
            return f"should list each of its {what} once"
        return None if all(item(x) for x in v) else f"has {what} that aren't allowed"

    return check


def _port(v: Any) -> str | None:
    ok = isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 65535
    return None if ok else "should be a port number from 1 to 65535"


def _path(v: Any) -> str | None:
    return None if isinstance(v, str) and v.startswith("/") else "should start with /"


def _pattern(rx: re.Pattern[str], what: str):
    def check(v: Any) -> str | None:
        return None if isinstance(v, str) and len(v) <= 300 and rx.fullmatch(v) else what

    return check


def _host_or_url(v: Any) -> str | None:
    return None if is_host(v) or _is_url(v) else "should be a host name or a web address"


def _url(v: Any) -> str | None:
    return None if _is_url(v) else "should be a web address starting with http:// or https://"


_SENDS = _list_of(lambda x: x in SENDS, what="values")
_TARGETS = _list_of(lambda x: x == "setup_address" or is_host(x), what="hosts")
_COMMON = {"component": _text, "note": _text}


class Entry:
    def __init__(self, fields, required=(), any_of=(), when=()):
        self.fields = {**fields, **_COMMON}
        self.required = required
        self.any_of = any_of  # at least one of these fields
        self.when = when  # (field, value, then required field)


SECTIONS: dict[str, Entry] = {
    "connections": Entry(
        {
            "destination": _destination,
            "destination_set_by": _one_of(*SET_BY),
            "port": _port,
            "source": _one_of("home_assistant", "browser"),
            "purpose": _text,
            "run_by": _one_of(*RUN_BY),
            "run_by_name": _text,
            "network": _one_of("home", "internet", "either"),
            "encrypted": _one_of("always", "never", "setting"),
            "encryption_setting": _text,
            "when": _one_of("always", "setting", "user_action"),
            "setting": _text,
            "condition": _text,
            "on_by_default": _bool,
            "sends": _SENDS,
        },
        required=("source", "purpose", "when"),
        any_of=("destination", "destination_set_by"),
        when=(
            ("when", "setting", "setting"),
            ("destination_set_by", "setting", "setting"),
            ("encrypted", "setting", "encryption_setting"),
        ),
    ),
    "links": Entry({"host": _host, "url": _url, "purpose": _text}, any_of=("host", "url")),
    "pages": Entry(
        {
            "path": _path,
            "protection": _one_of("none", "own_token", "signed_link", "webhook"),
            "local_only": _bool,
            "purpose": _text,
            "checks": _text,
        },
        required=("path", "protection", "purpose"),
    ),
    "credentials": Entry(
        {
            "what": _text,
            "asked_in": _one_of(
                "config_flow", "options_flow", "yaml", "card_config", "environment"
            ),
            "stored_in": _one_of("config_entry", "secrets_yaml", "card_config", "own_storage"),
            "sent_to": _list_of(
                lambda x: x == "setup_address" or is_host(x), at_least=1, what="hosts"
            ),
        },
        required=("what", "asked_in", "sent_to"),
    ),
    "login_tokens": Entry(
        {
            "kind": _one_of("long_lived", "refresh", "access", "dashboard_session"),
            "admin_user": _bool,
            "lifetime": _pattern(_LIFETIME, 'should read like "30 minutes" or "365 days"'),
            "given_to": _TARGETS,
            "purpose": _text,
        },
        required=("kind", "purpose"),
    ),
    "home_assistant_access": Entry(
        {
            "uses": _one_of(
                "secrets_file",
                "other_apps_settings",
                "other_apps_credentials",
                "user_list",
                "change_users",
                "login_store",
                "storage_files",
                "supervisor_api",
                "location_history",
                "patches_home_assistant",
                "actions",
            ),
            "actions": _list_of(
                lambda x: isinstance(x, str) and bool(_ACTION.fullmatch(x)),
                at_least=1,
                what="actions",
            ),
            "purpose": _text,
        },
        required=("uses", "purpose"),
        when=(("uses", "actions", "actions"),),
    ),
    "embedded_keys": Entry(
        {
            "file": _text,
            "kind": _one_of(
                "vendor_client_key", "vendor_certificate", "public_key", "test_value", "service_key"
            ),
            "same_for_every_user": _bool,
        },
        required=("file", "kind", "same_for_every_user"),
    ),
    "telemetry": Entry(
        {
            "destination": _destination,
            "type": _one_of("usage_stats", "analytics", "crash_reports"),
            "contents": _text,
            "on_by_default": _bool,
            "setting": _text,
            "run_by": _one_of(*RUN_BY),
            "run_by_name": _text,
            "sends": _SENDS,
        },
        required=("destination", "type", "contents", "on_by_default"),
    ),
    "encoded_content": Entry(
        {"file": _text, "kind": _one_of("image", "font", "key", "lookup_table", "data", "code")},
        required=("file", "kind"),
    ),
    "compiled_code": Entry(
        {"file": _text, "built_from": _url, "built_by": _one_of("ci", "developer")},
        required=("file", "built_by"),
    ),
    "runtime_downloads": Entry(
        {
            "what": _text,
            "kind": _one_of("python_package", "javascript", "script", "lua", "binary"),
            "destination": _host_or_url,
            "destination_set_by": _one_of(*SET_BY),
            "setting": _text,
            "pinned": _bool,
        },
        required=("what", "kind", "pinned"),
        any_of=("destination", "destination_set_by"),
        when=(("destination_set_by", "setting", "setting"),),
    ),
    "generated_files": Entry({"path": _text}, required=("path",)),
}

# --- reading --------------------------------------------------------------------------------


class _Refused(Exception):
    pass


def _key(k: Any) -> str:
    return sanitize_untrusted(str(k), 40)


def _events_ok(text: str) -> None:
    """Refuse what the safe loader would still accept but a reader shouldn't trust."""
    stack: list[list[Any]] = []  # [kind, keys seen, expecting a key]
    docs = 0
    for n, ev in enumerate(yaml.parse(text, Loader=yaml.SafeLoader)):
        if n > MAX_EVENTS:
            raise _Refused("is too large to read")
        if isinstance(ev, yaml.AliasEvent) or getattr(ev, "anchor", None):
            raise _Refused("uses YAML anchors or aliases")
        if getattr(ev, "tag", None):
            raise _Refused("uses YAML tags")
        if isinstance(ev, yaml.DocumentStartEvent):
            docs += 1
            if docs > 1:
                raise _Refused("holds more than one YAML document")
        top = stack[-1] if stack else None
        is_key = bool(top and top[0] == "map" and top[2])
        if isinstance(ev, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            if is_key:
                raise _Refused("has a key that isn't text")
            if top and top[0] == "map":
                top[2] = True
            stack.append(["map" if isinstance(ev, yaml.MappingStartEvent) else "seq", set(), True])
            if len(stack) > MAX_DEPTH:
                raise _Refused("is nested too deeply")
        elif isinstance(ev, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            stack.pop()
        elif isinstance(ev, yaml.ScalarEvent) and top and top[0] == "map":
            if is_key:
                if ev.value == "<<" and ev.style is None:
                    raise _Refused("uses a YAML merge key")
                if ev.value in top[1]:
                    raise _Refused(f"has the key {_key(ev.value)} twice")
                top[1].add(ev.value)
            top[2] = not is_key


def _check(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return ["the file should hold a list of sections, starting with version: 1"]
    problems: list[str] = []
    if "version" not in data:
        problems.append("version: missing (it should be 1)")
    elif data["version"] != 1 or isinstance(data["version"], bool):
        problems.append("version: Barkley reads version 1")
    for key, value in data.items():
        if not isinstance(key, str):
            problems.append("a key that isn't text")
            continue
        if key == "version" or key.startswith("x-"):
            continue
        spec = SECTIONS.get(key)
        if spec is None:
            problems.append(f"{_key(key)}: not a section of version 1")
            continue
        if not isinstance(value, list):
            problems.append(f"{key}: should be a list")
            continue
        for i, entry in enumerate(value):
            problems += [f"{key}[{i}]{p}" for p in _check_entry(spec, entry)]
        if len(problems) >= MAX_PROBLEMS:
            break
    return problems[:MAX_PROBLEMS]


def _check_entry(spec: Entry, entry: Any) -> list[str]:
    if not isinstance(entry, dict):
        return [": should be an entry with fields"]
    out = []
    for k, v in entry.items():
        if not isinstance(k, str):
            out.append(": a key that isn't text")
        elif k.startswith("x-"):
            continue
        elif k not in spec.fields:
            out.append(f".{_key(k)}: not a field here")
        elif (why := spec.fields[k](v)) is not None:
            out.append(f".{k}: {why}")
    out += [f".{k}: missing" for k in spec.required if k not in entry]
    if spec.any_of and not any(k in entry for k in spec.any_of):
        out.append(f": needs {' or '.join(spec.any_of)}")
    for field, value, then in spec.when:
        if entry.get(field) == value and then not in entry:
            out.append(f".{then}: missing (needed when {field} is {value})")
    return out


def _clean(v: Any) -> Any:
    if isinstance(v, str):
        return sanitize_untrusted(v, TEXT_MAX)
    if isinstance(v, list):
        return [_clean(x) for x in v]
    return v


def _keep(data: dict[str, Any]) -> dict[str, Any]:
    """Only what version 1 defines, clipped. Keys are the schema's own names."""
    out: dict[str, Any] = {}
    for key, spec in SECTIONS.items():
        if key not in data:
            continue  # missing: "not stated"; an empty list means "none"
        out[key] = [
            {k: _clean(v) for k, v in entry.items() if k in spec.fields}
            for entry in data[key][:MAX_ENTRIES]
        ]
        if len(data[key]) > MAX_ENTRIES:
            out.setdefault("_clipped", []).append(key)
    return out


def _read_bytes(root: Path) -> bytes | None:
    path = root / NAME
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _Refused("isn't a plain file" if path.is_symlink() else "couldn't be read") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _Refused("isn't a plain file")
        chunks, size = [], 0
        while size <= MAX_BYTES and (chunk := os.read(fd, 16384)):
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    if size > MAX_BYTES:
        raise _Refused(f"is larger than {MAX_BYTES // 1024} KB")
    return b"".join(chunks)


def read(root: Path | None) -> dict[str, Any] | None:
    """None without a file. Otherwise {"state": "read", "data": …} for a file that follows
    version 1, or {"state": "ignored", "problems": [...]} for one Barkley didn't use."""
    if root is None:
        return None
    try:
        raw = _read_bytes(root)
        if raw is None:
            if (root / NAME).is_symlink():  # a dangling link: refused, not missing
                raise _Refused("isn't a plain file")
            return None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _Refused("isn't UTF-8 text") from exc
        try:
            _events_ok(text)
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise _Refused("isn't valid YAML") from exc
    except _Refused as why:
        return {"state": "ignored", "problems": [f"The file {why}."]}
    except RecursionError:
        return {"state": "ignored", "problems": ["The file is nested too deeply."]}
    problems = _check(data)
    if problems:
        return {"state": "ignored", "problems": problems}
    return {"state": "read", "data": _keep(data)}
