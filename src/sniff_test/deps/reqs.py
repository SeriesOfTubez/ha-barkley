"""Parse and validate requirement strings without the `packaging` library.

Manifest requirements are attacker-controlled and end up in a file that uv reads. uv
requirement files accept options (`-e`, `--index-url`, `-r`, `-c`), and editable
requirements can make uv run a build backend. So anything that isn't a plain PEP 508
`name[extras] specifiers ; markers` requirement is never written to that file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_EXTRAS = rf"\[\s*(?:{_NAME}(?:\s*,\s*{_NAME})*)?\s*\]"
_VERSION_ONE = r"(?:===|==|!=|<=|>=|~=|<|>)\s*[A-Za-z0-9.*+!_-]+"
_VERSIONS = rf"{_VERSION_ONE}(?:\s*,\s*{_VERSION_ONE})*"
_MARKER = r"[A-Za-z0-9_.'\"<>=!~ ()\-]+"
_PEP508 = re.compile(
    rf"^\s*(?P<name>{_NAME})\s*(?P<extras>{_EXTRAS})?\s*"
    rf"(?P<spec>\(\s*{_VERSIONS}\s*\)|{_VERSIONS})?\s*"
    rf"(?:;\s*(?P<marker>{_MARKER}))?\s*$"
)
_NAME_ONLY = re.compile(rf"^\s*({_NAME})")
_NAME_AT = re.compile(rf"^\s*({_NAME})\s*(?:{_EXTRAS})?\s*@")
_URLISH = re.compile(r"://|^\s*(?:git|hg|svn|bzr)\+|^\s*file:|\s@\s|^\s*[./\\~]|@\s*\w+:")


class ReqKind(StrEnum):
    PLAIN = "plain"  # safe PEP 508 requirement from an index
    URL = "url"  # VCS / direct URL / local path: bypasses the index
    INVALID = "invalid"  # option-like or malformed


@dataclass(frozen=True)
class Requirement:
    raw: str
    kind: ReqKind
    name: str | None  # normalized name, when one can be read
    pinned: str | None = None  # version when the spec is exactly `==X`


def normalize(name: str) -> str:
    """PEP 503 normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse(raw: object) -> Requirement:
    text = raw if isinstance(raw, str) else repr(raw)
    if not isinstance(raw, str) or "\n" in text or "\r" in text or "\0" in text:
        return Requirement(text, ReqKind.INVALID, None)
    if text.lstrip().startswith("-"):
        return Requirement(text, ReqKind.INVALID, None)
    if _URLISH.search(text):
        m = _NAME_AT.match(text)
        return Requirement(text, ReqKind.URL, normalize(m.group(1)) if m else None)
    m = _PEP508.match(text)
    if not m:
        m2 = _NAME_ONLY.match(text)
        return Requirement(text, ReqKind.INVALID, normalize(m2.group(1)) if m2 else None)
    spec = (m["spec"] or "").strip("() ")
    pinned = None
    if spec.startswith("==") and "," not in spec and "*" not in spec:
        pinned = spec[2:].strip()
    return Requirement(text.strip(), ReqKind.PLAIN, normalize(m["name"]), pinned)


def constraint_names(text: str) -> dict[str, str | None]:
    """Names in a constraints file -> pinned version (None when not an exact `==` pin)."""
    out: dict[str, str | None] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        req = parse(line)
        if req.kind is ReqKind.PLAIN and req.name:
            out[req.name] = req.pinned
    return out


_FINAL_RX = re.compile(
    r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(?:post|rev|r)[-_.]?(\d*)|-(\d+))?$", re.I
)


def final_version_key(version: str) -> tuple[int, tuple[int, ...], int] | None:
    """Sort key for a final PEP 440 release (epoch, release, post); None for anything else.

    Pre-releases, dev releases and local versions return None: callers that compare
    versions here only ever want final releases.
    """
    m = _FINAL_RX.match(version.strip())
    if not m:
        return None
    release = tuple(int(x) for x in m.group(2).split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    post = m.group(3) if m.group(3) is not None else m.group(4)
    return (int(m.group(1) or 0), release, -1 if post is None else int(post or 0))
