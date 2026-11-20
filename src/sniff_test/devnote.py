"""The developer's note: the docstring of the Python function or class around an item.
A 0.15 scan stores it with the item (`context.items[id].doc`, report/context.docstring);
for an older scan it is read from the code snippet stored for the AI (report["context"]).

Panel-only (logic.PANEL_ONLY): nothing here changes what a scan finds or stores. The text
is the developer's own words from the scanned repository, so it is untrusted: the caller
escapes it, shows it labelled as the developer's, never beside a found or possible threat,
and never lets it change a reading (his decisions, 2026-11-20).

Plain line walking only (no regular expressions on scanned text), so it stays linear on
hostile input, and the walk is bounded by the snippet's own length.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MAX_LINES = 20  # a docstring longer than this is cut, with "…"
MAX_CHARS = 800
_QUOTES = ('"""', "'''")
_PREFIXES = ("", "r", "R", "u", "U")


@dataclass(frozen=True)
class Note:
    file: str
    start: int  # first and last line of the docstring in the file
    end: int
    text: str


def _segment(report: dict[str, Any], item_id: str) -> tuple[dict[str, Any], int] | None:
    """The stored snippet segment that holds the item's own line, and that line."""
    ctx = report.get("context") or {}
    item = (ctx.get("items") or {}).get(item_id)
    if not isinstance(item, dict):
        return None
    snip = (ctx.get("snippets") or {}).get(item.get("snippet"))
    file, line = item.get("file"), item.get("line")
    if not isinstance(snip, dict) or not isinstance(file, str) or not isinstance(line, int):
        return None
    if not file.endswith(".py"):
        return None
    for seg in snip.get("segments") or []:
        if not isinstance(seg, dict) or seg.get("file") != file:
            continue
        start, code = seg.get("start"), seg.get("code")
        if isinstance(start, int) and isinstance(code, list) and start <= line < start + len(code):
            return seg, line
    return None


def _indent(s: str) -> int:
    return len(s) - len(s.lstrip(" \t"))


def _opens(stripped: str) -> str | None:
    """The quote a docstring line opens with, or None."""
    for p in _PREFIXES:
        for q in _QUOTES:
            if stripped.startswith(p + q):
                return q
    return None


def _from_doc(doc: dict[str, Any]) -> Note | None:
    """The note from a stored docstring: {"file", "start", "code", "cut"}."""
    file, start, code = doc.get("file"), doc.get("start"), doc.get("code")
    if not isinstance(file, str) or not isinstance(start, int) or not isinstance(code, list):
        return None
    code = [c if isinstance(c, str) else "" for c in code]
    if not code:
        return None
    first = code[0].strip()
    opener = next(
        (p + q for p in _PREFIXES for q in (*_QUOTES, '"', "'") if first.startswith(p + q)),
        None,
    )
    if opener is None:
        return None
    quote = opener.lstrip("rRuU")
    lines = [first[len(opener) :], *[c.strip() for c in code[1:]]]
    cut = bool(doc.get("cut"))
    if not cut and lines[-1].endswith(quote):
        lines[-1] = lines[-1][: -len(quote)]
    if len(lines) > MAX_LINES:
        lines = [*lines[:MAX_LINES], "…"]
    elif cut:
        lines.append("…")
    text = " ".join(" ".join(lines).split())
    if not text or text == "…":
        return None
    if len(text) > MAX_CHARS:
        text = text[: MAX_CHARS - 1].rstrip() + "…"
    return Note(file, start, start + len(code) - 1, text)


def note(report: dict[str, Any], item_id: str) -> Note | None:
    """The docstring of the innermost `def`/`class` around the item: the one the scan
    stored with the item, else (a scan from before 0.15) the one above the item's line
    within the stored segment, or None when there is none or it isn't fully in the segment."""
    item = ((report.get("context") or {}).get("items") or {}).get(item_id)
    if isinstance(item, dict) and isinstance(item.get("doc"), dict):
        return _from_doc(item["doc"])
    found = _segment(report, item_id)
    if found is None:
        return None
    seg, line = found
    start: int = seg["start"]
    code = [c if isinstance(c, str) else "" for c in seg["code"]]
    at = line - start
    # the nearest enclosing header: a def/class line indented less than the item's line
    limit = _indent(code[at]) if code[at].strip() else 10**6
    head = None
    for i in range(at, -1, -1):
        s = code[i].lstrip(" \t")
        if s.startswith(("def ", "async def ", "class ")) and _indent(code[i]) < limit:
            head = i
            break
        if s and _indent(code[i]) < limit:
            limit = _indent(code[i])
    if head is None:
        return None
    # the header may run over several lines: it ends at the first line ending in ":"
    i = head
    while i < len(code) and not code[i].split("#", 1)[0].rstrip().endswith(":"):
        i += 1
    i += 1
    while i < len(code) and not code[i].strip():
        i += 1
    if i >= len(code):
        return None
    first = code[i].strip()
    q = _opens(first)
    if q is None:
        return None
    body = first[first.index(q) + 3 :]
    lines: list[str] = []
    j = i
    while True:
        if q in body:
            lines.append(body[: body.index(q)])
            break
        lines.append(body)
        j += 1
        if j >= len(code) or j - i >= MAX_LINES:
            if j >= len(code):  # the docstring runs past what the scan kept
                return None
            lines.append("…")
            break
        body = code[j].strip()
    text = " ".join(x.strip() for x in lines)
    # paragraphs: a blank docstring line became a double space
    text = " ".join(text.split())
    if not text:
        return None
    if len(text) > MAX_CHARS:
        text = text[: MAX_CHARS - 1].rstrip() + "…"
    return Note(str(seg["file"]), start + i, start + j, text)
