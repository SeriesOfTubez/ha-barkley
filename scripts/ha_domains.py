"""Regenerate src/sniff_test/data/ha_domains.txt: Home Assistant's built-in integration domains.

    GITHUB_TOKEN=$(gh auth token) uv run python scripts/ha_domains.py [TAG]

TAG defaults to HA's latest release. Reads only the folder names under
homeassistant/components at that tag (two GitHub API calls), nothing is downloaded or run.
Older domains are kept: the list is used to refuse "this is the app's own sub-integration"
for a built-in name, so a name too many only keeps a finding.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from sniff_test.fetch.github import GitHub

OUT = Path(__file__).resolve().parent.parent / "src" / "sniff_test" / "data" / "ha_domains.txt"
_DOMAIN = re.compile(r"^[a-z0-9_]+$")


def main() -> None:
    gh = GitHub()
    tag = sys.argv[1] if len(sys.argv) > 1 else gh.latest_release("home-assistant", "core")["tag_name"]
    top = gh.get_json(f"/repos/home-assistant/core/contents/homeassistant?ref={tag}")
    sha = next(x["sha"] for x in top if x["name"] == "components" and x["type"] == "dir")
    tree = gh.get_json(f"/repos/home-assistant/core/git/trees/{sha}")
    if tree.get("truncated"):
        sys.exit("tree truncated")
    names = {x["path"] for x in tree["tree"] if x["type"] == "tree" and _DOMAIN.match(x["path"])}
    old = set()
    if OUT.exists():
        old = {ln for ln in OUT.read_text("utf-8").splitlines() if ln and not ln.startswith("#")}
    header = (
        "# Home Assistant's built-in integration domains (homeassistant/components).\n"
        f"# Source: home-assistant/core at {tag} ({len(names)} domains), plus any listed before.\n"
        "# A nested manifest with one of these domains is never counted as the app's own.\n"
    )
    OUT.write_text(header + "\n".join(sorted(names | old)) + "\n", "utf-8")
    print(f"{tag}: {len(names)} domains, {len(names | old)} written")


if __name__ == "__main__":
    main()
