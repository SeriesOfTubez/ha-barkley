"""Repo security habits: context from the repo's own files and two GitHub lookups."""

from datetime import UTC, datetime

from test_server import HOSTILE

from sniff_test import ui
from sniff_test.analyzers import repo_hygiene as rh
from sniff_test.fetch.github import GitHubError, RateLimitError
from sniff_test.models import Target, TargetKind

NOW = datetime(2026, 11, 10, tzinfo=UTC)


def _tree(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def test_files_show_scanners_dependabot_and_policy(tmp_path):
    root = _tree(tmp_path, {
        ".github/workflows/codeql.yml": "steps:\n  - uses: github/codeql-action/init@v3\n",
        ".github/workflows/ci.yml": "steps:\n  - run: pip-audit -r requirements.txt\n"
                                    "  # - uses: aquasecurity/trivy-action@master\n",
        ".github/dependabot.yml": "updates:\n  - package-ecosystem: \"pip\"\n"
                                  "  - package-ecosystem: github-actions\n",
        "SECURITY.md": "Report privately.",
    })  # fmt: skip
    h = rh.scan_files(root)
    assert sorted(s["name"] for s in h.scanners) == ["CodeQL", "pip-audit"]  # comment ignored
    assert h.dependabot == ["github-actions", "pip"]
    assert h.security_policy == "SECURITY.md" and not h.renovate


def test_bare_repo_and_symlinks_count_as_nothing(tmp_path):
    (tmp_path / "x").write_text("uses: github/codeql-action")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "dependabot.yml").symlink_to(tmp_path / "x")
    h = rh.scan_files(tmp_path)
    assert h.scanners == [] and h.dependabot is None and h.security_policy is None


def test_update_prs_and_security_issues():
    pulls = [
        {"user": {"login": "dependabot[bot]"}, "created_at": "2026-07-01T00:00:00Z"},
        {"user": {"login": "renovate[bot]"}, "created_at": "2026-11-09T00:00:00Z"},
        {"user": {"login": "someone"}, "created_at": "2026-01-01T00:00:00Z"},
    ]
    p = rh.update_prs(pulls, NOW)
    assert (
        p["open"] == 2 and p["oldest_days"] == 132 and p["by"] == {"Dependabot": 1, "Renovate": 1}
    )
    issues = [
        {"number": 1, "title": "Token leak: security", "created_at": "2026-11-01T00:00:00Z"},
        {"number": 2, "title": "Crash on start", "labels": [{"name": "Security"}]},
        {"number": 3, "title": "CVE-2026-12345 in aiohttp"},
        {"number": 4, "title": "security fix", "pull_request": {}},  # a PR, not an issue
        {"number": 5, "title": "Insecurely worded but unrelated: securityless"},
    ]  # fmt: skip
    s = rh.security_issues(issues, NOW)
    assert [i["number"] for i in s["items"]] == [1, 2, 3] and s["of"] == 4


class GH:
    def __init__(self, fail=None):
        self.fail = fail
        self.paths = []

    def get_json(self, path):
        self.paths.append(path)
        if self.fail:
            raise self.fail
        return []


def _target(tmp_path):
    return Target("a/b", TargetKind.INTEGRATION, tmp_path, tmp_path, repo="a/b", ref="v1")


def test_run_makes_two_lookups_and_rate_limit_is_raised(tmp_path):
    gh = GH()
    h = rh.run(_target(tmp_path), gh, NOW)
    assert len(gh.paths) == 2 and h.update_prs["open"] == 0 and h.security_issues["open"] == 0
    try:
        rh.run(_target(tmp_path), GH(RateLimitError("u", 0.0, False)), NOW)
        raise AssertionError("a rate limit must not become a result")
    except RateLimitError:
        pass
    h = rh.run(_target(tmp_path), GH(GitHubError("404")), NOW)
    assert h.update_prs is None and h.errors
    assert rh.run(Target("x", TargetKind.INTEGRATION, tmp_path), GH(), NOW) is None


def test_cross_check_and_page_section(tmp_path):
    h = rh.Hygiene(dependabot=["pip"], update_prs={"open": 3, "oldest_days": 120, "of": 3},
                   security_issues={"open": 1, "of": 7, "items": [
                       {"number": 9, "title": HOSTILE, "age_days": 3}]})  # fmt: skip
    d = rh.to_dict(h, {"dep-vuln"}, "integration")
    assert d["dependabot_but_known_vulns"] and not d["scored"]
    assert not rh.to_dict(h, {"dep-vuln"}, "plugin")["dependabot_but_known_vulns"]  # npm
    html = ui.hygiene_html({"target": {"repo": "a/b"}, "hygiene": d})
    assert "Dependabot is set up to propose updates for Python packages" in html
    assert (
        "<b>3</b> dependency-update pull requests are waiting to be merged. "
        "The oldest is 4 months old." in html
    )
    assert 'href="https://github.com/a/b/issues/9"' in html
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "but this release ships some with known vulnerabilities (listed above)" in html
    assert "never changes the score" in html
    assert ui.hygiene_html({}) == ""  # reports from before 0.6.0


def test_turned_off_pulls_and_issues_need_no_request(tmp_path):
    t = _target(tmp_path)
    t.repo_meta = {"full_name": "a/b", "has_pull_requests": False, "has_issues": False}
    gh = GH()
    h = rh.run(t, gh, NOW)
    assert gh.paths == [] and h.update_prs == {"off": True} and not h.errors
    html = ui.hygiene_html({"target": {"repo": "a/b"}, "hygiene": rh.to_dict(h, set(), "plugin")})
    assert "Pull requests are turned off" in html and "Issues are turned off" in html


def test_report_json_handles_turned_off_issues(tmp_path):
    from types import SimpleNamespace

    from sniff_test.report.json_report import _hygiene_json

    h = rh.Hygiene(update_prs={"off": True}, security_issues={"off": True})
    scan = SimpleNamespace(hygiene=h, target=SimpleNamespace(kind="plugin"))
    assert _hygiene_json(scan, [])["security_issues"] == {"off": True}
