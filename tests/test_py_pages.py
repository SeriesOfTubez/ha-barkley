"""(0.15) The address each login-free page answers on (analyzers/py_pages.py)."""

from sniff_test.analyzers import py_pages
from sniff_test.models import Category, Finding, Severity

VIEWS = """\
from homeassistant.components.http import HomeAssistantView


class TokenView(HomeAssistantView):
    url = "/api/acme/token"
    extra_urls = ["/api/acme/token/{id}", "/api/acme/t"]
    name = "api:acme:token"
    requires_auth = False


class BuiltView(HomeAssistantView):
    url = f"/api/{DOMAIN}/built"
    requires_auth = False


class SettingView(HomeAssistantView):
    url = f"/api/{options['path']}"
    requires_auth = False


class PlainView(HomeAssistantView):
    url: str = "/api/acme/plain"
    requires_auth = False
"""


def _f(line: int, rule: str = "ha-unauth-view") -> Finding:
    return Finding(rule, "t", Severity.LOW, Category.INBOUND, "m", "views.py", line)


def test_the_page_address_is_read_from_the_class(tmp_path):
    (tmp_path / "const.py").write_text('BASE = "/api/acme"\nDOMAIN = "acme"\n')
    (tmp_path / "views.py").write_text("from .const import DOMAIN\n" + VIEWS)
    got = py_pages.annotate([_f(5), _f(12), _f(17), _f(22), _f(5, "ha-read-secrets")], tmp_path)
    assert [f.page for f in got] == [
        "/api/acme/token (+2 more)", "/api/acme/built", "", "/api/acme/plain", None
    ]  # fmt: skip


def test_names_are_followed_without_looping(tmp_path):
    (tmp_path / "a.py").write_text("from .b import X\nY = X\n")
    (tmp_path / "b.py").write_text("from .a import Y\nX = Y\n")
    (tmp_path / "views.py").write_text(
        "from .a import Y\nclass V(HomeAssistantView):\n    url = Y + '/x'\n"
    )
    f = py_pages.annotate([_f(2)], tmp_path)[0]
    assert f.page == ""


def test_a_file_that_does_not_parse_leaves_findings_unchanged(tmp_path):
    (tmp_path / "views.py").write_text("class (:\n")
    assert py_pages.annotate([_f(1)], tmp_path)[0].page is None
