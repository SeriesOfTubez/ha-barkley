"""(0.14.1, #18) A VM CPU without x86-64-v2: every scan failed with the loader's own words.
Barkley now says why and how to fix it, on the scan and in Diagnostics."""

from __future__ import annotations

from sniff_test import cpu, doctor

# A CPU type that hides the v2 instructions (only baseline flags) and a modern one.
KVM64 = (
    "processor\t: 0\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca "
    "cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx lm nopl pni cx16 hypervisor\n"
)
HOST = KVM64.replace("cx16 hypervisor", "cx16 lahf_lm popcnt sse4_1 sse4_2 ssse3 avx avx2")

LOADER = (
    "semgrep exit 127: /opt/tools/semgrep/lib/python3.13/site-packages/semgrep/bin/libs/"
    "libresolv.so.2: CPU ISA level is lower than required"
)


def test_the_missing_v2_flags_are_named():
    assert cpu.missing_v2(KVM64, "x86_64") == ["lahf_lm", "popcnt", "sse4_1", "sse4_2", "ssse3"]
    assert cpu.missing_v2(HOST, "x86_64") == []
    assert cpu.missing_v2(KVM64, "aarch64") is None  # not an x86-64 question
    assert cpu.missing_v2("no flags line", "x86_64") is None
    assert cpu.missing_v2(KVM64.replace(" pni", ""), "x86_64")[2] == "pni"  # SSE3


def test_a_failed_scan_says_why_and_the_fix():
    out = cpu.explain(LOADER)
    assert out.startswith(LOADER)
    assert "use host" in out and "x86-64-v2-AES or above" in out
    assert "shut the VM down completely" in out
    assert cpu.explain(out) == out  # said once
    assert cpu.explain("semgrep exit 2: something else") == "semgrep exit 2: something else"


def test_diagnostics_warns_before_a_scan_fails():
    bad = doctor.cpu_check(["popcnt", "sse4_2"])
    assert not bad.ok and "missing popcnt, sse4_2" in bad.summary and "x86-64-v2-AES" in bad.summary
    assert doctor.cpu_check([]).ok
    assert doctor.cpu_check(None).ok


# (0.15, #18 follow-up) "flag this problem ... at the top of the page": a notice from the
# start, not only in Diagnostics and on a failed scan.


def test_the_page_says_so_at_the_top_from_the_start(tmp_path):
    from sniff_test import server
    from sniff_test.store import Store

    store = Store(tmp_path / "s.db")
    page = server.render_index("", store, [], "t", cpu_gap=["popcnt", "sse4_2"]).decode()
    head_end = page.index("</div>", page.index("</h1>")) + len("</div>")
    assert page[head_end:].startswith('<div class="banner bad">')  # first, under the heading
    assert "Scans can't run on this CPU." in page[head_end : head_end + 1200]
    assert "Missing: popcnt, sse4_2." in page and server.e(cpu.FIX, 600) in page
    assert f'href="{server.DOCS_CPU}"' in page and 'rel="noopener noreferrer"' in page
    for nothing in ([], None):
        quiet = server.render_index("", store, [], "t", cpu_gap=nothing).decode()
        assert "Scans can't run on this CPU" not in quiet


def test_the_docs_link_points_at_the_cpu_section():
    from pathlib import Path

    from sniff_test import server

    page = Path(__file__).resolve().parents[1] / "docs" / "Diagnostics-and-troubleshooting.md"
    assert '## Every scan fails: "CPU ISA level is lower than required"' in page.read_text()
    assert server.DOCS_CPU.endswith(
        "/docs/diagnostics-and-troubleshooting/"
        "#every-scan-fails-cpu-isa-level-is-lower-than-required"
    )


def test_startup_checks_the_cpu_once_and_logs_it(tmp_path, monkeypatch, capsys):
    import threading

    from test_server import Calls, get

    from sniff_test import server
    from sniff_test.store import Store

    monkeypatch.setattr(cpu, "missing_v2", lambda *a, **k: ["popcnt"])
    httpd = server.serve(Store(tmp_path / "s.db"), Calls(), "127.0.0.1", 0, {"127.0.0.1"})
    try:
        assert httpd.panel.cpu_gap == ["popcnt"]
        assert "CPU: missing popcnt." in capsys.readouterr().err
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        _, _, index = get(f"http://127.0.0.1:{httpd.server_address[1]}/")
        assert "Scans can't run on this CPU." in index
    finally:
        httpd.shutdown()
