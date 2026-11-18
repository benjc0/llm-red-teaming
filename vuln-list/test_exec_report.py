"""The executive report's PDF step: browser discovery and graceful fallback,
plus a real render when a browser is present.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import exec_report  # noqa: E402


def test_find_chrome_prefers_env(monkeypatch):
    monkeypatch.setenv("APT_CHROME", "my-browser")
    monkeypatch.setattr(exec_report.shutil, "which",
                        lambda name: "/opt/my-browser" if name == "my-browser" else None)
    assert exec_report.find_chrome() == "/opt/my-browser"


def test_find_chrome_falls_back_to_path(monkeypatch):
    monkeypatch.delenv("APT_CHROME", raising=False)
    monkeypatch.delenv("CHROME", raising=False)
    monkeypatch.setattr(exec_report.shutil, "which",
                        lambda name: "/usr/bin/chromium" if name == "chromium" else None)
    assert exec_report.find_chrome() == "/usr/bin/chromium"


def test_render_pdf_without_browser_is_not_fatal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(exec_report, "find_chrome", lambda: None)
    html = tmp_path / "r.html"
    html.write_text("<!doctype html><title>t</title><h1>hi</h1>")
    assert exec_report.render_pdf(html) is None            # returns, does not raise
    assert "skipping PDF" in capsys.readouterr().out
    assert not (tmp_path / "r.pdf").exists()


@pytest.mark.skipif(exec_report.find_chrome() is None, reason="no Chromium/Chrome available")
def test_render_pdf_produces_a_pdf(tmp_path):
    html = tmp_path / "r.html"
    html.write_text("<!doctype html><title>t</title><h1>Executive report</h1><p>body</p>")
    pdf = exec_report.render_pdf(html)
    assert pdf is not None and pdf.is_file()
    assert pdf.read_bytes().startswith(b"%PDF")
