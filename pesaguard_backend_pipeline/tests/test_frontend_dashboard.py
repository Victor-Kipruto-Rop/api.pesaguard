"""Regression tests for the communications operations dashboard frontend."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "communications"

pytestmark = pytest.mark.skipif(
    not FRONTEND.is_dir(),
    reason=(
        "retired communications-dashboard target is absent; restore "
        "pesaguard_backend_pipeline/frontend/communications to reactivate this contract"
    ),
)


def read(name: str) -> str:
    return (FRONTEND / name).read_text(encoding="utf-8")


def test_no_hardcoded_insecure_default():
    html = read("index.html")
    assert 'value="http://localhost' not in html


def test_labels_and_button_types():
    html = read("index.html")
    assert '<label for="search">Search recipient</label>' in html
    assert '<label for="status">Filter by status</label>' in html
    for bid in ("refresh", "reload", "connect", "load-templates", "disconnect", "clear-token"):
        assert f'id="{bid}"' in html
    assert html.count('type="button"') >= 4


def test_live_regions_and_metadata():
    html = read("index.html")
    assert 'aria-live="polite"' in html
    assert 'aria-atomic="true"' in html
    assert 'name="color-scheme"' in html
    assert 'name="description"' in html
    assert 'autocomplete="off"' in html
    assert 'href="/"' in html


def test_csp_present():
    html = read("index.html")
    assert "Content-Security-Policy" in html
    assert "frame-ancestors 'none'" in html
    nginx = (FRONTEND.parent / "nginx.conf").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in nginx
    assert "X-Frame-Options" in nginx


def test_status_options_cover_backend_enum():
    html = read("index.html")
    for value in ("created,queued,processing,accepted,submitted,sent,delivered,"
                  "opened,clicked,bounced,complained,failed,rejected,expired,"
                  "cancelled,retrying,dead_letter").split(","):
        assert f'value="{value}"' in html


def test_tenant_banner_and_states():
    html = read("index.html")
    assert 'id="tenant-banner"' in html
    assert 'id="session-state"' in html
    assert 'id="connection-error"' in html
    assert 'aria-busy' in html


def test_no_export_ui(js=None):
    """Dashboard policy: delivery data cannot be copied out of the tenant ledger.

    There is no export button, no export JS, and the footer states the policy.
    The API route also requires a distinct export permission; nothing in the
    frontend ever calls it.
    """
    html = read("index.html")
    app = read("app.js")
    assert 'id="export"' not in html
    assert "communications/export" not in app
    assert "disabled in this dashboard" in html


def test_app_memory_only_token():
    js = read("app.js")
    assert "localStorage.setItem('pg_token'" not in js
    assert "localStorage.setItem(\"pg_token\"" not in js
    assert "sessionStorage" not in js
    assert "localStorage.removeItem('pg_token')" in js


def test_app_rejects_insecure_urls():
    js = read("app.js")
    assert "isSecureApi" in js
    assert "DEV_HOSTS" in js or "localhost" in js
    assert "401" in js and "403" in js and "429" in js


def test_app_safe_dom_and_masking():
    js = read("app.js")
    assert "innerHTML" not in js
    assert "textContent" in js
    assert "maskRecipient" in js
    assert "createElement" in js


def test_app_tenant_display_only():
    js = read("app.js")
    assert "tenant" in js.lower()
    # Tenant banner text comes from the token payload for display; filtering
    # stays server-side (product_routes filters every query by tenant_id()).
    assert "decodeTenant" in js
    assert "filter_by(tenant_id" in (Path(__file__).resolve().parent.parent
                                     / "communications"
                                     / "product_routes.py").read_text()


def test_no_token_in_url_or_logs():
    js = read("app.js")
    assert "encodeURIComponent(state.token" not in js
    assert "?token" not in js.lower()
    assert "console.log(state.token" not in js


def test_accessibility_markup():
    html = read("index.html")
    js = read("app.js")
    assert "'caption'" in js or '"caption"' in js
    assert "scope" in js and "col" in js
    assert 'class="sr-only"' in html
    assert 'class="skip-link"' in html
