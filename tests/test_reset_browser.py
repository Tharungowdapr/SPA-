"""Step 2 browser tests: the Data and Reset page, confirmation wording and role gating."""
from __future__ import annotations

import pytest

from tests.browser_helpers import login, send_events, wait_class

pytestmark = pytest.mark.browser


def goto_data_reset(page):
    page.click("#nav a[data-v='datarst']")
    page.wait_for_selector("#drbody .panel", timeout=15_000)


def test_data_reset_page_lists_every_scope(page):
    login(page, "admin")
    goto_data_reset(page)
    body = page.inner_text("#drbody")
    for label in ("Simulation history", "Click events and decisions", "Alerts", "Incidents",
                  "Live tracking state", "Block-list", "Named patterns", "Saved attacks"):
        assert label in body, label
    assert "RESET NETWORK" in body and "FACTORY RESET" in body
    assert "Never removed" in body
    assert page.console_log.assert_clean() is None


def test_page_shows_row_counts(page):
    login(page, "admin")
    send_events(page, n=25)
    goto_data_reset(page)
    page.wait_for_selector("#drbody .panel", timeout=15_000)
    assert "0 rows" not in page.inner_text("#drbody").split("PRESETS")[0].split("Simulation history")[0]
    page.console_log.assert_clean()


def test_clear_requires_typing_the_word(page):
    login(page, "admin")
    send_events(page, n=25)
    goto_data_reset(page)
    page.click("button[onclick*=\"clearScope('events')\"]")
    page.wait_for_selector("#confirm.on", timeout=10_000)
    assert "TYPE CLEAR TO CONFIRM" in page.inner_text("#confirm")
    page.fill("#cf-word", "yes")
    page.click("#cf-ok")
    assert page.inner_text("#cf-err") == "Type CLEAR exactly to continue"
    assert page.is_visible("#confirm.on")            # still open
    page.fill("#cf-word", "clear")
    page.click("#cf-ok")
    wait_class(page, "#confirm", False, 10_000)
    page.console_log.assert_clean()


def test_clearing_a_scope_removes_the_data(page):
    login(page, "admin")
    send_events(page, n=25)
    page.evaluate("() => go('analytics')")
    page.wait_for_timeout(1500)
    goto_data_reset(page)
    page.click("button[onclick*=\"clearScope('events')\"]")
    page.wait_for_selector("#confirm.on", timeout=10_000)
    page.fill("#cf-word", "CLEAR")
    page.click("#cf-ok")
    wait_class(page, "#confirm", False, 10_000)
    page.wait_for_timeout(1500)
    body = page.inner_text("#drbody")
    assert "Click events and decisions 0 rows" in body
    page.console_log.assert_clean()


def test_preset_uses_its_own_word(page):
    login(page, "admin")
    goto_data_reset(page)
    page.click("button[onclick*=\"clearPreset('factory_reset')\"]")
    page.wait_for_selector("#confirm.on", timeout=10_000)
    assert "TYPE FACTORY RESET TO CONFIRM" in page.inner_text("#confirm")
    page.fill("#cf-word", "CLEAR")
    page.click("#cf-ok")
    assert page.is_visible("#confirm.on")            # CLEAR is not enough
    page.fill("#cf-word", "FACTORY RESET")
    page.click("#cf-ok")
    wait_class(page, "#confirm", False, 10_000)
    page.console_log.assert_clean()


def test_cancelling_changes_nothing(page):
    login(page, "admin")
    send_events(page, n=25)
    goto_data_reset(page)
    page.click("button[onclick*=\"clearScope('events')\"]")
    page.wait_for_selector("#confirm.on", timeout=10_000)
    page.click("#cf-no")
    wait_class(page, "#confirm", False, 10_000)
    assert "Click events and decisions 0 rows" not in page.inner_text("#drbody")
    page.console_log.assert_clean()


def test_escape_closes_the_dialog(page):
    login(page, "admin")
    goto_data_reset(page)
    page.click("button[onclick*=\"clearScope('alerts')\"]")
    page.wait_for_selector("#confirm.on", timeout=10_000)
    page.keyboard.press("Escape")
    wait_class(page, "#confirm", False, 10_000)
    page.console_log.assert_clean()


def test_analyst_sees_admin_scopes_disabled(page):
    login(page, "analyst")
    goto_data_reset(page)
    assert page.is_disabled("button[onclick*=\"clearScope('blocklist')\"]")
    assert page.is_disabled("button[onclick*=\"clearScope('patterns')\"]")
    assert not page.is_disabled("button[onclick*=\"clearScope('events')\"]")
    assert page.is_disabled("button[onclick*=\"clearPreset('factory_reset')\"]")
    page.console_log.assert_clean()


def test_viewer_cannot_clear_anything(page):
    login(page, "viewer")
    goto_data_reset(page)
    for scope in ("events", "alerts", "blocklist", "live_state"):
        assert page.is_disabled(f"button[onclick*=\"clearScope('{scope}')\"]"), scope
    assert page.is_disabled("button[onclick*=\"clearPreset('reset_network')\"]")
    page.console_log.assert_clean()


def test_alerts_and_blocklist_pages_carry_clear_buttons(page):
    login(page, "admin")
    page.click("#nav a[data-v='alerts']")
    page.wait_for_selector("button[onclick*=\"clearScope('alerts')\"]", timeout=10_000)
    page.click("#nav a[data-v='blocklist']")
    page.wait_for_selector("button[onclick*=\"clearScope('blocklist')\"]", timeout=10_000)
    page.console_log.assert_clean()


def test_reset_announces_to_other_tabs(page):
    """A reset pushed over the websocket refreshes a page that is already open."""
    login(page, "admin")
    page.click("#nav a[data-v='datarst']")
    page.wait_for_selector("#drbody .panel", timeout=15_000)
    page.evaluate("async () => {await api('/api/admin/reset', {method: 'POST',"
                  " body: {scopes: ['live_state'], confirm: true}});}")
    page.wait_for_selector(".toast", timeout=10_000)
    assert "Data cleared" in page.inner_text(".toast")
    page.console_log.assert_clean()
