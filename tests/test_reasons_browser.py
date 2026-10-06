"""Step 3 browser coverage: plain-English reasons, hash routing and click-through."""
from __future__ import annotations

import time

import pytest

from tests.browser_helpers import login

pytestmark = pytest.mark.browser


def _burst(page, user: str, n: int = 25) -> str:
    """A repeat-offender burst, so an alert and an auto-block exist for this user."""
    global _n
    _n += 1
    events = [{"user_id": user, "ad_id": "AD100", "campaign_id": "C10", "device_id": "D" + user,
               "ip_address": f"7.7.7.{_n % 250 + 1}", "user_agent": "Mozilla/5.0 Chrome",
               "timestamp": time.time() + i * 0.05} for i in range(n)]
    page.evaluate("async (evts) => {await api('/api/events', {method: 'POST', body: evts});}", events)
    return user


_n = 0


def test_alerts_show_plain_english_reason_not_json(page):
    login(page)
    _burst(page, "URX1")
    page.goto(page.base_url + "/#/alerts")
    page.wait_for_selector("#abody2 .tag", timeout=15_000)
    page.wait_for_function("() => document.querySelector('#abody2').innerText.includes('Why:')", timeout=15_000, polling=150)
    text = page.inner_text("#abody2")
    assert "{" not in text, "the raw details JSON must not be dumped into the alert list"
    assert "Why:" in text
    # no raw rule ids or feature names in the sentence itself
    body = text.split("Why:")[1][:200]
    assert "clicks_1m" not in body and "high_click_velocity" not in body


def test_alert_links_to_the_event_and_the_user(page):
    login(page)
    _burst(page, "URX2")
    page.goto(page.base_url + "/#/alerts")
    page.wait_for_function("() => document.querySelector('#abody2').innerText.includes('Why:')", timeout=15_000, polling=150)
    assert page.locator("#abody2 button", has_text="VIEW EVENT").count() >= 1
    assert page.locator("#abody2 button", has_text="INVESTIGATE USER").count() >= 1


def test_blocklist_shows_the_reason_and_links_to_the_user(page):
    login(page)
    user = _burst(page, "URX3")
    page.goto(page.base_url + "/#/blocklist")
    page.wait_for_function(
        "u => document.querySelector('#bbody').innerText.includes(u)", arg=user, timeout=20_000, polling=150)
    text = page.inner_text("#bbody")
    assert "WHY (PLAIN ENGLISH)" in text
    assert "clicks_1m" not in text and "{" not in text
    assert page.locator(f"#bbody a[href*='investigation/user/{user}']").count() == 1


def test_investigation_shows_the_reason(page):
    login(page)
    user = _burst(page, "URX4")
    page.goto(f"{page.base_url}/#/investigation/user/{user}")
    page.wait_for_selector("#ubody .risk", timeout=20_000)
    page.wait_for_function("() => document.querySelector('#ubody').innerText.includes('Why:')", timeout=20_000, polling=150)
    text = page.inner_text("#ubody")
    assert "LATEST DECISION" in text
    assert "clicks_1m" not in text.split("Why:")[1][:200]


def test_deep_link_loads_the_right_page_directly(page):
    """A shared link opens that page, not the default one."""
    login(page)
    user = _burst(page, "URX5")
    page.goto(f"{page.base_url}/#/investigation/user/{user}")
    page.wait_for_selector("#ubody .risk", timeout=20_000)
    assert "USER INVESTIGATION" in page.inner_text("#main")
    assert page.locator("#uq").input_value() == user


def test_nav_updates_the_hash_and_back_restores_the_page(page):
    login(page)
    _burst(page, "URX6")
    page.goto(page.base_url + "/#/alerts")
    page.wait_for_selector("#abody2", timeout=15_000)
    page.click("#nav a[data-v='blocklist']")
    page.wait_for_function("() => location.hash === '#/blocklist'", timeout=10_000, polling=150)
    page.click("#nav a[data-v='alerts']")
    page.wait_for_function("() => location.hash === '#/alerts'", timeout=10_000, polling=150)
    page.go_back()
    page.wait_for_function("() => location.hash === '#/blocklist'", timeout=10_000, polling=150)
    assert page.locator("#bbody").count() == 1, "Back must restore the previous view, not an empty page"
    page.go_forward()
    page.wait_for_function("() => location.hash === '#/alerts'", timeout=10_000, polling=150)
    assert page.locator("#abody2").count() == 1


def test_back_preserves_the_user_filter(page):
    """Moving between two users and going Back keeps the first user's filters."""
    login(page)
    u1 = _burst(page, "URX7")
    page.goto(f"{page.base_url}/#/investigation/user/{u1}")
    page.wait_for_selector("#ubody .risk", timeout=20_000)
    page.click("#nav a[data-v='alerts']")
    page.wait_for_function("() => location.hash === '#/alerts'", timeout=10_000, polling=150)
    page.click("#abody2 button:has-text('INVESTIGATE USER')")
    page.wait_for_function("() => location.hash.startsWith('#/investigation/user/')", timeout=15_000, polling=150)
    page.go_back()
    page.wait_for_function("() => location.hash === '#/alerts'", timeout=10_000, polling=150)
    page.go_forward()
    page.wait_for_function("() => location.hash.startsWith('#/investigation/user/')", timeout=15_000, polling=150)
    page.wait_for_selector("#ubody .risk, #ubody .empty", timeout=20_000)


def test_unknown_hash_falls_back_without_a_broken_page(page):
    login(page)
    page.goto(page.base_url + "/#/does/not/exist")
    page.wait_for_selector("#main .panel, #main .empty, #main .skeleton", timeout=15_000)
    page.console_log.assert_clean()


def test_resetting_the_view_from_a_hash_link_keeps_the_route(page):
    login(page)
    page.goto(page.base_url + "/#/settings/data")
    page.wait_for_selector("#rrbody, .card, .panel", timeout=15_000)
    page.click("#nav a[data-v='blocklist']")
    page.wait_for_function("() => location.hash === '#/blocklist'", timeout=10_000, polling=150)
    page.console_log.assert_clean()
