"""Helpers shared by the Playwright tests: signing in and pushing traffic through the real API."""
from __future__ import annotations

import time


def wait_class(page, selector: str, on: bool, timeout: int = 15_000) -> None:
    """Wait until `selector` does (or no longer) carry the `on` class.

    Playwright's default `visible` state check cannot be used for dialogs that are hidden when closed.
    """
    page.wait_for_function(
        "([sel, want]) => {const el = document.querySelector(sel);"
        " return !!el && el.classList.contains('on') === want;}",
        arg=[selector, on], timeout=timeout, polling=150)


def login(page, who: str = "admin") -> None:
    """Sign in through the real login form."""
    page.wait_for_selector("#login.on", timeout=15_000)
    page.fill("#lemail", f"{who}@aegis.local")
    page.fill("#lpass", f"{who}123")
    page.click("#login button.p")
    wait_class(page, "#login", False)


_seq = 0


def send_events(page, user: str | None = None, n: int = 30) -> str:
    """Push a burst of clicks through the API so pages have rows to show.

    Each call uses a fresh user: the server blocks repeat offenders, and the browser tests share
    one long-lived server, so reusing a user id would leave later tests with rejected traffic.
    """
    global _seq
    _seq += 1
    user = user or f"UWEB{_seq:03d}"
    events = [{"user_id": user, "ad_id": "AD100", "campaign_id": "C10", "device_id": "D" + user,
               "ip_address": f"7.7.7.{_seq % 250 + 1}", "user_agent": "Mozilla/5.0 Chrome",
               "timestamp": time.time() + i * 0.05} for i in range(n)]
    page.evaluate("async (evts) => {await api('/api/events', {method: 'POST', body: evts});}", events)
    return user


def goto(page, view: str, ready: str | None = None, timeout: int = 15_000) -> None:
    page.click(f"#nav a[data-v='{view}']")
    page.wait_for_selector(ready or "#main .panel, #main .skeleton", timeout=timeout)
