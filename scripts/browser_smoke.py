#!/usr/bin/env python3
"""Local-only Playwright smoke test. Uses a fresh SQLite DB and no external sites.

Requires an already-installed Playwright and Chromium. It never installs software.
Run: python scripts/browser_smoke.py --browser-executable /usr/bin/chromium
Screenshots and a machine-readable result are written under tests/browser-artifacts.
A browser launch restriction is reported as blocked, never as a passed UI check.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from silk.server import make_server


async def run(args, report):
    try:
        from playwright.async_api import async_playwright, expect
    except ImportError:
        report.update(status="blocked", blocker="Optional Playwright dependency is not installed; no browser checks ran.")
        return 2

    artifacts = Path(args.artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="silk-browser-") as temporary:
        server = make_server(Path(temporary) / "browser.sqlite3", port=0, dispatch=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        browser = None
        page = None
        try:
            async with async_playwright() as playwright:
                launch = {"headless": True}
                executable = args.browser_executable or shutil.which("chromium") or shutil.which("google-chrome")
                if executable:
                    launch["executable_path"] = executable
                try:
                    browser = await playwright.chromium.launch(**launch)
                except Exception as error:
                    report.update(status="blocked", blocker="Already-installed Chromium could not launch in this execution environment.", detail=str(error))
                    return 2
                report["browser_version"] = browser.version
                context = await browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
                external_requests = []
                errors = []

                async def network_guard(route):
                    url = route.request.url
                    if urlsplit(url).netloc != urlsplit(origin).netloc:
                        external_requests.append(url)
                        await route.abort("blockedbyclient")
                    else:
                        await route.continue_()

                await context.route("**/*", network_guard)
                page = await context.new_page()
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.set_default_timeout(10000)

                async def checkpoint(name):
                    report["checks"].append(name)
                    print("PASS", name, flush=True)

                async def state():
                    response = await context.request.get(origin + "/api/state")
                    assert response.ok, f"State HTTP {response.status}"
                    return await response.json()

                async def switch(owner):
                    await page.locator("#owner-select").select_option(owner)
                    await expect(page.locator("#owner-select")).to_have_value(owner)
                    await expect(page.locator("#owner-select")).to_be_enabled()
                    await expect(page.locator("#connection-status")).to_contain_text("Live")
                    assert (await state())["current_owner"]["id"] == owner

                async def double_activate(locator):
                    # Synchronous consecutive clicks deliberately test the UI's own busy guard.
                    await locator.evaluate("button => { button.click(); button.click(); }")

                await page.goto(origin, wait_until="networkidle")
                await expect(page.locator("#owner-select")).to_have_value("alice")
                await expect(page.locator("#connection-status")).to_contain_text("Live")
                assert (await state())["messages"] == []
                await checkpoint("fresh local demo loads with no authorized messages")
                await page.screenshot(path=str(artifacts / "01-empty-desktop.png"), full_page=True)

                await page.locator('[data-action="invite"]').click()
                await page.locator("#invitation-purpose").fill("Unsaved draft that must not follow an owner switch")
                await page.locator("#close-invitation").click()
                await expect(page.locator("#invitation-form")).to_be_hidden()
                await switch("bob")
                await expect(page.locator("#invitation-purpose")).not_to_have_value("Unsaved draft that must not follow an owner switch")
                await switch("alice")
                await checkpoint("cancel and owner switching clear stale invitation input")

                await page.locator('[data-action="invite"]').click()
                await page.locator("#invitation-purpose").fill("Find a local fixture study meeting")
                await double_activate(page.locator("#send-invitation"))
                await expect(page.locator("[data-invitation-id]")).to_have_count(1)
                snapshot = await state()
                assert len(snapshot["invitations"]) == 1
                assert snapshot["grants"] == [] and snapshot["messages"] == []
                await checkpoint("double invite creates one invitation and no grant or message")

                await switch("bob")
                await double_activate(page.locator('[data-action="accept-invitation"]'))
                await expect(page.locator('[data-grant-id]')).to_have_count(1)
                assert len((await state())["grants"]) == 1
                await switch("alice")
                await page.locator('[data-action="compose"]').click()
                await page.locator("#meeting-title").fill("Stale meeting draft")
                await switch("bob")
                await expect(page.locator("#message-form")).to_be_hidden()
                await expect(page.locator("#meeting-title")).not_to_have_value("Stale meeting draft")
                await expect(page.locator("#meeting-options input")).to_have_count(0)
                await switch("alice")
                await page.locator('[data-action="compose"]').click()
                await checkpoint("recipient consent creates one grant; owner switch clears composer")

                title = '<img src=x onerror="window.fixtureXss=true"> Mock study meeting'
                await page.locator("#meeting-title").fill(title)
                held = asyncio.Event()
                release = asyncio.Event()
                retry_keys = []
                first = True

                async def lose_first_response(route):
                    nonlocal first
                    retry_keys.append(route.request.post_data_json["idempotency_key"])
                    if first:
                        first = False
                        await route.fetch()  # Commit the request locally, then lose only its response.
                        held.set()
                        await release.wait()
                        await route.abort("failed")
                    else:
                        await route.continue_()

                await page.route("**/api/messages", lose_first_response)
                await double_activate(page.locator("#send-message"))
                await asyncio.wait_for(held.wait(), timeout=10)
                await expect(page.locator("#owner-select")).to_be_disabled()
                await expect(page.locator("#send-message")).to_be_disabled()
                release.set()
                await expect(page.locator("#message-retry-hint")).to_be_visible()
                await expect(page.locator("#send-message")).to_be_enabled()
                await page.locator("#send-message").click()
                await expect(page.locator("#message-form")).to_be_hidden()
                snapshot = await state()
                assert len(snapshot["messages"]) == 1
                assert len(retry_keys) == 2 and retry_keys[0] == retry_keys[1]
                assert snapshot["grants"][0]["turns_used"] == 1
                message_id = snapshot["messages"][0]["id"]
                await expect(page.locator(f'[data-message-id="{message_id}"] h3')).to_have_text(title)
                assert await page.locator("#messages img").count() == 0
                assert await page.evaluate("window.fixtureXss === undefined")
                await page.unroute("**/api/messages", lose_first_response)
                await checkpoint("uncertain response retries same key; double clicks and XSS remain harmless")

                await switch("bob")
                await expect(page.locator('[data-action="approve-message"]')).to_be_visible()
                await double_activate(page.locator('[data-action="approve-message"]'))
                await expect(page.locator(f'[data-message-id="{message_id}"] .receipt-box')).to_be_visible()
                receipt = (await state())["messages"][0]["receipt"]
                assert receipt["decision"] == "approved"
                assert receipt["execution"] == "simulation_only_no_calendar_write"
                await page.reload(wait_until="networkidle")
                await expect(page.locator("#owner-select")).to_have_value("bob")
                assert (await state())["messages"][0]["receipt"] == receipt
                await checkpoint("owner-only approval yields one durable simulation receipt after reload")
                await page.screenshot(path=str(artifacts / "02-approved-desktop.png"), full_page=True)

                # A delayed Alice snapshot must never overwrite Bob's newer owner view.
                await switch("alice")
                state_held = asyncio.Event()
                state_release = asyncio.Event()
                first_state = True

                async def hold_stale_snapshot(route):
                    nonlocal first_state
                    if first_state:
                        first_state = False
                        response = await route.fetch()
                        state_held.set()
                        await state_release.wait()
                        try:
                            await route.fulfill(response=response)
                        except Exception:
                            # Expected if the UI aborted this superseded fetch during owner switch.
                            pass
                    else:
                        await route.continue_()

                await page.route("**/api/state", hold_stale_snapshot)
                await page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
                await asyncio.wait_for(state_held.wait(), timeout=10)
                await switch("bob")
                state_release.set()
                await page.wait_for_timeout(100)
                await expect(page.locator("#owner-select")).to_have_value("bob")
                await expect(page.locator('[data-action="compose"]')).to_have_count(0)
                await page.unroute("**/api/state", hold_stale_snapshot)
                await checkpoint("a late previous-owner state response cannot restore stale controls")

                await context.set_offline(True)
                await page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
                await expect(page.locator("#connection-status")).to_contain_text("interrupted")
                for button in await page.locator('[data-mutation]').all():
                    await expect(button).to_be_disabled()
                await context.set_offline(False)
                await page.locator("#retry-connection").click()
                await expect(page.locator("#connection-status")).to_contain_text("Live")
                await checkpoint("network interruption disables mutations and reconnect restores current state")

                await switch("alice")
                await page.locator('[data-action="compose"]').click()
                await page.locator("#meeting-title").fill("Revocation must cancel this request")
                await page.locator("#send-message").click()
                await expect(page.locator("#message-form")).to_be_hidden()
                await switch("bob")
                await expect(page.locator('[data-action="approve-message"]')).to_be_visible()
                await page.locator('[data-action="revoke-grant"]').click()
                await expect(page.locator('[data-action="approve-message"]')).to_have_count(0)
                snapshot = await state()
                assert snapshot["grants"][0]["status"] == "revoked"
                second = next(message for message in snapshot["messages"] if message["id"] != message_id)
                assert second["status"] == "cancelled" and second["receipt"] is None
                assert next(message for message in snapshot["messages"] if message["id"] == message_id)["receipt"] == receipt
                await checkpoint("revocation cancels the pending proposal and preserves completed receipt")

                await page.set_viewport_size({"width": 390, "height": 844})
                assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "Mobile layout overflows horizontally"
                await page.screenshot(path=str(artifacts / "03-mobile.png"), full_page=True)
                assert not errors, f"Browser runtime errors: {errors}"
                assert not external_requests, f"Unexpected external requests: {external_requests}"
                await checkpoint("mobile layout has no horizontal overflow; no runtime errors or external requests")
                report.update(status="passed", artifacts=[str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path) for path in artifacts.glob("*.png")])
                await browser.close()
                return 0
        except Exception as error:
            report.update(status="failed", failure=str(error))
            if page:
                try:
                    await page.screenshot(path=str(artifacts / "failure.png"), full_page=True)
                except Exception:
                    pass
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass
            return 1
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            server.service.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-executable", help="Path to an already-installed Chromium executable")
    parser.add_argument("--artifacts", default=str(ROOT / "tests" / "browser-artifacts"))
    args = parser.parse_args()
    report = {"status": "started", "mode": "local-fixture-only", "checks": []}
    result = asyncio.run(run(args, report))
    destination = Path(args.artifacts)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "detail"}, indent=2))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
