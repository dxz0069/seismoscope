"""Policy-bounded Playwright evidence collection for pre-started local services."""

from __future__ import annotations

import base64
import ipaddress
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse


@dataclass
class BrowserEvidence:
    type: str
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "url": self.url,
        }


@dataclass
class BrowserExecutionResult:
    success: bool
    url: str
    evidence: list[BrowserEvidence] = field(default_factory=list)
    console_logs: list[dict[str, Any]] = field(default_factory=list)
    network_requests: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    execution_time: float = 0.0
    status: str = "completed"
    predicate_satisfied: bool = False
    predicate: str = ""
    controls: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "status": self.status,
            "url": self.url,
            "predicate": self.predicate,
            "predicate_satisfied": self.predicate_satisfied,
            "controls": self.controls,
            "evidence": [item.to_dict() for item in self.evidence],
            "console_logs": self.console_logs,
            "network_requests": self.network_requests,
            "error": self.error,
            "execution_time": self.execution_time,
        }


class PlaywrightExecutor:
    """Run explicit positive/negative browser controls against a loopback URL."""

    def __init__(self, *, allow_non_loopback: bool = False, max_dom_chars: int = 100_000):
        self.allow_non_loopback = allow_non_loopback
        self.max_dom_chars = max(10_000, int(max_dom_chars))
        self._playwright_available = self._check_playwright()

    @staticmethod
    def _check_playwright() -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    async def execute_xss_controls(
        self,
        *,
        url: str,
        selector: str,
        positive_payload: str,
        negative_payload: str,
        marker: str = "__VIBE_SEC_XSS__",
        submit_selector: str | None = None,
        timeout_ms: int = 15_000,
    ) -> BrowserExecutionResult:
        predicate = f"positive control sets window[{marker!r}] or opens a marker dialog; negative control does not"
        scope_error = self._validate_url(url)
        if scope_error:
            return BrowserExecutionResult(False, url, error=scope_error, status="blocked", predicate=predicate)
        if not selector or not positive_payload or not negative_payload:
            return BrowserExecutionResult(
                False, url, error="selector and both control payloads are required",
                status="blocked", predicate=predicate,
            )
        if not self._playwright_available:
            return BrowserExecutionResult(
                False, url, error="Playwright is not available", status="unavailable", predicate=predicate,
            )

        from playwright.async_api import async_playwright

        started = time.monotonic()
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                try:
                    positive = await self._run_control(
                        browser, url, selector, positive_payload, marker,
                        submit_selector=submit_selector, timeout_ms=timeout_ms, collect_evidence=True,
                    )
                    negative = await self._run_control(
                        browser, url, selector, negative_payload, marker,
                        submit_selector=submit_selector, timeout_ms=timeout_ms, collect_evidence=False,
                    )
                finally:
                    await browser.close()
        except Exception as exc:
            return BrowserExecutionResult(
                False, url, error=str(exc), status="failed", predicate=predicate,
                execution_time=time.monotonic() - started,
            )
        satisfied = bool(positive["marker_observed"] and not negative["marker_observed"])
        return BrowserExecutionResult(
            True,
            url,
            evidence=positive["evidence"],
            console_logs=positive["console_logs"],
            network_requests=positive["network_requests"],
            execution_time=time.monotonic() - started,
            status="completed",
            predicate_satisfied=satisfied,
            predicate=predicate,
            controls={
                "positive": {"marker_observed": positive["marker_observed"]},
                "negative": {"marker_observed": negative["marker_observed"]},
            },
        )

    async def _run_control(
        self,
        browser,
        url: str,
        selector: str,
        payload: str,
        marker: str,
        *,
        submit_selector: str | None,
        timeout_ms: int,
        collect_evidence: bool,
    ) -> dict[str, Any]:
        context = await browser.new_context()
        page = await context.new_page()
        logs: list[dict[str, Any]] = []
        requests: list[dict[str, Any]] = []
        dialogs: list[str] = []
        target_host = (urlparse(url).hostname or "").lower()

        async def route_handler(route):
            request_host = (urlparse(route.request.url).hostname or "").lower()
            if request_host != target_host:
                await route.abort()
            else:
                await route.continue_()

        await context.route("**/*", route_handler)
        page.on("console", lambda message: logs.append({"type": message.type, "text": message.text[:2000]}))
        page.on("request", lambda request: requests.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
        }))

        async def dismiss_dialog(dialog):
            dialogs.append(dialog.message[:1000])
            await dialog.dismiss()

        page.on("dialog", dismiss_dialog)
        try:
            await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            await page.locator(selector).first.fill(payload, timeout=timeout_ms)
            if submit_selector:
                await page.locator(submit_selector).first.click(timeout=timeout_ms)
            else:
                await page.locator(selector).first.press("Enter", timeout=timeout_ms)
            await page.wait_for_timeout(500)
            marker_value = await page.evaluate("name => window[name] === true", marker)
            marker_observed = bool(marker_value or any(marker in item for item in dialogs))
            evidence: list[BrowserEvidence] = []
            if collect_evidence:
                screenshot = await page.screenshot(full_page=True)
                evidence.append(BrowserEvidence("screenshot", base64.b64encode(screenshot).decode("ascii"), url=url))
                dom = await page.content()
                evidence.append(BrowserEvidence("dom_snapshot", dom[:self.max_dom_chars], url=url))
            return {
                "marker_observed": marker_observed,
                "evidence": evidence,
                "console_logs": logs[:200],
                "network_requests": requests[:500],
            }
        finally:
            await context.close()

    async def verify_xss_vulnerability(self, url: str, payload: str) -> dict[str, Any]:
        del payload
        return {
            "verified": False,
            "status": "needs_evidence",
            "explanation": "selector, positive payload, negative payload, and marker are required",
            "evidence": [],
            "url": url,
        }

    def _validate_url(self, url: str) -> str | None:
        parsed = urlparse(str(url))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return "Browser target must be an HTTP(S) URL"
        if self.allow_non_loopback:
            return None
        hostname = parsed.hostname.lower()
        if hostname == "localhost":
            return None
        try:
            if ipaddress.ip_address(hostname).is_loopback:
                return None
        except ValueError:
            pass
        return "Browser verification is restricted to loopback targets"
