"""Retry/backoff policy for recoverable agent and tool failures."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional, Tuple, Type


@dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 8.0
    exponential: bool = True
    retryable_exceptions: Tuple[Type[BaseException], ...] = (Exception,)
    non_retryable_markers: Tuple[str, ...] = (
        "invalid_request_error",
        "authentication_error",
        "permission_denied",
        "incorrect api key",
        "error code: 400",
        "error code: 401",
        "error code: 403",
    )

    def __post_init__(self) -> None:
        self.max_attempts = max(1, int(self.max_attempts))
        self.base_delay_seconds = max(0.0, float(self.base_delay_seconds))
        self.max_delay_seconds = max(self.base_delay_seconds, float(self.max_delay_seconds))

    def should_retry(self, attempt: int, error: Optional[BaseException] = None) -> bool:
        if attempt >= self.max_attempts:
            return False
        if error is None:
            return True
        if not isinstance(error, self.retryable_exceptions):
            return False
        message = str(error).lower()
        return not any(marker in message for marker in self.non_retryable_markers)

    def delay_for(self, attempt: int) -> float:
        exponent = max(0, int(attempt) - 1)
        delay = self.base_delay_seconds * (2**exponent if self.exponential else 1)
        return min(self.max_delay_seconds, delay)

    async def wait(self, attempt: int) -> None:
        delay = self.delay_for(attempt)
        if delay:
            await asyncio.sleep(delay)
