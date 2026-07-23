from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class HostRateLimiter:
    def __init__(self, requests_per_second: float):
        self.interval = 1.0 / requests_per_second
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._last_request: dict[str, float] = {}

    async def wait(self, hostname: str) -> None:
        async with self._locks[hostname]:
            now = time.monotonic()
            remaining = self.interval - (now - self._last_request.get(hostname, 0.0))
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._last_request[hostname] = time.monotonic()
