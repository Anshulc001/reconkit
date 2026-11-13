"""Pacer: delays, jitter, shuffling, parallel limits and rate limiting (docs/03 section 7)."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Literal, TypeVar

from reconkit.config import SpeedPreset

StageMode = Literal["passive", "active"]


def _number(value: float) -> str:
    """Render a rate as `10`, not `10.0`, when it is a whole number."""
    return str(int(value)) if float(value).is_integer() else str(value)


Clock = Callable[[], float]
Sleep = Callable[[float], Awaitable[None]]
T = TypeVar("T")


class Pacer:
    """One pacing object per run, built from the chosen speed preset.

    Randomness and sleeping are injected so tests never wait and never depend
    on global state. Pacing only sleeps; it never prints or touches the network.
    """

    def __init__(
        self,
        preset: SpeedPreset,
        *,
        rate_flags: Mapping[str, str] | None = None,
        rng: random.Random | None = None,
        sleep: Sleep | None = None,
    ) -> None:
        self._preset = preset
        self._rate_flags = {name.lower(): flag for name, flag in (rate_flags or {}).items()}
        self._rng = rng if rng is not None else random.Random()
        self._sleep = sleep if sleep is not None else asyncio.sleep
        self._tools_seen = 0

    @property
    def preset(self) -> SpeedPreset:
        return self._preset

    def reset(self) -> None:
        """Start a new stage: the next tool is the first one and does not wait."""
        self._tools_seen = 0

    def parallel_limit(self, mode: StageMode) -> int:
        if mode == "passive":
            return self._preset.passive_max_parallel_tools
        return self._preset.active_max_parallel_tools

    def next_pause_range(self, mode: StageMode = "passive") -> tuple[float, float] | None:
        """Delay range the next tool would sample, or None when there is no pause."""
        low, high = self._delay_range(mode)
        return None if high <= 0 else (low, high)

    async def before_tool(self, mode: StageMode = "passive") -> float:
        """Wait before a tool starts; the first tool of a stage never waits."""
        if self._tools_seen == 0:
            self._tools_seen = 1
            return 0.0
        self._tools_seen += 1
        return await self._pause(*self._delay_range(mode))

    async def before_host(self) -> float:
        """Wait between active-stage hosts."""
        return await self._pause(*self._preset.active_host_delay)

    def order(
        self,
        items: Sequence[T],
        *,
        kind: Literal["host", "port"] = "host",
    ) -> list[T]:
        """Return a new list, shuffled only when the preset enables it."""
        ordered = list(items)
        shuffle = self._preset.shuffle_hosts if kind == "host" else self._preset.shuffle_ports
        if shuffle:
            self._rng.shuffle(ordered)
        return ordered

    def tool_rate_args(self, tool: str, mode: StageMode) -> list[str]:
        """Rate-limit flags for a CLI tool; empty when the tool has none.

        Passive tools use the passive request rate, active tools the active one;
        nmap and masscan always take their active-preset timings.
        """
        name = tool.lower()
        if name == "nmap":
            return [f"-T{self._preset.nmap_timing}"]
        if name == "masscan":
            return ["--max-rate", str(self._preset.masscan_max_rate)]
        flag = self._rate_flags.get(name)
        if flag is None:
            return []
        rate = (
            self._preset.passive_requests_per_second
            if mode == "passive"
            else self._preset.active_requests_per_second
        )
        return [flag, _number(rate)]

    def _delay_range(self, mode: StageMode) -> tuple[float, float]:
        if mode == "passive":
            return self._preset.passive_tool_delay
        return self._preset.active_tool_delay

    async def _pause(self, low: float, high: float) -> float:
        if high <= 0:
            return 0.0
        delay = self._rng.uniform(low, high)
        if delay > 0:
            await self._sleep(delay)
        return delay


class RateLimiter:
    """Async spacing of requests per second, shared by HTTP adapters."""

    def __init__(
        self,
        rate: float,
        *,
        clock: Clock | None = None,
        sleep: Sleep | None = None,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self._interval = 1.0 / rate
        self._clock = clock if clock is not None else time.monotonic
        self._sleep = sleep if sleep is not None else asyncio.sleep
        self._next_at = self._clock()
        self._lock = asyncio.Lock()

    @property
    def interval(self) -> float:
        return self._interval

    async def wait(self) -> float:
        """Block until the next slot; returns how long it waited."""
        async with self._lock:
            now = self._clock()
            delay = self._next_at - now
            if delay > 0:
                await self._sleep(delay)
                now = self._clock()
            self._next_at = max(now, self._next_at) + self._interval
            return max(delay, 0.0)
