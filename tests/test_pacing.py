"""Pacing tests: fake clock, seeded RNG, no real sleeping and no network."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Literal

import pytest

from reconkit.config import load_config, resolve_speed
from reconkit.core.pacing import Pacer, RateLimiter

CONFIG = Path(__file__).resolve().parents[1] / "config.yaml"


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def make_pacer(
    speed: str = "slow",
    *,
    delay: str | None = None,
    rate_flags: dict[str, str] | None = None,
) -> tuple[Pacer, FakeClock]:
    config = load_config(CONFIG, speed=speed, delay=delay)
    clock = FakeClock()
    pacer = Pacer(
        resolve_speed(config),
        rate_flags=rate_flags,
        rng=random.Random(1234),
        sleep=clock.sleep,
    )
    return pacer, clock


async def test_slow_delays_and_parallel_limits() -> None:
    pacer, clock = make_pacer("slow")
    assert pacer.parallel_limit("passive") == 1
    assert pacer.parallel_limit("active") == 1
    assert await pacer.before_tool("passive") == 0.0
    assert clock.sleeps == []
    delay = await pacer.before_tool("passive")
    assert 5 <= delay <= 30
    assert clock.sleeps == [delay]
    host_delay = await pacer.before_host()
    assert 1 <= host_delay <= 5


async def test_normal_values() -> None:
    pacer, clock = make_pacer("normal")
    assert pacer.parallel_limit("passive") == 3
    assert pacer.parallel_limit("active") == 2
    assert await pacer.before_tool("passive") == 0.0
    assert 1 <= await pacer.before_tool("passive") <= 5
    assert await pacer.before_tool("active") >= 2
    assert len(clock.sleeps) == 2


async def test_fast_never_sleeps() -> None:
    pacer, clock = make_pacer("fast")
    assert pacer.parallel_limit("passive") == 99
    assert await pacer.before_tool("passive") == 0.0
    assert await pacer.before_tool("passive") == 0.0
    assert await pacer.before_tool("active") == 0.0
    assert await pacer.before_host() == 0.0
    assert clock.sleeps == []


async def test_first_tool_and_reset() -> None:
    pacer, clock = make_pacer("slow")
    assert await pacer.before_tool("active") == 0.0
    await pacer.before_tool("active")
    assert len(clock.sleeps) == 1
    pacer.reset()
    assert await pacer.before_tool("active") == 0.0
    assert len(clock.sleeps) == 1


def test_shuffle_is_deterministic_and_a_permutation() -> None:
    items = [f"h{i}.example.com" for i in range(10)]
    original = list(items)
    first, _ = make_pacer("slow")
    second, _ = make_pacer("slow")
    shuffled = first.order(items)
    assert shuffled == second.order(items)
    assert sorted(shuffled) == sorted(items)
    assert shuffled != items
    assert items == original


def test_fast_preserves_order() -> None:
    items = ["c.example.com", "a.example.com", "b.example.com"]
    pacer, _ = make_pacer("fast")
    assert pacer.order(items) == items
    assert pacer.order([443, 80, 22], kind="port") == [443, 80, 22]


def test_next_pause_range() -> None:
    slow, _ = make_pacer("slow")
    assert slow.next_pause_range("passive") == (5.0, 30.0)
    assert slow.next_pause_range("active") == (10.0, 60.0)
    fast, _ = make_pacer("fast")
    assert fast.next_pause_range("passive") is None


def test_tool_rate_args_slow() -> None:
    pacer, _ = make_pacer("slow", rate_flags={"subfinder": "-rl"})
    assert pacer.tool_rate_args("nmap") == ["-T2"]
    assert pacer.tool_rate_args("masscan") == ["--max-rate", "100"]
    assert pacer.tool_rate_args("subfinder") == ["-rl", "10"]
    assert pacer.tool_rate_args("SubFinder") == ["-rl", "10"]
    assert pacer.tool_rate_args("naabu") == []
    assert pacer.tool_rate_args("unknown-tool") == []


def test_tool_rate_args_follow_preset() -> None:
    pacer, _ = make_pacer("fast", rate_flags={"httpx": "-rate-limit"})
    assert pacer.tool_rate_args("httpx") == ["-rate-limit", "300"]
    assert pacer.tool_rate_args("nmap") == ["-T4"]
    assert pacer.tool_rate_args("masscan") == ["--max-rate", "1000"]


async def test_delay_override_applies() -> None:
    pacer, clock = make_pacer("slow", delay="7-9")
    assert pacer.next_pause_range("passive") == (7.0, 9.0)
    assert await pacer.before_tool("passive") == 0.0
    delay = await pacer.before_tool("passive")
    assert 7 <= delay <= 9
    assert clock.sleeps == [delay]


async def test_rate_limiter_spacing() -> None:
    clock = FakeClock()
    limiter = RateLimiter(2.0, clock=clock.time, sleep=clock.sleep)
    assert limiter.interval == 0.5
    assert await limiter.wait() == 0.0
    assert await limiter.wait() == pytest.approx(0.5)
    assert await limiter.wait() == pytest.approx(0.5)
    assert clock.now == pytest.approx(1.0)
    assert clock.sleeps == pytest.approx([0.5, 0.5])


def test_rate_limiter_rejects_bad_rate() -> None:
    with pytest.raises(ValueError):
        RateLimiter(0)


async def test_before_host_zero_skips_sleep() -> None:
    pacer, clock = make_pacer("normal")
    assert await pacer.before_host() >= 0
    assert len(clock.sleeps) <= 1
    fast, fast_clock = make_pacer("fast")
    assert await fast.before_host() == 0.0
    assert fast_clock.sleeps == []


def test_mode_literal_accepts_strings() -> None:
    mode: Literal["passive", "active"] = "active"
    pacer, _ = make_pacer("slow")
    assert pacer.parallel_limit(mode) == 1
