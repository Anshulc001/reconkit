"""Wildcard DNS detection (docs/03_ARCHITECTURE.md, docs/09_TOOL_CONTRACTS.md).

The detector resolves a few random labels under the target and reports the
wildcard answer set. It does not own a resolver: the engine injects the DNS
adapter's `resolve_host` bound to the run context, so probes go through the
same resolver and there is no second DNS stack.

A timeout, SERVFAIL, empty answer or unexpected error is `unknown`, never
`none`: reading it as "no wildcard" would silently let wildcard noise into the
results.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from reconkit.core.runner import validate_target

if TYPE_CHECKING:
    from reconkit.adapters.dnspython import DnsResult

Probe = Callable[[str], Awaitable["DnsResult"]]


class Rng(Protocol):
    """The one random operation the detector needs, injected for tests."""

    def choice(self, seq: str) -> str: ...


_LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_LABEL_LENGTH = 12


class WildcardStatus(StrEnum):
    NONE = "none"
    PRESENT = "present"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class WildcardResult:
    """What the random-label probes found, including why they could not tell."""

    status: WildcardStatus
    ips: frozenset[str] = frozenset()
    cnames: frozenset[str] = frozenset()
    probes: int = 0
    resolved: int = 0

    def matches(self, *, ips: Iterable[str] = (), cnames: Iterable[str] = ()) -> bool:
        """True when a host resolves only to the wildcard answer."""
        if self.status is not WildcardStatus.PRESENT:
            return False
        host_cnames = {value.strip().lower().rstrip(".") for value in cnames}
        host_cnames.discard("")
        if host_cnames & self.cnames:
            return True
        host_ips = {value.strip() for value in ips}
        host_ips.discard("")
        return bool(host_ips) and host_ips <= self.ips


class WildcardDetector:
    """Probe random labels with an injected, already-paced resolver call."""

    def __init__(
        self,
        *,
        probe: Probe,
        rng: Rng,
        probes: int = 3,
    ) -> None:
        if probes < 1:
            raise ValueError("wildcard probes must be at least 1")
        self._probe = probe
        self._rng = rng
        self._probes = probes

    async def detect(self, target: str) -> WildcardResult:
        root = validate_target(target)
        hosts = self._labels(root)
        results: list[DnsResult | None] = []
        for host in hosts:
            try:
                results.append(await self._probe(host))
            except Exception:
                # A probe must never abort the scan; an unexpected resolver
                # error is the same "cannot tell" state as a timeout.
                results.append(None)

        resolved = [
            result for result in results if result is not None and result.outcome == "resolved"
        ]
        if resolved:
            return WildcardResult(
                status=WildcardStatus.PRESENT,
                ips=frozenset(ip for result in resolved for ip in result.ips),
                cnames=frozenset(
                    cname.lower().rstrip(".") for result in resolved for cname in result.cnames
                ),
                probes=len(results),
                resolved=len(resolved),
            )
        if results and all(
            result is not None and result.outcome == "nxdomain" for result in results
        ):
            return WildcardResult(status=WildcardStatus.NONE, probes=len(results))
        return WildcardResult(status=WildcardStatus.UNKNOWN, probes=len(results))

    def _labels(self, root: str) -> list[str]:
        labels: set[str] = set()
        while len(labels) < self._probes:
            labels.add("".join(self._rng.choice(_LABEL_ALPHABET) for _ in range(_LABEL_LENGTH)))
        return [f"{label}.{root}" for label in sorted(labels)]
