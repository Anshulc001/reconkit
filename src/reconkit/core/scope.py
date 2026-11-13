"""Scope gate: load scope.yaml and decide what may be touched (docs/05 sections 2-3)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal, NamedTuple

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from reconkit.core.runner import validate_host, validate_target
from reconkit.errors import ConfigError, ScopeError

DEFAULT_SCOPE_PATH = Path("scope.yaml")
MAX_PATTERN_LEN = 200
_SPEED_RANK: dict[str, int] = {"slow": 0, "normal": 1, "fast": 2}
_SCOPE_KEYS = frozenset(
    {
        "program",
        "authorization",
        "expires",
        "in_scope",
        "out_of_scope",
        "in_scope_cidrs",
        "allow_active",
        "allow_intrusive",
        "max_speed",
        "notes",
    }
)


class Scope(BaseModel):
    """Parsed scope.yaml (docs/05 section 2)."""

    model_config = ConfigDict(extra="forbid")

    program: str | None = None
    authorization: str
    expires: date | None = None
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    in_scope_cidrs: list[str] = Field(default_factory=list)
    allow_active: bool = False
    allow_intrusive: bool = False
    max_speed: Literal["slow", "normal", "fast"] = "slow"
    notes: str | None = None


@dataclass(frozen=True)
class _Rule:
    label: str
    exact: str | None = None
    suffix: str | None = None
    regex: re.Pattern[str] | None = None

    def matches(self, host: str) -> bool:
        if self.exact is not None:
            return host == self.exact
        if self.suffix is not None:
            return host.endswith(self.suffix)
        if self.regex is not None:
            return self.regex.fullmatch(host) is not None
        return False


class ActiveCheck(NamedTuple):
    """Result of a successful active-stage gate check."""

    scope: Scope
    match: str
    hosts: list[str]
    dropped: int


class ScopeGate:
    """A loaded scope file with compiled matchers."""

    def __init__(
        self,
        scope: Scope,
        in_rules: tuple[_Rule, ...],
        out_rules: tuple[_Rule, ...],
        networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
        path: Path,
    ) -> None:
        self.scope = scope
        self._in_rules = in_rules
        self._out_rules = out_rules
        self._networks = networks
        self.path = path

    def in_rule(self, host: str) -> _Rule | None:
        return next((rule for rule in self._in_rules if rule.matches(_normalize(host))), None)

    def out_rule(self, host: str) -> _Rule | None:
        return next((rule for rule in self._out_rules if rule.matches(_normalize(host))), None)

    def allows(self, host: str) -> bool:
        normalized = _normalize(host)
        if any(rule.matches(normalized) for rule in self._out_rules):
            return False
        return any(rule.matches(normalized) for rule in self._in_rules)

    def ip_allowed(self, ip: str) -> bool:
        address = ipaddress.ip_address(ip)
        return any(address in network for network in self._networks)


def _normalize(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _path(path: Path | str | None) -> Path:
    return Path(path) if path is not None else DEFAULT_SCOPE_PATH


def load_scope(path: Path | str | None = None) -> ScopeGate:
    """Load and validate scope.yaml.

    Unknown keys raise ConfigError (likely a typo); a missing or unreadable
    file and invalid values raise ScopeError.
    """
    scope_path = _path(path)
    try:
        raw = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScopeError(f"scope gate: cannot read {scope_path}\nfix: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ScopeError(f"scope gate: invalid YAML in {scope_path}\nfix: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScopeError(
            f"scope gate: {scope_path} must contain a mapping\n"
            "fix: copy scope.example.yaml and edit it"
        )
    unknown = sorted(str(key) for key in raw if key not in _SCOPE_KEYS)
    if unknown:
        raise ConfigError(
            f"unknown key(s) in {scope_path}: {', '.join(unknown)}\n"
            "fix: check scope.example.yaml for the supported fields"
        )
    try:
        scope = Scope.model_validate(raw)
    except ValidationError as exc:
        raise ScopeError(f"scope gate: invalid scope in {scope_path}\nfix: {exc}") from exc

    in_rules = tuple(_compile_entry(entry) for entry in scope.in_scope)
    out_rules = tuple(_compile_entry(entry) for entry in scope.out_of_scope)
    networks = tuple(_compile_cidr(cidr) for cidr in scope.in_scope_cidrs)
    return ScopeGate(scope, in_rules, out_rules, networks, scope_path)


def _compile_entry(entry: str) -> _Rule:
    text = entry.strip().lower().rstrip(".")
    if not text:
        raise ConfigError("scope entry is empty\nfix: remove it or name a host")
    if text.startswith("re:"):
        pattern = text[3:].strip()
        if not pattern:
            raise ConfigError(
                f"empty regex in scope entry {entry!r}\nfix: add a pattern after 're:'"
            )
        if len(pattern) > MAX_PATTERN_LEN:
            raise ConfigError(
                f"regex in {entry!r} is longer than {MAX_PATTERN_LEN} characters\n"
                "fix: use a wildcard entry instead"
            )
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"invalid regex in scope entry {entry!r}\nfix: {exc}") from exc
        return _Rule(label=text, regex=compiled)
    if text.startswith("*."):
        domain = text[2:]
        if not domain:
            raise ConfigError(f"invalid scope entry {entry!r}\nfix: name a domain after '*.'")
        try:
            normalized = validate_host(domain)
        except ValueError as exc:
            raise ConfigError(f"invalid scope entry {entry!r}\nfix: {exc}") from exc
        return _Rule(label=text, suffix=f".{normalized}")
    try:
        label = validate_host(text)
    except ValueError as exc:
        raise ConfigError(f"invalid scope entry {entry!r}\nfix: {exc}") from exc
    return _Rule(label=label, exact=label)


def _compile_cidr(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise ConfigError(f"invalid CIDR in scope: {cidr!r}\nfix: {exc}") from exc


def _fail(cause: str, fix: str) -> ScopeError:
    return ScopeError(f"scope gate: {cause}\nfix: {fix}")


def _today(today: date | None) -> date:
    return today if today is not None else date.today()


def _check_expiry(scope: Scope, today: date) -> None:
    if scope.expires is not None and today > scope.expires:
        raise _fail(
            f"scope expired on {scope.expires.isoformat()}",
            "update expires after confirming your authorization is still valid",
        )


def require_active(
    target: str,
    hosts: Iterable[str],
    speed: str,
    today: date | None = None,
    *,
    path: Path | str | None = None,
) -> ActiveCheck:
    """Gate an active stage and re-check every host (docs/05 section 2).

    Checks run in order: scope file exists, authorization is set, not expired,
    `allow_active`, target allowed, `max_speed`. Any failure raises ScopeError.
    """
    scope_path = _path(path)
    if not scope_path.exists():
        raise _fail(
            f"{scope_path} not found",
            "copy scope.example.yaml to scope.yaml and list your authorized targets",
        )
    gate = load_scope(scope_path)
    scope = gate.scope
    day = _today(today)

    if not scope.authorization.strip():
        raise _fail(
            "authorization is empty",
            "set authorization to a link or note proving written permission",
        )
    _check_expiry(scope, day)
    if not scope.allow_active:
        raise _fail(
            "allow_active is false",
            "set allow_active: true only if you are authorized to send active traffic",
        )

    try:
        root = validate_target(target)
    except ValueError as exc:
        raise _fail(f"invalid target {target!r}", str(exc)) from exc
    out_rule = gate.out_rule(root)
    if out_rule is not None:
        raise _fail(
            f"{root} is out of scope ({out_rule.label})",
            "remove it from out_of_scope or choose an in-scope target",
        )
    match = gate.in_rule(root)
    if match is None:
        raise _fail(
            f"{root} is not in scope",
            "add it (or a wildcard) to in_scope in scope.yaml",
        )

    if speed not in _SPEED_RANK:
        raise _fail(f"unknown speed {speed!r}", "use slow, normal or fast")
    if _SPEED_RANK[speed] > _SPEED_RANK[scope.max_speed]:
        raise _fail(
            f"speed {speed!r} exceeds max_speed {scope.max_speed!r}",
            "lower --speed or raise max_speed in scope.yaml",
        )

    allowed: list[str] = []
    dropped = 0
    seen: set[str] = set()
    for host in hosts:
        try:
            normalized = validate_host(host)
        except ValueError:
            dropped += 1
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        if gate.allows(normalized):
            allowed.append(normalized)
        else:
            dropped += 1
    return ActiveCheck(scope=scope, match=match.label, hosts=allowed, dropped=dropped)


def ip_allowed(ip: str, *, path: Path | str | None = None) -> bool:
    """True only when the IP is inside in_scope_cidrs; no CIDRs means no IPs."""
    return load_scope(path).ip_allowed(ip)


def check_target(
    target: str,
    *,
    today: date | None = None,
    path: Path | str | None = None,
) -> str:
    """Return the human-readable scope decision for one target (docs/08 flow 3)."""
    host = validate_target(target)
    scope_path = _path(path)
    if not scope_path.exists():
        return "BLOCKED (scope file not found)"
    gate = load_scope(scope_path)
    out_rule = gate.out_rule(host)
    if out_rule is not None:
        return f"BLOCKED (out_of_scope: {out_rule.label})"
    expiry = gate.scope.expires
    if expiry is not None and _today(today) > expiry:
        return f"BLOCKED (scope expired {expiry.isoformat()})"
    match = gate.in_rule(host)
    if match is not None:
        return f"ALLOWED (matches {match.label})"
    return "BLOCKED (not in scope)"


def passive_warning(target: str, *, path: Path | str | None = None) -> str | None:
    """Warn when a passive run targets something outside an existing scope file."""
    scope_path = _path(path)
    if not scope_path.exists():
        return None
    try:
        gate = load_scope(scope_path)
    except (ConfigError, ScopeError) as exc:
        return f"warning: {exc}\nwarning: continuing with passive stages only"
    host = _normalize(target)
    if gate.allows(host):
        return None
    return f"warning: {host} is outside scope.yaml\nwarning: continuing with passive stages only"
