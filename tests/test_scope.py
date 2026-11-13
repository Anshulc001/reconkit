"""Scope gate tests: temp files only, no network."""

from __future__ import annotations

import inspect
from datetime import date
from pathlib import Path

import pytest
import yaml

from reconkit.core import scope as scope_module
from reconkit.core.scope import (
    ScopeGate,
    check_target,
    ip_allowed,
    load_scope,
    passive_warning,
    require_active,
)
from reconkit.errors import ConfigError, ScopeError

TODAY = date(2026, 11, 13)
EXAMPLE_SCOPE = Path(__file__).resolve().parents[1] / "scope.example.yaml"


def write_scope(tmp_path: Path, **overrides: object) -> Path:
    data: dict[str, object] = {
        "program": "Test program",
        "authorization": "https://example.com/security",
        "expires": date(2027, 1, 31),
        "in_scope": ["example.com", "*.example.com"],
        "out_of_scope": ["admin.example.com"],
        "in_scope_cidrs": ["203.0.113.0/24"],
        "allow_active": True,
        "allow_intrusive": False,
        "max_speed": "normal",
    }
    data.update(overrides)
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_example_scope_loads() -> None:
    gate = load_scope(EXAMPLE_SCOPE)
    assert gate.scope.program == "Example Bug Bounty Program"
    assert check_target("api.example.com", today=TODAY, path=EXAMPLE_SCOPE) == (
        "ALLOWED (matches *.example.com)"
    )


def test_missing_scope_file(tmp_path: Path) -> None:
    with pytest.raises(ScopeError, match="not found"):
        require_active("example.com", [], "slow", TODAY, path=tmp_path / "missing-scope.yaml")


def test_empty_authorization(tmp_path: Path) -> None:
    path = write_scope(tmp_path, authorization="   ")
    with pytest.raises(ScopeError, match="authorization is empty"):
        require_active("example.com", [], "slow", TODAY, path=path)


def test_missing_authorization_key(tmp_path: Path) -> None:
    data = {
        "in_scope": ["example.com"],
        "allow_active": True,
    }
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ScopeError, match="invalid scope"):
        load_scope(path)


def test_expired_scope(tmp_path: Path) -> None:
    path = write_scope(tmp_path, expires=date(2026, 1, 1))
    with pytest.raises(ScopeError, match="expired on 2026-01-01"):
        require_active("example.com", [], "slow", TODAY, path=path)


def test_expiry_is_inclusive(tmp_path: Path) -> None:
    path = write_scope(tmp_path, expires=TODAY)
    require_active("example.com", [], "slow", TODAY, path=path)


def test_allow_active_false(tmp_path: Path) -> None:
    path = write_scope(tmp_path, allow_active=False)
    with pytest.raises(ScopeError, match="allow_active is false"):
        require_active("example.com", [], "slow", TODAY, path=path)


def test_out_of_scope_wins(tmp_path: Path) -> None:
    path = write_scope(tmp_path)
    with pytest.raises(ScopeError, match="out of scope"):
        require_active("admin.example.com", [], "slow", TODAY, path=path)
    result = require_active(
        "example.com", ["api.example.com", "admin.example.com"], "slow", TODAY, path=path
    )
    assert result.hosts == ["api.example.com"]
    assert result.dropped == 1


def test_wildcard_depth_but_not_apex(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope=["*.example.com"], out_of_scope=[])
    gate = load_scope(path)
    assert gate.allows("api.example.com")
    assert gate.allows("a.b.example.com")
    assert not gate.allows("example.com")
    assert not gate.allows("badexample.com")


def test_regex_entries(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope=[r"re:^api-[0-9]+\.example\.org$"], out_of_scope=[])
    gate = load_scope(path)
    assert gate.allows("api-12.example.org")
    assert gate.allows("API-12.Example.ORG.")
    assert not gate.allows("api-x.example.org")
    assert not gate.allows("api-12.example.org.evil.com")


def test_regex_must_fullmatch(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope=["re:api"], out_of_scope=[])
    gate = load_scope(path)
    assert gate.allows("api")
    assert not gate.allows("api.example.com")


def test_invalid_regex_is_config_error(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope=["re:("])
    with pytest.raises(ConfigError, match="invalid regex"):
        load_scope(path)


def test_overlong_regex_is_config_error(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope=["re:" + "a" * 201])
    with pytest.raises(ConfigError, match="longer than 200"):
        load_scope(path)


def test_cidr_allow_and_deny(tmp_path: Path) -> None:
    path = write_scope(tmp_path)
    assert ip_allowed("203.0.113.9", path=path) is True
    assert ip_allowed("198.51.100.9", path=path) is False


def test_no_cidrs_means_no_ips(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope_cidrs=[])
    assert ip_allowed("203.0.113.9", path=path) is False


def test_case_and_trailing_dot(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope=["example.com"], out_of_scope=[])
    assert check_target("Example.COM.", today=TODAY, path=path) == ("ALLOWED (matches example.com)")
    assert check_target("api.example.com", today=TODAY, path=path) == ("BLOCKED (not in scope)")


def test_underscore_hosts_are_in_scope(tmp_path: Path) -> None:
    path = write_scope(tmp_path)
    result = require_active(
        "example.com", ["dev_api.example.com", "*.api.example.com"], "slow", TODAY, path=path
    )
    assert result.hosts == ["dev_api.example.com", "api.example.com"]


def test_max_speed_cap(tmp_path: Path) -> None:
    path = write_scope(tmp_path, max_speed="normal")
    require_active("example.com", [], "normal", TODAY, path=path)
    with pytest.raises(ScopeError, match="max_speed"):
        require_active("example.com", [], "fast", TODAY, path=path)


def test_unknown_speed(tmp_path: Path) -> None:
    path = write_scope(tmp_path)
    with pytest.raises(ScopeError, match="unknown speed"):
        require_active("example.com", [], "turbo", TODAY, path=path)


def test_every_host_is_rechecked(tmp_path: Path) -> None:
    path = write_scope(tmp_path)
    result = require_active(
        "example.com",
        [
            "api.example.com",
            "admin.example.com",
            "evil.test",
            "not a host",
            "API.EXAMPLE.COM.",
        ],
        "slow",
        TODAY,
        path=path,
    )
    assert result.hosts == ["api.example.com"]
    assert result.dropped == 3
    assert result.match == "example.com"
    assert result.scope.program == "Test program"


def test_target_outside_scope(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope=["example.org"])
    with pytest.raises(ScopeError, match="is not in scope"):
        require_active("example.com", [], "slow", TODAY, path=path)


def test_malformed_yaml(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text("in_scope: [unclosed\n", encoding="utf-8")
    with pytest.raises(ScopeError, match="invalid YAML"):
        load_scope(path)


def test_non_mapping_yaml(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(ScopeError, match="must contain a mapping"):
        load_scope(path)


def test_unknown_key_is_config_error(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope_typo=["example.com"])
    with pytest.raises(ConfigError, match="unknown key"):
        load_scope(path)


def test_invalid_scope_entry(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope=["-bad.example.com"])
    with pytest.raises(ConfigError, match="invalid scope entry"):
        load_scope(path)


def test_invalid_cidr(tmp_path: Path) -> None:
    path = write_scope(tmp_path, in_scope_cidrs=["not-a-cidr"])
    with pytest.raises(ConfigError, match="invalid CIDR"):
        load_scope(path)


def test_check_target_texts(tmp_path: Path) -> None:
    path = write_scope(tmp_path)
    assert check_target("example.com", today=TODAY, path=path) == ("ALLOWED (matches example.com)")
    assert check_target("admin.example.com", today=TODAY, path=path) == (
        "BLOCKED (out_of_scope: admin.example.com)"
    )
    assert check_target("other.test", today=TODAY, path=path) == "BLOCKED (not in scope)"
    assert check_target("example.com", today=date(2027, 2, 1), path=path) == (
        "BLOCKED (scope expired 2027-01-31)"
    )
    assert check_target("example.com", today=TODAY, path=tmp_path / "none.yaml") == (
        "BLOCKED (scope file not found)"
    )


def test_passive_warning(tmp_path: Path) -> None:
    assert passive_warning("example.com", path=tmp_path / "none.yaml") is None
    path = write_scope(tmp_path)
    assert passive_warning("api.example.com", path=path) is None
    warning = passive_warning("example.net", path=path)
    assert warning is not None
    assert "outside scope.yaml" in warning
    assert "passive stages only" in warning


def test_no_bypass_parameter() -> None:
    forbidden = {"force", "skip", "bypass", "ignore", "no_scope", "dangerous"}

    def params(func: object) -> set[str]:
        return {name.lower() for name in inspect.signature(func).parameters}  # type: ignore[call-overload]

    functions = [
        value
        for _, value in inspect.getmembers(scope_module, inspect.isfunction)
        if value.__module__ == scope_module.__name__
    ]
    methods = [
        value
        for _, value in inspect.getmembers(ScopeGate, inspect.isfunction)
        if not value.__name__.startswith("_")
    ]
    for func in [*functions, *methods]:
        assert not params(func) & forbidden, func.__name__
