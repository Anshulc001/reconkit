"""subfinder binary adapter (docs/09_TOOL_CONTRACTS.md).

Provider keys are file-based in subfinder. The adapter writes the allowed env
values into a temporary provider-config.yaml (mode 0600), passes it with `-pc`,
and removes it in a finally block; key values never reach argv or a log.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import yaml

from reconkit.adapters.base import BinaryAdapter, Finder, parse_subdomain_lines
from reconkit.core.runner import validate_target
from reconkit.errors import ToolFailed
from reconkit.models import Record, RunContext, Stage

PROVIDERS = {
    "CERTSPOTTER_API_KEY": "certspotter",
    "PDCP_API_KEY": "chaos",
    "GITHUB_TOKEN": "github",
    "VT_API_KEY": "virustotal",
}


class SubfinderAdapter(BinaryAdapter):
    name = "subfinder"
    stage = Stage.SUBS
    binary = "subfinder"
    version_args = ["-version"]
    identity_markers = ("current version", "subfinder")
    needs_home = True

    def __init__(self, *, finder: Finder | None = None, fixtures_dir: Path | None = None) -> None:
        super().__init__(finder=finder, fixtures_dir=fixtures_dir)
        self._provider_config: Path | None = None

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        path = self._write_provider_config(ctx)
        self._provider_config = path
        try:
            yield
        finally:
            self._provider_config = None
            if path is not None:
                path.unlink(missing_ok=True)

    def _write_provider_config(self, ctx: RunContext) -> Path | None:
        data = {provider: [ctx.env[env]] for env, provider in PROVIDERS.items() if ctx.env.get(env)}
        if not data:
            return None
        fd, name = tempfile.mkstemp(prefix="reconkit-subfinder-", suffix=".yaml")
        path = Path(name)
        try:
            os.chmod(path, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                yaml.safe_dump(data, handle)
        except (OSError, yaml.YAMLError):
            try:
                os.close(fd)
            except OSError:
                pass
            path.unlink(missing_ok=True)
            raise ToolFailed("subfinder: cannot write provider config") from None
        return path

    def build_command(self, ctx: RunContext) -> list[str]:
        try:
            target = validate_target(ctx.target)
        except (TypeError, ValueError):
            raise ToolFailed("subfinder: invalid target") from None
        argv = [self.binary, "-d", target, "-silent", "-nc", "-duc"]
        argv += ctx.pacer.tool_rate_args(self.name, "passive")
        if self._provider_config is not None:
            argv += ["-pc", str(self._provider_config)]
        return argv

    def parse_output(self, raw: str) -> list[Record]:
        return parse_subdomain_lines(raw, self.name)
