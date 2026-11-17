"""httprobe adapter (docs/09_TOOL_CONTRACTS.md).

httprobe reads hostnames on stdin and prints every `scheme://host` that answered,
which is the whole liveness question. It has no input flag and no `-version`, so
the identity probe is `-h` plus two strings only httprobe prints.

Real flags (verified on this box, `httprobe -h`): `-c` concurrency, `-p
proto:port` extra probe, `-s` skip the default probes, `-t` timeout in
milliseconds, `-v` errors to stderr. The default probes are `http:80` and
`https:443`; there is no `-prefer-https` flag in this build.
"""

from __future__ import annotations

from reconkit.adapters.base import BinaryAdapter, normalize_url, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import HostState, HostStatusRecord, Record, RunContext, Stage


class HttprobeAdapter(BinaryAdapter):
    name = "httprobe"
    stage = Stage.LIVE
    binary = "httprobe"
    # `httprobe -version` exits 2 with "flag provided but not defined"; `-h`
    # exits 0 and prints the usage these two markers come from.
    version_args = ["-h"]
    identity_markers = ("skip the default probes", "concurrency level")
    needs_home = False

    def _hosts(self, ctx: RunContext) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()
        for raw in ctx.hosts:
            try:
                host = validate_host(raw)
            except (TypeError, ValueError):
                continue
            if host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts

    def build_command(self, ctx: RunContext) -> list[str]:
        if not self._hosts(ctx):
            raise ToolFailed("httprobe: no hosts to probe")
        # `-t` is milliseconds (real help: "timeout (milliseconds)"). The default
        # probes (http:80, https:443) stay as they are: no extra port is invented
        # and `-s` is never passed, so a hit means what the tool documents.
        return [
            self.binary_path() or self.binary,
            "-t",
            str(max(1, int(ctx.timeout * 1000))),
        ]

    def stdin_text(self, ctx: RunContext) -> str | None:
        hosts = self._hosts(ctx)
        return "".join(f"{host}\n" for host in hosts) or None

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[str] = set()
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line:
                continue
            url = normalize_url(line)
            if url is None:
                raise ParseError(f"httprobe: line is not a URL {line!r}")
            host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
            try:
                fqdn = validate_host(host)
            except (TypeError, ValueError):
                raise ParseError(f"httprobe: invalid host in {line!r}") from None
            if fqdn in seen:
                continue
            seen.add(fqdn)
            # httprobe answers only what answered: one ALIVE per host, no state
            # guess, no status code (the tool prints none).
            records.append(HostStatusRecord(fqdn=fqdn, source=self.name, state=HostState.ALIVE))
        return records
