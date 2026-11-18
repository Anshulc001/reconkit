"""OWASP Amass v5 adapter (docs/09_TOOL_CONTRACTS.md).

Verified on this box (amass 5.1.3, `/usr/bin/amass`):

- `amass --version` prints only `v5.1.3` - no program name - so the identity
  probe is `amass enum -h`, whose banner carries
  `OWASP Amass Project - @owaspamass` (verified: exit 0, same on stdout).
  A bare version string can not tell amass from any other Go binary.
- v5's tree is `assoc|engine|enum|subs|track|viz`; the enumeration command is
  `amass enum -d DOMAIN`. `-passive` still parses but prints
  `Deprecated since passive is the default setting`, so the adapter does not
  pass it (`tools.yaml` records the same note).
- **stdout carries no findings at all.** v5 is a thin client for its own
  engine (`POST /api/v1/sessions`): a real run writes the decorative
  `Session Scope` / `FQDN:` / target block to stdout and nothing else, while the
  findings go into the engine session. Verified twice on 2026-11-18: the raw
  capture of run 84 held exactly that header (with 187 names scanned on stderr)
  and no hostnames, so the parser used to turn the header's target into one
  record - always exactly 1 item, always the target itself, which adds nothing.
- **The findings are read back with `subs`.** `amass subs -d DOMAIN -names`
  prints one name per line from the engine's graph database (verified: the same
  8 hosts the scan table showed). The adapter therefore declares
  `post_command`, so a successful `enum` is followed by one `subs -names` whose
  stdout is what gets parsed. `subs` reads the database, so it returns every
  name amass knows for the domain, not only the ones this run added; that is the
  honest answer for a passive source and the engine dedupes it anyway.
- `-o` does not exist in v5 (`-oA`, `-dir`, and `subs -o` do), and `-dir` only
  writes the config templates, so neither is a findings channel.
- The parser stays tolerant of the `enum` header (`SECTION_LABELS`) because
  that text may still arrive if a future amass version prints it again.

Amass is the slowest passive source, which is why `tools.yaml` says to keep it
last; the engine runs the stage's tools concurrently and its phase timeout, not
an adapter flag, bounds the run (no pacing, MASTER_PLAN D3).
"""

from __future__ import annotations

from reconkit.adapters.base import BinaryAdapter, normalize_subdomains, strip_ansi
from reconkit.core.runner import validate_host, validate_target
from reconkit.errors import ToolFailed
from reconkit.models import Record, RunContext, Stage

# Real `amass enum` stdout labels, verified on the installed v5.1.3.
SECTION_LABELS = frozenset({"session scope", "fqdn:", "fqdns:", "ips:", "asns:", "cidrs:"})


class AmassAdapter(BinaryAdapter):
    name = "amass"
    stage = Stage.SUBS
    binary = "amass"
    version_args = ["enum", "-h"]
    identity_markers = ("owasp amass project",)
    # Amass keeps its settings under ~/.config/amass; without HOME it would
    # create that directory in the current working directory.
    needs_home = True

    def build_command(self, ctx: RunContext) -> list[str]:
        try:
            target = validate_target(ctx.target)
        except (TypeError, ValueError):
            raise ToolFailed(f"amass: invalid target {ctx.target!r}") from None
        return [self.binary_path() or self.binary, "enum", "-d", target]

    def post_command(self, ctx: RunContext) -> list[str] | None:
        """Read this run's findings back out of the engine database.

        `enum` prints no names (see the module docstring), and `subs -names` is
        the only documented way to get them; without it the tool always reports
        the target and nothing else.
        """
        try:
            target = validate_target(ctx.target)
        except (TypeError, ValueError):
            raise ToolFailed(f"amass: invalid target {ctx.target!r}") from None
        return [self.binary_path() or self.binary, "subs", "-d", target, "-names"]

    def parse_output(self, raw: str) -> list[Record]:
        """Take the hostnames out of amass's decorative stdout.

        A real run prints `Session Scope` / `FQDN:` around the target, so only
        lines that validate as hostnames are kept; nothing decorative is ever
        turned into a record, and empty output is a successful empty answer.
        """
        names: list[str] = []
        for line in strip_ansi(raw).splitlines():
            text = line.strip()
            if not text or text.lower() in SECTION_LABELS:
                continue
            try:
                validate_host(text)
            except (TypeError, ValueError):
                continue
            names.append(text)
        return normalize_subdomains(names, self.name)


__all__ = ["AmassAdapter"]
