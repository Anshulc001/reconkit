# Code Style & Conventions

## 1. General Principles

- Prefer readable code over clever code.
- Small, focused functions and modules.
- Reuse existing utilities (`runner`, `pacing`, `store`, `ui`).
- Consistency over novelty. No unnecessary abstractions or dependencies.

## 2. Naming

| Item | Convention |
|---|---|
| Modules / files | `snake_case.py` (adapter file = tool name, for example `subfinder.py`; `httpx_tool.py` to avoid clashing with the `httpx` library) |
| Classes | `PascalCase` (`SubfinderAdapter`) |
| Functions / variables | `snake_case` |
| Constants | `UPPER_SNAKE_CASE` |
| Enums | `PascalCase` class, `UPPER` members (`HostState.ALIVE`) |
| DB tables / columns | `snake_case`, tables plural |
| CLI commands / flags | `kebab-case` flags (`--min-sources`), lowercase command words |
| Tool names in `tools.yaml` | lowercase, underscores (`github_subdomains`) |

## 3. Python Rules

- Python 3.11+. Type hints on all function signatures. `from __future__ import annotations` at top of modules.
- Pydantic v2 models for all data crossing a boundary (adapter output, config, DB rows to UI).
- `pathlib.Path` for paths. No string path concatenation.
- `async def` for I/O stages; keep CPU-bound parsing synchronous.
- No global mutable state. Pass a `RunContext` object.
- No `print()`: use `ui.py` (Rich). No bare `except:`.

## 4. Imports

- Order: stdlib, third-party, local (ruff `I` rules).
- Absolute imports from `reconkit`.
- Respect dependency rules in docs/03_ARCHITECTURE.md (adapters never import store/scope/ui/cli).

## 5. Modules and Functions

- A function does one logical thing and has a clear name (`parse_subfinder_line`, not `process`).
- Keep functions under ~40 lines; split if longer.
- Adapters: one class per file, about 50 lines excluding parsing helpers.

## 6. Error Handling

- Define exceptions in `reconkit/errors.py`: `ScopeError`, `ToolNotInstalled`, `ToolFailed`, `ToolTimeout`, `ParseError`, `ConfigError`, `InstallError`.
- Adapters convert failures into a `ToolResult(status=...)` instead of crashing the stage.
- The CLI maps exceptions to exit codes (docs/02_CLI_UX.md) and one-line messages.
- Do not swallow errors silently. Do not expose secrets or full tracebacks unless `-v`.

## 7. Comments and Docstrings

- Comments explain **why**, tradeoffs, non-obvious behavior. Not what the code says.
- Public functions and classes get short docstrings (one-line summary + args/returns when not obvious).

## 8. Logging

- Use the standard `logging` module with Rich handler configured in `ui.py`.
- Never log secrets (see docs/05_SECURITY.md).

## 9. Formatting and Tools

- Formatter and linter: **ruff** (`ruff format`, `ruff check`). Line length 100.
- Type checking: **mypy** (strict on `src/reconkit`).
- Tests: **pytest** (+ `pytest-asyncio`).
- Dependencies declared and pinned (compatible ranges) in `pyproject.toml`. Ask before adding a new one.

Suggested ruff rule sets: `E,F,I,B,UP,S` (includes `S602/S604/S605` to block `shell=True`).

## 10. Do

- Reuse existing patterns and helpers.
- Keep changes focused; update docs and tests together with code.
- Remove dead code.
- Inject time, randomness and sleep so code is testable.

## 11. Don't

- Create duplicate utilities.
- Call `subprocess`, `sqlite3`, or `print` outside their owner modules.
- Hard-code tool names, URLs, or install sources outside `tools.yaml` (adapters may hold their own API URL constants for HTTP sources).
- Change unrelated files.
- Add flags, columns or behavior that are not in the docs.

## 12. Adapter Skeleton (reference)

```python
from __future__ import annotations
from reconkit.adapters.base import BaseToolAdapter
from reconkit.models import RunContext, SubdomainRecord, Stage

class AssetfinderAdapter(BaseToolAdapter):
    name = "assetfinder"
    stage = Stage.SUBS

    def build_command(self, ctx: RunContext) -> list[str]:
        return [self.binary_path(), "--subs-only", ctx.target]

    def parse_output(self, raw: str) -> list[SubdomainRecord]:
        records = []
        for line in raw.splitlines():
            host = line.strip().lower().rstrip(".")
            if host:
                records.append(SubdomainRecord(fqdn=host, source=self.name))
        return records
```

(Check the real tool flags before use. Do not guess.)
