# SETUP.md - set up reconkit

reconkit runs on Linux (Kali or Ubuntu, native). That is the only
supported platform.
reconkit installs nothing.

You need **Python 3.11 or newer**. Do the environment steps once, then activate
the virtual environment in every new terminal.

## 1. Create the environment (reconkit itself)

```bash
cd /path/to/reconkit
./scripts/setup.sh
source .venv/bin/activate
```

`setup.sh` is the one command for a fresh clone: it creates `.venv`, installs
reconkit in editable mode with its dev tools, sets the repo's git hooks, adds
`~/.reconkit/bin` to the venv's `PATH`, installs every missing tool from
`tools.yaml`, and finishes with `reconkit doctor`. Pass `--check`, `--only
<tool>` or `--dry-run` to report instead of installing. The two steps are also
available separately: `bootstrap.sh` (environment only) and `install-tools.sh`
(tools only).

The manual equivalent:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

If the `python3` on your system is older than 3.11, install a newer one from
python.org or use `uv`.

## 2. `reconkit: command not found`

This is the most common setup problem. It means the virtual environment is not
active in **this** terminal.

```bash
source .venv/bin/activate
command -v reconkit          # should point inside .venv/bin
```

Run `source .venv/bin/activate` again every time you open a new terminal, or
call the script directly without activating: `.venv/bin/reconkit doctor`.

## 3. Check which tools are available

**To check which scanning tools are available, run `reconkit doctor`.**
`./scripts/setup.sh` already installs what the registry can install
automatically (`apt`, `go install`, `pipx`); `./scripts/install-tools.sh` does
only the tool half. Run either as your normal user, not with `sudo`.

```bash
./scripts/install-tools.sh --check   # report only
./scripts/install-tools.sh --yes     # install everything missing
```

Kali packages every tool. Ubuntu/Debian can lack `findomain`, `massdns` and
`rustscan`; the script reports each one it cannot install and keeps going, and
[docs/10_TOOL_SOURCES.md](docs/10_TOOL_SOURCES.md) gives the upstream source.
`dnsreaper` always has to be installed by hand. The reconkit CLI itself installs
nothing and skips any tool that is missing.

`doctor` prints one row per tool (installed, version, path), per-stage coverage,
system packages, `scope.yaml` presence, the database path and the API key names
that are set. Missing tools are shown as `missing`; a same-named but wrong
program is shown as `wrong program`.

## 4. API keys (optional)

Free mode needs no keys. Copy the template and fill in what you have; reconkit
never writes `.env`:

```bash
cp .env.example .env
chmod 600 .env     # optional
```

## 5. Define your scope

Active stages use a scope file when one is present.

```bash
cp scope.example.yaml scope.yaml
nano scope.yaml        # replace with targets you own or are authorized to test
reconkit scope check -d example.com
```

Only include targets you own or have **explicit written permission** to test.

## 6. First runs

```bash
reconkit passive -d example.com --mock     # fixtures only; no network or external tools
reconkit passive -d <authorized-domain>    # real passive sources
reconkit diff -d <authorized-domain>
reconkit live -d <authorized-domain> --active
reconkit ports -d <authorized-domain> --active
```

Active scans with a `scope.yaml` stay inside it; out-of-scope hosts are dropped.
With no scope file, active scanning runs unrestricted against the targets you
named (docs/05 rule 2). There is no speed preset or throttling.

## Troubleshooting

| Problem | Fix |
|---|---|
| `reconkit: command not found` | The venv is not active in this terminal: `source .venv/bin/activate`. Or run `.venv/bin/reconkit`. |
| A tool shows `missing` although it is on the machine | Put it on `PATH` or in `~/.reconkit/bin` (checked first), then re-run `reconkit doctor`. A Go binary usually lands in `~/go/bin`. |
| `naabu` fails with a `pcap.h` error | `naabu` needs `libpcap-dev`; `doctor` lists it under system packages. |
| `httpx` runs the wrong program | Two different programs share the name. Put ProjectDiscovery's binary in `~/.reconkit/bin` (checked first); `bootstrap.sh` puts that directory first in the activated venv's `PATH`. Re-activate and run `reconkit doctor`. |
| Python is older than 3.11 | Use Python 3.11+ from python.org or `uv`, then re-run `./scripts/bootstrap.sh`. |

## Useful checks

```bash
pytest -q
ruff check .
ruff format --check .
mypy src/reconkit
```
