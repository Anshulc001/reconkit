# SETUP.md - install reconkit

reconkit has two supported ways to run:

- **Kali or Ubuntu (native or WSL2):** the full tool set and real scans. You install the tools yourself with `apt`, `go install` or a release download ([docs/10_TOOL_SOURCES.md](docs/10_TOOL_SOURCES.md)).
- **Windows:** `doctor`, `--mock` runs and the pure-Python passive flow. reconkit installs nothing on any platform.

You need **Python 3.11 or newer** on both. Do the steps once, then activate the virtual environment in every new terminal.

## Part A - Kali / Ubuntu (full setup)

### 1. Install the base packages

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git golang-go libpcap-dev jq curl
python3 --version      # must be 3.11 or newer
```

If `python3` is older than 3.11, install `uv` (it can fetch Python 3.11 for the venv) or a newer Python from your distribution, then continue. `scripts/bootstrap.sh` uses `uv` when present and otherwise requires Python 3.11+.

### 2. Put the project on the Linux filesystem

Use a path such as `~/reconkit` or `~/Desktop/reconkit`. Do **not** run from `/mnt/c/...`: it is slow and can cause SQLite locking and line-ending problems.

### 3. Create the environment

```bash
cd /path/to/reconkit
./scripts/bootstrap.sh
source .venv/bin/activate
```

`bootstrap.sh` creates `.venv`, installs reconkit in editable mode with its dev tools, sets the repo's git hooks and adds `~/.reconkit/bin` to the venv's `PATH`.

The manual equivalent, if you prefer not to use the script:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### 4. `reconkit: command not found`

This is the most common setup problem. It means the virtual environment is not active in **this** terminal.

```bash
source .venv/bin/activate
command -v reconkit          # should point inside .venv/bin
reconkit doctor
```

Run `source .venv/bin/activate` again every time you open a new terminal, or call the script directly without activating:

```bash
.venv/bin/reconkit doctor
```

### 5. Check what is installed

```bash
reconkit doctor
```

`doctor` prints one row per tool (installed, version, path), per-stage coverage, system packages, `scope.yaml` presence, the database path and the API key names that are set. Missing tools are shown as `missing`; a same-named but wrong program is shown as `wrong program`.

### 6. Install the recon tools (yourself)

reconkit does not install tools: `install`, `update` and `doctor --fix` were removed on 2026-11-17 (docs/MASTER_PLAN.md D4). `reconkit doctor` tells you what is missing; you install it.

```bash
reconkit doctor          # read the Missing tools line and the table's installed/version columns
```

For each missing tool, docs/10_TOOL_SOURCES.md §1 gives its exact source, the same string `tools.yaml` carries in `source:`:

- **apt packages** (nmap, massdns, amass, whatweb, nikto, masscan, sqlmap, dnsutils for `dig`): `sudo apt install -y <package>`. reconkit never runs `sudo` and never asks for your password.
- **Go tools** (subfinder, assetfinder, dnsx, gau, katana, nuclei, ...): `go install <package>@latest`. Binaries land in `~/go/bin`; put that directory on `PATH` or copy the binary into `~/.reconkit/bin` (checked first).
- **Release downloads** (httpx, tlsx, naabu, rustscan, chaos, ...): fetch the Linux asset from the project's releases page and place the binary on `PATH` or in `~/.reconkit/bin`.
- **Python tools**: `wafw00f` is `pipx install wafw00f`; `dnsreaper` has no package and is installed by hand from its repository.

Re-run `reconkit doctor` to confirm. `webanalyze` needs `webanalyze -update` once per working directory, and `nuclei` templates are refreshed with `nuclei -ut`.

API keys are optional (free mode needs none). Copy the template and fill in what you have; reconkit never writes `.env`:

```bash
cp .env.example .env
chmod 600 .env     # optional
```

### 7. Define your scope

Active stages require a scope file.

```bash
cp scope.example.yaml scope.yaml
nano scope.yaml        # replace with targets you own or are authorized to test
reconkit scope check -d example.com
```

Only include targets you own or have **explicit written permission** to test.

### 8. First runs

```bash
reconkit passive -d example.com --mock     # fixtures only; no network or external tools
reconkit passive -d <authorized-domain>    # real passive sources
reconkit diff -d <authorized-domain>
reconkit live -d <authorized-domain> --active
reconkit ports -d <authorized-domain> --active
```

Active scans with a `scope.yaml` stay inside it; out-of-scope hosts are dropped. With no scope file, active scanning runs unrestricted against the targets you named (docs/05 rule 2). There is no speed preset or throttling.

## Part B - Windows (mock/passive and doctor only)

If you have a Linux machine (or WSL2 Kali), use Part A there for the real tools. On native Windows you can still run the CLI, `doctor`, fixtures and the pure-Python passive flow.

### 1. Create the environment

PowerShell:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Git Bash:

```bash
./scripts/bootstrap.sh
source .venv/Scripts/activate
```

If `py -3.11` is not available, install Python 3.11+ from python.org or use `uv`.

### 2. Run what Windows supports

```powershell
reconkit doctor
reconkit passive -d example.com --mock
```

If PowerShell blocks the activation script, run `.venv\Scripts\activate.bat` from `cmd.exe`, or call `.venv\Scripts\reconkit.exe` directly.

### 3. Real tools need Linux, but there is no install command

reconkit installs nothing, on Windows or anywhere else: `install`, `update` and `doctor --fix` were removed on 2026-11-17. To run the real tools, use a native Kali/Ubuntu checkout or WSL2 Kali and install them yourself with the sources in [docs/10_TOOL_SOURCES.md](docs/10_TOOL_SOURCES.md). A native Linux box does not require WSL2.

## Troubleshooting

| Problem | Fix |
|---|---|
| `reconkit: command not found` | The venv is not active in this terminal: `source .venv/bin/activate` (Linux/Git Bash) or `.venv\Scripts\Activate.ps1` (PowerShell). Or run `.venv/bin/reconkit`. |
| A tool shows `missing` after you installed it | Put it on `PATH` or in `~/.reconkit/bin` (checked first), then re-run `reconkit doctor`. Go tools land in `~/go/bin` by default. |
| `naabu` fails with a `pcap.h` error | `sudo apt install -y libpcap-dev` and retry; `doctor` lists it under system packages. |
| `httpx` runs the wrong program | Two different programs share the name. Put ProjectDiscovery's binary in `~/.reconkit/bin` (checked first); `bootstrap.sh` puts that directory first in the activated venv's `PATH`. Re-activate and run `reconkit doctor`. |
| `database is locked` or very slow scans | Move the project off `/mnt/c/...` to the Linux filesystem. |
| Python is older than 3.11 | Install `uv` or a newer Python, then re-run `./scripts/bootstrap.sh`. |

## Useful checks

```bash
pytest -q
ruff check .
ruff format --check .
mypy src/reconkit
```
