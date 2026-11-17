# SETUP.md - install reconkit

reconkit has two supported ways to run:

- **Kali or Ubuntu (native or WSL2):** the full tool set, real scans and the installer.
- **Windows:** `doctor`, `--mock` runs and the pure-Python passive flow. `reconkit install` and `update` refuse on Windows and exit `1`.

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

### 6. Install the recon tools

```bash
sudo -v                            # cache your sudo ticket first (optional but recommended)
reconkit install --all --dry-run   # show every action; changes nothing
reconkit install --all             # install core tools into ~/.reconkit/bin
```

- `apt` packages (nmap, massdns, ...) ask for confirmation before running `sudo -n apt-get install`.
- reconkit never reads or stores your sudo password. If the cached ticket has expired, an apt tool is skipped with a hint; run `sudo -v` again and retry.
- Without a terminal (CI, a pipe), sudo confirmations are declined automatically and only those tools are skipped.
- On an interactive terminal, `install` also asks once whether to add API keys. Free mode needs none; choosing keys copies `.env.example` to `.env` (never overwrites) and prints the Keys table.

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

### 3. The installer refuses on Windows

```text
$ reconkit install --all
Use WSL2 Kali (see SETUP.md)
```

That is expected and exits `1`. `install` and `update` only run on Linux. Use a native Kali/Ubuntu checkout or WSL2 Kali for the full tool install; a native Linux box does not require WSL2.

## Troubleshooting

| Problem | Fix |
|---|---|
| `reconkit: command not found` | The venv is not active in this terminal: `source .venv/bin/activate` (Linux/Git Bash) or `.venv\Scripts\Activate.ps1` (PowerShell). Or run `.venv/bin/reconkit`. |
| `Use WSL2 Kali (see SETUP.md)` | You ran `install`/`update` on Windows. Run them from a Linux checkout. |
| `sudo: a password is required` during install | Run `sudo -v` in the same terminal, then retry. reconkit does not ask for the password itself. |
| `naabu` fails with a `pcap.h` error | `sudo apt install -y libpcap-dev` and retry; `doctor` lists it under system packages. |
| `httpx` runs the wrong program | The installer places ProjectDiscovery's binary in `~/.reconkit/bin`; `bootstrap.sh` puts that directory first in the activated venv's `PATH`. Re-activate and run `reconkit doctor`. |
| Every `github_release` tool fails with HTTP 403 | Unauthenticated GitHub release lookups are limited to 60/hour per IP. Wait for the reset time and retry. |
| `database is locked` or very slow scans | Move the project off `/mnt/c/...` to the Linux filesystem. |
| Python is older than 3.11 | Install `uv` or a newer Python, then re-run `./scripts/bootstrap.sh`. |

## Useful checks

```bash
pytest -q
ruff check .
ruff format --check .
mypy src/reconkit
```
