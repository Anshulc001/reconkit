# SETUP.md - Windows + WSL2 Kali + VS Code (beginner guide)

Do these steps once. You need Windows 10 (build 19041+) or Windows 11.

## Step 1 - Install Kali in WSL2

Open **PowerShell as Administrator** and run:

```powershell
wsl --install -d kali-linux
```

Restart if asked. Open **Kali Linux** from the Start menu and create a Linux username and password.

Check that it is WSL 2:

```powershell
wsl -l -v
```

The `VERSION` column for `kali-linux` should say `2`.

## Step 2 - Install VS Code and the WSL extension (on Windows)

1. Install Visual Studio Code on Windows.
2. Press `Ctrl+Shift+X`, search **WSL** (publisher: Microsoft), click Install.

## Step 3 - Install base packages (inside Kali)

In the Kali window:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git golang-go libpcap-dev jq curl
python3 --version      # must be 3.11 or newer
git config --global core.autocrlf input
```

Everything else (subfinder, httpx, naabu, nuclei, ...) is installed later by `reconkit install --all`.

## Step 4 - Create the project inside Kali

```bash
mkdir -p ~/reconkit
cd ~/reconkit
code .
```

`code .` opens VS Code on Windows, connected to Kali. The window's bottom-left corner should say **WSL: kali-linux**.

> Always keep the project in `~/reconkit` (the Linux filesystem), not in `/mnt/c/...`. It is much faster and avoids SQLite locking and line-ending bugs.

## Step 5 - Put the generated files into the project

Option A (simplest): in VS Code (connected to Kali), create files and paste the content.

Option B: copy downloaded files from Windows. Example if they are in your Downloads folder:

```bash
cp -r /mnt/c/Users/<YourWindowsName>/Downloads/reconkit/. ~/reconkit/
```

Option C: in Windows Explorer, type `\\wsl$\kali-linux\home\<your-kali-user>\reconkit` in the address bar and drag files in.

## Step 6 - Python environment (after the Phase 2 code is in the folder)

```bash
cd ~/reconkit
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run `source .venv/bin/activate` again every time you open a new terminal.

## Step 7 - Install the recon tools and check

```bash
reconkit install --all --dry-run   # shows what would be installed
reconkit install --all             # installs into ~/.reconkit/bin
reconkit doctor                    # per-stage readiness report
```

## Step 8 - Define your scope (required for active scans)

```bash
cp scope.example.yaml scope.yaml
nano scope.yaml                    # replace with your authorized targets
```

Only put targets in `scope.yaml` that you own or have **written permission** to test.

## Step 9 - First runs

```bash
reconkit passive -d example.com --mock     # fake data, checks the pipeline works
reconkit passive -d <your-authorized-domain>
reconkit diff -d <your-authorized-domain>
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `wsl --install` shows help text | Update Windows, or run `wsl --update` |
| `naabu` build error about `pcap.h` | `sudo apt install -y libpcap-dev` |
| `httpx` runs the wrong program | The installer puts the correct one in `~/.reconkit/bin`, which comes first in lookup. Run `reconkit doctor`. |
| Commands not found after install | Open a new terminal and run `source .venv/bin/activate` |
| Slow disk or `database is locked` | Move the project from `/mnt/c/...` to `~/reconkit` |
