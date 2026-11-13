# Tool Installer

Goal: users do not have the tools installed, so `reconkit install` and `reconkit update` fetch them safely, driven only by `tools.yaml`.

## 1. Commands

```
reconkit install [TOOL...|--all] [--dry-run]
reconkit update  [TOOL...|--all] [--dry-run]
reconkit doctor [--fix]            # --fix = offer to install what is missing
```

- `--all` installs `core` tier tools only. `opt_in` tools install only when named.
- `--dry-run` prints every action (download URL, checksum source, target path, apt packages) and makes no filesystem changes. Resolving the latest release is a read-only GitHub API request (mocked in tests), so nothing remote is changed either.
- `apt` always asks before `sudo`; no flag skips that confirmation (docs/05 §5). `--stage` and `--yes` are not part of this build; docs/02 §2 is the command surface.
- On an interactive TTY, `install` asks once: "Free only, or add keys?". Choosing keys copies `.env.example` to `.env` (never overwrites) and prints the path plus the Keys table. With no TTY on stdin it never prompts and defaults to free mode; `install` has no `--silent`/`--json` flags in this build (policy in `docs/05_SECURITY.md` §6.1, implemented in Part 10).

## 2. Platform

- Supported: Linux (Kali in WSL2, Kali, Debian/Ubuntu), amd64 and arm64.
- `doctor` runs on every platform and reports what it finds; `--mock` and the pure-Python adapters also work on native Windows (docs/MASTER_PLAN.md Part 10).
- On native Windows, `install` and `update` print `Use WSL2 Kali (see SETUP.md)` and exit `1`. On macOS they print `Linux is required (see SETUP.md)` and exit `1`. They never run `apt` and never attempt a half-working install (docs/08 Flow 1).

## 3. Install Methods (from `tools.yaml`)

| Method | How | Notes |
|---|---|---|
| `github_release` | Query the GitHub Releases API for the latest (or pinned) version, download the asset for linux and the CPU arch, verify checksum, extract the binary to `~/.reconkit/bin` | Preferred: no Go needed, no sudo |
| `go_install` | `go install <package>@version` with `GOBIN=~/.reconkit/bin` | Fallback; needs Go; slower |
| `apt` | `sudo apt install -y <package>` after confirmation | For system packages (nmap, whatweb, libpcap-dev, massdns, ...) |
| `pipx` | `pipx install <package>` (installing pipx via apt if needed) | Python tools such as wafw00f |
| `none` | HTTP/Python adapters, nothing to install | crtsh, dnspython, pyprobe, ... |

Order: `github_release`, then its `fallback` (usually `go_install`).

Version policy: `@latest` in a `go_install` package means the newest release. A `tool_versions` pin in `config.yaml` overrides `@latest` for `go_install`, and selects the pinned release for `github_release`; without a pin the latest release is used.

## 3a. Required system packages

Tools may declare `requires_apt` (example: naabu needs `libpcap-dev`) and `requires` (other tools, example: puredns needs massdns). The installer installs dependencies first and reports them in `--dry-run`.

## 3b. Prerequisites

- `system_packages` in `tools.yaml` is the authoritative list (python3, python3-venv, python3-pip, git, golang-go, libpcap-dev, jq, curl). The `dig` entry additionally installs the `dnsutils` package, which is not in that list.
- Python 3.11 or newer, from the interpreter that runs reconkit; never a pinned apt Python.
- Go tools use `GOBIN=~/.reconkit/bin`; that directory comes first in the run-time lookup order (§5), so no PATH edit is needed to run a Go tool. `scripts/bootstrap.sh` also prepends it to the venv `activate` script.
- `pipx` is installed with `apt` when a `pipx` tool is chosen, using the same sudo confirmation as every other apt action.

## 3c. Install plans

`installer/registry.py` turns each `tools.yaml` entry into one `InstallPlan`:

- `name`, `binary` (defaults to the tool name), `method` (`github_release`, `go_install`, `apt`, `pipx` or `none`), `package` (Go package, apt package or pipx spec), `repo`, `asset_pattern`, `checksums_pattern`, `asset_name`, `version` (default `latest`), `version_args` (from `version_cmd`, the post-install check), `fallback` (one nested plan), `requires_apt` and `requires`.
- A `tool_versions` pin in `config.yaml` sets `version` and rewrites a `go_install` package's trailing `@latest` to `@<pin>`. Without a pin the version is `latest`.
- An entry with no `install` block (for example `httpx_tech`, which reuses the `httpx` binary) becomes a `none` plan.
- `resolve_plan()` returns the primary plan followed by its fallback, so the caller tries them in order.
- An unknown method, a missing `package`/`repo`, or a malformed field raises `ConfigError` before anything is downloaded.

## 3d. Backends: argv, child environment, sudo

Every backend goes through `core.runner.run_exec`, which creates the child with **only** the keys passed in `env` (docs/05 section 4). The exact dicts, no more and no less:

| Backend | argv | child env |
|---|---|---|
| `apt` | `sudo -n apt-get install -y <package...>` | `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `DEBIAN_FRONTEND=noninteractive`, `LC_ALL=C` |
| `go_install` | `go install <package>@<version>` | `HOME`, `GOBIN=<bin dir>`, `PATH` (copied from the parent so `go` is found; nothing else is copied) |
| `pipx` | `pipx install <spec>` | `HOME`, `PATH`, `PIPX_BIN_DIR=<bin dir>`, `PIPX_HOME=$HOME/.local/pipx` |

- `sudo -n` is deliberate. `run_exec` gives the child `stdin` from `DEVNULL` and captures its output, so an interactive sudo password prompt cannot work; `-n` fails immediately instead of hanging. A failure whose output says a password is required is reported as `skipped` with "sudo needs a password: run `sudo -v` in this terminal and retry". reconkit never runs as root and never reads or passes a sudo password.
- Confirmation: every apt action calls a `confirm(message)` callback supplied by the caller. `False` means **no subprocess starts at all**; the tool is marked `skipped`. The installer modules neither print nor prompt themselves, so the CLI owns the prompt text and tests can prove a declined prompt skips the call.
- Installing `pipx` is a prerequisite with its own confirmation line ("pipx is required for wafw00f: sudo apt-get install -y pipx"), separate from the tool's own ("wafw00f: pipx install wafw00f"). A sudo-bearing prerequisite is never folded into one ambiguous message.
- Package names are validated before they reach argv: apt `^[a-z0-9][a-z0-9+.-]*$`; go and pipx specs `^[A-Za-z0-9._+/-]+(@[A-Za-z0-9._-]+)?$`, plus `git+https://github.com/...` for pipx (dnsreaper). Anything else is a `ConfigError`, never a command line.
- Residual risk, accepted and named: `go_install` and `pipx` inherit `PATH` from the parent process. `go` and `pipx` can live in asdf shims, snap paths, `/usr/local/go/bin` or a user prefix, so a hardcoded path list would either run the wrong toolchain or fail on a working setup. This is the only parent-environment value that reaches any child, it is passed explicitly as a single key (never the whole environment), and the `apt` path stays hardcoded because `sudo` and `apt-get` always live in the system directories. No other parent variable is forwarded; if a future backend needs one, it needs its own line here.
- After an apt, go or pipx install, `version_cmd` runs as the post-install check. Package-manager installs have **no** `.prev` rollback (nothing safe to roll back to); a failed check marks the tool `failed` and the report says so.
- `--dry-run` prints the argv and the sudo requirement and starts no process, prompts nothing.

## 4. Verification (fail closed)

For `github_release`:
1. Download the checksums file named by `checksums_pattern`.
2. Compute SHA-256 of the downloaded asset; compare.
3. Mismatch, missing checksum when `verify_checksums: true`, or unexpected asset name: **do not install**, report the reason, continue with other tools, exit code 5.
4. After install run `version_cmd`; if it fails, remove the binary and report `failed`.

Other rules:
- HTTPS only. `github_release` contacts exactly four hosts: `api.github.com` (release lookup), `github.com` (release download URLs), `objects.githubusercontent.com` and `release-assets.githubusercontent.com` (the hosts GitHub redirects release assets to). Any other host, or plain HTTP, is a failed install; the allowlist is `ALLOWED_HOSTS` in `installer/github_release.py`. `go_install` uses the Go module proxy and `pipx` uses PyPI; no other host is contacted.
- Download to a temp dir with a size limit: `ARCHIVE_LIMIT` is 200 MiB for the archive and `MEMBER_LIMIT` is 100 MiB for one extracted member, and `CHECKSUMS_LIMIT` is 64 KiB for the checksums file. Extract only the expected binary name (`<binary>` or `<binary>.exe`); refuse archive paths that are absolute or contain `..` (zip-slip). A zip or tar.gz containing no such member is a failed install, never a silent success.
- Files get mode `0755`. The directory `~/.reconkit/bin` is `0700`.
- No `curl | bash`, no running scripts from downloads.
- Optional `GITHUB_TOKEN` is used only to raise API rate limits and is never logged.

## 5. Lookup Order at Run Time

1. `~/.reconkit/bin/<binary>` (our managed copy)
2. `PATH`

`doctor` shows which copy is used and warns when a same-named but different program is found first (the `httpx` Python CLI case).

## 5a. Doctor

`doctor` implements docs/01 Feature 2 and docs/08 Flow 1, and changes nothing:

- tool table: installed, version, resolved path, identity verified, tier (rendering rules in docs/02 section 5);
- per-stage coverage (`subs 6/11 ready`);
- system packages (`system_packages` plus every tool's `requires_apt`, for example `libpcap-dev`; `dnsutils` lives in the `dig` entry's `install` block, which `ToolSpec` does not expose), Python version, `scope.yaml` presence, DB writability and `config.yaml` presence;
- the Keys table (tool, set/missing, what it adds, sign-up URL), names only, never values;
- `Missing tools: N. Run: reconkit install --all` when anything is missing;
- `--json` writes one document; warnings keep exit code `0`. Python < 3.11 or an unreadable `config.yaml` exits `1`.

`--fix` offers the same actions as `install` for the missing tools.

## 6. Update Behavior

- `update` compares installed version (from `version_cmd`) with latest release (or the pin in `config.yaml` `tool_versions`) and updates only when different.
- Updates never happen silently during a scan. Only `update` (and `install`) change tools.
- After updating `nuclei`, also refresh templates (`nuclei -ut` once confirmed against `--help`).
- `doctor` warns when a tool's major version is newer than the version its parser fixture was recorded against. This needs per-tool fixture metadata that `tools.yaml` does not carry yet, so the warning is Phase 3.
- Rollback: previous binary kept as `<name>.prev` until the new version passes its version check.

## 7. Output Examples

```
reconkit install --all --dry-run
  subfinder   github_release  projectdiscovery/subfinder  -> ~/.reconkit/bin/subfinder
  naabu       github_release  projectdiscovery/naabu      -> ~/.reconkit/bin/naabu  (needs apt: libpcap-dev)
  nmap        apt             nmap                        (sudo required)
```

## 8. Failure Handling

| Situation | Behavior |
|---|---|
| No internet | Report per tool; exit 5 |
| GitHub API rate limit | Suggest setting `GITHUB_TOKEN`; skip remaining |
| Asset not found for arch | Try fallback method; otherwise report |
| Checksum mismatch | Refuse install; keep old version |
| apt declined | Skip apt tools; mark `skipped`, no process starts |
| sudo needs a password | Skip; tell the user to run `sudo -v` and retry (never prompt for the password ourselves) |
| pipx missing | Ask to `apt install pipx` as its own confirmed step, then install the tool |
| Go missing for fallback | Say how to install `golang-go` |

## 9. Tests

- Registry parsing and YAML anchors/merge keys (`<<`); top-level `x-` keys (for example `x-pd-release`) are ignored.
- Asset name templating (`{name}`, `{version}`, `{arch}`).
- Checksum verification pass/fail with local files.
- Zip-slip rejection.
- `--dry-run` makes no filesystem changes; HTTP is mocked, so no real network request is made.
- Non-Linux platform message.
