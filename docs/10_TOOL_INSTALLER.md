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

## 4. Verification (fail closed)

For `github_release`:
1. Download the checksums file named by `checksums_pattern`.
2. Compute SHA-256 of the downloaded asset; compare.
3. Mismatch, missing checksum when `verify_checksums: true`, or unexpected asset name: **do not install**, report the reason, continue with other tools, exit code 5.
4. After install run `version_cmd`; if it fails, remove the binary and report `failed`.

Other rules:
- HTTPS only. `github_release` downloads come from `api.github.com`, `github.com` and the GitHub release asset hosts. `go_install` uses the Go module proxy and `pipx` uses PyPI; no other host is contacted.
- Download to a temp dir with a size limit; extract only the expected binary name; refuse archive paths that escape the temp dir (zip-slip).
- Files get mode `0755`. The directory `~/.reconkit/bin` is `0700`.
- No `curl | bash`, no running scripts from downloads.
- Optional `GITHUB_TOKEN` is used only to raise API rate limits and is never logged.

## 5. Lookup Order at Run Time

1. `~/.reconkit/bin/<binary>` (our managed copy)
2. `PATH`

`doctor` shows which copy is used and warns when a same-named but different program is found first (the `httpx` Python CLI case).

## 5a. Doctor

`doctor` implements docs/01 Feature 2 and docs/08 Flow 1, and changes nothing:

- tool table: installed, version, resolved path, identity verified, tier;
- per-stage coverage (`subs 6/11 ready`);
- system packages (`libpcap-dev`, `dnsutils`, `jq`), Python version, `scope.yaml` presence, DB writability and `config.yaml` presence;
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
| apt declined | Skip apt tools; mark `skipped` |
| Go missing for fallback | Say how to install `golang-go` |

## 9. Tests

- Registry parsing and YAML anchors/merge keys (`<<`); top-level `x-` keys (for example `x-pd-release`) are ignored.
- Asset name templating (`{name}`, `{version}`, `{arch}`).
- Checksum verification pass/fail with local files.
- Zip-slip rejection.
- `--dry-run` makes no filesystem changes; HTTP is mocked, so no real network request is made.
- Non-Linux platform message.
