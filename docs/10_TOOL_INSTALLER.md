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
- `install` is idempotent: a tool whose binary is already usable (the managed copy in `~/.reconkit/bin`, else `PATH`, and its `version_cmd` (the program named by its first element, defaulting to the tool binary, plus the remaining arguments) exits 0) is reported `already installed` and nothing runs for it. There is no `--force` flag in docs/02, so a reinstall is requested by naming the tool under `update`.
- `update` only replaces what is out of date where a version source exists: the GitHub release tag for `github_release`, the pin or `@version` for `go_install`. `apt` and `pipx` have no comparable local version query here, so they re-run their package-manager install (which is itself a no-op when the package is current); that is a named limitation, not a claim of comparison. Because there is no comparison, `update --all` asks the sudo confirmation again for every apt/pipx tool on every run, even when the package is already current.
- Exit codes are aggregated once over every selected tool: `0` all installed or already current, `5` some failed or were declined, `6` every selected tool failed (docs/02 section 6). A declined sudo step counts as a failure for `5`/`6` but starts no process.
- The summary is one row per tool: `tool`, `method`, `result` (`installed`, `already installed`, `up to date`, `skipped`, `failed`, `would install` under `--dry-run`), and `detail` (version, path or reason).
- `config.yaml` `tool_versions` is passed to `load_plans(versions=...)`, so a pin applies to both `install` and `update`; without a pin the latest release is used.
- The managed directory is `installer.registry.bin_dir()` -> `~/.reconkit/bin`, created `0700` on first install.
- After a successful `nuclei` install or update, `nuclei -ut` runs to refresh templates (flag confirmed against `nuclei --help`: `-ut, -update-templates`). A failed template refresh is reported in the summary but does not mark the tool failed.
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
| `apt` | `sudo apt-get install -y <package>` after confirmation | For system packages (nmap, whatweb, libpcap-dev, massdns, ...) |
| `pipx` | `pipx install <package>` (installing pipx via apt if needed) | Python tools such as wafw00f |
| `none` | HTTP/Python adapters, nothing to install | crtsh, dnspython, pyprobe, ... |

Order: `github_release`, then its `fallback` (usually `go_install`).

Version policy: `@latest` in a `go_install` package means the newest release. A `tool_versions` pin in `config.yaml` overrides `@latest` for `go_install`, and selects the pinned release for `github_release`; without a pin the latest release is used.

## 3a. Required system packages

Tools may declare `requires_apt` (example: naabu needs `libpcap-dev`) and `requires` (other tools, example: puredns needs massdns).

- `requires_apt` is installed **before** the tool's own backend runs, with its own confirmation line: `naabu: sudo apt-get install -y libpcap-dev (required by naabu)`. The two prompts are never merged: a declined prerequisite raises `InstallSkipped` for the tool, so the tool itself is not installed either. `--dry-run` lists the prerequisite as its own step and starts no process.
- Prerequisites are only reached when the tool is actually installed. An already-installed tool is skipped by the idempotency rule in section 1, so `install <tool>` does not repair a missing `requires_apt` package for it; use `update <tool>` or install the package yourself.
- `requires` (another reconkit tool) is parsed into the plan but is **not** auto-installed: `puredns` needs `massdns`, which is itself an apt tool. Installing tool-in-tool dependencies is deferred to a future part; install the named tool explicitly.

## 3b. Prerequisites

- `system_packages` in `tools.yaml` is the authoritative list (python3, python3-venv, python3-pip, git, golang-go, libpcap-dev, jq, curl). The `dig` entry additionally installs the `dnsutils` package, which is not in that list.
- Python 3.11 or newer, from the interpreter that runs reconkit; never a pinned apt Python.
- Go tools use `GOBIN=~/.reconkit/bin`; that directory comes first in the run-time lookup order (§5), so no PATH edit is needed to run a Go tool. `scripts/bootstrap.sh` also prepends it to the venv `activate` script.
- `pipx` is installed with `apt` when a `pipx` tool is chosen, using the same sudo confirmation as every other apt action.

## 3c. Install plans

`installer/registry.py` turns each `tools.yaml` entry into one `InstallPlan`:

- `name`, `binary` (defaults to the tool name), `tier` (from `tools.yaml`, used by `--all` to select `core` only), `method` (`github_release`, `go_install`, `apt`, `pipx` or `none`), `package` (Go package, apt package or pipx spec), `repo`, `asset_pattern`, `checksums_pattern`, `asset_name`, `member` (the archive member to extract when the release renames the binary; defaults to `binary`), `verify_checksums` (per-plan override of the `install.verify_checksums` config key; `false` only for a release that publishes no checksums), `version` (default `latest`), `version_command` (from `version_cmd[0]`: the program that reports the version, resolved on `PATH`, defaulting to `binary`; a distro package with no version flag such as `massdns` names `dpkg-query`), `version_args` (from `version_cmd[1:]`, the post-install check), `version_regex` (optional, from the tool's top-level `version_regex`), `fallback` (one nested plan), `requires_apt` and `requires`.
- A `none` plan means "reconkit cannot install this": the tool reuses another binary (`httpx_tech`) or has no supported distribution (for example `dnsreaper`, whose repository has no `setup.py`/`pyproject.toml`, so `pipx` refuses it). `install`/`update` report `nothing to install` and `doctor` keeps reporting the tool as missing until the user installs it by hand.
- **`version_regex` is how a banner-first tool reports its version.** `installed_version()` searches the whole `version_cmd` output with the tool's `version_regex` and returns the first capture group (or the whole match when the pattern has no group), so `katana`'s ASCII logo and `nuclei`'s ANSI-coloured `[INF]` line no longer become the version column and `_same_version()` can call those tools up to date. When the field is absent - or present and nothing matches - the fallback is unchanged: the first non-empty line of the output, exactly as today. A pattern that does not compile is a `ConfigError` when the registry loads, before any command runs. The pattern describes a property of the tool, which is why it lives in `tools.yaml` next to `version_cmd`; the `katana` and `nuclei` patterns were taken from their real banners on Kali (12j).
- Registry values verified against real releases on 2026-11-13: `findomain` publishes no checksums asset, so its plan sets `verify_checksums: false`; the `chaos-client` zip contains the binary `chaos-client`, so its plan sets `member: chaos-client`; `puredns` has no `version` subcommand and uses `--version`.
- `rustscan` verified against real releases on 2026-11-17: the latest (2.4.1) publishes `x86_64-linux-rustscan.tar.gz.zip`, a nested archive the single-layer extractor cannot read, and uses `x86_64`/`aarch64` names that `{arch}` (`amd64`/`arm64`) does not produce; no recent release publishes checksums. The pin is `config.yaml` `tool_versions: { rustscan: "2.3.0" }` (the registry takes pins from there, not from `tools.yaml`), with `asset_pattern: "rustscan-{version}-x86_64-linux.zip"`, flat member `rustscan` and `verify_checksums: false`, amd64 only. Nested-archive extraction is a future capability, not built.
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
- Confirmation: every apt action calls a `confirm(message)` callback supplied by the caller. `False` means **no subprocess starts at all**; the tool is marked `skipped`. The installer modules neither print nor prompt themselves, so the CLI owns the prompt text and tests can prove a declined prompt skips the call. With no TTY on stdin (CI, a pipe, `ssh host reconkit install`) the CLI does not prompt at all: the answer is `False`, so only that sudo tool is skipped and the rest of the selection still runs. `typer.confirm` on a TTY-less stdin would abort the whole run instead.
- Installing `pipx` is a prerequisite with its own confirmation line ("pipx is required for wafw00f: sudo apt-get install -y pipx"), separate from the tool's own ("wafw00f: pipx install wafw00f"). A sudo-bearing prerequisite is never folded into one ambiguous message.
- Package names are validated before they reach argv: apt `^[a-z0-9][a-z0-9+.-]*$`; go and pipx specs `^[A-Za-z0-9._+/-]+(@[A-Za-z0-9._-]+)?$`, plus `git+https://github.com/...` for pipx (dnsreaper). Anything else is a `ConfigError`, never a command line.
- Residual risk, accepted and named: `go_install` and `pipx` inherit `PATH` from the parent process. `go` and `pipx` can live in asdf shims, snap paths, `/usr/local/go/bin` or a user prefix, so a hardcoded path list would either run the wrong toolchain or fail on a working setup. This is the only parent-environment value that reaches any child, it is passed explicitly as a single key (never the whole environment), and the `apt` path stays hardcoded because `sudo` and `apt-get` always live in the system directories. No other parent variable is forwarded; The `nuclei -ut` template refresh is part of the same exception: it passes `HOME` and `PATH` and nothing else. If a future backend needs one, it needs its own line here.
- After an apt, go or pipx install, `version_cmd` runs as the post-install check: `version_cmd[0]` (default `binary`) with the remaining arguments. Package-manager installs have **no** `.prev` rollback (nothing safe to roll back to); a failed check marks the tool `failed` and the report says so.
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
- Release lookups are **unauthenticated**: `release_for` sends no token, so the limit is GitHub's 60 requests/hour per source IP and 13 `github_release` tools can exhaust it in one run. When that happens every remaining `github_release` tool reports `release lookup failed with HTTP 403` and the run continues; wait for `x-ratelimit-reset` and retry. Authenticated lookups are not implemented yet (see the Open risk in `docs/PROGRESS.md`); a `GITHUB_TOKEN` in `.env` currently only reaches `github_subdomains`.

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

`--fix` runs the same selection as `install --all`; tools that are already installed are skipped by the idempotency rule in section 1, so it never reinstalls a working tool.

A tool's `installed` state comes from its adapter when it has one. Most phase-3 tools have no adapter yet, so `doctor` falls back to the same resolution an install uses (section 5: the managed copy first, then `PATH`) and runs the plan's `version_cmd` (`version_command`, default `binary`, plus its arguments) as the identity probe; a copy that exists but whose `version_cmd` fails is reported as `wrong program`, never as installed. A `none` plan (for example `dnsreaper`) stays `missing` because reconkit cannot install it.

## 6. Update Behavior

- `update` compares installed version (from `version_cmd`) with latest release (or the pin in `config.yaml` `tool_versions`) and updates only when different. `apt` and `pipx` have no such comparison and re-run their package-manager install; section 1 states that limitation and the extra sudo prompts it causes. A `go_install` tool pinned to a version is compared against the pin; an `@latest` Go tool carries no installed-version metadata to compare, so `update` re-runs `go install` and reports `installed` even when nothing changed. That re-run is a byte-level no-op (Go's build cache): `reconkit update assetfinder` on 2026-11-13 left `sha256 d5173bdac4eb2054438adaea2c4c1b7173923224516976bf6df7e40fc6def4e7` unchanged. It is a reporting gap, not a corrupting reinstall. Resolving the current version properly (a module-proxy lookup compared against the installed build metadata) would be a new mechanism, so it is deliberately deferred to a future part and is not part of 10f.
- Updates never happen silently during a scan. Only `update` (and `install`) change tools.
- After installing or updating `nuclei`, templates are refreshed with `nuclei -ut` (implemented; `-ut, -update-templates` confirmed from `nuclei --help`, engine v3.11.1). A failed refresh is reported but does not mark the tool failed.
- `doctor` warns when a tool's major version is newer than the version its parser fixture was recorded against. This needs per-tool fixture metadata that `tools.yaml` does not carry yet, so the warning is Phase 3.
- Rollback: previous binary kept as `<name>.prev` until the new version passes its version check.

## 7. Output Examples

```
tool               method          result         detail
subfinder          github_release  would install  subfinder: install to /home/kali/.reconkit/bin/subfinder
assetfinder        go_install      would install  assetfinder: go install github.com/tomnomnom/assetfinder@latest -> /home/kali/.reconkit/bin/assetfinder
massdns            apt             would install  massdns: sudo apt-get install -y massdns (sudo required)
```

## 8. Failure Handling

| Situation | Behavior |
|---|---|
| No internet | Report per tool; exit 5 |
| GitHub API rate limit | Every `github_release` tool reports `release lookup failed with HTTP 403` and the run continues (exit 5). The limit is per source IP, 60/hour unauthenticated; this release-lookup client sends no token, so wait for `x-ratelimit-reset` or use an authenticated IP. Recommended before a first-time `install --all` on a shared IP: see the Open risk in `docs/PROGRESS.md` |
| Asset not found for arch | Try fallback method; otherwise report |
| Checksum mismatch | Refuse install; keep old version |
| Release publishes no checksums | Only when the plan says `verify_checksums: false`; otherwise fail closed |
| Tool has no supported distribution | `none` plan: report `nothing to install`, keep it in doctor as missing |
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
