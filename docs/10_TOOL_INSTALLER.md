# Tool Installer

Goal: users do not have the tools installed, so `reconkit install` and `reconkit update` fetch them safely, driven only by `tools.yaml`.

## 1. Commands

```
reconkit install [TOOL...|--all] [--stage subs] [--dry-run] [--yes]
reconkit update  [TOOL...|--all] [--dry-run]
reconkit doctor [--fix]            # --fix = offer to install what is missing
```

- `--all` installs `core` tier tools only. `opt_in` tools install only when named.
- `--dry-run` prints every action (download URL, checksum source, target path, apt packages) and changes nothing.
- `--yes` skips confirmations except the sudo/apt one.

## 2. Platform

- Supported: Linux (Kali in WSL2, Kali, Debian/Ubuntu), amd64 and arm64.
- On native Windows or macOS: print `Use WSL2 Kali (see SETUP.md)` and exit. Do not attempt a half-working install.

## 3. Install Methods (from `tools.yaml`)

| Method | How | Notes |
|---|---|---|
| `github_release` | Query the GitHub Releases API for the latest (or pinned) version, download the asset for linux and the CPU arch, verify checksum, extract the binary to `~/.reconkit/bin` | Preferred: no Go needed, no sudo |
| `go_install` | `go install <package>@version` with `GOBIN=~/.reconkit/bin` | Fallback; needs Go; slower |
| `apt` | `sudo apt install -y <package>` after confirmation | For system packages (nmap, whatweb, libpcap-dev, massdns, ...) |
| `pipx` | `pipx install <package>` (installing pipx via apt if needed) | Python tools such as wafw00f |
| `none` | HTTP/Python adapters, nothing to install | crtsh, dnspython, pyprobe, ... |

Order: `github_release`, then its `fallback` (usually `go_install`).

## 3a. Required system packages

Tools may declare `requires_apt` (example: naabu needs `libpcap-dev`) and `requires` (other tools, example: puredns needs massdns). The installer installs dependencies first and reports them in `--dry-run`.

## 4. Verification (fail closed)

For `github_release`:
1. Download the checksums file named by `checksums_pattern`.
2. Compute SHA-256 of the downloaded asset; compare.
3. Mismatch, missing checksum when `verify_checksums: true`, or unexpected asset name: **do not install**, report the reason, continue with other tools, exit code 5.
4. After install run `version_cmd`; if it fails, remove the binary and report `failed`.

Other rules:
- HTTPS only. Download hosts: `api.github.com`, `github.com`, GitHub release asset hosts. Nothing else.
- Download to a temp dir with a size limit; extract only the expected binary name; refuse archive paths that escape the temp dir (zip-slip).
- Files get mode `0755`. The directory `~/.reconkit/bin` is `0700`.
- No `curl | bash`, no running scripts from downloads.
- Optional `GITHUB_TOKEN` is used only to raise API rate limits and is never logged.

## 5. Lookup Order at Run Time

1. `~/.reconkit/bin/<binary>` (our managed copy)
2. `PATH`

`doctor` shows which copy is used and warns when a same-named but different program is found first (the `httpx` Python CLI case).

## 6. Update Behavior

- `update` compares installed version (from `version_cmd`) with latest release (or the pin in `config.yaml` `tool_versions`) and updates only when different.
- Updates never happen silently during a scan. Only `update` (and `install`) change tools.
- After updating `nuclei`, also refresh templates (`nuclei -ut` once confirmed against `--help`).
- `doctor` warns when a tool's major version is newer than the version its fixture parser was tested against.
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
- `--dry-run` makes no filesystem or network changes (use mocked HTTP).
- Non-Linux platform message.
