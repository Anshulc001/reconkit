#!/usr/bin/env bash
# scripts/install-tools.sh - install or update every tool reconkit uses
# (Kali, Debian or Ubuntu).
#
# The tool list is NOT in this file: it is read from tools.yaml, which stays the
# only registry of what reconkit may run (docs/MASTER_PLAN.md D21). Each
# `kind: binary` entry's `source:` string decides how it is installed:
#
#   apt: <pkg>                 -> sudo apt-get install -y <pkg>
#   go install <module>@latest -> GOBIN=~/.reconkit/bin go install <module>@latest
#   pipx install <pkg>         -> pipx install <pkg>
#   release: <url> sha256=<hex> -> download, verify the pinned SHA-256, unpack
#                                (zip, with a plain binary or a .deb inside),
#                                install to ~/.reconkit/bin
#   build: <git-url>@<commit>  -> clone that commit, run make, install bin/<binary>
#   python: <git-url>@<commit> -> clone that commit, build a private venv from
#                                requirements.txt, write a launcher in
#                                ~/.reconkit/bin (tools with no console script)
#   anything else              -> reported as manual, with its upstream URL
#
# `release:` and `build:` are the two ways to install a tool a distro does not
# package (findomain, massdns, rustscan on Ubuntu). Both are pinned in
# tools.yaml: an archive URL plus its SHA-256, or a git commit. The download must
# be https on github.com and is never piped into a shell; `build:` runs the
# project's own Makefile at the pinned commit. The last step is
# `reconkit doctor --json`, so a tool that exists but is the wrong program
# (identity != ok) still counts as a failure - that probe is the adapter's own
# (docs/09).
#
# Usage:
#   ./scripts/install-tools.sh              # install what is missing
#   ./scripts/install-tools.sh --dry-run    # print the commands, change nothing
#   ./scripts/install-tools.sh --check      # report what is present/missing
#   ./scripts/install-tools.sh --update     # re-run every source for every tool
#   ./scripts/install-tools.sh --only gau   # one tool (bash pattern allowed)
#   ./scripts/install-tools.sh --yes        # no confirmation prompt
#
# Run it as your normal user, NOT with sudo: it escalates for apt itself. As
# root, Go would install into /root/.reconkit/bin where your user cannot find it.

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN_DIR="${HOME}/.reconkit/bin"
OPT_DIR="${HOME}/.reconkit/opt"
REGISTRY="${ROOT}/tools.yaml"

DRY_RUN=0
CHECK_ONLY=0
UPDATE=0
ASSUME_YES=0
ONLY=""

usage() {
  sed -n '1,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --check) CHECK_ONLY=1 ;;
    --update) UPDATE=1 ;;
    -y | --yes) ASSUME_YES=1 ;;
    --only)
      shift
      ONLY="${1:-}"
      [ -n "${ONLY}" ] || {
        echo "error: --only needs a tool name" >&2
        exit 2
      }
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option ${1}" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ "$(id -u)" -eq 0 ]; then
  cat >&2 <<'EOF'
error: run this script as your normal user, not with sudo or as root.

It calls sudo itself for apt, and Go must install into YOUR home
(~/.reconkit/bin), which is the directory reconkit looks in first. As root the
Go binaries would land in /root/.reconkit/bin and no scan could see them.
EOF
  exit 2
fi

[ -f "${REGISTRY}" ] || {
  echo "error: ${REGISTRY} not found" >&2
  exit 2
}

# PyYAML is needed to read the registry. The project venv usually has it.
PY=""
for candidate in "${ROOT}/.venv/bin/python" python3; do
  if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -c 'import yaml' 2>/dev/null; then
    PY="${candidate}"
    break
  fi
done
if [ -z "${PY}" ]; then
  echo "error: python3 with PyYAML is required (sudo apt-get install -y python3-yaml)" >&2
  exit 2
fi

# What doctor already considers usable. `command -v` is not enough: the
# project's own httpx dependency installs a console script called `httpx`, so an
# activated venv made the script report that namesake as "have" and skip
# ProjectDiscovery's binary. Ask doctor, whose identity check is the documented
# verdict, and fall back to a path check only before reconkit is installed.
RECONKIT=""
for candidate in "${ROOT}/.venv/bin/reconkit" reconkit; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    RECONKIT="${candidate}"
    break
  fi
done

PLAN=$(mktemp)
READY=""
if [ -n "${RECONKIT}" ]; then
  READY=$(mktemp)
  "${RECONKIT}" doctor --json 2>/dev/null | "${PY}" -c '
import json, sys

try:
    doc = json.load(sys.stdin)
except json.JSONDecodeError:
    raise SystemExit(0)
for row in doc.get("tools", []):
    if row.get("kind") == "binary" and row.get("installed") == "yes":
        print(row.get("tool", ""))
' >"${READY}" || true
fi
trap 'rm -f "${PLAN}" "${READY}"' EXIT

"${PY}" - "${REGISTRY}" "${ONLY}" >"${PLAN}" <<'PYEOF'
import re
import sys

import yaml

registry, only = sys.argv[1], sys.argv[2]
tools = yaml.safe_load(open(registry, encoding="utf-8"))["tools"]

seen_targets: set[str] = set()
manual: list[tuple[str, str]] = []
rows: list[tuple[str, str, str, str]] = []

for name, spec in sorted(tools.items()):
    if spec.get("kind") != "binary":
        continue
    if only and only not in name and only not in str(spec.get("binary", name)):
        continue
    binary = str(spec.get("binary", name))
    source = str(spec.get("source", "")).strip()

    apt = re.match(r"apt:\s*([^\s(]+)", source)
    go = re.search(r"go install\s+(\S+)", source)
    pipx = re.match(r"pipx install\s+(\S+)", source)
    release = re.match(r"release:\s*(\S+)\s+sha256=([0-9a-fA-F]{64})\s*$", source)
    build = re.match(r"build:\s*(\S+?)(?:@([0-9a-fA-F]{7,40}))?\s*$", source)
    python = re.match(r"python:\s*(\S+?)(?:@([0-9a-fA-F]{7,40}))?\s*$", source)

    if apt:
        rows.append(("apt", apt.group(1), binary, name))
    elif release:
        rows.append(
            ("release", f"{release.group(1)}|{release.group(2).lower()}", binary, name)
        )
    elif build:
        target = build.group(1) + ("|" + build.group(2) if build.group(2) else "")
        rows.append(("build", target, binary, name))
    elif python:
        target = python.group(1) + ("|" + python.group(2) if python.group(2) else "")
        rows.append(("python", target, binary, name))
    elif go:
        # The hint lives inside a prose string, so it ends with punctuation:
        # "(or: go install <module>@latest; the archive member is ...)".
        module = go.group(1).rstrip("),.;")
        rows.append(("go", module, binary, name))
    elif pipx:
        rows.append(("pipx", pipx.group(1), binary, name))
    else:
        manual.append((binary, source or "no source recorded"))

# Two registry rows can share one binary (httpx / httpx_tech), and one package
# can provide several binaries (dnsutils -> dig); install each target once.
# Each row must carry ITS OWN registry name: `have()` asks doctor about that
# name, so a leftover loop variable made every row ask about the last tool and
# the whole plan looked installed whenever that one tool was (2026-11-20).
for kind, target, binary, tool_name in rows:
    key = f"{kind}:{target}"
    if key in seen_targets:
        continue
    seen_targets.add(key)
    print(f"install\t{kind}\t{target}\t{binary}\t{tool_name}")

covered = {binary for _, _, binary, _ in rows}
for binary, source in manual:
    # httpx_tech reuses the httpx binary; the httpx row already installs it.
    if binary in covered:
        continue
    print(f"manual\t{binary}\t{source}")
PYEOF

if [ ! -s "${PLAN}" ]; then
  echo "error: no tools matched '${ONLY}' in ${REGISTRY}" >&2
  exit 2
fi

have() {
  # `doctor` is authoritative when it ran: it proves identity, not presence.
  # Without reconkit, fall back to the managed directory and PATH.
  if [ -n "${READY}" ]; then
    grep -qxF -- "$1" "${READY}"
  else
    [ -x "${BIN_DIR}/${1}" ] || command -v "${1}" >/dev/null 2>&1
  fi
}

apt_pkgs=()
go_mods=()
go_names=()
pipx_pkgs=()
release_targets=()
release_bins=()
build_targets=()
build_bins=()
python_targets=()
python_bins=()
missing=()

while IFS=$'\t' read -r tag a b c d; do
  case "${tag}" in
    install)
      kind="${a}"
      target="${b}"
      binary="${c}"
      tool="${d:-${c}}"
      if have "${tool}" && [ "${UPDATE}" -eq 0 ]; then
        printf 'have    %-16s %s\n' "${binary}" "${target}"
        continue
      fi
      case "${kind}" in
        apt)
          apt_pkgs+=("${target}")
          printf 'apt     %-16s %s\n' "${binary}" "${target}"
          ;;
        go)
          go_mods+=("${target}")
          go_names+=("${binary}")
          printf 'go      %-16s %s\n' "${binary}" "${target}"
          ;;
        pipx)
          pipx_pkgs+=("${target}")
          printf 'pipx    %-16s %s\n' "${binary}" "${target}"
          ;;
        release)
          release_targets+=("${target}")
          release_bins+=("${binary}")
          printf 'release %-16s %s\n' "${binary}" "${target%%|*}"
          ;;
        build)
          build_targets+=("${target}")
          build_bins+=("${binary}")
          printf 'build   %-16s %s\n' "${binary}" "${target%%|*}"
          ;;
        python)
          python_targets+=("${target}")
          python_bins+=("${binary}")
          printf 'python  %-16s %s\n' "${binary}" "${target%%|*}"
          ;;
      esac
      ;;
    manual)
      # No automatic source in the registry - but it may be present already,
      # in which case it is not a gap (findomain/rustscan on this box).
      if have "${a}"; then
        printf 'have    %-16s (installed by hand)\n' "${a}"
      else
        printf 'manual  %s\t%s\n' "${a}" "${b}"
      fi
      ;;
  esac
done <"${PLAN}"

if [ "${CHECK_ONLY}" -eq 1 ]; then
  echo
  echo "check only: nothing was installed"
  exit 0
fi

if [ "${#apt_pkgs[@]}" -eq 0 ] && [ "${#go_mods[@]}" -eq 0 ] && \
   [ "${#pipx_pkgs[@]}" -eq 0 ] && [ "${#release_bins[@]}" -eq 0 ] && \
   [ "${#build_bins[@]}" -eq 0 ] && [ "${#python_bins[@]}" -eq 0 ]; then
  echo
  echo "nothing to install"
else
  echo
  if [ "${ASSUME_YES}" -eq 0 ] && [ "${DRY_RUN}" -eq 0 ]; then
    read -r -p "Proceed with ${#apt_pkgs[@]} apt package(s), ${#go_mods[@]} go module(s), ${#pipx_pkgs[@]} pipx package(s), ${#release_bins[@]} release archive(s), ${#build_bins[@]} source build(s), ${#python_bins[@]} python checkout(s)? [y/N] " reply
    case "${reply}" in
      y | Y) ;;
      *)
        echo "aborted"
        exit 1
        ;;
    esac
  fi

  run() {
    if [ "${DRY_RUN}" -eq 1 ]; then
      printf 'dry-run: %s\n' "$*"
    else
      "$@"
    fi
  }

  # Go and pipx themselves are prerequisites, not tools.
  if [ "${#go_mods[@]}" -gt 0 ] && ! command -v go >/dev/null 2>&1; then
    echo "go is missing; installing golang-go first"
    run sudo apt-get install -y golang-go
  fi
  if [ "${#pipx_pkgs[@]}" -gt 0 ] && ! command -v pipx >/dev/null 2>&1; then
    echo "pipx is missing; installing pipx first"
    run sudo apt-get install -y pipx
  fi

  # release/build need a few ordinary tools; install them only when missing.
  need_build=()
  [ "${#release_bins[@]}" -gt 0 ] && need_build+=(curl unzip ca-certificates)
  [ "${#build_bins[@]}" -gt 0 ] && need_build+=(git make gcc)
  [ "${#python_bins[@]}" -gt 0 ] && need_build+=(git)
  if [ "${#need_build[@]}" -gt 0 ]; then
    absent=()
    for need in "${need_build[@]}"; do
      command -v "${need}" >/dev/null 2>&1 || absent+=("${need}")
    done
    if [ "${#absent[@]}" -gt 0 ]; then
      echo "installing prerequisites: ${absent[*]}"
      run sudo apt-get update -y
      run sudo apt-get install -y "${absent[@]}"
    fi
  fi
  # A venv needs ensurepip, which Debian/Ubuntu split into python3-venv.
  if [ "${#python_bins[@]}" -gt 0 ] && ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    echo "python3-venv is missing; installing it first"
    run sudo apt-get update -y
    run sudo apt-get install -y python3-venv
  fi

  if [ "${#apt_pkgs[@]}" -gt 0 ]; then
    echo
    echo "== apt (${#apt_pkgs[@]}) =="
    if ! command -v sudo >/dev/null 2>&1; then
      echo "error: sudo is not installed and apt needs it. As root, run:" >&2
      printf '  apt-get install -y %s\n' "${apt_pkgs[*]}" >&2
      exit 2
    fi
    # Ask for the password once, up front, instead of in the middle of a
    # half-finished install. Without a terminal there is nobody to ask, so say
    # so instead of hanging.
    if ! sudo -n true 2>/dev/null; then
      if [ -t 0 ]; then
        echo "sudo needs a password; asking once now"
        sudo -v || {
          echo "error: sudo was refused" >&2
          exit 2
        }
      else
        echo "error: sudo needs a password and this shell cannot prompt for one." >&2
        echo "       Run the script from a terminal, or allow apt via sudoers." >&2
        exit 2
      fi
    fi
    run sudo apt-get update -y
    # One package at a time: a distro that does not package one tool (Ubuntu has
    # no amass/findomain/massdns/rustscan) must not stop apt from installing
    # every other tool in the same batch.
    for pkg in "${apt_pkgs[@]}"; do
      if run sudo apt-get install -y "${pkg}"; then
        :
      else
        printf 'warning: apt could not install %s on this system; install that tool by hand (see docs/10_TOOL_SOURCES.md)\n' "${pkg}" >&2
      fi
    done
  fi

  if [ "${#go_mods[@]}" -gt 0 ]; then
    echo
    echo "== go install (${#go_mods[@]}) -> ${BIN_DIR} =="
    run mkdir -p "${BIN_DIR}"
    for index in "${!go_mods[@]}"; do
      printf '>> %s\n' "${go_mods[index]}"
      # `go install` verifies each module with sum.golang.org; a brief network
      # failure there failed two tools in a clean run (2026-11-20, D99). One
      # retry, then the doctor verdict reports it like any other gap.
      if [ "${DRY_RUN}" -eq 1 ]; then
        run env GOBIN="${BIN_DIR}" go install "${go_mods[index]}"
      elif ! env GOBIN="${BIN_DIR}" go install "${go_mods[index]}"; then
        echo "retrying ${go_mods[index]} once"
        env GOBIN="${BIN_DIR}" go install "${go_mods[index]}" || \
          printf 'warning: go install failed for %s\n' "${go_mods[index]}" >&2
      fi
    done
  fi

  if [ "${#pipx_pkgs[@]}" -gt 0 ]; then
    echo
    echo "== pipx (${#pipx_pkgs[@]}) =="
    for pkg in "${pipx_pkgs[@]}"; do
      printf '>> %s\n' "${pkg}"
      if [ "${UPDATE}" -eq 1 ]; then
        run pipx upgrade "${pkg}" || run pipx install "${pkg}"
      else
        run pipx install "${pkg}"
      fi
    done
  fi

  if [ "${#release_bins[@]}" -gt 0 ] || [ "${#build_bins[@]}" -gt 0 ]; then
    run mkdir -p "${BIN_DIR}"
  fi

  if [ "${#release_bins[@]}" -gt 0 ]; then
    echo
    echo "== release archives (${#release_bins[@]}) -> ${BIN_DIR} =="
    for index in "${!release_bins[@]}"; do
      binary="${release_bins[index]}"
      url="${release_targets[index]%%|*}"
      sha="${release_targets[index]#*|}"
      if [ "${DRY_RUN}" -eq 1 ]; then
        printf 'dry-run: curl -fsSL %s | verify sha256 %s -> %s\n' "${url}" "${sha}" "${BIN_DIR}/${binary}"
        continue
      fi
      work=$(mktemp -d)
      printf '>> %s\n' "${url}"
      if ! curl -fsSL --proto '=https' --tlsv1.2 -o "${work}/archive" "${url}"; then
        echo "warning: download failed for ${binary}; see docs/10_TOOL_SOURCES.md" >&2
        rm -rf "${work}"
        continue
      fi
      if ! printf '%s  %s\n' "${sha}" "${work}/archive" | sha256sum -c - >/dev/null 2>&1; then
        echo "warning: SHA-256 mismatch for ${binary}; refusing that archive" >&2
        rm -rf "${work}"
        continue
      fi
      mkdir -p "${work}/unpacked"
      if ! unzip -q -o "${work}/archive" -d "${work}/unpacked"; then
        echo "warning: cannot unpack the archive for ${binary}" >&2
        rm -rf "${work}"
        continue
      fi
      source_path="${work}/unpacked/${binary}"
      deb=$(find "${work}/unpacked" -maxdepth 1 -name '*.deb' -print -quit)
      if [ -n "${deb}" ]; then
        mkdir -p "${work}/root"
        dpkg-deb -x "${deb}" "${work}/root" || true
        source_path="${work}/root/usr/bin/${binary}"
      fi
      if [ -f "${source_path}" ]; then
        install -m 0755 "${source_path}" "${BIN_DIR}/${binary}"
      else
        echo "warning: ${binary} was not inside the archive" >&2
      fi
      rm -rf "${work}"
    done
  fi

  if [ "${#build_bins[@]}" -gt 0 ]; then
    echo
    echo "== source builds (${#build_bins[@]}) -> ${BIN_DIR} =="
    for index in "${!build_bins[@]}"; do
      binary="${build_bins[index]}"
      url="${build_targets[index]%%|*}"
      commit="${build_targets[index]}"
      [ "${commit}" = "${url}" ] && commit="" || commit="${commit#*|}"
      if [ "${DRY_RUN}" -eq 1 ]; then
        printf 'dry-run: git clone %s %s && make && install bin/%s\n' "${url}" "${commit:-HEAD}" "${binary}"
        continue
      fi
      work=$(mktemp -d)
      printf '>> %s %s\n' "${url}" "${commit:-HEAD}"
      if ! git clone -q --no-checkout --depth 1 "${url}" "${work}/src"; then
        echo "warning: cannot clone ${url} for ${binary}" >&2
        rm -rf "${work}"
        continue
      fi
      if [ -n "${commit}" ]; then
        if ! git -C "${work}/src" fetch -q --depth 1 origin "${commit}" || \
           ! git -C "${work}/src" checkout -q FETCH_HEAD; then
          echo "warning: cannot check out ${commit} for ${binary}" >&2
          rm -rf "${work}"
          continue
        fi
      else
        git -C "${work}/src" checkout -q HEAD || true
      fi
      if ! make -C "${work}/src" -j"$(nproc 2>/dev/null || echo 2)" >/dev/null 2>&1; then
        echo "warning: make failed for ${binary}" >&2
        rm -rf "${work}"
        continue
      fi
      if [ -f "${work}/src/bin/${binary}" ]; then
        install -m 0755 "${work}/src/bin/${binary}" "${BIN_DIR}/${binary}"
      else
        echo "warning: ${binary} was not at bin/${binary} after make" >&2
      fi
      rm -rf "${work}"
    done
  fi

  # A Python tool with no console script (`python:` in tools.yaml): the pinned
  # checkout keeps its own venv under ~/.reconkit/opt/<binary>, and the managed
  # bin gets a launcher, so every adapter still invokes one binary path.
  if [ "${#python_bins[@]}" -gt 0 ]; then
    echo
    echo "== python checkouts (${#python_bins[@]}) -> ${BIN_DIR} =="
    run mkdir -p "${BIN_DIR}" "${OPT_DIR}"
    for index in "${!python_bins[@]}"; do
      binary="${python_bins[index]}"
      url="${python_targets[index]%%|*}"
      commit="${python_targets[index]}"
      [ "${commit}" = "${url}" ] && commit="" || commit="${commit#*|}"
      dest="${OPT_DIR}/${binary}"
      if [ "${DRY_RUN}" -eq 1 ]; then
        printf 'dry-run: git clone %s %s -> %s && python3 -m venv && pip install -r requirements.txt && launcher %s\n' \
          "${url}" "${commit:-HEAD}" "${dest}" "${BIN_DIR}/${binary}"
        continue
      fi
      printf '>> %s %s\n' "${url}" "${commit:-HEAD}"
      rm -rf "${dest}"
      if ! git clone -q --no-checkout --depth 1 "${url}" "${dest}"; then
        echo "warning: cannot clone ${url} for ${binary}" >&2
        continue
      fi
      if [ -n "${commit}" ]; then
        if ! git -C "${dest}" fetch -q --depth 1 origin "${commit}" || \
           ! git -C "${dest}" checkout -q FETCH_HEAD; then
          echo "warning: cannot check out ${commit} for ${binary}" >&2
          rm -rf "${dest}"
          continue
        fi
      else
        git -C "${dest}" checkout -q HEAD || true
      fi
      if ! python3 -m venv "${dest}/.venv"; then
        echo "warning: cannot create the ${binary} virtualenv" >&2
        continue
      fi
      "${dest}/.venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
      if [ -f "${dest}/requirements.txt" ]; then
        if ! "${dest}/.venv/bin/pip" install -q -r "${dest}/requirements.txt" >/dev/null 2>&1; then
          echo "warning: pip could not install ${binary} requirements" >&2
          continue
        fi
      fi
      # google-cloud-dns==0.34.1 imports pkg_resources, removed in setuptools 81.
      "${dest}/.venv/bin/pip" install -q 'setuptools<81' >/dev/null 2>&1 || true
      {
        printf '#!/bin/sh\n'
        printf '# written by reconkit setup (docs/10 section 5); %s has no console script.\n' "${binary}"
        printf 'exec "%s/.venv/bin/python" "%s/main.py" "$@"\n' "${dest}" "${dest}"
      } >"${BIN_DIR}/${binary}"
      chmod 0755 "${BIN_DIR}/${binary}"
    done
  fi
fi

if [ "${DRY_RUN}" -eq 1 ]; then
  echo
  echo "dry-run: nothing was installed"
  exit 0
fi

# ---------------------------------------------------------------- verification
# doctor is the adapter's own check (installed / path / identity). No second
# checker here: a binary that exists but is the wrong program must fail.
if [ -z "${RECONKIT}" ]; then
  echo
  echo "note: reconkit is not on PATH, so the doctor check was skipped."
  echo "      install it (pip install -e .) and run: reconkit doctor"
  exit 0
fi

echo
echo "== verification: ${RECONKIT} doctor =="
DOCTOR_JSON=$("${RECONKIT}" doctor --json 2>/dev/null)
"${RECONKIT}" doctor --no-color 2>&1 | tail -n 12

# Binaries the registry has no automatic install for; reported, not failed.
MANUAL_BINS=$(grep -E '^manual' "${PLAN}" | cut -f2 | tr '\n' ' ')

VERDICT=$(
  printf '%s' "${DOCTOR_JSON}" | RECONKIT_MANUAL="${MANUAL_BINS}" "${PY}" -c '
import json
import os
import sys

only = sys.argv[1]
manual = set(os.environ.get("RECONKIT_MANUAL", "").split())
try:
    doc = json.load(sys.stdin)
except json.JSONDecodeError:
    print("unreadable")
    raise SystemExit(0)

bad = []
for row in doc.get("tools", []):
    if row.get("kind") != "binary":
        continue
    tool = str(row.get("tool", ""))
    if only and only not in tool and only not in str(row.get("path") or ""):
        continue
    if tool in manual:
        # No automatic install exists for it (seen when the script ran).
        continue
    if row.get("installed") != "yes":
        bad.append(f"missing:{tool}")
    elif row.get("identity") != "ok":
        bad.append(f"wrong-program:{tool}")
print("\t".join(bad) if bad else "clean")
' "${ONLY}"
)

if [ "${VERDICT}" = "clean" ]; then
  echo
  if [ -n "${ONLY}" ]; then
    echo "every binary matching '${ONLY}' is installed and identified correctly."
  else
    echo "every installable registry binary is installed and identified correctly."
  fi
  exit 0
fi

echo
echo "not ready:"
printf '%s\n' "${VERDICT}" | tr '\t' '\n' | sed 's/^/  /'
echo
echo "Registry entries with no automatic install (install these by hand):"
grep -E '^manual' "${PLAN}" | cut -f2- | sed 's/^/  /'
exit 1
