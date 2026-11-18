#!/usr/bin/env bash
# scripts/install-tools.sh - install or update every tool reconkit uses (Kali/Debian).
#
# The tool list is NOT in this file: it is read from tools.yaml, which stays the
# only registry of what reconkit may run (docs/MASTER_PLAN.md D21). Each
# `kind: binary` entry's `source:` string decides how it is installed:
#
#   apt: <pkg>                 -> sudo apt-get install -y <pkg>
#   go install <module>@latest -> GOBIN=~/.reconkit/bin go install <module>@latest
#   pipx install <pkg>         -> pipx install <pkg>
#   anything else              -> reported as manual, with its upstream URL
#
# It never downloads a release archive itself: `go install` and `apt-get` fetch
# from their own official sources, and the manual list points at the registry's
# URL for a human to decide. The last step is `reconkit doctor --json`, so a tool
# that exists but is the wrong program (identity != ok) still counts as a
# failure - that probe is the adapter's own (docs/09).
#
# Usage:
#   ./scripts/install-tools.sh              # install what is missing
#   ./scripts/install-tools.sh --dry-run    # print the commands, change nothing
#   ./scripts/install-tools.sh --check      # report what is present/missing
#   ./scripts/install-tools.sh --update     # re-run apt/go/pipx for every tool
#   ./scripts/install-tools.sh --only gau   # one tool (bash pattern allowed)
#   ./scripts/install-tools.sh --yes        # no confirmation prompt
#
# Run it as your normal user, NOT with sudo: it escalates for apt itself. As
# root, Go would install into /root/.reconkit/bin where your user cannot find it.

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN_DIR="${HOME}/.reconkit/bin"
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

PLAN=$(mktemp)
trap 'rm -f "${PLAN}"' EXIT

"${PY}" - "${REGISTRY}" "${ONLY}" >"${PLAN}" <<'PYEOF'
import re
import sys

import yaml

registry, only = sys.argv[1], sys.argv[2]
tools = yaml.safe_load(open(registry, encoding="utf-8"))["tools"]

seen_targets: set[str] = set()
manual: list[tuple[str, str]] = []
rows: list[tuple[str, str, str]] = []

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

    if apt:
        rows.append(("apt", apt.group(1), binary))
    elif go:
        # The hint lives inside a prose string, so it ends with punctuation:
        # "(or: go install <module>@latest; the archive member is ...)".
        module = go.group(1).rstrip("),.;")
        rows.append(("go", module, binary))
    elif pipx:
        rows.append(("pipx", pipx.group(1), binary))
    else:
        manual.append((binary, source or "no source recorded"))

# Two registry rows can share one binary (httpx / httpx_tech), and one package
# can provide several binaries (dnsutils -> dig); install each target once.
for kind, target, binary in rows:
    key = f"{kind}:{target}"
    if key in seen_targets:
        continue
    seen_targets.add(key)
    print(f"install\t{kind}\t{target}\t{binary}")

covered = {binary for _, _, binary in rows}
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
  # Same lookup order the adapters use: the managed directory first, then PATH.
  [ -x "${BIN_DIR}/${1}" ] || command -v "${1}" >/dev/null 2>&1
}

apt_pkgs=()
go_mods=()
go_names=()
pipx_pkgs=()
missing=()

while IFS=$'\t' read -r tag a b c; do
  case "${tag}" in
    install)
      kind="${a}"
      target="${b}"
      binary="${c}"
      if have "${binary}" && [ "${UPDATE}" -eq 0 ]; then
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
      esac
      ;;
    manual)
      printf 'manual  %s\n' "${a}"
      ;;
  esac
done <"${PLAN}"

if [ "${CHECK_ONLY}" -eq 1 ]; then
  echo
  echo "check only: nothing was installed"
  exit 0
fi

if [ "${#apt_pkgs[@]}" -eq 0 ] && [ "${#go_mods[@]}" -eq 0 ] && [ "${#pipx_pkgs[@]}" -eq 0 ]; then
  echo
  echo "nothing to install"
else
  echo
  if [ "${ASSUME_YES}" -eq 0 ] && [ "${DRY_RUN}" -eq 0 ]; then
    read -r -p "Proceed with ${#apt_pkgs[@]} apt package(s), ${#go_mods[@]} go module(s), ${#pipx_pkgs[@]} pipx package(s)? [y/N] " reply
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
    run sudo apt-get install -y "${apt_pkgs[@]}"
  fi

  if [ "${#go_mods[@]}" -gt 0 ]; then
    echo
    echo "== go install (${#go_mods[@]}) -> ${BIN_DIR} =="
    run mkdir -p "${BIN_DIR}"
    for index in "${!go_mods[@]}"; do
      printf '>> %s\n' "${go_mods[index]}"
      run env GOBIN="${BIN_DIR}" go install "${go_mods[index]}"
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
fi

if [ "${DRY_RUN}" -eq 1 ]; then
  echo
  echo "dry-run: nothing was installed"
  exit 0
fi

# ---------------------------------------------------------------- verification
# doctor is the adapter's own check (installed / path / identity). No second
# checker here: a binary that exists but is the wrong program must fail.
RECONKIT=""
for candidate in "${ROOT}/.venv/bin/reconkit" reconkit; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    RECONKIT="${candidate}"
    break
  fi
done

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
