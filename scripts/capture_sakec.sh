#!/usr/bin/env bash
# One capture pass per tool against a single domain (2026-11-19 scale batch).
#
# This is a capture, not a scan: no engine, no stages, no scope file, no writes
# to the database. Each tool runs once, its raw stdout goes to
# captures/sakec/<tool>.txt and its wall clock into captures/sakec/timings.json.
# Every call is bounded by a 300 s `timeout`, which shows the shape of a real
# tool's runtime without letting one hang the capture.
#
# Usage: scripts/capture_sakec.sh [domain]
#        (default: sakec.ac.in; captures/ is gitignored because it is third-party
#         data, not project material)
set -uo pipefail

DOMAIN="${1:-sakec.ac.in}"
OUT="captures/sakec"
BIN="${HOME}/.reconkit/bin"
mkdir -p "$OUT"

# The managed bin directory first, then PATH: the tools live in both places on
# this box, and `capture` must use the same binary a scan would.
PATH="${BIN}:${PATH}"
export PATH
LIMIT=300

# resolve <tool>: the command name, or nothing with a loud message.
resolve() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "MISSING $1" >&2
    return 1
  fi
  command -v "$1"
}

# run <tool> <label> <cmd...>: bounded run, raw stdout to <tool>.txt, wall clock recorded.
run() {
  local tool="$1" label="$2"; shift 2
  local file="${OUT}/${tool}.txt"
  local started ended status
  started=$(date +%s.%N)
  timeout "${LIMIT}" "$@" >"${file}" 2>"${OUT}/${tool}.err"
  status=$?
  ended=$(date +%s.%N)
  local seconds
  seconds=$(awk -v a="$started" -v b="$ended" 'BEGIN { printf "%.2f", b - a }')
  local lines
  lines=$(wc -l <"${file}" | tr -d ' ')
  printf '%s\t%s\t%s\t%s\t%s\n' "$tool" "$label" "$seconds" "$lines" "$status" >>"${OUT}/rows.tsv"
  echo "${tool}: ${seconds}s, ${lines} lines, exit ${status}"
}

: >"${OUT}/rows.tsv"

if resolve subfinder >/dev/null; then
  run subfinder "subfinder -d ${DOMAIN} -silent" subfinder -d "$DOMAIN" -silent
fi
if resolve assetfinder >/dev/null; then
  run assetfinder "assetfinder --subs-only ${DOMAIN}" assetfinder --subs-only "$DOMAIN"
fi

# crtsh has no binary: it is reconkit's own HTTP adapter call, run exactly as the
# engine would (honest User-Agent, same URL, same parser), with the tool's raw
# response written to the capture file.
if [ -d "$(dirname "$0")/../src" ]; then
  started=$(date +%s.%N)
  timeout "${LIMIT}" python "$(dirname "$0")/capture_crtsh.py" "$DOMAIN" \
    >"${OUT}/crtsh.txt" 2>"${OUT}/crtsh.err"
  status=$?
  ended=$(date +%s.%N)
  seconds=$(awk -v a="$started" -v b="$ended" 'BEGIN { printf "%.2f", b - a }')
  lines=$(wc -l <"${OUT}/crtsh.txt" | tr -d ' ')
  printf '%s\t%s\t%s\t%s\t%s\n' crtsh "CrtshAdapter().run() HTTP call" "$seconds" "$lines" "$status" >>"${OUT}/rows.tsv"
  echo "crtsh: ${seconds}s, ${lines} lines, exit ${status}"
fi

if resolve gau >/dev/null; then
  run gau "gau ${DOMAIN}" gau "$DOMAIN"
fi
if resolve katana >/dev/null; then
  run katana "katana -u https://${DOMAIN}/ -d 2 -silent" katana -u "https://${DOMAIN}/" -d 2 -silent
fi
# httprobe reads the hosts subfinder and assetfinder found, deduplicated.
if resolve httprobe >/dev/null; then
  sort -u "${OUT}/subfinder.txt" "${OUT}/assetfinder.txt" 2>/dev/null | grep -v '^\s*$' \
    >"${OUT}/subs.txt"
  cat "${OUT}/subs.txt" | run httprobe "httprobe < captured subs (${DOMAIN})" httprobe
fi

{
  echo "{"
  echo '  "domain": "'"${DOMAIN}"'",'
  echo '  "limit_s": '"${LIMIT}"','
  echo '  "tools": {'
  awk -F'\t' '
    BEGIN { first = 1 }
    {
      if (!first) printf ",\n"
      printf "    \"%s\": {\"command\": \"%s\", \"seconds\": %s, \"lines\": %s, \"exit\": %s}", $1, $2, $3, $4, $5
      first = 0
    }
    END { printf "\n" }
  ' "${OUT}/rows.tsv"
  echo "  }"
  echo "}"
} >"${OUT}/timings.json"

echo "wrote ${OUT}/timings.json"
