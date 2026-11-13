import sys

print("boom", file=sys.stderr)
raise SystemExit(3)
