# Tool manuals - shots

Stage `shots` of `reconkit`. Verified on the canonical Kali checkout
(`/home/kali/Desktop/reconkit`, Python 3.14.8) on **2026-11-16**. Every
`--help` block and every test block below is the tool's own raw output,
captured on that machine; nothing here is written from memory.

Authorized target used for the one safe test: **testfire.net** (already in
`scope.yaml`). One command per tool, no payloads, no brute force.

Tools from the `vulns` stage are deliberately absent - see
`docs/tool_manuals/README.md` ("Skipped").

| Tool | Kind | Tier | Mode | Phase | Adapter in this build |
|---|---|---|---|---|---|
| `gowitness` | binary | opt_in | active | 3 | no |



---

## `gowitness`

- **Registry:** binary, opt_in, active, phase 3, `stage: shots`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/sensepost/gowitness
- **Installed on this box:** `/home/kali/.reconkit/bin/gowitness`, v3 build with `git hash: dev`, `build env: dev`, `build time: dev`
- **Where it comes from:** github.com/sensepost/gowitness (this is how the binary used for the Phase 1 manual was obtained) - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** see note - v3 uses `scan` subcommands and file input

#### Real `--help` (raw, full)

Captured with `gowitness -h` (exit 0, wrote to stdout):

```
               _ _                   
 ___ ___ _ _ _|_| |_ __ ___ ___ ___ 
| . | . | | | | |  _|  | -_|_ -|_ -|
|_  |___|_____|_|_||_|_|___|___|___|
|___|    v3, with <3 by @leonjza

Usage:
  gowitness [command]

Available Commands:
  help        Help about any command
  report      Work with gowitness reports
  scan        Perform various scans
  version     Get the gowitness version

Flags:
  -D, --debug-log      Enable debug logging
  -h, --help           help for gowitness
      --no-log-color   Disable colors in log output
      --profile        Enable CPU, memory, and trace profiling (writes to profiles/<timestamp>/)
  -q, --quiet          Silence (almost all) logging

Use "gowitness [command] --help" for more information about a command.
```


#### Real test on testfire.net

Command:

```
gowitness scan single --url https://testfire.net --screenshot-path /tmp/p1/test/shots
```


Output (raw, exit code 0):

```

--- stderr ---
2026/11/16 08:59:19 WARN no writers have been configured. to persist probe results, add writers using --write-* flags
2026/11/16 09:00:27 INFO result 🤖 target=https://testfire.net status-code=200 title="Altoro Mutual" have-screenshot=false
```


#### Notes and errors hit

Output (exit 0, stderr):

```
WARN no writers have been configured. to persist probe results, add writers using --write-* flags
INFO result 🤖 target=https://testfire.net status-code=200 title="Altoro Mutual" have-screenshot=false
```

**Two things a future adapter must know:**

1. It is a v3 command tree: `gowitness scan single --url ...`, not
   `gowitness single ...`. `-h` shows `report`, `scan`, `version`.
2. `have-screenshot=false`: the probe ran (status 200, real title) but no
   Chromium was found to take the picture. A screenshot feature needs a browser
   installed; this box has Chrome (see the session's system info) but gowitness
   did not pick it up automatically.
3. A `WARN no writers have been configured` means nothing is persisted unless
   `--write-db`/`--write-csv` is passed; the default writes only the image.

