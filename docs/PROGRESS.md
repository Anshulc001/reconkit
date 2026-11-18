# PROGRESS

Read this after `AGENTS.md`, before touching code. Update it in every commit that changes `src/` or `tests/`, and in every commit that closes named work. Detail lives in `docs/REVIEW_LOG.md`; the trimmed history (task table, module map, per-part deviations, the full risk list and all Part 11 material) is in its **PROGRESS archive (moved 2026-11-15 by the PROGRESS.md trim)** section at the end of that file.

## RESUME HERE

- Status: **AUDIT CLOSE-OUT (Part A) DONE - the url_probe/httpx batch's five missing raw proofs are pasted in `docs/REVIEW_LOG.md` ("2026-11-18 (audit close-out)"), no code change.** A.1 the complete 196-line `~/.reconkit/bin/httpx -h` plus `flag provided but not defined: -insecure`; A.2 a fresh 20-row fixture (10 certificate-invalid https + 10 http 200) classified in one pass as `-2|10` / `200|10`; A.3 the full `_dedupe_www_variants` body before (`4b97928^`) and after; A.4 `grep -n 'url_probe' config.yaml` (`21:  url_probe: 600`, `36:url_probe:`); A.5 two identical 5-row DBs where the two stale `404` rows survive the default pass (`probing 3 URL(s)`, `404|2` + `200|3`) and are rewritten by `--reprobe-urls` (`probing 5 URL(s)`, `200|5`). Nothing contradicts the earlier report. Next action: Part B (urlfinder cap).
- Previous status: **REGRESSION FIXED IN PART 1'S PROBE LOOP, AND PART 3 DONE (url_probe phase timeout, D26).** Part 1's client-reuse edit had left the per-batch commit block dedented out of the `for` loop, so a multi-batch pass would have written only its **last** batch; found while writing Part 3's partial-on-timeout test (`1/2 probed` with both rows still `NULL`), fixed by re-indenting the commit inside the loop, and disclosed in REVIEW_LOG. No real run hit it (every measured pass was a single batch). Part 3 then bounds the pass: `timeouts.url_probe` (600 s in `config.yaml`, new field on `Timeouts`) or `--phase-timeout` wraps `_run_url_probe` in `asyncio.wait_for`; on timeout the finished batches stay committed, the pass is recorded `partial`, the warning reads `url_probe: timed out after Ns (M/N URL(s) probed)`, a `CompletionGap` names it (`--json` `complete_with_gaps`) and the run exits **0**, never 5. Suite 888 -> 891. Next action: none; report.
- Previous status: **VERIFICATION FOLLOW-UP, PART 1 DONE (D24) and PART 2 DONE (D25); Part 3 next.**
- Previous status: **VERIFICATION FOLLOW-UP, PART 2 DONE (www dedup requires a known status, D25).** Verification of the four-part batch found `_dedupe_www_variants` comparing `status_code` with `==`, so `NULL == NULL` counted as "same status": a pair of ALIVE names with no HTTP status on either side but a shared IP was marked `duplicate_of` from DNS evidence alone (seen in a mock run: `www.testfire.net.duplicate_of = testfire.net` with both statuses `NULL`). The shared-IP branch now requires both codes present and equal; a no-status pair is left alone (no `duplicate_of`, no note). The 3xx/2xx, both-2xx and different-IP branches are unchanged; no schema, state or confidence change. Suite 882 -> 883. D25, PIT-61. **Part 1 of this follow-up (PD httpx batch probe) is BLOCKED on an owner ruling:** PD httpx v1.12.0 has no `-insecure` flag, skips TLS verification silently (a `www.-only` certificate on `https://testfire.net/` returns 200), emits **no JSON line at all** for a failed URL (no `tls_error`, no error field), and sends a random browser User-Agent by default; measured on 158 URLs it took 9.19 s against Python httpx's 4.59 s, so the speed premise did not hold on this box, and swapping transports would erase the `-2` distinction added in Part 4. Part 3 (url_probe phase timeout) waits with Part 1 because its shape depends on the transport decision. Next action: owner ruling on the probe transport; then Part 3.
- Previous status: **BATCH 2026-11-18 PART 4 DONE (url_probe stage, D23) - batch complete.** The urls stage records what the archives and the crawler returned and never said which URLs still answer, so a 2019 `/admin` and a page that answered today were the same evidence. `Stage.URL_PROBE` now runs after `urls` in `active` and `full` (never `passive`: it sends HTTP) and is **engine-owned** - no adapter, no `tools.yaml` entry, no Tools-table row - through `Engine._run_url_probe()`: one httpx `GET` per stored URL with the honest `reconkit/0.1` UA, `threads`/`batch_size`/`timeout_s`/`max_urls` from the new `config.yaml` `url_probe:` block (5000/200/50/10 s), no retries, and the same `_active_hosts()` scope gate as every active stage. Results go to **`urls.status_code` (schema 9 -> 10, additive)**: the HTTP status, `-1` for no answer (refused, timeout, DNS failure), **`-2` when the server answered with a certificate that does not verify** (hostname mismatch or untrusted chain) - a case the first real testfire.net run exposed, where every URL stored `-1` and a live site looked dead because its certificate is issued for `www.testfire.net`; verification is never disabled, so the fact is recorded as itself. `NULL` alone means "not probed yet", a stored answer (`-1`/`-2`/status) is never retried, and `--skip-url-probe` removes the stage; `--mock` sends nothing, leaves NULLs and warns. `_empty_stages()` excludes it, so a tool-less probe cannot make a complete run exit 5. Host state, confidence, `diff` and every count query are untouched. Real proof (testfire.net, `max_urls: 20`, `--tools pyprobe,katana,gau`): `url_probe: finished 20 URL(s)`, `-2|40` and `|365` NULL in the DB, exit 0; three direct requests gave `http://testfire.net/` **200**, `https://www.testfire.net/` **-2**, `https://does-not-exist.testfire.net/` **-1**. Suite 869 -> 882, PIT-60. Next action: none - the four-part batch is closed; report and stop.
- Previous status: **BATCH 2026-11-18 PART 3 DONE (www/non-www deduplication, D22).** `www.X` and `X` are one website: a post-`live` pass `Engine._dedupe_www_variants()` reads the rows the live stage just wrote (plus the current run's host set) and writes **metadata only** on the newest status row - new columns `host_status_history.duplicate_of` and `.www_note`, **schema 8 -> 9** (`_SCHEMA_V9`, additive, both `NULL` on every existing row; disclosed deviation: the brief said 7 -> 8, but 8 was already spent on Part 1's `tool_runs` rebuild). Rules: one 3xx and one 2xx -> the 3xx name is `duplicate_of` the 2xx name; both 2xx -> neither is marked, both get `has www sibling at <other>`; same non-2xx status and a shared IP -> `www.X` is `duplicate_of X`; same status, different **known** IPs -> neither marked, both get `www variant on a different server`; one alive one dead/DNS-only, or an unknown IP set -> nothing. `Store.set_host_duplicate()` updates the newest row and never appends one, so `state`, `status_code`, `confidence`, the confidence formula, `diff` and every count query are untouched. Display: a **Notes** column (added only when some row has a note, so an ordinary table keeps six columns) shows `-> redirects to <host>` / `-> duplicate of <host>` / `canonical` / the two sibling notes; the summary line gains `N hosts (M unique after www-dedup)` only when a duplicate exists; `--json` carries `hosts[].duplicate_of`, `hosts[].www_note` and a top-level `www_dedup` object. Mock proof (`run -d www-pair.test --active --no-scope --mock`, new synthetic fixtures `tests/fixtures/{dnspython,pyprobe}/www-pair.test.synthetic.json`): bare 301 -> `www.www-pair.test` 200 becomes `canonical`, bare row `-> redirects to www.www-pair.test`, `17 hosts (16 unique after www-dedup)`, `www_dedup.applied=true`; real testfire.net run (`--tools assetfinder,dnspython,pyprobe`) showed the other branch - both 200, so both got `has www sibling at ...` and nothing was marked. Suite 855 -> 869. Next action: Part 4 (url_probe stage).
- Previous status: **BATCH 2026-11-18 PART 2 DONE (katana JSON skip, hakrawler/subjs caps, urlfinder inactivity kill).** Three defects from the sakec.ac.in scan. (1) **`katana: invalid JSON line` threw away a whole crawl**: the parser now skips a line it cannot use (non-JSON, or JSON that is not an object) and keeps the rest; `hakrawler`, `gospider` and `subjs` got the same rule for a line with no usable URL. Skipped lines reach the Tools detail as one message per line up to 10, then `skipped N unusable line(s); last: ...`, and the status stays `ok`. `urlfinder` keeps its stricter archive rule. (2) **`hakrawler`/`subjs` owned the whole urls stage** (timeout, 0 items): they get `runtime_cap_s` 120 s and 60 s, keep their partial stdout and report `ok N` with `capped at <n>s; kept partial output` instead of `timeout` - a capped run with 0 items is also `ok`, because the tool worked and we stopped it. (3) **`urlfinder`'s flat 180 s cap is gone**: `urls.urlfinder_min_s/max_s/idle_s` (180/1800/60) give a floor, an inactivity kill and a ceiling in the new config block; the runner gained `idle_timeout`/`min_runtime` and `ExecResult.idle_killed`, and the engine hands the values down as `RunContext.limits`. Real: `katana ok 58`, `hakrawler ok 66`, `subjs ok 0`, then `urlfinder ok 933 in 18.1 s` and `gau ok 345`, all exit 0. Suite 840 -> 855. PIT-58. Next action: Part 3 (www/non-www deduplication).
- Previous status: **BATCH 2026-11-18 PART 1 DONE (external-service gaps + stale docs).** A real `run -d sakec.ac.in --active --no-scope` exited `5` although every failing tool had been *refused by its provider* (`otx` 429, `hackertarget` free quota, `crtsh` 502). Those are now the new tool status `gap` (owner ruling, no D number): one classifier `base.classify_external_gap()` (429/rate-limit/too-many-requests, quota/api-count-exceeded, upstream 502/503/504/5xx) feeds `ToolStatus.GAP` from `HttpAdapter` (status code), from a parser (quota body) and from `BaseToolAdapter.run` (binary stderr/exit). A gap is excluded from the failure total, becomes a completion gap (exit `0`, `completion.gaps`, the stderr block) and is stored as `tool_runs.status='gap'`, which is **schema 8** (`_SCHEMA_V8` rebuilds `tool_runs` because SQLite cannot alter a CHECK). A 404, a refused connection, a TLS error and a parse error stay `failed`. Real evidence on testfire.net: `subs` exited **0** with `tools: 7 ok, 2 gap, 0 failed` and the block naming both services; the same run exited 5 before. Same commit: the four stale statements from the state dump ("Nothing is pushed" - both refs are at `a49e4b5`; the `tech`/`urls`/`vulns` "no adapter" Open risk - waves 4-8 closed it; "Suite 827" - actually 824; `docs/05` "reconkit runs no installer script" - `scripts/install-tools.sh` exists since D21). Suite 824 -> 840. PIT-55. Next action: Part 2 of the same batch.
- Previous status: **LINUX ONLY AND NUCLEI REDACTION FIXED (2026-11-18).** (1) **Linux only, no other platform anywhere** (owner decision): the OS-specific branches in `runner.py`/`workspace.py`/`subfinder.py`/`base.py`, the reserved-device-name rejection and the other-platform venv fallback are deleted, and every doc, log entry, script and gate instruction names Linux only; the docs commit is `6b904eb`. Suite 827 -> 821 because the reserved-name cases went with the behaviour they pinned (the "827" in this paragraph was itself stale: the verified count on this checkout is **824**, see the baseline line below). (2) **A real `--full` run on testfire.net found a real defect:** `nuclei` failed with `invalid JSON line`. Cause: the redaction patterns for `Cookie`/`Set-Cookie`/`Authorization` and the secret pairs ran to the next *real* newline, while a JSONL tool escapes its newlines, so every matching line had its remaining fields replaced by `***` (PIT-54). The value patterns now also stop at an escaped line end, the line stays valid JSON, and the cookie value is still masked. Regression: `test_redaction_keeps_a_jsonl_line_parseable`. (3) **Predictable runtimes** (owner request): `urlfinder` is killed at 180 s by a new `runtime_cap_s` and its partial stdout is parsed (its own `-max-time` is not enforced: measured still running at 5m52s with `-max-time 3`; before this a timeout discarded every URL found); `nikto` passes its own `-maxtime <share>s` per host so it stops cleanly and writes JSON instead of being killed at 600 s with 0 findings; `nuclei` gets `-or`, because the unused request/response pair pushed a real run past the 1 MB stdout cap and truncated the last JSON line (`invalid JSON line`). (4) Live evidence for this batch is recorded in REVIEW_LOG; every run used `testfire.net` from `scope.yaml`. The final `--full` run took **1466 s with 0 timeouts** (38 ok, 2 failed from upstream quotas): `nuclei ok 112`, `urlfinder ok 933 (capped)`, `nikto ok 8`, against 2027 s for the same command before the caps.
- Previous status: **REPORTS IN BOTH MODES, LIVE SPINNER, AMASS FIXED (2026-11-18, D20).** Owner batch after a real `reconkit run -d testfire.net --active --no-scope --only-alive` run. Three changes, each with docs first: (1) **every scan now writes its report** - the writer was gated on the interactive plan, so a `-d`/`-l` run printed tables and saved nothing; it now writes `results/<domain>/<UTC stamp>/report.txt` + `report.json` on both paths, and a flagged run gets every `REPORT_FIELDS` key (the questions only choose columns). (2) **a live status line** - the durable progress lines only appear when a tool *finishes*, so a 600 s `gau` looked like a hang; a new transient `activity` channel carries `<stage>: <done>/<total> tool(s) done, <n>s elapsed - running: <tools>` to a Rich spinner on stderr, drawn only when stderr is a terminal and never on stdout. (3) **amass was broken** - v5.1.3 `enum` is a thin client for its own engine and prints only the `Session Scope` header, so the adapter harvested the target from that header and always reported exactly 1 item; findings are now read back with `amass subs -d DOMAIN -names` through a new documented `post_command` hook (real read-back for testfire.net: the same 8 hosts the table showed). **Two owner premises did not hold, and were reported instead of re-implemented:** stage tools were already concurrent (`asyncio.gather`, weights in REVIEW_LOG: urls did 1581 s of tool time in a 664 s stage), and no duplicates pass between stages (`discovered` is a `set`, `urls` is a `dict`, DB has `UNIQUE(target_id, fqdn)` / `UNIQUE(target_id, url)`; measured 1655 stored URLs = 1655 distinct, 41 hosts = 41 distinct, 0 duplicate groups). Then, with the owner's "do whatever is good, speed is only for the passive recon tools": (4) **the report follows the display filters** and records them (`selection: 8 of 42 hosts (ALIVE)`), so a `--only-alive` artifact matches the table without ever looking like a complete scan; the DB still keeps every host. (5) **the passive tools got their real timeout semantics back** - `gau --timeout` and `urlfinder -timeout` are *per-request HTTP timeouts*, and both adapters were passing the 600 s per-tool budget, so one slow archive source could block the whole stage; measured `gau` 0 items/600 s -> **345 items/31 s**, `urlfinder` 932/554 s -> **996 items/15 s**, and through the engine `reconkit urls -d testfire.net --active --no-scope --tools gau,urlfinder` finished the stage in **15 s wall clock** with `gau ok 345`, `urlfinder ok 933`. Active tools were not touched. (6) **waybackurls was asking one question 42 times** - the adapter fed every discovered host on stdin, but the tool asks `*.<line>/*` and its own `-no-subs` help proves one apex already covers its subdomains; it now gets the apex once (plus any host outside it, for multi-domain scopes) and does the same job in **2.4 s instead of 302 s**; the remaining 0 items are archive.org answering **503 Temporarily Offline** to wildcard CDX queries, not a reconkit defect (`gau` still returns 345 URLs from the same archive). Also verified the owner's question directly: `waybackurls`/`urlfinder`/`unfurl` are installed in `~/.reconkit/bin` and `reconkit doctor` shows `Installed yes / Identity ok` with the path - a bare `command -v` misses them only because that directory is on the child PATH. Suite 816 -> 827. Next action: none.
- Previous status: **SHOTS STAGE WIRED (2026-11-17, D19).** `Stage.SHOTS` is no longer orphaned: it now sits in `STAGE_ORDER` between `urls` and `vulns` and therefore in `MODE_STAGES["full"]`; `passive` and `active` still do not request it and there is no `shots` stage command. `gowitness` is therefore runnable: `reconkit run -d testfire.net --full --no-scope --include-noisy --mock --tools pyprobe,httpx,tlsx,gowitness` prints `gowitness shots ok 2` and exit 0, while `--active` shows no shots stage at all (raw output in REVIEW_LOG). One gowitness fix was needed for that proof: `--mock` now takes the base fixture path before the empty-host early return, so a mock run reports the fixture's URLs instead of 0 items. `_persist_stage` deliberately has no `shots` branch - screenshots stay files plus `screenshots.jsonl` (D17). **Disclosed conflict:** the batch expected `gowitness` to be tier-skipped in `--full` without `--include-noisy`; it is not, because `--full` sets `include_noisy = True` in the CLI and `--tools` bypasses the tier gate by design. No stage-specific gate was invented; `test_full_runs_gowitness_without_the_noisy_flag_because_full_implies_it` pins the real behaviour and D19 records the ruling question. Suite 811 -> 816. Next action: none; ask the owner only if screenshots must stay behind an explicit flag in full mode.
- Previous status: **FINAL ADAPTER PUSH, PART 2 DONE (2026-11-17): 44 OF 48 TOOLS ADAPTED.** Wave 8 shipped `dig`, `massdns`, `puredns` (dns/passive/core), `gowitness` (shots/active/opt_in) and `nikto` (vulns/active/opt_in). Resolvers are packaged (`src/reconkit/data/resolvers.txt`, 16 public resolvers, D16) with the new `--resolvers PATH` override; `puredns` passes `-b <abs massdns>` because a child process only gets the env keys the engine hands it. `nikto -h` lists `-Format json`, so the JSON path is taken (the pre-approved plain-text fallback was not needed) and every finding is `severity="info"`, `kind="nikto"`, one process per host. gowitness writes `results/<target>/<UTC stamp>/screenshots/*.png` plus a `screenshots.jsonl` manifest - **files, not DB rows** (D17, no model, no schema bump); it defaults to `jpeg`, so the adapter passes `--screenshot-format png`, and on this box it produced no file because Chromium is absent (`failed to initialize chrome context`), reported as an error string with 0 items. **`Stage.SHOTS` is in no `MODE_STAGES` row**, so no CLI path runs gowitness yet: wiring it is a mode-table change and needs a ruling; the adapter is complete and tested for a one-line wiring. `dig` was kept, not skipped as redundant: `dnspython` is the resolver with the wildcard/dangling-CNAME logic, `dig` is an independent second DNS source that raises a `DNS_ONLY` host from LOW to MEDIUM. Proofs: doctor `yes/ok` for all five; mock run `--tools pyprobe,httpx,tlsx,dig,massdns,puredns,nikto` -> `dig ok 3`, `massdns ok 3`, `puredns ok 3`, `nikto ok 2`, exit 0; the deferred **masscan sudo proof** ran under `echo kali | sudo -S` -> `masscan ok 3` (non-root control: `skipped requires root / sudo`); gowitness manifest proven with a stand-in binary (real gowitness cannot screenshot without Chrome). Suite 795 -> 811. Next action: owner ruling on wiring the `shots` stage; the adapter programme is closed (D15 dnsreaper + 3 intrusive tools remain by design).
- Previous status: **FINAL ADAPTER PUSH, PART 1 DONE (2026-11-17): SUBS STAGE CLOSED.** `urlscan` (http), `amass`, `findomain`, `chaos` and `github_subdomains` are implemented, tested and committed; every `subs` tool now has an adapter. Real testfire.net run `--tools urlscan,findomain,pyprobe` -> `urlscan ok 3` (urlscan.io search API, no key needed), `findomain ok 35`, `pyprobe ok 7 ALIVE`; mock run -> `urlscan ok 2`, `amass ok 4`, `findomain ok 9`, `chaos skipped (requires PDCP_API_KEY)`, `github_subdomains skipped (requires GITHUB_TOKEN)`, exit 0. New rule: a tool that cannot run without a key is a **selection** skip via the adapter class attribute `requires_env` (D18), never a runtime SKIPPED. Real-output traps found: `amass --version` prints only `v5.1.3` (identity probe is `amass enum -h`), amass stdout is a `Session Scope`/`FQDN:` block rather than a name list, and `github-subdomains -o` defaults to `<domain>.txt` in the CWD so the adapter always passes a workspace path. **`dnsreaper` is closed as not adaptable (D15)**: no PyPI package, no console script; `subzy` covers takeover. Suite 780 -> 795. Next action: Part 2 (dig, massdns, puredns, gowitness, nikto) + the deferred masscan sudo proof.
- Previous status: **WAVE 6 DONE (2026-11-17): PORTS STAGE CLOSED.** `nmap`, `rustscan`, `smap` and `masscan` (ports) are implemented, tested and committed; every stage except six tools now has an adapter (39). `--ports` reaches all four, but differently: `nmap` swaps `--top-ports 1000` for `-p`, `rustscan` swaps `--top` for `-p`, `masscan` gets `-p<list>` (its `DEFAULT_PORTS` fallback when the operator gave none, because it has no top-ports option), and `smap` **filters** its passive results because it cannot choose what Shodan observed. `masscan` is `needs_root`: a non-root process skips it at selection with `requires root / sudo` (recorded, not a gap, run stays exit 0) and never touches `sudo`; the adapter keeps the same guard. `rustscan` needs **no nmap** - verified with `PATH` emptied: `-g` prints `IP -> [ports]` with `No Nmap`, so the nmap dependency the brief assumed does not exist in 2.3.0 (no `--` passthrough either). `masscan` writes the **list** format (`-oL`), not JSON: `-oJ` cannot be observed without root and `sudo -n` asks for a password here. Real testfire.net run (`--tools pyprobe,nmap,rustscan,smap,masscan --ports 80,443,8080`) stored `80,443,8080` open with sources `nmap`+`rustscan`+`smap`, `HIGH`, and `Apache Tomcat/Coyote JSP engine 1.1` as the nmap version. That run exposed a real defect: `_persist_ports` threw away `service`/`version`, so the documented `-sV` confidence bump never fired - fixed (D14). Suite 758 -> 780. Next action: none; wave 7 (subs: urlscan, amass, findomain, chaos, github_subdomains) when the owner asks.
- Previous status: **FFUF DONE; WAVE 6 PORTS IN PROGRESS (2026-11-17).** `ffuf` (vulns/opt_in) is implemented, tested and committed with the inline packaged wordlist `src/reconkit/data/wordlists/common.txt` (118 paths, package data, D13) and `--ffuf-wordlist PATH` to override it; findings are `FindingRecord(kind="path", severity="info")`. Real run on testfire.net stored 12 matches (`302 /admin`, `/admin/login`, ...). Two real-run defects were fixed before commit: the URL must use the `FFUF` keyword (`FUZZ` there exits 0 with no results), and the `FHOST` roots must not end in `/` (otherwise `//admin`). **`dnsreaper` is still unadapted**: it has no PyPI package and no `setup.py`/`pyproject.toml` - it is `main.py` + `requirements.txt`, so it needs a checkout plus a script-launching adapter kind that the contract does not have; reported, not improvised. Suite 751 -> 758. Next action: Part 2, ports adapters (nmap, rustscan, smap, masscan).
- Previous status: **ADAPTER WAVE 5 PARTIAL (2026-11-17).** `nuclei` and `subzy` (vulns) are implemented, tested and committed; **`dnsreaper` and `ffuf` are blocked and not written** - dnsreaper is not installed on this box, so its real flags cannot be verified (AGENTS rule 7), and no ffuf wordlist exists anywhere in the repo or `~/.reconkit`, so an ffuf adapter would have to invent one (stop rule). Both need an owner ruling. Real runs on testfire.net: `nuclei ok 14` findings (swagger exposure, weak ciphers, missing security headers), `subzy ok 0` (no takeover); the first real runs found two output traps - nuclei prints `host` as `host:port` (PIT-53) and subzy writes `null` instead of `[]`. `FindingRecord` was reused (no new model) and its severity literal gained `unknown` (42 installed nuclei templates declare it); **findings are still not persisted** (no `findings` table, no VULNS persist branch) - they reach `--json` and the raw output file only. New shared hook `read_output(ctx)` for `--output`-only tools. Suite 742 -> 751. Next action: none until the two blockers are ruled on.
- Previous status: **D12 DONE (2026-11-17).** D12 (owner ruling): the WAF merge is deterministic by a new `waf_priority` on `ToolSpec`/`tools.yaml` (`wafw00f` 100 > `cdncheck` 80 > `whatweb` 50 > `httpx_tech` 20 > everything 0), so two WAF tools can no longer flip the stored name with completion order. **This is a schema change: 6 -> 7** (`host_status_history.waf_priority INTEGER NOT NULL DEFAULT 0`, additive). Three fresh-DB mock runs store `Cloudflare`/100 every time where the wave-4 code stored `httpx_tech`'s `cloudflare`. Suite 736 -> 742. Next action: Part 2, adapter wave 5 (nuclei, subzy, dnsreaper, ffuf).
- Previous status: **ADAPTER WAVE 4 DONE (2026-11-17).** `unfurl` (urls/passive, per `tools.yaml:158` - the brief said active; the registry won, same ruling as gau/urlfinder), `wafw00f` and `whatweb` (tech/active) and `httpx_tech` (tech/active, inherits the `httpx` command through the new `httpx_hosts()`/`httpx_fqdn()` helpers) are implemented, tested and committed. Every `tech` and `urls` tool now has an adapter. `whatweb --log-json=-` exits 1 without `--quiet` (verified on the binary), so `--quiet` is part of the command. The waf/tech merge question was answered from the code and left unchanged: `tech` is a merged list, `waf` is one string whose winner is the first tool to finish in a pass and the latest pass across runs - an open item for a ruling, since merging needs a schema change. Real: `doctor` all four `yes`/`ok`; mock run 5/5 tools (`httpx_tech ok 2`, `whatweb ok 1`, `wafw00f ok 1`, `unfurl ok 4`), DB `testfire.net tech_json=["Apache","Apache Tomcat","HTTPServer","Java"] waf=cloudflare`; adversarial PATH still rejects Python `/usr/bin/httpx` for `httpx_tech` (`wrong program`/`failed`). Suite 726 -> 736. Next action: none.
- Previous status: **ADAPTER WAVE 3 DONE (2026-11-17).** `hakrawler`, `gospider`, `subjs` (urls/active) and `urlfinder` (urls/passive, per `tools.yaml:159` - the brief said active; the registry won, same ruling as gau) are implemented, tested and committed. The first real hakrawler crawl exposed PIT-52 (a page's `javascript:` link made the strict parser fail the tool); `base.is_non_web_reference()` now skips non-HTTP links in all four parsers. Real testfire.net runs: `hakrawler ok 66`, `gospider ok 67`, `subjs ok 0` (host has no `.js`), `urlfinder ok 932`; mock run 4/4 tools, 16 unique URLs stored. Suite 712 -> 726. Next action: none.
- Previous status: **BOTH PARTS DONE (D10 mode expansion `756af8e`; D11 adapter wave 2 + tech persistence).** Wave 2 added `httprobe` (live), `webanalyze` + `cdncheck` (tech), `waybackurls` (urls/passive) and the tech-stage persistence they needed (D11: `_persist_tech` annotates the newest status row, never appends one). Suite 687 -> 691 (Part 1) -> 712 (Part 2). Real runs on testfire.net: `httprobe ok 1`, `webanalyze ok 1` with `tech_json = ["Apache Tomcat", "Java"]` stored, `cdncheck ok 0` (no CDN/WAF match, the documented shape); `waybackurls` runs `ok 0` because the archive endpoint times out from this box, so its parsing proof is `--mock`. Next action: none.
- Previous status: **MODE EXPANSION DONE (D10); ADAPTER WAVE 2 IN PROGRESS.** D10 (2026-11-17): `passive` = subs+dns+urls (passive tools only), `active` = subs+dns+live+tech+urls, `full` unchanged. Confirmed by real `--mock` runs in all three modes (gau `ok` in passive, katana skipped `tool mode not included in passive mode`; active runs tech + both urls tools; full runs all seven). Suite 687 -> 691. Next action: Part 2, adapter wave 2 (httprobe, webanalyze, cdncheck, waybackurls), one commit, stop-and-report if any adapter balloons.
- Previous status: **BATCH 2026-11-17 PARTS 1 AND 2 DONE.** Part 2 (adapter wave 1) added four adapters - `dnsx` (dns/passive), `tlsx` (live/active, liveness-only + SAN discovery), `katana` (urls/active), `gau` (urls/passive) - and fixed the live-discovery persistence bug found while scoping tlsx (PIT-49: `_persist_live_discoveries` now writes a `subdomains` row for every host a live pass discovered, not only for the hosts it was given). gau gained the Ruling C `version_regex`. Suite 672 -> 687. Open item for the owner: `urls` is not a stage of `--active`, so katana/gau only run in `--full` (the batch prompt assumed otherwise) - the mode table was left unchanged. Next action: none.
- Previous status: **BATCH 2026-11-17 PART 1 DONE (D9 completion gaps).** Part 1: `--full`/`--active` now exit 0 when a requested stage had no runnable tool, with a stderr gaps block (`⚠ full scan completed with gaps — N stage(s) ...`) and a top-level `--json` `completion` object (`complete` / `complete_with_gaps` + `gaps`); exit 5 is reserved for a failed/timed-out tool or a stage emptied by a deliberate rule, and "nothing usable at all" still exits 4. AGENTS.md item 11 (adapter pre-approval) and MASTER_PLAN D9 added. Next action: Part 2 (four adapters, one commit, stop-and-report if any adapter balloons).
- Previous status: **MODE UNIFICATION BATCH S1-S7 DONE (2026-11-17).** Scan modes are one table (`MODE_STAGES` + `MODE_TOOLS` in `engine.py`): passive = subs+dns/passive tools/core; active = subs+dns+live/passive+active/core; full = all seven stages/passive+active/core+opt_in+intrusive. `--full` is new (implies `--active` and `--include-noisy`); CLI `--active` narrows to subs+dns+live; `exploitation: true` tools (sqlmap, dalfox, crlfuzz) never auto-run in any mode. Also added: scope pre-flight warning, `--no-scope` + `scan_runs.scope_mode` (schema 6), `--only-alive`/`--only-states`/`--status-codes`, `--ports`/`--header`/`--user-agent`/`--redact-headers`, extended interactive Q&A, out-of-scope `[a/b/c/d]` prompt. Baseline before this batch: 637 passed. Next action: none.
- Previous status: **PART 12 AND PART 13 ARE COMPLETE (2026-11-16).** Part 12 closed on 2026-11-15 (12a-12k). Part 13 - the interactive scan mode, stderr progress and per-domain saved reports - is implemented, tested, self-reviewed (S1-S7) and committed, with docs written first. Phase 1 of the same session (the `docs/tool_manuals/` library) is closed in `8dc2829`.
- What Part 13 changed, in one line: a scan command with **no** `-d`/`-l` **and** a real terminal asks five questions and then runs the ordinary scan inputs; a domain file becomes the ordinary `-l` path (one full scan and one `results/<domain>/<UTC stamp>/` folder per domain, `report.txt` + `report.json`); progress now goes to stderr for every mode except `--silent`, including `--json`. Every flag-based invocation is unchanged, including no prompts and no report folders (tests `test_a_flagged_run_never_asks_a_question`, `test_a_listed_run_never_asks_a_question`, `test_a_flagged_run_writes_no_report_folder`). **Superseded 2026-11-18 (D20):** a flagged run now writes its own report folder too; the test is `test_a_flagged_run_writes_its_own_report_folder`. The no-prompt promise stands.
- All four owner tasks (2026-11-17) are implemented, tested and committed: D1 `c99eaee`, D2 `6642ee4`, D3 `6a2db4d`, the interactive-mode fix `10b3a48`, Task 4 docs with this entry. Nothing else is queued; Part 13's uncertainties stay under "Open risks".
- The verification follow-up (2026-11-17) closes the eight findings from the accepted 4-task batch (`F1`-`F8`, report section V-UNEXPECTED) in one commit: `--active` help text, the owner verification commands, five historical pacing markers, the core package docstring, two dead `pyproject` ignores, the AGENTS `config.yaml` row, two tool manuals and the D3 test counts. Documentation and help text only - no behaviour, flag, schema or test change.
- **Owner-requested behavior changes (2026-11-17):** D1 (no scope file = unrestricted active scanning) is committed (`c99eaee`), D2 (naabu is scope-mode dependent) is committed (`6642ee4`), D3 (all speed/throttle control removed) is committed with this entry, and Task 4 (the end-to-end interactive-flow section in docs/02) is the next action.
- **httpx_tech false positive FIXED (2026-11-17, MASTER_PLAN D5, V-UNEXPECTED item 1; commit `fix: httpx_tech rejects Python httpx via version_regex miss rule`).** `httpx_tech` was presence-only, so with only Python's `/usr/bin/httpx` visible doctor said `yes` / `identity: ok` where the `httpx` adapter row correctly said `wrong program`. It now carries `version_cmd: [httpx, -version]` + `version_regex: 'Current Version:\s*v?([0-9]+\.[0-9]+\.[0-9]+)'`, and `installed_version()` treats a declared regex that does not match as `None` (not installed). Re-tested both ways: normal PATH -> `version: "1.12.0"`; Python-only PATH -> `wrong program` / `identity: failed`. 638 passed. The other 12 presence-only tools stay as they are and are now documented as a known limitation (docs/10 section 3).
- **Installer removal COMPLETE (2026-11-17, MASTER_PLAN D4, owner request "user-requested removal of install/update commands").** `install`, `update`, `doctor --fix` and `src/reconkit/installer/` are deleted; `tools.yaml` `install:` blocks became inert `source:` strings; `doctor` uses `ToolSpec` through `core/toolcheck.py` and no longer imports the installer. Full evidence, every changed test and the 730 -> 635 count reconciliation are in REVIEW_LOG "Installer removal D4". Nothing else queued; next action: none.
- **Install/doc backlog batch (2026-11-17, T1-T6 + one correction; the commands named here were removed later the same day by D4).** `reconkit install rustscan` works from its real 2.3.0 release (`f638c05`); the seven banner-first tools show a real version (`e0ef81d`); smap/gospider/subjs/urlfinder show one and the five Go-flag tools are documented path rows (`cb1fcd2`); `assetfinder -h` exit code corrected (`74c9102`, `-version` exit 2 corrected in `a037014`); amass v5 note (`24f64a3`); webanalyze `-update` recorded (`583e530`). Every one confirmed against the real binaries on this box.
- **Install residue removal S1-S7 COMPLETE (2026-11-17, cleanup only; commit `chore: remove install residue; docs/10 becomes tool reference (reconkit installs nothing)`).** Stale installer test bytecode deleted (5 `.pyc`; `__pycache__` dirs 73 -> 73); `config.yaml` `tool_versions` and its `AppConfig` field and `doctor` warning are gone; docs/10 is now a 149-line tool reference (48-row table, sections 1-4) with no install command anywhere; SETUP.md keeps only the editable self-install plus the doctor pointer; README, docs/01/02/05/08 and the seven tool manuals lost their install instructions; `tools.yaml`'s `source` comment is provenance-only, values unchanged. Full evidence in REVIEW_LOG "Install residue removal S1-S7".
- **Doctor shows no version COMPLETE (2026-11-17, MASTER_PLAN D6, owner ruling; commit `feat: doctor shows installed/path/identity only; versions hidden (version_cmd kept for identity checks)`).** The table is now `Tool`, `Stage`, `Tier`, `Installed`, `Path`, `Identity`; `ToolCheck` and every `doctor --json` tool object lost the version key; the `Missing tools: N` footer now says `Scans will use the tools that are installed and skip the rest. Per-tool provenance: docs/10_TOOL_SOURCES.md.` `core.toolcheck.installed_version()`, `InstallStatus.version`, `tools.yaml`'s `version_cmd`/`version_regex` and every `source:` value are untouched, so the D5 identity check still rejects Python's `/usr/bin/httpx` (`wrong program` / `identity: failed`) while the real ProjectDiscovery copy is `yes` / `ok`. Full evidence in REVIEW_LOG "Doctor shows no version D6".
- **Next action:** none. D21 (2026-11-18) adds `scripts/install-tools.sh`: the owner asked for one script that installs every tool with apt/go and then verifies with `doctor`. The CLI still installs nothing (D4 stands for the command surface and the safety rules); the script has no catalogue of its own, reads `tools.yaml` `source:` strings, downloads nothing itself, refuses to run as root, and ends with `doctor --json` so a wrong-program binary fails. Nine release-only ProjectDiscovery entries gained `(or: go install ...)` hints, each verified with `go install -n` before being written. Verified on this box: `--check` (33 have / 2 go / 3 manual), `--only gau` exit 0, `--only dalfox --yes` installed to `~/.reconkit/bin` in 13 s with `identity ok`. Also verified for the owner's question: `waybackurls`/`urlfinder`/`unfurl` were never missing - they live in `~/.reconkit/bin` and `doctor` already showed them; a bare `command -v` missed them because that directory is on the child PATH only. Suite 827. **Update (2026-11-18):** `findomain` and `rustscan` are no longer manual - Kali packages both (`apt-cache policy`: `11.0.0-beta.2-0kali2`, `2.4.1-0kali1`), so their `source:` is now `apt:` and the script installs them with sudo. Both apt builds were checked against the flags the adapters send (`-t/-q`, `-a/-g/-n/--ulimit/--top`), findomain printed bare subdomains on a real `-t example.com -q` run, and `doctor` resolves `/usr/bin` for both with `identity ok` after the hand-installed copies were moved to `/tmp/*.hand.bak`. Final counts: 38 have, 1 manual (`dnsreaper`). Two registry tests were rewritten to the new truth. Suite 827 at the time (re-verified 2026-11-18: **824**). The nested-archive item under "Open risks" is moot for reconkit (it installs nothing since D4) and stays only as a note about rustscan 2.4.1. Four follow-up items remain from the S1-S7 entry's Findings (the 19 frozen `source:` values, nine "Install command: nothing to install" manual bullets, AGENTS.md's stale installer references, the historical rustscan transcript); the doctor footer finding is now closed by D6.
- Baseline on this checkout (`/home/kali/Desktop/reconkit`, Python 3.14.8, schema version 10) after the verification follow-up's Part 3 (D26) including the config-default follow-up: `892 passed`, `ruff check .` clean, `ruff format --check .` 92 files, `mypy src/reconkit` clean (62 source files). Immediately after Part 3 (`891 passed`), `ruff check .` clean, `ruff format --check .` 92 files, `mypy src/reconkit` clean (62 source files). After the same follow-up's Part 1 (D24): `888 passed`, `ruff check .` clean, `ruff format --check .` 92 files, `mypy src/reconkit` clean (62 source files). After the same follow-up's Part 2 (D25): `883 passed`, `ruff check .` clean, `ruff format --check .` 92 files, `mypy src/reconkit` clean (62 source files). After Part 4 of the 2026-11-18 batch: `882 passed`, `ruff check .` clean, `ruff format --check .` 92 files, `mypy src/reconkit` clean (62 source files). After Part 3 (schema 9): `869 passed`, `ruff check .` clean, `ruff format --check .` 92 files, `mypy src/reconkit` clean (62 source files). After Part 2 (schema 8): `855 passed`, `ruff check .` clean, `ruff format --check .` 92 files, `mypy src/reconkit` clean (62 source files). After Part 1: `840 passed`, `ruff check .` clean, `ruff format --check .` 91 files, `mypy src/reconkit` clean (62 source files). Before the batch (schema version 7) after D20 (reports/spinner/amass/passive timeouts/waybackurls): **`824 passed`** (re-measured 2026-11-18; the earlier `827` here was stale by three), `ruff check .` clean, `ruff format --check .` 91 files, `mypy src/reconkit` clean (62 source files). After D19 (shots wiring): `816 passed`, `ruff check .` clean, `ruff format --check .` 90 files, `mypy src/reconkit` clean (62 source files). Before this batch: `811` after wave 8; `795` after wave 7. Earlier: `780` after wave 6. Before the ports adapters: `758` after ffuf. Earlier: `751` after wave 5, `742` after D12, `736` after wave 4, `726` after wave 3, `712` after wave 2, `691` after D10, `687` after wave 1, `672` after D9, `637` after D6. The count is unchanged from S1-S7 because one doctor test was deleted and one added; pre-S1 `638`; pre-D5 `635`; pre-D4 `730 passed`, 67 files, 35 source files.
- **Pushed (2026-11-18):** local `main` and `reconkit/main` both point at `a49e4b5` (`docs: finish removing the last platform words and the /mnt/c example`); the owner asked for the work to reach GitHub after the live runs were clean. The old "nothing is pushed / `reconkit/main` is still `5fd1d9a`" line was stale. Push only when the owner asks (`git push reconkit main`).
- Already decided, do not reopen: no scope-bypass flag; consensus lives in `engine.py`; adapters never import `store`/`scope`/`ui`/`cli`; `subjack` replaced by `subzy` + nuclei takeover templates; reconkit installs nothing, so there is no installer platform rule (D4, 2026-11-17); free mode is default, keys only from `.env`; the ports ceiling is permanent (12i).
- Do NOT: new dependencies; new modules/files/CLI commands not in docs/02-03; `assert` in `src/`; new lint/type suppressions; `shell=True`; the whole environment to a child; adapters importing store/scope/ui/cli; consensus outside `engine.py`; pushing.
- Read first: `AGENTS.md`, this block, the last 3 per-part entries in `REVIEW_LOG` (they are above the archive section), and the current part in `docs/MASTER_PLAN.md`.

## Environment

- **Canonical checkout: Kali, `/home/kali/Desktop/reconkit`** (native Linux, the only supported platform). There is no other working copy: the old second checkout was abandoned by the owner on 2026-11-18, when support for non-Linux platforms was removed from the docs. Do not create a second checkout.
- Venv: `.venv` (`python3 -m venv`, Python 3.14.8), activate with `source .venv/bin/activate`.
- Gate (run all four, report PASS/FAIL with `if cmd; then ... else ... fi`, never `echo $?`; no pipe before the `if`, or use `set -o pipefail`):

  ```bash
  pytest -q
  ruff check .
  ruff format --check .
  mypy src/reconkit
  ```

- Pre-commit hook (`.githooks/pre-commit`) runs those checks and requires `docs/PROGRESS.md` when `src/` or `tests/` change; `git config core.hooksPath .githooks` comes from `scripts/bootstrap.sh`. There is no wrapper script for the four checks; run them directly.
- `.gitattributes` forces LF for `*.py`, `*.md`, `*.yaml`, `*.toml`, `*.sh`, `.githooks/*`; some docs are CRLF on disk and git warns on checkout - that is pre-existing, not an edit.
- Commits are authored by `Anshul <anshulc4444@gmail.com>`; no attribution trailers are added, by anyone or any tool.

## Task status

| Part | Commits | State |
|---|---|---|
| a | `f4d81e2` | done - skeleton, pyproject, `config.yaml`, docs |
| b | `0e39f18`, `9423eaa` | done - `errors`, `models`, `config`, `core/runner` |
| c | `45b0ba8` | done - `core/scope` gate |
| d | `0a3010b` | done - `core/pacing.py` (removed 2026-11-17, MASTER_PLAN D3; the commit stays in history) |
| e | `1ba2fd8` | done - `core/store.py`, `redact()`, diff queries |
| f | `89ba34f`, `80ddd93`, `ee06075` | done - all phase-2 adapters |
| g | `36cd3a4` (+ Part 7) | done - wildcard, workspace, engine, confidence, resume, exit codes |
| h | Part 8 commit | done - `ui.py` + `cli.py` |
| i | `9c4319b`, `5df7e98`, `66b117c` | done - `doctor.py` + `installer/` (`installer/` deleted 2026-11-17, MASTER_PLAN D4; the commits stay in history) |
| j / 11 | `cc70b15` ... close-out | done - audit, fixes, report delivered |
| 12 | one commit per item | 12a, 12b, 12c, 12d, 12e, 12f, 12g, 12h, 12i, 12j, 12k done - Part 12 complete |
| 13 | one commit | interactive scan mode, stderr progress, per-domain saved reports - done 2026-11-16 |

There is no `core/consensus.py`: consensus lives in `engine.py`. Order and module names follow docs/01 section 8 and docs/03 section 5. Per-part hashes and full evidence are in `REVIEW_LOG`; the old table is in its archive.

## Deviations and assumptions

Standing ones only; the per-part history (Part 5 - Part 10f, the bug-fix session, the `diff` two-miss rule) is in the `REVIEW_LOG` archive.

- **D22 (2026-11-18): www/non-www deduplication is metadata only.** Schema 8 -> 9 adds `host_status_history.duplicate_of` and `.www_note` (both nullable, no default) and `Store.set_host_duplicate()` updates the host's **newest** status row - it never appends a row and never writes `state`, `status_code`, `confidence` or `checked_at`, so host-state definitions, the confidence formula, `diff`, `status` and every count query are unchanged (the frozen boundary). **Disclosed deviation:** the batch said 7 -> 8, but 8 was already spent on Part 1's `tool_runs` rebuild, so the dedup columns are schema 9. **Disclosed narrowing:** the batch's "if IPs differ -> different server" is applied only when both IP sets are known and disjoint; with no DNS evidence for a name the pass says nothing. The Notes column is added only when a row has a note (an ordinary table keeps six columns) and the unique count appears in the summary line only when a duplicate exists, so no existing output changed shape.
- **D23 (2026-11-18): the url probe stores an answer, never a guess.** Schema 9 -> 10 adds `urls.status_code` (nullable, no default) and `--skip-url-probe` removes the stage. Values: the HTTP status, `-1` for "no answer" (refused, timeout, DNS failure), `-2` for "answered with a certificate that does not verify". **Disclosed deviation:** the batch assumed schema 8; 8 and 9 were already spent by Parts 1 and 3. **Disclosed addition:** `-2` is not in the brief - the first real testfire.net run stored `-1` for every URL of a live site whose certificate is issued for `www.testfire.net`, and reporting that as "dead" would be false; verification stays on, so the fact gets its own value. `NULL` keeps its single meaning ("not probed yet"), a stored answer is never retried, `--mock` sends nothing, and host state, confidence, `diff` and every count query are untouched.
- **D25 (2026-11-18): www dedup needs a known, equal status.** `_dedupe_www_variants` now requires both `status_code` values to be present and equal before the shared-IP branch can mark `www.X` as `duplicate_of X`. `NULL` is "no status observed", not a shared status, so a pair with no code on either side is left alone (no `duplicate_of`, no note). No schema change, no state, confidence or count change. Found by verification (PIT-61), not by a scan.
- **D26 (2026-11-18): `url_probe` respects the stage deadline.** `timeouts.url_probe: 600` is a new `Timeouts` field, and `--phase-timeout` (or that value) wraps `_run_url_probe` in `asyncio.wait_for`. A timed-out pass keeps every committed batch, leaves the rest `NULL`, is recorded `partial`, appends a `URL_PROBE` `CompletionGap` (`--json` `complete_with_gaps`) and does not turn the run into a failure. Same commit repairs D24's dedented per-batch commit (a multi-batch pass would have written only its last batch).
- **D24 (2026-11-18): the url probe keeps Python httpx; one client per pass, 100 threads, `--reprobe-urls`.** PD httpx was measured and rejected (no `-insecure`, TLS verification off by default so cert-invalid URLs read 200, no JSON line for failures, random UA by default, and 9.19 s vs 3.44 s on 158 URLs). `threads` 50 -> 100 and a single `AsyncClient` per pass cut the same 158-URL pass from 4.59 s to 3.44 s with identical answers including 58 `-2`. `--reprobe-urls` probes every stored URL, not only `NULL` ones, overwriting `status_code` in place; with `--skip-url-probe` it warns and continues.
- **Linux only (2026-11-18, owner decision).** Kali or Ubuntu, native, is the only supported and tested platform. The docs, code, tests and scripts no longer carry any other platform's branches, paths or claims, and the four checks are run directly.

- `types-PyYAML` is a dev dependency for strict mypy. Enums use `StrEnum` (ruff UP042) instead of the docs' `(str, Enum)`; same values.
- `--delay` applied to both passive and active `tool_delay` (not `host_delay`); the flag and the pacer were removed on 2026-11-17 (MASTER_PLAN D3), so this line is history.
- Ruff excludes `docs/`; per-file ignores live in `pyproject.toml` with reasons (`tests/**` S101, `tests/fakebin/**` S603, `tests/test_runner.py` S603, `tests/test_binary_adapters.py` S603, `src/reconkit/core/runner.py` S603). The two scoped S311 ignores (the pacer's jitter RNG and the seeded test RNG) were removed with the module on 2026-11-17 (MASTER_PLAN D3).
- Exit codes: Scope 3, ToolNotInstalled 4, ToolFailed/Timeout/Install 5, Parse 1, Config 2, usage 2, "every requested tool failed to install" 6 (retired). 12k made every zero-tool stage exit 5; **D9 (2026-11-17) narrowed that**: a zero-tool stage whose only skips are `no adapter yet (phase N)` / `not installed` is a completion gap and exits 0, while a failed/timed-out tool or a stage emptied by tier/tool-mode/exploitation/scope rules still exits 5. If every requested stage is empty and nothing ran, the run still exits 4.
- `scope.yaml` defaults: missing `expires` = never expires; missing `max_speed` = `slow`. `check_target` reports `out_of_scope` before expiry, and raises `ValueError` on an invalid target.
- `.env` is the only key source (`Engine.open`); the CLI has no `os.environ`/`getenv`, so shell-exported key variables are ignored.
- 12a: `dns` raw files go to `meta/` because the workspace keeps exactly six directories; `Workspace.write` caps every caller at `runner.MAX_OUTPUT_BYTES`.
- 12b: `subdomains.provenance` defaults to `dns` and the `subs` upgrade is sticky; NEW is first-discovery-sighting, not `first_seen_run`. `status --json` does not expose `provenance`.
- 12c: `duration_s` is adapter-reported; `0.0` means "not measured"; `_run_one` fills its own clock only then.
- 12d: the task text asked for a plain connect failure to store "a different, distinguishable reason", but `MASTER_PLAN.md` 12d and docs/09 say it stores none (no record at all); the documents won. The row rule covers the kept-previous-state case. 12e has since closed the other half: a first-run inconclusive `live` pass that got a record now writes its own `UNKNOWN` row, so the reason lands there too.
- 12f: `cli.py` imports only `configure_redaction` and `redact` from `core.store` (docs/03 section 9); six typed `render_error(str(exc))` sites stay outside its ruled scope.
- 12g: `STALE_AFTER_S = 900` and 12d's `DETAIL_MAX_CHARS = 200` are module constants, not config keys, because the rulings allowed no new config.
- 12k: `scan_runs.status` for an empty stage still reads `completed`; only the warning and the exit code changed.
- **D16 (2026-11-17): bundled resolvers + `--resolvers`.** `massdns` and `puredns` need a resolver file and the build downloads nothing (rule 4), so `src/reconkit/data/resolvers.txt` ships 16 public resolvers as package data (`pyproject` `data/*.txt`) and `--resolvers PATH` replaces it; a missing file is a failed result, never a silent fallback to the system resolver. `ScanOptions.resolvers`/`RunContext.resolvers` are the plumbing.
- **D17 (2026-11-17): screenshots are per-run files.** gowitness writes `results/<target>/<UTC stamp>/screenshots/*.png` and a `screenshots.jsonl` manifest; no table, no `ScreenshotRecord`, no schema bump, and `status`/`diff` do not show them (docs/04 section 3.1). `RunContext.results_dir` (the configured `results_dir`) is new plumbing so the adapter never reads `config.yaml` itself. Disclosure: a real screenshot needs a Chrome binary the adapter never guesses, so on this box the honest result is 0 files with an error string. (The stage was unreachable from the CLI when D17 was written; D19 later wired it into `full`.)
- **D19 (2026-11-17): the shots stage is wired into full mode.** `Stage.SHOTS` is in `STAGE_ORDER` (between `urls` and `vulns`) and so in `MODE_STAGES["full"]`; `passive`/`active` do not request it, and no `shots` command was added. `gowitness` mock runs now go through the base fixture path before the empty-host return. No persistence branch: files + `screenshots.jsonl` only (D17). Disclosed: `--full` implies `--include-noisy` and `--tools` bypasses the tier gate, so a "tier-skipped in full" proof cannot exist without a new rule; none was added.
- **Wave 3 note (2026-11-17):** the brief said all four url tools are `mode: active`, but `tools.yaml:159` has `urlfinder` as `mode: passive`. The registry won (gau precedent, wave 1 Ruling B), so urlfinder also runs in a passive scan. The active url tools receive bare hostnames from the engine, so `hakrawler`/`gospider`/`subjs` add the scheme themselves (`https://<host>/` then `http://<host>/`, the pyprobe order) and `-insecure` is never passed. A page's `javascript:`/`mailto:` links are skipped, not parse failures (PIT-52).
- **D11 (2026-11-17): tech persistence + stdin input.** Forced by adapter wave 2. The `tech` stage had no persistence branch (PIT-51), so `_persist_tech` now merges `tech`/`waf` into the host's newest `host_status_history` row via `Store.update_host_extras` and never appends a state row or changes `state`. `run_exec(..., stdin_text=...)` plus the adapter hook `stdin_text(ctx)` give httprobe/waybackurls their host list without a shell (PIT-50). Report items: the owner's `--tools webanalyze|cdncheck` proof commands fail on empty input (tech is fed the alive hosts, so a `live` pass must be in the same run), and real `waybackurls` returns 0 URLs here because the archive CDX endpoint times out - its parsing proof is `--mock`.
- **D10 (2026-11-17): mode table expansion.** `passive` = subs+dns+urls (passive tools only), `active` = subs+dns+live+tech+urls, `full` = all seven; `MODE_TOOLS` unchanged. Two disclosure items: (a) the owner's literal `active` order put `urls` before `live`; every tuple is `STAGE_ORDER` order instead, so the help text lists stages in the order they run (urls after live, tech before urls). (b) the expansion exposed a real input gap - the urls stage is fed the alive hosts, so in a passive run it would have had none; a `mode: passive` urls tool now receives `[target, *discovered]` via the `tool_hosts` override, while an active urls tool keeps the alive hosts and is skipped in passive mode by the tool-mode rule. `--active` is still refused on `subs`/`dns`/`passive`/`lite` (the guard is now a command list, not a stage-subset test).
- 2026-11-17 (Part 2): the four wave-1 adapters are `kind: binary`, `tier: core`, `needs_home = True`; their fixtures live flat in `tests/fixtures/adapters/<tool>.synthetic.*` (owner-specified path) and `base._read_fixture` gained one fallback so `--mock` finds them. Registration is `adapters/__init__.py` `ADAPTERS` - there is no other adapter map. A live pass now persists the subdomains it discovers (`provenance='subs'`), so a `live` row can be a discovery result (docs/04 section 5).
- 12h: the SQLite persistence block stays on the event loop by ruling; docs/03 section 11 states the reason (single writer, `check_same_thread` on the main-thread connection) and the bound (one transaction per stage). Both `scope.yaml` reads - the active gate and the `ip_allowed` predicate - moved to `to_thread`, not just the gate.
- 12j: `version_regex` is a `tools.yaml` field next to `version_cmd` (not a config key); it is compiled and rejected at registry load, and the first capture group is the version. **Changed 2026-11-17 (D5):** the first-line fallback now applies only when the field is *absent*; a declared pattern that does not match means "not installed" (V-UNEXPECTED item 1).
- **2026-11-16 (Phase 1, docs only):** a new documentation tree
  `docs/tool_manuals/` (8 files: `README.md` plus one per stage) was created
  outside `docs/02`/`docs/03`. This is the documentation-only exception the
  owner granted for the tool-manual library. `docs/09` section 9 gained a
  pointer to it; no `src/` file changed in that phase.
- **2026-11-16 (Phase 1):** the whole `vulns` stage (nuclei, subzy, dnsreaper,
  nikto, ffuf, dalfox, crlfuzz, sqlmap) is deferred as "recon-only scope for now,
  revisit later": no manual, no install, no test. Reading the task's "vulnerability
  scanning tools" as the stage `tools.yaml` itself calls "Takeover and exposure/
  misconfiguration checks" is an interpretation the owner may narrow.
- **2026-11-16 (Phase 1; the command named here was removed 2026-11-17 by
  D4):** `reconkit install gowitness` was run (go_install, no sudo) so the tool
  could be documented; `rustscan` was attempted and failed on the registry
  placeholder asset name, which is flagged in the manuals README instead of
  being patched. No sudo command was run in either phase.
- **2026-11-16 (Part 13 / Phase 2), new config key:** `results_dir: results` in
  `config.yaml` and `AppConfig.results_dir` (with a default, so a config file
  written before Part 13 still loads). Store directory for the saved reports;
  `results/` is in `.gitignore`.
- **2026-11-16 (Part 13), no new module:** the report writer (`REPORT_FIELDS`,
  `report_fields`, `field_value`, `format_field_value`, `report_directory`,
  `report_document`, `report_text`, `write_field_report`) lives in the existing
  `ui.py`, and the five prompts plus `_MODE_STAGES`/`_InteractivePlan` live in the
  existing `cli.py`, instead of adding `report.py`/`interactive.py` that docs/02-03
  do not name. Both are documented in docs/02 section 2b/5 and docs/03.
- **2026-11-16 (Part 13), behaviour change:** `--json` now writes progress to
  stderr (docs/02 `### Progress` changed before the code). Only `--silent`
  suppresses it. stdout stays exactly one JSON document.
- **2026-11-16 (Part 13), three existing tests changed** (none removed), each
  because of that one documented change: `test_mock_json_is_one_valid_document_and_exit_zero`
  and `test_mock_scope_denial_returns_three` in `tests/test_cli.py` now assert
  `"subs: running" in result.stderr` instead of `result.stderr == ""`;
  `tests/test_ui.py::test_progress_is_suppressed_for_silent_and_json_modes` was
  renamed `test_progress_is_suppressed_only_in_silent_mode` and asserts the new
  message shape (`"subs: running 3 tool(s)"`, `"(4s)"`). All other assertions in
  those tests are unchanged.
- **2026-11-16 (Part 13), stored fields with defaults:** `HostSnapshot` gained
  `source_count`/`ips`/`title`/`location`/`tech` (defaulted) and
  `Store.host_rows()` now LEFT JOINs the latest `host_status_history` row once
  instead of running two correlated subqueries. The host table and the `--json`
  host shape are unchanged; the new values are only used by the report.
- **2026-11-17 (owner-requested deviation D1), no scope file means
  unrestricted active scanning.** With no scope file at the resolved path
  (default `./scope.yaml`, `--scope` overrides), `--active` active/full runs scan
  the operator's `-d`/`-l` targets and everything discovered under them with no
  auto-derived scope object, no implicit restriction and no exit 3. A scope file
  that IS present keeps the unchanged gate and is only ever read. Docs 02/03/05
  and `MASTER_PLAN.md` "Dated deviations" record it. Changed test:
  `test_mock_scope_denial_returns_three` became
  `test_mock_run_without_a_scope_file_is_unrestricted` (it asserted the removed
  exit 3), and `test_mock_scope_file_denial_returns_three` keeps the exit-3
  coverage against a real file. New: `test_no_scope_file_runs_active_stages_unrestricted`,
  `test_a_present_scope_file_is_enforced_exactly_as_before`,
  `test_no_scope_file_never_loads_or_derives_a_scope_object`.
- **2026-11-17 (owner-requested Task 4), the interactive flow is documented end
  to end.** docs/02 section 2b gained "The flow end to end (2026-11-17)": launch,
  the five questions with their exact prompt text, the plan echo, the per-target
  run and report folder, the no-scope-file vs scope-file-present branch (naabu's
  resolve-and-verify path), and the statement that no speed option exists. Docs
  only; no code or test changed.
- **2026-11-17 (D1 follow-up), interactive mode never assumes a scan mode.**
  The `Scan mode: passive, active or full` question had typer's `default="passive"`
  and turned a bad word into exit 2; the owner's wording is "must not proceed
  until a valid choice is made, no silent default, no assuming passive". It now
  prints `invalid scan mode '...'` and asks again until one of the three words is
  typed, and end of input at that question cancels with exit 2 before any engine
  run. docs/02 section 2b point 3 states it. Changed test: the
  `("example.com\nn\nsideways\nall\nn\n", "invalid scan mode")` case was removed
  from the `test_a_bad_answer_is_a_usage_error` parametrization and replaced by
  `test_the_mode_is_asked_until_a_valid_answer_is_typed` (three prompt renders,
  the run starts on the third answer) and `test_no_mode_answer_means_no_scan`
  (EOF at the mode question, engine never called); the other three parametrized
  cases are unchanged.
- **2026-11-17 (owner-requested deviation D2), naabu is scope-mode dependent.**
  No scope file: naabu is an ordinary active tool (no pre-resolution gate, no
  IP-only restriction, no skip). Scope file present: the engine resolves each
  in-scope target itself (`adapters.pyscan.default_resolve`, injectable), checks
  every address against `in_scope_cidrs` via the same `ip_allowed` predicate
  `pyscan` uses, and passes naabu only verified IPs through `-host` - never a
  bare domain. Resolution failure / out-of-scope target is omitted; if nothing
  verifies, naabu is a recorded `blocked:` skip. Passive: never runs. 11c-G-7's
  permanent block is superseded (MASTER_PLAN D2). Real `naabu -h` confirms
  `-host string[]  hosts to scan ports for (comma-separated)`; a real
  `127.0.0.1` scan confirms IP input. Changed tests: `test_naabu_stays_blocked_because_it_resolves_inside_the_binary`
  -> `test_naabu_is_selectable_in_active_mode` (asserted the removed block);
  `test_aggressive_yes_adds_the_ports_stages` (assertion text follows the
  reworded notice); `test_aggressive_no_leaves_the_plan_alone` (now supplies a
  present scope file instead of relying on the checkout's git-ignored one);
  `test_no_scope_file_never_lets_an_active_tool_run` ->
  `test_a_present_scope_file_blocks_an_out_of_scope_interactive_target` (same
  reason). New: the six `test_*_naabu*`/`test_scope_file_*` cases in
  `tests/test_engine.py`, `test_naabu_accepts_verified_ip_inputs`.
- **2026-11-17 (owner-requested deviation D3), all speed/throttle control is
  removed.** `--speed`, `--delay`, the `fast` typed confirmation, the `speeds`
  block and `default_speed` in `config.yaml`, `core/pacing.py` (pacer, rate
  limiter, shuffle, rate-flag table) and `tools.yaml`/registry `rate_flag` are
  gone; `RunContext` carries no `pacer`/`limiter`/`speed`; every stage starts
  its tools together under `asyncio.gather` with no sleep or semaphore; schema
  5 drops `scan_runs.speed`. A `scope.yaml` `max_speed` is still accepted so a
  real scope file loads, and is ignored (there is no speed left to cap). Docs
  02/03/05/06/07/08/09, README, SETUP and AGENTS rule 3 were updated; MASTER_PLAN
  D3 records the decision. Tests removed (measured on the collected node ids: 32 test functions deleted
  and 4 renamed, so 44 parametrized node ids disappeared and 12 appeared - suite
  745 -> 713 passed; 17 of the deleted ones were the whole of
  `tests/test_pacing.py`, which tested the deleted module, so its file went with
  it; the interactive-mode fix below then removed one parametrized case and
  added two tests, 713 -> 714): `test_slow_delays_and_parallel_limits`,
  `test_normal_values`, `test_fast_never_sleeps`, `test_first_tool_and_reset`,
  `test_shuffle_is_deterministic_and_a_permutation`, `test_fast_preserves_order`,
  `test_next_pause_range`, `test_tool_rate_args_slow_passive_vs_active`,
  `test_tool_rate_args_normal`, `test_tool_rate_args_fast`,
  `test_tool_rate_args_nmap_and_masscan_use_active_values`,
  `test_tool_rate_args_unknown`, `test_delay_override_applies`,
  `test_rate_limiter_spacing`, `test_rate_limiter_rejects_bad_rate`,
  `test_before_host_zero_skips_sleep`, `test_mode_literal_accepts_strings`
  (all test_pacing.py; the behaviour and the module no longer exist), plus
  `test_rate_limiter_is_used_before_the_request` (test_adapters.py; asserted the
  limiter call inside the HTTP adapter), `test_dnspython_awaits_limiter_per_query`,
  `test_pyprobe_awaits_limiter`,
  `test_pyprobe_waits_between_hosts_when_dispatch_is_sequential`,
  `test_pyscan_awaits_limiter_per_query_and_connection`,
  `test_pyscan_respects_the_pacer_parallel_limit`,
  `test_pyscan_uses_pacer_order_for_ports`,
  `test_pyscan_waits_between_hosts_before_dispatching_the_next`
  (test_python_adapters.py; each asserted a pacer/limiter call that no longer
  exists in the adapter), `test_delay_override_applies_to_active_and_passive`,
  `test_delay_range_in_file_is_rejected`, `test_invalid_delay_override`,
  `test_invalid_speed_name`, `test_speed_override` (test_config.py; the settings
  themselves were deleted), `test_max_speed_cap` and `test_unknown_speed`
  (test_scope.py; `require_active` no longer takes or checks a speed). Tests
  changed and renamed: `test_slow_mode_runs_one_tool_at_a_time` ->
  `test_tools_start_together_without_a_pace_limit` (asserted the slow parallel
  limit of 1; now asserts both tools are inside `run()` at the same time),
  `test_fast_active_requires_typed_confirmation` ->
  `test_speed_and_delay_flags_are_gone` (asserted the removed prompt; now
  asserts both flags exit 2), `test_subfinder_command_and_rate_flag` ->
  `test_subfinder_command_has_no_rate_flag` (same parsed args minus `-rl`),
  `test_rate_flags_come_from_tools_yaml` -> `test_no_rate_flag_survives_in_tools_yaml`
  (asserts the field and the YAML key are absent), and the `-rl`/`-rate`/`-T`
  expectations in `test_binary_adapters.py` were dropped from the command
  assertions. New: `test_a_speeds_block_is_rejected`,
  `test_config_has_no_speed_fields`, `test_speed_and_delay_arguments_no_longer_exist`
  (test_config.py), `test_pyscan_probes_its_ports_without_an_artificial_limit`
  (test_python_adapters.py), `test_v4_database_migrates_by_removing_the_speed_column`,
  `test_create_scan_run_writes_no_speed_column` (test_store.py),
  `test_max_speed_is_accepted_and_ignored` (test_scope.py), and the three v1/v2/v3
  migration fixtures gained the `scan_runs` table because schema 5 alters it.
- **2026-11-16 (Part 13), a multi-domain file does not use a tool's own list
  flag:** the interactive file path reuses `-l` (one full scan per domain), even
  though `subfinder -dL`, `dnsx -l`, `httpx -l`, `tlsx -l`, `naabu -list`,
  `nmap -iL` etc. exist, because one report folder per domain requires results
  that are attributable to one domain. Recorded so a later part does not flip it
  by accident.
- **2026-11-17 (verification follow-up F1), the `--active` help text states the
  real rule.** The two `--active` options in `cli.py` (the shared scan command
  and the root callback) said `Allow active stages inside scope.`, which stopped
  being true with D1. They now share one module constant `_ACTIVE_HELP`:
  `Allow active stages. A scope.yaml, when present, is enforced; with no scope
  file, active scanning is unrestricted.` docs/02 section 3 quotes the same
  words, and section 2's sentence now says only that, instead of claiming the
  scope question says it too. No test asserted the old string (`grep -rn "inside
  scope" tests/` -> no match), so no test changed.
- **2026-11-17 (verification follow-up F2), the owner verification commands
  match the current CLI.** Both `reconkit run` examples in "Owner verification
  commands" lost `--speed slow` (the flag exits 2 now), and the naabu
  expectation is the D2 rule - hostnames with no scope file, verified IPs with a
  scope file, `blocked: no in-scope IP for any target` when nothing verifies -
  instead of the superseded 11c-G-7 skip.
- **2026-11-17 (verification follow-up F3), five pacing-era lines are marked
  historical, not deleted.** In this file: the task-table row d (`core/pacing.py`),
  the standing `--delay` line, the S311-ignore clause, the Part 13 open risk that
  cites `--speed fast`, and the "Where things live" map entry for
  `core/pacing.py`. Each now carries `removed 2026-11-17, MASTER_PLAN D3` so the
  audit trail stays readable.
- **2026-11-17 (verification follow-up F4), the core package docstring no
  longer lists `pacing`.** `src/reconkit/core/__init__.py` now reads `Core
  services: runner, scope, store, workspace, wildcard.`
- **2026-11-17 (verification follow-up F5), the two dead `pyproject.toml`
  per-file ignores are gone.** `src/reconkit/core/pacing.py` and
  `tests/test_pacing.py` no longer exist, so their scoped S311 entries were
  removed; no ignore was added or widened.
- **2026-11-17 (verification follow-up F6), the AGENTS source-of-truth row.**
  `config.yaml` is now listed as `timeouts, thresholds`; the `speeds` block it
  named was deleted with D3.
- **2026-11-17 (verification follow-up F7), three tool-manual references
  describe current behaviour.** The two F7 named were `docs/tool_manuals/urls.md`
  (now: `-rl` was the registry's `rate_flag` until 2026-11-17 and reconkit no
  longer passes it) and `docs/tool_manuals/ports.md`'s naabu paragraph (now: the
  D2 scope-mode-dependent rule and its `blocked:` reason, replacing "never runs
  this tool / 11c-G-7 permanently"). The manual sweep found a third of the same
  class that F7 did not name, `docs/tool_manuals/ports.md:418` in the nmap notes,
  which still described `rate_flag: -T` as current; the owner approved adding it
  to the same commit, so it now says the field was removed on 2026-11-17 and no
  adapter passes `-T` any more. `docs/tool_manuals/urls.md:484` is hakrawler's
  own `--delay` flag help, not a reconkit claim, and was left alone.
- **2026-11-17 (install backlog T1), `rustscan` installs from its real release.**
  The placeholder `asset_pattern: "verify-at-implementation"` is gone. The
  registry now names `repo: bee-san/RustScan`, `asset_pattern:
  "rustscan-{version}-x86_64-linux.zip"` and `verify_checksums: false`, and the
  version pin `2.3.0` lives in `config.yaml` `tool_versions` because
  `load_plans(versions=...)` is the only place the registry reads a pin from (a
  `version:` key inside `install:` is ignored - chosen the working way, not the
  literal one). Why 2.3.0: 2.4.1 publishes `x86_64-linux-rustscan.tar.gz.zip`, a
  nested archive the single-layer extractor cannot read, its `x86_64`/`aarch64`
  names do not match `{arch}` (`amd64`/`arm64`), and no recent release publishes
  checksums. Clean version in doctor needs a `version_regex`, because the first
  line is `rustscan 2.3.0` and the table cell truncates it: regex
  `^rustscan (\d+\.\d+\.\d+)$` -> `2.3.0`. Changed tests: (1)
  `tests/test_installer_github_release.py::test_rustscan_placeholder_cannot_resolve`
  -> `test_rustscan_pinned_plan_resolves_its_real_asset`; old: asserted
  `asset_pattern == "verify-at-implementation"` and that resolution fails; new:
  asserts the real repo, pattern, `verify_checksums is False`, the pinned
  `releases/tags/2.3.0` request and the resolved asset name; reason: the
  placeholder no longer exists. (2)
  `tests/test_config.py::test_unknown_top_level_key_is_rejected`: old built its
  fixture with `.replace("tool_versions: {}", ...)`; new appends the unknown key
  to the real file; reason: the literal `{}` is gone (rustscan pin), so the old
  test silently stopped injecting anything and passed nothing through the
  schema check - the append form tests the same thing without coupling to one
  line's spelling.
- **2026-11-17 (install backlog T2), seven tools report a real version.**
  `chaos`, `dnsx`, `httpx`, `tlsx`, `naabu`, `cdncheck` share
  `version_regex: 'Current [Vv]ersion: (v?\d+\.\d+\.\d+)'`; `wafw00f` uses
  `'WAFW00F you have is[^\n]*?(v?\d+\.\d+\.\d+)'` because its value is
  ANSI-wrapped. **Pre-check result:** no doctor or `installed_version()` change
  was needed - it reads `stdout or stderr`, and the real probes showed the PD
  six write the banner to stderr (stdout empty) while `wafw00f` writes to
  stdout, so the capture was already receiving the text; only extraction from
  the first line was wrong. Values now shown: `0.5.2`, `1.3.1`, `v1.12.0`,
  `v1.4.0`, `2.7.0`, `v1.4.0`, `v2.4.2`. No existing test asserted the old
  first-line behaviour for these tools; new test
  `tests/test_installer_registry.py::test_the_seven_version_patterns_extract_their_real_banner`
  (7 parametrized cases) pins each real banner -> expected version, and a
  mutation (dropping the ANSI tolerance from the wafw00f pattern) makes it fail.
- **2026-11-17 (install backlog T3), four tools report a version and five are
  documented as path rows.** `smap` (`-h`, stdout, `Smap 1.0.0-beta`),
  `gospider` (`--version`, stdout, `Version: v1.1.6`), `subjs` (`-version`,
  stdout, `subjs version: 1.0.1`) and `urlfinder` (`-version`, **stderr**,
  `[INF] Current Version: v0.0.3`) now carry `version_cmd` + `version_regex`.
  Their patterns are unanchored on purpose: smap and gospider print a multi-line
  body after the version, so the first draft's `^...$` patterns silently failed
  and doctor fell back to the first line (`Smap`, `Version:`) - caught before
  the commit and re-verified. `github_subdomains`, `webanalyze`, `waybackurls`,
  `unfurl` and `httprobe` genuinely have no version output (`-version` ->
  `flag provided but not defined: -version`), so they carry no probe and
  doctor's Version column shows the resolved path **by design** (docs/10).
  `httprobe`'s old `version_cmd: [httprobe, -h]` was removed - it put
  `Usage of ***/httprobe:` in the Version column, which is worse than the
  documented path. New tests:
  `test_the_four_probed_tools_extract_their_real_output` (4 cases) and
  `test_tools_without_a_version_flag_have_no_probe` (5 cases); no existing test
  changed.
- **2026-11-17 (install backlog T4), `assetfinder -h` exits 0, not 2.**
  docs/09's assetfinder row claimed "exits 2" from reading Go `flag` source and
  said the binary was not installed. Measured here:
  `assetfinder -h` writes `Usage of assetfinder:` + `-subs-only` to **stderr**,
  stdout is 0 bytes, exit **0** (the subs manual already said exit 0, so the two
  docs disagreed and the manual was right). The row now states the measured
  behaviour and that the identity probe has been exercised on the real binary
  (`reconkit doctor --json` -> `'identity': 'ok'`). Note `-h` exits 0 but
  `-version` exits **2**: my first reading said 0 and was a pipe artifact
  (`... | head; echo $?` reports `head`), corrected before the batch report.
  The five Go-flag tools in T3 (`github_subdomains`, `webanalyze`,
  `waybackurls`, `unfurl`, `httprobe`) measured `-version` -> exit **2**, which
  is what docs/10 says. Docs-only change: the
  adapter and its test already expected exit 0
  (`tests/test_binary_adapters.py::test_assetfinder_usage_identity`,
  `returncode=0`), so no code or test changed.
- **2026-11-17 (install backlog T5), the amass note matches v5.1.3.**
  `amass -version` -> `v5.1.3`; `amass -h` -> `Usage: amass
  [assoc|engine|enum|subs|track|viz] [options]`; `amass enum -h` lists
  `-passive` with `Deprecated since passive is the default setting`. The
  registry note said "Always run in passive mode (-passive)", which is stale for
  v5: passive needs no flag. `tools.yaml`, docs/09's per-stage notes and the
  subs manual now say passive is the default, `-passive` is deprecated (still
  parsed), and an adapter must be checked against `amass enum -h` first. No
  test added or changed: the change is a note string and prose, and a test
  pinning that prose would lock wording rather than behaviour (the registry
  still loads, which the gate exercises).
- **2026-11-17 (install backlog T6), the webanalyze preparation step is in the
  registry.** Measured: a scan in a directory without `technologies.json` exits
  **1** with `error: can not open apps file : could not find the technologies
  file: technologies.json`; `webanalyze -update` downloads 2,122,079 bytes of
  `technologies.json` **into the current working directory** and prints
  `app definition file updated` (exit 0). `tools.yaml` now carries that in
  `notes:` (with the `-apps` escape hatch), docs/09 has the same note in the
  per-stage list, and the manuals README flagged item 6 and the tech manual
  section are marked closed. No code or test changed (no `webanalyze` adapter
  exists; the step cannot be automated by doctor without writing into the
  user's CWD, which the installer does not do).
- **2026-11-17 (owner-requested removal D4), the installer is gone.**
  `reconkit install`, `reconkit update`, `doctor --fix`, the `.env` key prompt
  and `src/reconkit/installer/` (plans, apt/pipx/go_install backends, GitHub
  release download, checksum/archive verification) are deleted; so are
  `InstallError`/`InstallSkipped`, `render_install`/`_install_result`/
  `_install_detail` and the import of `InstallOutcome` in `ui.py`. `tools.yaml`
  `install:` blocks became inert `source:` strings (40 of them, one per binary
  tool; the 8 http/python adapters have none) and the `x-pd-release` anchor is
  gone; `ToolSpec` gained `binary`, `version_cmd`, `version_regex`, `source`.
  `installed_copy`/`installed_version` moved to `core/toolcheck.py` and take a
  `ToolSpec`; `bin_dir()` moved to `config.py`, and `adapters/base.
  managed_bin_dir()` imports it from there. `doctor` computes rows from
  `ToolSpec` only; exit code 6 is retired; `config.yaml` `tool_versions` and the
  `install:` block stay in the schema as accepted-and-ignored, and `doctor`
  prints one warning when `tool_versions` is non-empty. **One row changed:**
  `httpx_tech` was always `missing` because its plan was `method: none`; it now
  probes its shared `httpx` binary, so on this box it reads `yes`. That is the
  locked "ToolSpec.binary" rule, not an accident - see REVIEW_LOG for why the
  old behaviour could not be kept without an extra field. Tests: 39 in
  `tests/test_install_cli.py` deleted (one moved to `tests/test_config.py` as
  `test_managed_bin_dir_has_one_source_of_truth`), 28 + 18 + 10 in the three
  installer backend files deleted, `tests/test_installer_registry.py` replaced
  by `tests/test_tools_registry.py` (22 adapted, 12 re-expressed as `source:`
  validation), `test_fix_runs_the_installer` deleted, two `install/update
  --help` cases removed from `test_cli.py`, the doctor footer assertion and
  `report_for()` updated, plus two new tests
  (`test_an_uninstalled_tool_is_skipped_and_the_others_still_run`,
  `test_a_tool_versions_pin_is_reported_once_as_ignored`). 730 -> 635 collected.
  Full name/old/new/reason list in REVIEW_LOG "Installer removal D4".
- **2026-11-17 (verification follow-up F8), the D3 test-count wording uses the
  measured figures.** The D3 entry above now says 32 test functions deleted and
  4 renamed (44 collected node ids removed, 12 added, 745 -> 713), then one
  parametrized case removed and two tests added by the interactive-mode fix
  (713 -> 714). The disclosed name list is unchanged.

- **2026-11-17 (D5, V-UNEXPECTED item 1): `httpx_tech` reported Python
  `httpx` as installed; fixed with a `version_cmd` + `version_regex` and a
  regex-miss-means-not-installed rule.** The D4 fallback probed nothing for a
  tool with no `version_cmd`, so `httpx_tech` accepted whatever file named
  `httpx` was first found: with PD httpx hidden, doctor printed
  `yes | /usr/bin/httpx | ok` while the `httpx` adapter row printed
  `wrong program` for the same file. Fix: `tools.yaml` `httpx_tech` gains
  `version_cmd: [httpx, -version]` and
  `version_regex: 'Current Version:\s*v?([0-9]+\.[0-9]+\.[0-9]+)'`, and
  `core/toolcheck.installed_version()` returns `None` when a declared pattern
  does not match instead of falling through to the first output line. No new
  field, no change to `BinaryAdapter.check_installed()`, and the other 12
  presence-only tools are untouched (documented as a known limitation in
  docs/10 section 3). Tests, three new in `tests/test_tools_registry.py`:
  `test_the_python_httpx_cli_is_not_httpx_tech`,
  `test_projectdiscovery_httpx_is_httpx_tech`,
  `test_a_regex_miss_means_not_installed_for_any_tool`. One changed:
  `test_a_shared_binary_tool_still_has_a_source`, which asserted
  `httpx_tech.version_cmd is None` (old: the row was presence-only; new:
  `== ["httpx", "-version"]` and `version_regex is not None`; reason: the row
  now carries a probe, which is the whole point of the fix). 635 -> 638
  collected.
- **2026-11-17 (S1-S7, cleanup batch), `config.yaml` `tool_versions` is gone
  completely.** The key, the `AppConfig` field and the doctor warning were
  removed. Because `_StrictModel` uses `extra="forbid"`, a `config.yaml` that
  still carries `tool_versions` now fails to load with exit 2 instead of being
  accepted and ignored; docs/02 section 3 states that. This is the requested
  cleanup, not an accident, but it is a behaviour change for an older config,
  and the batch text said "no behavior changes" - so it is recorded here as the
  one unavoidable exception. Deleted test:
  `test_a_tool_versions_pin_is_reported_once_as_ignored`.
- **2026-11-17 (S1-S7), docs/10's section numbers moved.** The file was rewritten
  as a tool reference with four sections: 1 what it is, 2 the tool table, 3 how
  doctor checks a tool, 4 what reconkit does NOT do. Old §1 (per-tool sources)
  is now §2 and old §2 (lookup order) is now §3; old §3 (system packages) and
  old §6 (`.env` setup) no longer exist as sections. Every in-repo reference was
  re-pointed (`docs/01`, `docs/05`, `docs/08`, `docs/tool_manuals/README.md` and
  four `src/` docstrings); `docs/05` now points key setup at `.env.example` and
  `SETUP.md`, which still carries it.
- **2026-11-17 (S1-S7), the batch's class-(c) sweep went past the named files.**
  Sub-task 7 says a real-residue hit anywhere is fixed in the batch, so
  `docs/08`'s "Flow 2 - Install tools" steps (which spelled `sudo apt install`,
  `go install` and `pipx install`), 30 "**Install yourself:**" bullets across the
  seven tool manuals, and `docs/tool_manuals/ports.md`'s "Why 2.3.0 is pinned"
  block (which showed a `tool_versions` snippet for a key that no longer exists)
  were rewritten to provenance-only wording. No other manual content changed.
  The five items deliberately NOT changed are listed in the REVIEW_LOG entry's
  Findings; the doctor footer text is the important one - the batch requires it
  byte-identical, so it stays and still names `apt`/`go install`/release
  download.
- **2026-11-17 (D6), doctor no longer displays a version.** `ToolCheck.version`,
  the table column and the `doctor --json` key are removed. The probe machinery
  is untouched on purpose: `version_cmd`/`version_regex` and
  `installed_version()` still run, because a declared pattern that does not match
  is what marks a namesake as `wrong program` (D5). `InstallStatus.version` is
  kept although nothing displays it - it is the probe's return value and
  removing it would change the adapter contract for no visible gain. Deleted
  test: `test_unparsable_version_is_reported_as_unknown`; added:
  `test_a_doctor_row_and_its_json_object_carry_no_version`. The `Missing tools:`
  footer is reworded (the S1-S7 batch had frozen it pending this ruling), so
  `test_missing_tools_keep_exit_code_zero` and docs/01, docs/02 and docs/08 were
  updated with it.

- **2026-11-17 (S1-S7, D8): scan modes unified.** `MODE_STAGES` and
  `MODE_TOOLS` in `engine.py` are the only definition of a mode (stages, tool
  modes, tiers); CLI help, the interactive legend and docs/02 quote them.
  Deviations disclosed, each owner-approved or pre-approved (D7):
  (a) **CLI `--active` narrowed** from all seven stages to `subs`, `dns`,
  `live`, matching the interactive `active` mode; `ports`/`tech`/`urls`/`vulns`
  now need `--full` or the single-stage commands. Changed test:
  `test_stage_order_and_tool_rows` (was `ScanOptions(active=True)`, now
  `full=True`); changed test: `test_full_mode_does_not_request_the_deferred_vulns_stage`
  became `test_full_mode_requests_every_stage_including_vulns`.
  (b) **`--full` added** and implies `--active` + `--include-noisy`, so the
  `opt_in` tier is selectable under it; **exploitation-class tools never fire
  automatically** in any mode - `tools.yaml` gained `exploitation: true` for
  `sqlmap`, `dalfox`, `crlfuzz` and the engine skips them unless named with
  `--tools` (owner pre-ruling, preserves AGENTS "recon only"). Because no
  intrusive tool has an adapter, full mode records `no adapter yet (phase 3)`
  for them; no exploitation tool was run. (c) `--no-scope` added as an explicit
  opt-out of the scope file, not a bypass (AGENTS rule 2 amendment), with a loud
  warning and `scan_runs.scope_mode = unrestricted_flag`; schema 5 -> 6.
  (d) Selection-time skip reasons changed: intrusive/opt_in tools are now
  recorded with `tier not included in <mode> mode` instead of being dropped
  silently, and an active tool in passive mode reads `tool mode not included in
  passive mode` instead of `requires --active`. Changed tests:
  `test_naabu_is_selectable_in_active_mode`,
  `test_passive_mode_never_runs_naabu_with_or_without_a_scope_file`,
  `test_tier_gating_and_explicit_intrusive_refusal` (renamed
  `test_tools_flag_overrides_tier_gating`; it asserted that `--tools intrusive`
  raised ConfigError, the rule the owner replaced). (e) `--tools` no longer
  refuses an intrusive name: tier gating is bypassed, the tool-mode gate is not.
  (f) New flags: `--only-alive`, `--only-states`, `--ports`, `--status-codes`,
  `--header` (repeatable), `--user-agent`, `--redact-headers/--show-headers`;
  filters change output only, never the DB. (g) Interactive mode gained the
  no-scope question, ports, states, status codes, headers, user agent, a
  two-line plan echo, and the out-of-scope `[a]/[b]/[c]/[d]` prompt; the
  aggressive question is now skipped for `full` (every stage is already in it).
  (h) Docs 01/02/03/04/05/08/09, README and AGENTS updated; docs/10 unchanged as
  instructed. (i) `test_ui` JSON-shape and the four `test_store` migration
  assertions were updated for `scope_mode` and schema 6 (test-change rule).
- **2026-11-17 (S1-S7) consistency audit results.** `docs/02` section 2 now
  carries the "Scan modes (source of truth)" table. Stale text found and fixed
  in this batch: docs/01 PRD ("this build has no `--ports`/`--full` flags"),
  docs/02 (stage table said passive includes "passive ports/CDN info"; the
  `requires --active` skip reason in two places; the `--active` help quote),
  docs/08 flow 4 step 3 ("no live progress line" - progress has been on stderr
  since Part 13) and flow 6 step 4 (same `--ports`/`--full` claim), README
  ("active scans need `--active` **and** a matching `scope.yaml`", and the
  `live`/`ports`/`run` command-table rows). `grep` for mode rules outside the
  two dicts finds only `STAGE_ORDER`, `RAW_OUTPUT_DIRS`, single-stage command
  tuples and the aggressive `{LIVE, PORTS}` addition - all deliberate, none a
  per-mode rule.

## Open risks

- **2026-11-18, D21:** `scripts/install-tools.sh` ran its real apt branch under a pty (`--update --only nmap`, sudo prompt answered by the owner): `apt-get update` + `apt-get install -y nmap` -> `0 upgraded, 0 newly installed`, then `doctor` verification, exit 0, 10 s. A **fresh** apt install is still unproven (every apt tool was already present, so apt had nothing to do), and the script is not covered by `pytest`. Without a terminal it exits 2 with a clear message instead of hanging (verified).
- **2026-11-18, D21:** one registry entry has no automatic source and is printed rather than installed: `dnsreaper` (no PyPI package, no build files). It stays `manual` until someone verifies an install path from real evidence. `findomain` and `rustscan` left this list the same day - Kali's signed repository packages both, and their `source:` is now `apt:`.
- **2026-11-18, D21:** the Kali `findomain` package is `11.0.0-beta.2`, older than the 11.0.0 release zip it replaced, and the `rustscan` package is versioned `2.4.1` while its binary prints `rustscan 2.3.0`. Both work with the adapters (flags checked, `identity ok`), but the apt version number is not trustworthy for either.

- **FOUND 2026-11-18, not fixed, needs a ruling:** a `--mock` run stores the fixture's hosts under whatever target it was given. Run 69 (`testfire.net`, `subs`, `mock=1`, 2026-11-17 16:40) wrote the four `example.com` fixture hosts (`www`/`api`/`dev`/`blog.example.com`) into `subdomains` with `target_id` = testfire.net, so every later testfire.net report carries four hosts that have nothing to do with the target (42 rows, 38 real). The obvious fix - store only hosts equal to or under a scope domain - is not obviously correct, because a `scope.yaml` may name several unrelated domains and a discovered host is then legitimately outside the typed target (D1 phrase "typed target plus what is discovered in association with it" does not settle whether `example.com` was discovered *in association with* testfire.net). Stopped here instead of guessing.
- **12e is closed (PIT-47, 2026-11-15)**: a first `live` pass that got a record writes `UNKNOWN`/LOW with the reason, and a pass with no record still writes nothing. A later consumer that read "no row" as "not probed" must read the state instead.
- **CLOSED 2026-11-16 by Part 13:** `--json` used to write no progress at all while docs/02 said tables and progress stay on stderr. All scan modes now emit stage/tool progress on stderr; only `--silent` suppresses it, and stdout remains one JSON document.
- **Part 13, open for the owner:** the pty run (`results/testfire.net/...`, an in-scope domain at `--speed fast`, a flag removed on 2026-11-17 by MASTER_PLAN D3 - the historical run is unchanged) is the only real-network exercise of the interactive flow, so its prompts and report folders have exactly one piece of evidence.
- **Pre-existing, not caused by Part 13 and not fixed:** `reconkit run --active --mock` stores every host as `UNKNOWN` (the mock live adapter returns records the engine reads as inconclusive). Verified on the flag path before Part 13 existed; the interactive `active`/`full` modes inherit it. Needs its own ruling.
- **Part 13, accepted:** the saved report contains only values already stored in the run's DB (no recomputation), so a stored `title` that happened to contain a provider key would appear in `report.txt`/`report.json` exactly as it already appears in the SQLite file. Files are written 0600 inside `results_dir`.
- Six typed `render_error(str(exc))` sites in `cli.py` (scope check, `diff`, `status`, `doctor`, `install`) still bypass `redact()`; every message is built from our own values today, so no leak is known. Needs its own ruling.
- **Historical (installer removed 2026-11-17, D4):** `libpcap-dev` is absent and `sudo` needs a password here, so the apt prerequisite step never ran live; `naabu` is already installed, which also meant `install --all` did not attempt it.
- **Historical (installer removed 2026-11-17, D4):** the sudo-authenticated half of the installer never ran end to end: `massdns`, `amass`, `dig`, `nmap`, `whatweb` and `libpcap-dev` were only ever exercised as `skipped`.
- **Historical (installer removed 2026-11-17, D4):** GitHub release lookups were unauthenticated (60 requests/hour per IP); a 403 failed every `github_release` tool. Nothing looks up a release any more.
- **Historical (installer removed 2026-11-17, D4):** `update` re-ran `go install` for every `@latest` go_install tool and reported `installed` rather than `up to date`.
- `installed_version()` returns the first line of the version text, so `katana` shows `__` and `nuclei` shows `[I…`, which also defeats `_same_version()` for them; `sqlmap` has no `version_cmd` and shows a bare path.
- `BinaryAdapter.binary_path()` prefers any existing file in `~/.reconkit/bin` over `PATH`, so a broken managed copy shadows a working binary (deliberate, documented in docs/10 section 3 since the 2026-11-17 rewrite; mitigation is manual).
- Interactive Ctrl+C does not kill an already-running child (children lead their own process group, PIT-32); `killpg` remains UNTESTED on a real signal.
- **Historical (installer removed 2026-11-17, D4):** `SUDO_DENIAL_MARKERS`, `_fetch_text` and the non-UTF-8 checksums rejection went with the installer; `requires` (puredns -> massdns) is no longer a field and survives only in the source note.
- `doctor` does not check wordlists (no phase-2 adapter uses one); `dnsutils` is not checked because it appears only in the `dig` entry's `source:` string (it is not in `system_packages` or `requires_apt`).
- `scope.yaml` cannot express out-of-scope CIDRs; `in_scope_cidrs` is the only IP gate.
- Unverifiable tool facts, named: OTX's response shape was never observed live (anonymous 429, synthetic fixture); `assetfinder`'s identity probe is inferred from Go `flag` source; `rustscan`'s asset naming and `--version` are now verified against the real 2.3.0/2.4.1 releases and a real binary (2026-11-17, T1 below), so its entry is no longer in this list.
- `subfinder` provider keys cover only certspotter, chaos, github and virustotal; no real `subfinder` run has accepted the generated provider file yet.
- 11c-bis-1: `--help` renders switches as value-taking (`--json <bool>`); `typer>=0.12` has no upper bound and no test pins the rendering. 11c-bis-2: `reconkit --json doctor` accepts a global `--json` and silently ignores it.
- **Superseded 2026-11-17 (D2):** `naabu` is no longer permanently skipped. It runs unrestricted with no scope file, and on engine-verified IPs when a scope file is present; ports confidence can now exceed LOW when both `pyscan` and `naabu` report a port. The 12i "pyscan-only / LOW ceiling" risk is historical.
- Wildcard matches are a mark only: docs/09's "exclude from counts" names no count and no code filters it.
- **Closed 2026-11-17 (adapter waves 4-8):** `tech`, `urls` and `vulns` now have adapters and real runs behind them - `tech`: `webanalyze`, `cdncheck`, `wafw00f`, `whatweb`, `httpx_tech`; `urls`: `katana`, `gau`, `waybackurls`, `unfurl`, `hakrawler`, `gospider`, `subjs`, `urlfinder`; `vulns`: `nuclei`, `subzy`, `nikto`, `ffuf`. Only `dnsreaper` remains adapter-less (D15: no package, no console script). The old line "`tech`, `urls` and `vulns` have no adapter for any tool in their pools" was stale.
- 2026-11-16, for the owner: `docs/tool_manuals/README.md` lists six registry
  discrepancies flagged by the manual verification. **2026-11-17: all six are
  closed** by the install/doc backlog batch - `rustscan`'s placeholder asset
  (T1), the seven ASCII-art version columns (T2), the path-instead-of-version
  rows (T3), `assetfinder -h` exiting 0 (T4), `amass` v5.1.3 versus the v4 note
  (T5) and `webanalyze -update` (T6).
- **Historical, 2026-11-17 (T1 follow-up, moot after D4):** `reconkit`'s
  extractor unwrapped one archive layer only, so `rustscan` 2.4.1
  (`x86_64-linux-rustscan.tar.gz.zip`) could not be installed and the registry
  pinned 2.3.0. The installer was removed the same day, so 2.4.1 now needs a
  manual unpack; the registry keeps a 2.3.0 note in `source:` and the
  `tool_versions` pin is accepted-and-ignored.

## Notes for later tasks

- Where things live (the detailed per-function map is in the `REVIEW_LOG` archive): `errors.py` exceptions + exit codes; `models.py` enums and records; `config.py` strict loader; `core/runner.py` the only `subprocess` user (`run_exec`, `validate_target`, `validate_host`); `core/scope.py` the gate; `core/store.py` the only `sqlite3` user (schema/migrations, writes, diff reads, `redact`); `core/pacing.py` the `Pacer`/`RateLimiter` (removed 2026-11-17, MASTER_PLAN D3 - no such module now); `core/workspace.py` raw files; `core/wildcard.py`; `adapters/` one module per tool plus `base.py`/`registry.py`; `engine.py` the pipeline, state rule and consensus; `ui.py` rendering; `cli.py` Typer wiring; `doctor.py`; `core/toolcheck.py` the installed-copy/version probe (the installer was deleted 2026-11-17, MASTER_PLAN D4 - no such package now).
- `tool_runs` row-frequency: one per executed or skipped tool. `host_status_history`: one row per host per status pass (Part 9 change; docs/04 section 5).
- Fixtures are synthetic unless noted, written to the documented shapes, in `tests/fixtures/<tool>/`: `dnspython`, `pyprobe`, `pyscan` (JSON), `subfinder`, `assetfinder` (text), `httpx`, `naabu` (JSONL), plus real trimmed `crtsh`/`certspotter`/`hackertarget` responses and the synthetic `otx` one. No adapter test touches the network or a real binary.
- Key sources and sign-up URLs live in docs/05 section 6.1, docs/09 and the archived PROGRESS section (subfinder provider config: `docs.projectdiscovery.io/opensource/subfinder/install`, fetched 2026-11-13). Never guess a key name, flag or field; verify it and cite the URL and date (PIT-25).

## Owner verification commands

Run in `/home/kali/Desktop/reconkit` with `.venv` active. These are the checks no session here could perform; nothing in this file claims they passed.

```bash
cd /home/kali/Desktop/reconkit && source .venv/bin/activate
python --version                          # expect 3.11+
reconkit doctor                           # compare with `dpkg -l` / your .env; masscan identity is fixed (PIT-35)
# obtain any missing tool yourself (reconkit installs nothing since 2026-11-17):
#   docs/10_TOOL_SOURCES.md section 2 is the reference - provenance per tool, not instructions
reconkit doctor --json | python -m json.tool   # every tool ready; Keys rows reflect your .env

# Real active run. Fill in_scope_cidrs in scope.yaml first, or pyscan will
# (correctly) block every host:
reconkit run -d <authorized-host> --active --tools pyprobe,pyscan --db /tmp/verify.db -v
#   expect: pyprobe rows from real HTTP/TLS; pyscan rows only for addresses inside
#   in_scope_cidrs; with no CIDRs, a pyscan row reading blocked=<n> and no ports.
#   naabu (2026-11-17, MASTER_PLAN D2): with no scope file it runs like any other
#   active tool on the discovered hostnames; with a scope file present it runs
#   only on the IPs reconkit resolved and verified against in_scope_cidrs, so a
#   target that resolves outside them is skipped and, when nothing verifies, its
#   row reads "blocked: no in-scope IP for any target".

# killpg / Ctrl+C path (PIT-32, still UNTESTED on a real signal):
reconkit run -d <authorized-host> --active --tools httpx --db /tmp/verify.db -v &
# then Ctrl+C, and check `ps -ef | grep httpx` for an orphan process group
```
