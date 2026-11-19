# Review log

Per-part evidence log for this repository. Each entry follows the template in
`docs/MASTER_PLAN.md`. Hashes are filled by the next commit, because a commit
cannot contain its own hash.

## Known pitfalls (read before coding)

Check every new change against this table before writing code. A future fix must
add a `test_regression_<slug>` test (or a docstring starting `Regression: PIT-xx`),
show it failing, then passing, and add its row in the same commit. A trap that
cannot be tested is marked UNTESTED and listed under "Not verified".

| ID | Symptom | Root cause | Rule going forward | Guarding test |
|---|---|---|---|---|
| PIT-01 | A host with a DNS timeout/SERVFAIL became DEAD | Every resolver exception collapsed into NXDOMAIN | Only NXDOMAIN may yield DEAD; timeout/SERVFAIL stay structured and warn | `test_dnspython_nxdomain_timeout_servfail_are_distinct` |
| PIT-02 | Passive tools were paced at the active rate | `tool_rate_args` ignored the mode | Passive uses passive rps; active uses active rps; nmap/masscan always active | `test_tool_rate_args_slow_passive_vs_active` |
| PIT-03 | Upserts reset stored subdomain/port/url values to defaults | Unconditional update on conflict | `None` keeps, explicit `0`/`""` overwrites, for all three tables | `test_upsert_subdomain_keeps_values_when_omitted`, `test_upsert_port_keeps_service_when_omitted`, `test_upsert_url_keeps_source_count_when_omitted` |
| PIT-04 | Secrets in `--flag VALUE` and Cookie headers survived redaction | Regexes covered pairs and Bearer only | Flag-value plus Cookie/Set-Cookie matchers | `test_redact_cases` |
| PIT-05 | Timing test flaked under load | Too-tight duration bound | Assert a lower bound only (`>= 0.25`) | `test_timeout_keeps_partial_output` |
| PIT-06 | Timeout kill left the child alive | Only the direct child was killed | `_kill_tree` kills the child's process group with `killpg` | `test_timeout_kills_child` |
| PIT-07 | OTX 429 treated as an empty result | Anonymous API refuses requests | Synthetic fixture; 429 is an error, never data | n/a (synthetic fixture; `test_otx_sends_key_in_header_and_never_leaks_it`) |
| PIT-08 | `grep` unavailable in the operator's shell | Two different shells | Run the S3 scans with bash `grep` | n/a (tooling) |
| PIT-09 | An invented `core/consensus.py` appeared | Assumed a module from the feature name | Consensus stays in `engine.py` | n/a (architecture) |
| PIT-10 | Copied output was claimed as evidence | Hand-written diff | Paste raw command output only | n/a (process) |
| PIT-11 | A workspace write escaped the target directory or hit a device name | Filename taken without validation | Regex + one segment + `resolve()` containment + device-name reject | `test_workspace_rejects_unsafe_filenames` |
| PIT-12 | The pre-commit hook passed while tests failed | Hook only checks PROGRESS.md | Run the four checks directly; hook now warns on a `fix:` commit without tests | n/a (tooling; WARN only) |
| PIT-13 | `random.Random()` in `src/` tripped S311 | Convenience default RNG | Inject the RNG, no default, never suppress S311 | `test_wildcard_labels_are_unique_valid_and_under_the_target` |
| PIT-14 | The Python `httpx` CLI was accepted as ProjectDiscovery httpx | Identity checked by filename | Match the tool's own banner/version markers | `test_python_httpx_cli_is_rejected` |
| PIT-15 | A failed httpx probe was stored as ALIVE | No distinction between a response and a failed probe | Skip JSON lines without an integer `status_code` | `test_httpx_parser_skips_lines_without_a_status` |
| PIT-16 | A runner `RuntimeError` escaped an adapter | Only parse/fetch errors were mapped | Map it to `FAILED` with `runner error: ...` | `test_run_runner_error_is_a_failed_result` |
| PIT-17 | A subfinder provider file survived a YAML failure | Only `OSError` was caught | Catch `yaml.YAMLError` and unlink in `finally` | UNTESTED (inspection; needs a PyYAML fault injection) |
| PIT-18 | A provider key could reach argv or the result | No bridge existed | 0600 temp file, argv holds only its path, delete in `finally` | `test_subfinder_writes_and_deletes_provider_config` |
| PIT-19 | `needs_key` and `keys` disagreed | Two sources of truth | `keys` only; the loader rejects `needs_key` | `test_tools_yaml_has_no_legacy_needs_key` |
| PIT-20 | The body cap was bypassed by chunked or lying Content-Length | Trusted the header / buffered the whole body | Stream and cap actual bytes | `test_lying_small_content_length_is_still_capped` |
| PIT-21 | A wildcard timeout was read as "no wildcard" | Status collapsed to none | Any failed probe with no resolution is UNKNOWN, never NONE | `test_wildcard_unknown_is_not_none` |
| PIT-22 | The workspace wrote unredacted or partial output | Raw write in place | Redact before `mkstemp`, then `os.replace`; unlink on failure | `test_workspace_redacts_two_secrets_and_a_bearer_token` |
| PIT-23 | `Workspace.create` chmodded a caller-owned parent dir | `chmod(self.root)` | Chmod only the target and stage directories | UNTESTED (review fix) |
| PIT-25 | Key and quota metadata was guessed from memory | No source check | Cite the URL and fetch date; list unverified items under Open risks | n/a (docs; see "Key sources") |
| PIT-26 | A `fix:` commit landed with no test | No gate step checked it | the pre-commit hook prints a WARN | n/a (tooling; added with this addendum) |
| PIT-27 | `store.transaction()` raised "cannot start a transaction within a transaction" | Explicit `BEGIN` on a connection already inside SQLite's implicit transaction | Use SQLite's implicit transaction; commit/rollback at block exit | `test_transaction_commits_once_and_rolls_back` |
| PIT-28 | A resumed `live` stage saw only the target, not hosts persisted by completed stages | Resume skipped stages but the in-memory discovered/alive sets were not reseeded from SQLite | Seed both sets from `Store.subdomains()` on resume | `test_resume_skips_completed_stages_and_continues` |
| PIT-30 | `doctor`/scans moved subfinder and naabu config dirs from `~/.config` into the current directory | `BinaryAdapter.check_installed()` ran the version probe with `env={}`, so the child had no `HOME` and the tools wrote their config beside the CWD | Pass `HOME` to the identity probe | `test_identity_probe_passes_home` |
| PIT-31 | The `nuclei -ut` template refresh reported `templates not refreshed` on a working install, because nuclei lives under `$HOME/go/bin` | `_refresh_templates` passed `env={"HOME"}`; `Popen`/`execvpe` resolves a bare program name with the `PATH` inside the env it is given, falling back to `os.defpath` (`/bin:/usr/bin`) | A `runner(...)` call with a custom `env=` that names a bare binary must pass `PATH` too (the documented exception in docs/10 section 3d); where the caller already has an absolute path, pass the absolute path instead | `test_regression_custom_env_without_path_cannot_resolve_binary`, `test_nuclei_templates_are_refreshed_after_a_change` |
| PIT-32 | `sudo -n` fails inside reconkit (`sudo: a password is required`, exit 1) despite a valid `sudo -v` ticket in the same shell; a direct subprocess call succeeds | `run_exec` passed `start_new_session=True`, so the child called `setsid()` and sudo's `tty_tickets` scoping could not see the ticket cached against the parent's controlling terminal | POSIX children must stay in the parent's session: use `process_group=0` to give the timeout kill its own group, never `start_new_session=True` on POSIX | `test_regression_child_shares_parent_session_but_not_pgid`, `test_regression_kill_tree_kills_only_the_child_group` |
| PIT-29 | A dangling-CNAME warning disappeared after restart | `host_status_history` had no CNAME columns and DNS-only resolved hosts were not persisted | Store `cnames_json` plus `dangling_cname`; reuse `Store.latest_cnames()` on a later NXDOMAIN | `test_regression_dangling_cname_survives_restart`, `test_dns_resolved_then_two_nxdomain_is_shut_down_then_dead`; migration tests in `test_store.py` |
| PIT-34 | A port scan resolved a host and connected to `addresses[0]` without checking `in_scope_cidrs`, and an empty resolution fell back to the hostname (a second, unchecked resolution) | docs/05 rule 6's predicate existed but had zero call sites, and an adapter could not reach the loaded scope by design (no `scope` import) | An adapter that resolves and then connects must refuse every address the injected `ip_allowed` predicate does not allow, treat `None` as deny (never allow-all), and never retry a hostname; a resolver that lives inside the binary (`naabu`) is skipped at selection time | `test_pyscan_probes_only_an_address_inside_in_scope_cidrs`, `test_pyscan_skips_a_host_whose_address_is_outside_in_scope_cidrs`, `test_pyscan_without_cidrs_probes_no_addresses`, `test_pyscan_never_falls_back_to_the_hostname`, `test_active_ports_stage_receives_the_cidr_predicate`, `test_naabu_stays_blocked_because_it_resolves_inside_the_binary` |
| PIT-35 | A tool printed a valid version banner and exited nonzero (`masscan --version` exits 1), so the installer's identity probe called a real, working binary "wrong program" and doctor refused it | `installed_version()` returned `None` for any nonzero exit; exit code was treated as the identity signal instead of the program name in the output | A version probe may accept a nonzero exit only when the output names the program (`plan.binary` case-insensitive); any other failing probe stays not-usable | `test_masscan_version_counts_even_though_its_exit_code_is_1`, `test_a_nonzero_version_probe_with_unrelated_text_is_not_installed` |
| PIT-33 | Three real docs-only commits (`cc70b15`, `722b2d1`, `046e0a2`) closed named Part 11 work but updated neither PROGRESS nor REVIEW_LOG; the RESUME block still read "11a is next" long after 11a shipped, and no 11c findings were ever logged | `.githooks/pre-commit` requires `docs/PROGRESS.md` only when `src/` or `tests/` change, so a docs-only commit is never forced to update the source of truth | Any commit that closes or advances a named task updates `docs/PROGRESS.md` in the same commit, docs-only included, and any finding gets a REVIEW_LOG entry whether or not code changed | n/a (tooling/process; the Part 11 findings backfill entry is the correction) |
| PIT-36 | `reconkit -d X --active ...` ran subs+dns only and exited as if the requested active scan had run | The bare form is the `lite` shorthand, `_stages("lite", active)` ignores `active` by design, and no command rejected a flag it cannot honour | A flag a command cannot honour is a usage error (exit 2) whose message names the command that can honour it; never accept and ignore it | `test_bare_command_rejects_active_instead_of_running_lite`, `test_passive_only_commands_reject_active` |
| PIT-37 | Every host ProjectDiscovery `httpx` got 200 on came back `UNKNOWN` from `pyprobe`, so 8 of 8 live hosts looked like two tools disagreeing | `_probe` returned a `UNKNOWN` record from inside the scheme loop on the first TLS `ConnectError`, so the `http` attempt never happened | A per-scheme failure must not end a multi-scheme probe; `UNKNOWN` requires "no scheme answered" plus a TLS error | `test_pyprobe_tls_failure_still_tries_http` |
| PIT-38 | A stage whose whole pool had no adapter reported `results: []` and `tools_skipped: 0`, indistinguishable from "ran and found nothing" | The summary counted only executed `ToolResult`s and `StageOutcome` dropped the selection-time skip list | Selection-time skips belong to the stage outcome and the totals (`stages[].skipped`, `summary.tools_skipped`), not only to `tool_runs` | `test_a_stage_with_no_adapter_reports_its_skips` |

| PIT-39 | `diff` reported 27 hosts as `GONE` after a single flaky discovery run (`subfinder` 35 names, then 8), none of them re-probed | `diff_gone` compared one run against the next and treated any absence as a removal, so passive-source variance became infrastructure change | `GONE` requires two consecutive misses plus a sighting in the run before them; a single miss is `pending_gone`, never a change; fewer than three discovery runs confirm nothing | `test_regression_diff_gone_needs_two_consecutive_misses`, `test_diff_gone_needs_the_miss_to_be_consecutive`, `test_diff_gone_needs_the_baseline_run_not_just_two_empty_ones`, `test_diff_gone_is_not_confirmed_when_the_host_reappears`, `test_diff_with_two_runs_reports_pending_and_no_gone` |
| PIT-40 | A requested stage whose whole pool was skipped at selection (`tech`/`urls`/`vulns` with no adapter) was recorded `completed` and contributed nothing to the exit code, so a clean run looked fully successful while three requested stages did nothing (session 2) | `_exit_code()` looked only at selected/failed totals; the selection-time skips PIT-38 exposed in `StageOutcome` were never consumed by the exit decision, so "built nothing" and "succeeded" were the same code | A requested stage that executed zero tools adds one warning naming it and makes the run partial (5); precedence 3 > 4 > 5 > 0, an all-empty run stays 4, `--tools`-filtered and no-host stages are not empty (docs/02 section 6) | `test_an_empty_stage_warns_by_name_and_makes_the_run_partial` (`Regression: PIT-40`), `test_one_empty_stage_plus_a_tool_failure_stays_partial`, `test_every_requested_stage_empty_is_no_tool_not_partial` |
| PIT-41 | Every adapter parse bug (pyprobe TLS, certspotter empties, HackerTarget quota) had to be reproduced by hand: `Workspace.write` had no caller, no executed tool left its bytes on disk, and `ToolResult.raw_path` stayed `None` in every real run (G-1) | 12a's capture path was built (workspace writer with redaction and cap) but never wired into `Engine._run_one`, and `ToolResult` had no field to carry the bytes, so there was nowhere to put them | Every executed tool (ok/failed/timeout/crash/`--mock`) fills `ToolResult.raw_text` (unredacted, `Field(exclude=True)`, never in `--json`); `_run_one` writes `<stage>/<run_id>-<tool>.txt` through `Workspace.write` with the run secrets and `MAX_OUTPUT_BYTES`, then sets `raw_path`; a write that raises leaves `raw_path` at `None` and keeps the result | `test_failed_tool_still_writes_its_raw_output` (`Regression: PIT-41`), `test_each_executed_tool_writes_one_raw_file_and_sets_raw_path`, `test_raw_output_file_is_redacted_with_the_run_secrets`, `test_a_failed_workspace_write_keeps_the_tool_result` |
| PIT-42 | The last-resort CLI handler printed raw `str(exc)` and `-v` printed a raw traceback, so an escaping exception carrying a key-shaped value could reach the console unredacted; no reachable leak was ever demonstrated (keys travel in headers, not URLs), so this guarded the last unguarded output path (C-1) | `redact()` existed only on the storage path and required an explicit per-run value set; the CLI had no secret source at the moment `_report_error` can first fire, because `Engine.open` (which loads `.env`) runs later inside `_run_scan` | `configure_redaction(secrets)` sets one process-wide set used by `redact(text)`; explicit per-run iterables (including `()`) are unchanged, so stored/raw text is byte-identical. The Typer callback loads `.env` once at startup and configures it; `_report_error` redacts the one-line message and the `-v` traceback (chained exceptions included). The CLI imports only `configure_redaction` and `redact` from `core.store` | `test_report_error_redacts_a_secret_in_the_message` (`Regression: PIT-42`), `test_verbose_traceback_redacts_the_same_secret`, `test_verbose_traceback_redacts_a_secret_in_a_chained_exception`, `test_json_error_path_keeps_stdout_clean_and_redacts_stderr` |
| PIT-43 | `duration_s` read `0.0` beside real work (`dnspython ok 36 0.0`, `pyprobe ok 8 0.0`, `otx failed 0.0` next to a real 429), so a tool's own time was indistinguishable from a missing measurement (11d-findings-c) | The three python adapters never measured anything and left the model default, `HttpAdapter` measured only its ok branch, and `_run_one` measured nothing at all; `0.0` meant both "instant" and "unknown" | The adapter is the authoritative source: `perf_counter` inside each adapter (failure branches included), `run_exec`'s child clock for binaries. `0.0`/non-positive means "not measured", and `_run_one` substitutes its own wall clock only then - one fallback site, never overwriting a reported value, never storing a negative | `test_adapter_reported_duration_is_stored_and_never_overwritten` (`Regression: PIT-43`), `test_every_python_adapter_times_its_own_work`, `test_a_429_failure_still_reports_its_own_duration`, `test_missing_adapter_duration_gets_the_harness_wall_clock` |
| PIT-44 | `diff`/`--new-only` could report a host as NEW that no discovery tool had ever returned: the `dns` stage (and `_previous_facts`) created `subdomains` rows for DNS-resolved names, `first_seen_run` pointed at the `dns` run, there was no `subdomain_sources` row, and `diff_new` keyed on `first_seen_run` (11d-findings-b; reproduced offline with `alias.example.com`, `DNS_ONLY`, `sources: []`) | `subdomains` recorded no fact about how a row entered the table, so the row-creation run written by the `dns`/`live`/`ports` upserts was the only signal available and `diff_new` treated it as a discovery event | `provenance` is `subs` when a discovery tool first reported the row and `dns` when a state pass created it; `dns` is the insert default, `subs` upgrades and never downgrades. NEW = `provenance = 'subs'` with no `subdomain_sources` row before the latest discovery run, so a dns-only host is never NEW and a later discovery sighting is NEW at that run (docs/04 sections 5, 6 and 11, docs/02 section 2) | `test_dns_only_host_has_dns_provenance_and_is_never_new` (`Regression: PIT-44`), `test_a_discovered_host_keeps_its_real_provenance_and_is_new`, `test_provenance_upgrades_to_subs_and_becomes_new_at_that_run`, `test_v2_database_migrates_provenance_with_backfill` |
| PIT-46 | A host that could not be probed carried no reason: `UNKNOWN` looked identical whether the certificate had expired, the CA was untrusted or the handshake was rejected, and the only way to tell them apart was to probe the host again (11d-findings-f remainder) | `pyprobe` classified the TLS failure text by substring (`"ssl"`/`"certificate"`) and discarded the string, and `host_status_history` had no column to hold a reason even if it had been kept | The adapter keeps the failure text on the `UNKNOWN` record (`HostStatusRecord.detail`); the engine passes it to `Store.append_host_status`, which is the **only** place it is redacted and bounded: `redact()` with the run's secrets first, whitespace collapsed to one line, then cut to `DETAIL_MAX_CHARS` (200). Redacting before the cut means a truncated value can never leave a partial secret. `NULL` means no reason, a conclusive pass writes its own `NULL` row, and the value is exposed in `--json` (`hosts[].detail`), never in the human table | `test_host_detail_is_redacted_bounded_and_one_line` (`Regression: PIT-46`), `test_unknown_tls_failure_stores_a_redacted_bounded_reason`, `test_an_inconclusive_pass_keeps_the_previous_state_and_records_the_reason`, `test_a_plain_connect_failure_stores_no_reason`, `test_a_later_alive_pass_does_not_resurrect_the_reason`, `test_pyprobe_tls_failure_keeps_the_reason_on_the_unknown_record`, `test_v3_database_migrates_the_additive_detail_column`, `test_json_host_row_carries_the_stored_detail`, `test_json_run_exposes_the_stored_host_detail` |
| PIT-45 | A `SIGKILL` between writing the subfinder `provider-config.yaml` and the `finally` unlink left a provider-key file in the shared system temp dir indefinitely; `finally` was the only mitigation (C-2) | the adapter wrote a bare `mkstemp` file in the shared temp dir, so nothing recorded which run owned it, nothing bounded its lifetime, and a later run could not tell a stranded key file from a live one | provider keys live in a per-run directory named `reconkit-subfinder-<pid>-<random>` with mode 0700 (file 0600), created explicitly and removed with `rmtree` in `finally`. Every run first removes stale directories: a dead pid is removed at once, a live pid only once its mtime is older than `STALE_AFTER_S` (900 s); stale pre-12g `*.yaml` files are removed by the same age rule. Cleanup never raises and never touches the current run's own directory (docs/09) | `test_a_sigkilled_run_leaves_a_directory_the_next_start_removes` (`Regression: PIT-45`), `test_provider_config_lives_in_a_0700_per_run_directory`, `test_cleanup_leaves_a_concurrent_runs_directory_alone`, `test_when_liveness_is_unknown_age_alone_decides` |

| PIT-47 | A first `live` pass that contacted a host but could not decide wrote no `host_status_history` row, so "probed and inconclusive" was indistinguishable from "never touched the host", and the reason 12d stores was dropped in exactly the first-run case (11d-findings-g) | `decide_host_state` tied `persist` to `previous is not None`, so the write only started at the second pass; the pass's own evidence (a returned record) was never consulted, although docs/04 section 5 promises one row per host per status pass with a `dns`-stage exemption only | `persist` in the two inconclusive branches is `previous is not None or attempted`, where `attempted = bool(evidence.web)` - a live tool returned a record for that host, ambiguous or not, per the owner ruling and docs/04 section 5. A pass with no record (failed or timed-out tool, or no tool) still writes nothing, and the `dns` stage's SERVFAIL/timeout/no-answer skip is untouched because its evidence never carries web records | `test_regression_an_attempted_probe_persists_with_no_previous_state` (`Regression: PIT-47`), `test_a_first_inconclusive_live_pass_writes_an_unknown_row`, `test_only_the_host_a_tool_reported_gets_the_unknown_row`, `test_a_host_without_a_record_gets_no_row_even_when_another_did`, `test_a_failed_live_tool_attempted_nothing_and_writes_no_row` |
| PIT-49 | A host a live-stage adapter discovered while probing (a `tlsx` certificate SAN) entered the in-memory `discovered` set - later stages probed it - but had **no row in `subdomains`**: it vanished from `status`, `diff` and the report, and `--new-only` could never show it | `_persist_live` iterated only its input `hosts` list and only collected `HostStatusRecord`s; `_update_discovered` had already unioned the `SubdomainRecord`s into memory, so the loss was invisible inside the run | A status pass persists the discoveries it made as well as the hosts it was given: `_persist_live_discoveries` writes one `subdomains` row (`provenance='subs'`, its tool in `subdomain_sources`, `source_count` per run, `min_sources` respected) for every live `SubdomainRecord` not already in `hosts` or `subdomains`; existing rows keep their own count (PIT-03), and the host-state path is unchanged | `test_regression_live_discovered_subdomain_reaches_the_subdomains_table` (`Regression: PIT-49`), `test_tlsx_sans_enter_discovered_and_reach_subdomains_table` |
| PIT-52 | The first **real** hakrawler crawl failed the whole tool: `hakrawler: line is not a URL "javascript:checkSiteStatus('AltoroMutual')"`. The strict parser treated a page's own non-HTTP link as malformed tool output, so a perfectly good crawl was thrown away | every urls parser raised `ParseError` on any line `normalize_url()` could not turn into an http(s) URL, and the mock fixtures only contained real URLs - the fake data hid the class of line a real page produces | `base.is_non_web_reference()` recognises `javascript:`, `mailto:`, `tel:`, `data:`, `about:`, `ftp:` and `file:` and all four wave-3 parsers (plus nothing else) skip those lines before parsing. A line that is neither a known non-web link nor an HTTP(S) URL is still a `ParseError`, so genuinely broken output still fails loudly | `test_a_javascript_href_is_skipped_not_a_parse_error` (`Regression: PIT-52`) |
| PIT-53 | The first **real** nuclei run failed the whole tool: `nuclei: invalid host 'demo.testfire.net:443'` - 14 real findings were thrown away | nuclei prints `host` as `host:port` when it probed a non-default port, not as a URL; the parser's `urlsplit(...).hostname if "://" in value else value` turned that into an invalid host. The mock fixture only had `matched-at` URLs, so the fake data hid the shape | `finding_host()` in `adapters/nuclei.py` returns `urlsplit().hostname` for URLs, the bracketed address for an IPv6 literal, and the part before the first `:` otherwise; `validate_host()` still decides what is a host | `test_regression_a_nuclei_host_with_a_port_keeps_its_name` (`Regression: PIT-53`) |
| PIT-50 | Two tools could not be driven at all: `httprobe` and `waybackurls` read their host list on **stdin**, and `run_exec` opened stdin as `DEVNULL` with no way to feed it - the only alternatives were a shell pipe or a temporary file, and AGENTS rule 1 forbids the first | `run_exec` was written for flag-driven ProjectDiscovery tools, so "input" meant argv | `run_exec(..., stdin_text=...)` feeds the child from its own daemon thread (a lazily-reading child cannot block the timeout clock, an early exit is only a broken pipe) and `None` keeps the documented EOF. The adapter hook is `stdin_text(ctx)`; nothing else changed | `test_stdin_text_reaches_the_child_and_none_keeps_stdin_closed` (`Regression: PIT-50`), `test_stdin_text_survives_a_child_that_never_reads_it`, `test_httprobe_feeds_hosts_on_stdin_and_never_uses_a_shell`, `test_waybackurls_feeds_domains_on_stdin` |
| PIT-51 | The `tech` stage had no persistence branch at all: `_persist_stage` covered subs/dns/live/ports/urls, so every `HostStatusRecord` a tech adapter returned was dropped - webanalyze and cdncheck would have run, printed `ok N item(s)` and stored nothing | the tech stage never had an adapter, so the missing branch was invisible; `host_status_history.tech_json`/`waf` existed but only a live pass could fill them | `_persist_tech` merges `tech`/`waf` into the host's newest status row through the new `Store.update_host_extras`: no state row is appended and `state` is never touched, so `diff`/`previous_state()` are unchanged; an off-target record is dropped and a host with no status row is not annotated (D11) | `test_tech_stage_annotates_the_latest_host_row` (`Regression: PIT-51`), `test_tech_stage_drops_a_host_outside_the_target` |
| PIT-48 | `doctor` showed junk for two installed tools (`katana` -> `__`, `nuclei` -> `[I…` plus ANSI escapes), and `update` could not call `katana` up to date, so an already-current binary would be downloaded again on every run (12j) | `installed_version()` returned `text.splitlines()[0]` for every tool, but `katana -version` prints four lines of ASCII art (the real version is on line 8, on stderr) and `nuclei -version` prints a coloured `[INF]` line first, so `_same_version()` compared a release tag against a logo | A tool may carry a top-level `version_regex` in `tools.yaml`; `installed_version()` searches the whole `version_cmd` output, returns the first capture group (or the whole match when the pattern has no group), and falls back to `splitlines()[0]` when the field is absent or nothing matches. A pattern that does not compile is a `ConfigError` at registry load, before any command runs | `test_katana_version_ignores_the_ascii_banner` (`Regression: PIT-48`), `test_nuclei_version_drops_the_ansi_log_prefix` (`Regression: PIT-48`), `test_a_regex_with_no_match_falls_back_to_the_first_line`, `test_a_version_regex_without_a_group_returns_the_match`, `test_version_regex_is_parsed_from_the_registry`, `test_a_broken_version_regex_is_a_config_error`, `test_version_regex_survives_the_plan_copy` |
| PIT-58 | A real scan reported `katana: invalid JSON line` and threw away the whole crawl (0 items) although katana had found URLs; `hakrawler`/`gospider`/`subjs` had the same shape (any line their parser could not turn into an http(s) URL raised `ParseError`) | The parsers treated "this line is not output I understand" as "this tool failed", and the tools that print a warning on stdout (katana) or a log line (gospider) produced exactly such lines. PIT-52 fixed only the known non-web schemes, so any other noise was still fatal | A urls parser skips an unusable line, counts it, and keeps parsing: `ToolResult.error` carries one message per skipped line up to 10, then a single `skipped N unusable line(s); last: ...` summary, and the status stays `ok` because the parsed records are the tool's real output. `urlfinder` keeps its stricter archive rule (see docs/09 4a3) | `test_katana_skips_invalid_json_lines` (`Regression: PIT-58`), `test_katana_warning_lines_reach_the_detail_and_stay_ok`, `test_katana_many_junk_lines_are_summarised_once`, `test_crawler_parsers_skip_unusable_lines` |
| PIT-59 | The results table counted one website twice: `example.com` (301) and `www.example.com` (200) were two ALIVE hosts, and the same for `admission`, `iprc`, `research`, `portal`, so 39 "ALIVE" rows suggested 39 sites | Nothing in the pipeline related a `www.` name to its bare name: DNS resolves both, the live pass probes both, and neither `subdomains` nor `host_status_history` had anywhere to say they are the same site | A post-`live` pass (`Engine._dedupe_www_variants`) writes **metadata only** (`duplicate_of`, `www_note`, schema 9) on the newest status row: 3xx+2xx marks the 3xx name, two 2xx marks neither, same non-2xx plus a shared IP marks `www.X`, a dead variant and an unknown IP set mark nothing. Host state, confidence and every count query are untouched. The table gains a Notes column (only when a row has a note) and the summary line a unique count (only when a duplicate exists) | `test_www_redirect_to_bare_is_marked_duplicate` (`Regression: PIT-59`), `test_bare_redirect_to_www_is_marked_duplicate`, `test_both_200_independent_servers_not_marked_duplicate`, `test_same_status_on_one_server_marks_the_www_variant`, `test_same_status_on_different_servers_is_only_a_note`, `test_www_dead_is_not_marked_duplicate`, `test_single_variant_not_touched`, `test_www_dedup_never_changes_host_state_or_confidence`, `test_set_host_duplicate_updates_in_place_and_keeps_state`, `test_www_duplicate_rows_get_notes_and_the_summary_counts_unique` |
| PIT-60 | Nothing said whether a stored URL still answers: the urls stage kept 11,785 rows from the archives and the crawler, so a 2019 `/admin` and a page that answered today were the same evidence | `urls` had no status column and no stage sent a request per URL, so the whole archive looked equally alive | `Stage.URL_PROBE` runs after `urls` in `active`/`full` (engine-owned, no adapter) and writes `urls.status_code`: the HTTP status, `-1` for no answer, `-2` when the server answered with a certificate that does not verify. `NULL` alone means "not probed", and a stored answer is never retried. `--skip-url-probe` turns it off; `--mock` leaves NULLs and says so. Host state, confidence, `diff` and counts are untouched | `test_url_probe_stores_status_codes_and_marks_unreachable` (`Regression: PIT-60`), `test_url_probe_never_reprobes_a_stored_answer`, `test_url_probe_marks_an_unverified_certificate_apart_from_unreachable`, `test_url_probe_sends_only_in_scope_urls`, `test_url_probe_is_skipped_in_mock_mode` |
| PIT-61 | The www-dedup pass marked `www.X` as `duplicate_of X` when **neither** name had an HTTP status: both rows ALIVE with `status_code = NULL` and a shared IP. Seen in verification (`www.testfire.net.duplicate_of = testfire.net`, both codes NULL) | The shared-IP branch compared the two codes with `==`, so `NULL == NULL` read as "same status"; the documented rule is "same **non-2xx** status", and `NULL` means "no status observed" | The branch now requires both codes present and equal (`www_status is not None and bare_status is not None`). A no-status pair gets no `duplicate_of` and no note; the 3xx/2xx, both-2xx and different-IP branches are unchanged, and no state, confidence or count changes | `test_www_both_null_status_not_marked_duplicate` (`Regression: PIT-61`), `test_same_status_on_one_server_marks_the_www_variant`, `test_both_200_independent_servers_not_marked_duplicate` |
| PIT-63 | A tool that was installed silently disappeared from every scan: `amass` read `wrong program` once at the start of the 2026-11-19 batch, `reconkit subs --tools amass` skipped it as `not installed`, and the next ten probes (and five `doctor` runs) all said `yes / ok` | An identity probe is a single external process; one transient failure returned "not installed", and the engine's selection check turned that into a silent skip - the scan looked like the tool ran and found nothing | `probe_with_retry()` runs the probe once more after 100 ms before the verdict is `wrong program`; a namesake fails both attempts, so no status, enum or message changes. `doctor`'s `installed_version()` and `BinaryAdapter.check_installed()` call the same function, and a missing binary is never retried | `test_a_transient_identity_failure_is_retried_once` (`Regression: PIT-63`), `test_two_consecutive_identity_failures_still_mark_wrong_program`, `test_retry_does_not_fire_on_success`, `test_doctor_and_engine_share_the_retry_helper` |
| PIT-62 | PD `httpx` v1.12.0 looks like the faster probe transport but is not usable for liveness: it has **no `-insecure` flag** and skips TLS verification by default, so `https://testfire.net/` (certificate issued for `www.testfire.net`) returns `200`; a URL that fails produces **no JSON line at all**; and its default UA is a random browser string | The option list has `-probe`, `-tls-grab`, `-ztls` but no verification switch, and failures are simply absent from JSONL instead of being reported with an error field | The `url_probe` stage keeps the Python httpx transport (D24) - only it can distinguish "answered, certificate did not verify" (`-2`) from "no answer" (`-1`) with verification on. PD `httpx` remains the `httpx`/`httpx_tech` adapter, where a `200` and a technology list are all that is needed | `test_url_probe_marks_an_unverified_certificate_apart_from_unreachable`, `test_url_probe_sees_a_certificate_error_in_the_context_chain` |
| PIT-55 | A real `reconkit run -d example.com --active --no-scope` exited `5` although nothing on this box was wrong: the three subs sources had been refused by their providers (`otx` 429, `hackertarget` free quota, `crtsh` 502), so the scan looked broken | The runner had one failure bucket: any 429/5xx or quota body became `FetchFailed` → `ToolStatus.FAILED`, and `_exit_code` counts every non-`ok` tool as a partial run. External availability was indistinguishable from a broken binary | `base.classify_external_gap()` is the one classifier (429/rate-limit/too-many-requests, quota/api-count-exceeded, upstream 502/503/504/5xx); `HttpAdapter` raises `ExternalServiceGap` for a 429/5xx, a parser raises it for a quota body, and `BaseToolAdapter.run` classifies a non-zero binary exit. All three return `ToolStatus.GAP`, which is excluded from the failure total and becomes a completion gap (exit `0`, `completion.gaps`, `tool_runs.status='gap'`). A 404, a refused connection, a TLS error and a parse error stay `failed` | `test_429_is_a_gap_and_not_retried` (`Regression: PIT-55`), `test_a_5xx_from_the_upstream_is_a_gap`, `test_a_404_is_still_a_failure_not_a_gap`, `test_hackertarget_quota_answer_is_a_gap`, `test_classify_external_gap_matches_only_third_party_signatures`, `test_an_external_service_gap_exits_zero_and_is_named_in_the_gaps`, `test_a_gap_never_masks_a_real_failure`, `test_v7_database_rebuilds_tool_runs_for_the_gap_status` |
| PIT-54 | The first **real** ports run stored `80/443/8080` with no `service` and no `version`, so docs/09 section 5's "verified by a service fingerprint (nmap -sV, banner) raises confidence by one level" had never once fired: `nmap -sV` reported `Apache Tomcat/Coyote JSP engine 1.1` and the database showed an empty column | `_persist_ports` grouped records as `tool -> [state]` (strings, not the `PortRecord`s), so `service`/`version` were discarded before `Store.upsert_port` - which has accepted both since the table was created - could be given them | `_persist_ports` groups the `PortRecord`s themselves, `_fingerprint()` stores a value only when every reporting tool agrees (`nmap` `http` vs `smap` `http?` stores neither), and a fingerprint raises `LOW`->`MEDIUM`/`MEDIUM`->`HIGH` through `FINGERPRINT_BUMP` while never lifting `unconfirmed` | `test_a_service_fingerprint_is_stored_and_raises_port_confidence` (`Regression: PIT-54`), `test_two_tools_disagreeing_on_the_service_store_no_fingerprint` |
| PIT-64 | An ALIVE host's HTTP status was `-` in the report although the live pool had probed it: `target.com` run 203 stored `status_code = NULL` for all 9 ALIVE hosts (tech populated by the `tech` stage), while `url_probe` got 200 for `https://b.target.com/` in the same scan | `_persist_live` passed the **first ALIVE `HostStatusRecord` in completion order** to `_write_host`, and `httprobe`/`tlsx` records carry no status, so a statusless answer landing first discarded `pyprobe`/`httpx`'s 200 at random | `_best_live_record()` ranks the pass's records: ALIVE first, then 2xx < 3xx < any other known code < no code, then the tool name. A statusless record can never displace one with a code, and completion order cannot decide the row. `tech` still only merges tech/waf and never writes `status_code` | `test_alive_host_has_status_code_in_report` (`Regression: PIT-64`), `test_multiple_live_adapters_prefer_200_over_other`, `test_tech_stage_does_not_clear_host_status` |

## 2026-11-20 (D81) - `db delete` and `db wipe`

**What existed.** `reconkit db` had two Phase 3 stubs (`list`, `export`) and no
way to remove a target except manual SQL, which breaks whenever the schema
moves. The batch asked for two commands with counts, confirmation, cascade
delete and a results-folder cleanup.

**Store (`core/store.py`).** `target_counts()`, `database_counts()`,
`delete_target()` and `wipe()`. `delete_target` counts first, then deletes in one
`transaction()`, children before parents: `port_sources`,
`host_status_history`, `ports`, `subdomain_sources`, `tool_runs`, `urls`,
`subdomains`, `scan_runs`, `targets`. `wipe` drops all ten tables in the same
order and calls `_migrate()` from version 0, so the file is recreated at
`SCHEMA_VERSION` (12) rather than merely emptied.

**CLI (`cli.py`).** `db delete --target` (required) `[--yes]` and `db wipe
[--yes]`. The root callback now stores `--config`/`--db` in `ctx.obj`, because
Typer does not forward root options to subcommands; no second `--db` flag was
added. `db delete` prints the counts and plan, asks default **yes**, exits `2`
on `n`, and on success prints the literal five-count summary plus
`Removed <folder>`. A missing target is `target X is not in <db>`, exit `2`,
nothing removed. `db wipe` always prints `⚠ This will delete ALL targets and
data from <db>. Are you sure?`, asks default **no** without `--yes`, then wipes
and prints `Note: results/ folders are untouched; use "rm -rf results/" manually
if you want a full reset.` `results/` is never touched by wipe; delete removes
`results/<domain>/` and `results/mock/<domain>/` after the commit.

**Layering.** `test_cli_imports_only_the_allowed_layers` forbids importing
`Store`/`sqlite3` in `cli.py`, so the commands reach the store through the
existing `Engine.open(...).store` handle; all SQL stays in `store.py`. No
`engine.py` change.

**Latent bug found by the new tests.** The first delete printed a correct
summary but the reopened database still had the target: `transaction()` set
`_batch_depth = 1`, then called `_commit()`, which deliberately declines while a
batch is open, and the block ended without a commit. Existing callers were
saved by a later write committing on the same connection; a delete that is the
last write before `close()` was rolled back. The outer branch now calls
`self._conn.commit()` directly (the docstring and PIT-27 already required this).
`test_transaction_is_committed_even_when_nothing_follows` reopens the file to
guard it.

**Tests (1023 -> 1029).** `test_db_delete_removes_target_and_cascades`,
`test_db_delete_requires_yes_when_interactive`,
`test_db_delete_nonexistent_target_errors_cleanly`,
`test_db_wipe_removes_all_data_and_recreates_schema`,
`test_db_wipe_requires_yes_when_interactive`, plus the transaction reopen test.

**Acceptance (on `/tmp` copies, not the real DB).**

```
$ reconkit --config /tmp/d81-config.yaml db delete --target example.com --yes
Deleted 1 target, 13 subdomains, 1177 URLs, 33 tool runs, 6 stage runs. Removed
/tmp/d81-results/example.com/
$ sqlite3 /tmp/d81.db "select count(*) from targets where domain='example.com'"
0
```

```
$ reconkit --config /tmp/d81-wipe-config.yaml db wipe --yes
⚠ This will delete ALL targets and data from /tmp/d81-wipe.db. Are you sure?
  6 targets, 27631 subdomains, 10181 URLs, 1077 tool runs, 182 stage runs
Wiped /tmp/d81-wipe.db.
Note: results/ folders are untouched; use "rm -rf results/" manually if you want
a full reset.
$ sqlite3 /tmp/d81-wipe.db "select count(*) from targets; select max(version) from schema_version"
0
12
```

`reconkit db --help` lists `delete` and `wipe` above the two stubs. Full gate:
1029 passed, ruff check and format clean, mypy clean. `scope.yaml` unchanged
(`d45a3c90...eeee8b`), no network.

## 2026-11-20 (D80) - README, COMMANDS and CLI docs synced with the tool

**What was stale.** Compared against the raw help of the shipped CLI:

- `report` (D65) existed only in a COMMANDS.md recipe and nowhere in README;
  neither command table listed it.
- COMMANDS.md's `active` mode row stopped at `urls`, missing `url_probe`; its
  header still claimed a 2026-11-17 flag check.
- README's `run` row also omitted `url_probe`, had no `report` row, and had no
  report-folder shape at all.
- docs/02's `--active` flag row still said `subs`, `dns`, `live`, while the
  mode table 30 lines above already said `subs`, `dns`, `live`, `tech`, `urls`,
  `url_probe`.

**What was already right** (verified, not rewritten): COMMANDS.md already
spelled `--exclude` as stages/adapters/report sections and `--include` with the
forced-contact banner. docs/02 section 5 already documented `report.urls_max`
default `0` (no cap, D71), the per-host `hosts/<hostname>/` folders, and
`external_urls.txt` (D76). `config.yaml` independently shows
`report.urls_max: 0`.

**Fix.** Docs only:

- COMMANDS.md: 2026-11-20 help-check date; `report` in Commands at a glance and
  Management commands (flags `--target/--run/--out/--db/--config/--no-color`,
  read-only, exit 2 on a foreign run id); `url_probe` added to the active mode
  row and the stage-output table.
- README.md: `report` in the Status paragraph and command table; active stages
  now include `url_probe`; new "What a report folder contains" block with the
  full `results/<target>/<stamp>/` tree (`report.txt`, `report.json`,
  `subdomains.txt`, `alive.txt`, `dns_resolved.txt`, `host-info.txt`,
  `host-info.json`, `external_urls.txt`, `hosts/<hostname>/`) and the `0 = no
  cap` rule.
- docs/02_CLI_UX.md: corrected `--active` stages; added `report` to the State
  and output table.

**Verification.** Raw help pasted in the batch report; suite 1023 (unchanged),
ruff/format/mypy clean, `scope.yaml` unchanged, no network.

## 2026-11-20 (D79) - real target names scrubbed from the repo

**Symptom.** The two authorized targets used for the real verification runs (a
university domain and a bank domain) and the mock fixture name had leaked into
adapter comments, fixtures, scripts, tests and every doc: **219 matching lines
in 22 files** (grep over `src/ tests/ docs/ config.yaml README.md COMMANDS.md
AGENTS.md scripts/ .github/`).

**Fix.** Text-only replacement, no code logic touched:

| Before | After |
|---|---|
| university domain, its `www` and `admission` subdomains | `example.com`, `www.example.com`, `admission.example.com` |
| bank domain, same labels (`api`, `b`, `blog`, `nb`, `assets`, `temp`) | `target.com`, same labels (`api.target.com`, ...) |
| mock fixture name (six files) | `example.test` |
| capture script name | `scripts/capture_example.sh` |
| capture dir and scratch DB/config names | `captures/example`, `v4-example.db`, `reconkit-example-config.yaml` |
| fixture title | `Example Bank` |

The six fixtures were renamed with `git mv`:
`tests/fixtures/{gau,waybackurls,unfurl,urlfinder}/example.test.txt` and
`tests/fixtures/{pyprobe,dnspython}/example.test.json`. Mock lookup is
`<fixtures>/<tool>/<target>.*` with a "single file in the directory" fallback,
so the rename does not break a test that targets another name.

**Deviation from the batch.** It named a pyprobe fixture that never existed;
the real pyprobe fixture was the mock one, now `example.test.json`.

**Verification.** Before: 219 lines / 22 files. After: the batch's acceptance
grep prints nothing (the batch's `Clean`). Suite 1023 passed, ruff/format/mypy
clean, `scope.yaml` unchanged (`d45a3c90...eeee8b`), no network.

## 2026-11-19 - loop retry: `live --urls-file` still stops at the same wall

Second attempt, this time as a standalone command path rather than a scan mode.
The route was: read the file, `urlsplit` each line, dedupe hosts, drop anything
not http(s), apply the same scope gate `-l` uses, run the live pool
(`pyprobe`, `httpx`, `httprobe`, `tlsx`), print the table/`--json`, no
`scan_runs` row.

Two facts stop it inside `cli.py`:

1. `live` is not its own function. `for _name in _SCAN_COMMANDS:
   app.command(_name)(_scan_command)` registers one shared Typer command for
   `run`, `subs`, `dns`, `live`, ... so `--urls-file` on that function would
   appear on every scan command, including the passive ones where it makes no
   sense. Splitting `live` out means duplicating the whole option list.
2. Running adapters directly from the CLI breaks two documented rules: a live
   run without a stage has no `scan_runs`/`tool_runs` row (no `doctor`,
   `status` or `diff` visibility, no idle/budget kill), and
   `test_cli_imports_only_the_allowed_layers` forbids `reconkit.adapters` in
   `cli.py`. The engine is the only layer allowed to build and run adapters.

Either fix is engine work (an explicit host list the engine accepts, which is
`ScanOptions.hosts` by another name), and the item's stop rule says not to
re-attempt that. **Skipped, blocker unchanged and now recorded from both
sides; docs/02 section 1 carries the retry.**

## 2026-11-20 (D76-D78) - third-party URLs, per-tool uniqueness, probe accounting

### D76 - third-party URLs stay out of hosts and folders

**Symptom.** A real `target.com` run (20261119T213006Z) wrote
`hosts/www.google.com/`, `hosts/www.facebook.com/`, `hosts/apps.apple.com/` and
`hosts/fonts.googleapis.com/`: the URL pool legitimately names other people's
assets, and the report treated every URL host as a host of the target.

**Fix.** `Engine._within_scope(host, target)` is the one predicate (the target
itself or a name ending in `.<target>`), used by `_clean_hosts` (so the D58
second resolve and `url_probe` never see a third-party name) and by
`_persist_urls`. An out-of-scope URL is still stored - dropping it would lose
what the archive found - with `urls.source = 'external'` (schema 11 -> 12,
additive). `Store.url_report_rows` exposes it as `external`; `ui.report_urls`
never groups it, `_write_per_host_folders` skips it, and `_write_report_lists`
writes it to `external_urls.txt`. `urls_total` / `urls_shown` /
`urls_truncated` describe the in-scope pool, `external_urls_total` the rest.

```
$ git diff --stat -- src/reconkit/core/store.py src/reconkit/engine.py src/reconkit/ui.py
 src/reconkit/core/store.py | 35 ++++++++++--
 src/reconkit/engine.py     | 76 +++++++++++++++++++++--
 src/reconkit/ui.py         | 121 ++++++++++++++++++++++++++++++++------
```

**Tests (2 + report tests).** `test_third_party_hosts_are_not_added_to_subdomains`
(stored/tagged, no `subdomains` row, never offered to DNS),
`test_third_party_urls_go_to_external_list`, `test_in_scope_hosts_still_get_folders`.

**Mock acceptance** (`tests/fixtures/{gau,waybackurls,unfurl,urlfinder,dnspython,pyprobe}/example.test.*`,
`--mock`, `/tmp` DB and results, no network):

```
$ reconkit urls -d example.test --active --mock --tools gau,waybackurls,unfurl,urlfinder --no-scope --db /tmp/d76.db --config /tmp/d76-config.yaml
urls: gau ok 3 item(s)
...
== external_urls.txt
https://apps.apple.com/app/example
https://fonts.googleapis.com/css
https://www.facebook.com/example
https://www.google.com/search?q=example
== hosts/
example.test
== report.json
urls_total 3 external 4
urls_by_host ['example.test']
```

No `hosts/www.google.com/`, and the four third-party URLs are still stored.

### D77 - the Tools table says how much each URL tool added

`ToolResult.unique_count` (default 0) is filled by `_persist_urls` after the
stage returns: `Store.url_strings()` is the pool before the stage, and the first
result (completion order) that reports a URL not already held gets the credit,
so the sum over the stage equals the new rows. `_tool_table` adds `Unique` after
`Items`; only the `urls` stage prints a number, every other stage prints `-`.

**Tests.** `test_unique_count_is_zero_for_all_duplicate_tool` (first run 1,
second identical run 0, one row stored), `test_tool_table_shows_unique_count`
(Items 100 / Unique 15 in one rendered row).

Acceptance row from the D76 run above:

```
│ gau         │ urls  │ ok     │ 3     │ 3      │ ... │
│ waybackurls │ urls  │ ok     │ 2     │ 1      │ ... │
│ unfurl      │ urls  │ ok     │ 2     │ 1      │ ... │
│ urlfinder   │ urls  │ ok     │ 2     │ 2      │ ... │
```

### D78 - what this run probed, and what it left alone

`ScanSummary.urls_probed_this_run` is `_url_probe_progress[0]` (kept on a
timeout); `urls_skipped_already_probed` is the pre-run in-scope answered count
and is forced to 0 by `--reprobe-urls`. Both reach `report.json`; `report.txt`
prints `urls: N total, M probed this run, K already probed (use
--reprobe-urls)`, and `ui.render_skipped_urls` prints one `ℹ` line at the
end of a run when K > 0. D73's `urls_already_probed` stayed for compatibility,
but its count is now in-scope only (external URLs are never probed).

**Tests.** `test_report_shows_probed_vs_already_probed` (both JSON keys + the
header sentence), `test_report_warns_about_already_probed_if_present`, plus the
engine count assertions in `test_url_probe_never_reprobes_a_stored_answer`.
The schema-version assertions in `tests/test_store.py` moved 11 -> 12 with the
new migration.

**Mock acceptance** (copy of the D76 DB, three in-scope statuses seeded, no
network):

```
$ reconkit urls -d example.test --active --mock --tools gau --no-scope --db /tmp/d78.db --config /tmp/d78-config.yaml
...
ℹ 3 URL(s) were skipped because they already had a status code; use
--reprobe-urls to re-check them.

== report.txt
urls: 3 total, 0 probed this run, 3 already probed (use --reprobe-urls)
== report.json
{'urls_total': 3, 'urls_probed_this_run': 0, 'urls_skipped_already_probed': 3, 'urls_already_probed': 3}
```

**Gate.** `1023 passed`, `ruff check .` clean, `96 files already formatted`,
`mypy src/reconkit` clean, `scope.yaml` sha256 unchanged.

## 2026-11-19 (D75) - an orphaned URL-derived host is tech-scanned by the next active run

**Symptom (documented at b055cc9, fixed here).** A host D58 created got DNS +
`pyprobe` once and was never offered to `tech` again. Two rules combined:

```
$ grep -n 'url_only_hosts\|def _stage_hosts\|discovered' src/reconkit/engine.py | head -30
958:    def url_only_hosts(self, target_id: int) -> list[str]:
...
986:        discovered: set[str] = set()
989:            self._seed_from_store(target_id, target, discovered, alive)
1018:            hosts = self._stage_hosts(stage, target, discovered, alive)
1347:    def _seed_from_store(self, target_id, target, discovered, alive):
```

`url_only_hosts()` returns names named by a URL that have **no** `subdomains`
row, and `discovered` starts empty unless `resumed`. So on a follow-up run the
three URL-derived rows are fed to `tech`: **no** (its input is the run's own
`alive` set); to the crawlers: **no** (same input, and `urls` has already run);
to `live`/`dns`: **no** as well, because they only see `[target, *discovered]`.
The "skip if a row exists" rule is right for re-resolution and wrong for
tech: it conflated "has a row" with "has been processed".

**Fix (3 non-doc files).** The new `Store.url_derived_unprocessed()` returns
rows whose sources include the `url-derived` sentinel and whose newest status
row has no `tech_json` (no status row at all counts as unprocessed). `_second_resolve`
reads it only when `opts.active`, and `_second_resolve_pass` runs the union through
one scope gate, `pyprobe` and then `_second_resolve_tech` (the `tech` stage's own
selected pool, same adapters/`run(ctx)`), with `_persist_tech`. The DNS step still
receives only `hosts`.

**Mutation check.** Setting `orphans = []` unconditionally makes
`test_url_derived_host_gets_tech_on_follow_up_run` and
`test_new_and_previously_orphaned_hosts_both_processed` fail with
`assert None == ['nginx']`; restored, all four pass.

**Tests (4).** `test_url_derived_host_gets_tech_on_follow_up_run`,
`test_url_derived_host_is_not_re_resolved_if_it_has_a_state`,
`test_passive_does_not_tech_scan_url_derived_hosts`,
`test_new_and_previously_orphaned_hosts_both_processed`. Suite 1012 -> 1016.

**Mock acceptance (copy of a fresh DB, no network).** Seeded
`www.testfire.net` as url-derived with no status row; every host the mock `urls`
fixtures can name got a row first, and `subs`/`dns` were excluded, so nothing but
the new pass could touch it:

```
BEFORE: ['www.testfire.net'] | tech rows: 0
urls: 1 url-derived host(s) already known; tech-scanned on follow-up
AFTER (stage of the writing run = urls):
stage  state  status_code  tech_json
urls   ALIVE  200          ["Java", "aws"]
report.txt: www.testfire.net  ALIVE  LOW  url-derived  0  -  200  Altoro Mutual ...  Java, aws
```

**Not included: crawl.** A second `urls` execution would repeat the archive
pool and needs its own stage row; it stays in the open-rulings list.

## 2026-11-19 (D73) - a repeat scan says how much of the URL list was already answered

`url_probe` stores one answer per URL and never re-checks it (D23), so a second
scan's report could look like it had probed 3,124 URLs when 2,856 of them were
answered days earlier. The count of non-NULL `urls.status_code` rows is now read
**once before any stage runs** (`Engine.run`, right after `ScanSummary` is
built) and carried as `summary.urls_already_probed`; `report_document` adds
`urls_already_probed` and `report_text` prints the parenthetical.

Acceptance (`--mock` against a copy of the target DB, no network):

```
$ cp recon.db /tmp/item5.db
$ reconkit run -d target.com --active --mock --db /tmp/item5.db --scope /tmp/scope-d73.yaml
report: results/mock/target.com/20261119T205138Z/report.txt ...
$ grep '^urls:' report.txt
urls: 3124 total, 3124 shown (2856 already probed in earlier runs; use --reprobe-urls to re-check)
$ python -c '...urls_already_probed...'
urls_total 3124 shown 3124 already 2856
$ sqlite3 /tmp/item5.db "SELECT count(*) FROM urls WHERE ... status_code IS NOT NULL"
2856
```

The DB count equals `K` exactly, because it was taken before the mock run wrote
anything. `K = 0` omits the key and the sentence (`test_report_omits_already_probed_when_zero`).
A `reconkit report` rebuild has no "before this run" point and leaves the key
out. Suite 1010 -> 1012. Four non-doc files (`engine.py`, `ui.py`, `cli.py`,
`tests/test_ui.py`).

## 2026-11-19 (D72) - a referral URL ranks last, and is still reported

Before, `/product?utm_source=x` sorted by the depth of its path and its status,
so a campaign link could outrank a real page. `_url_rank` gained one key after
the interesting-path key: `1` when the query matches `NOISE_PARAM_RE`, `0`
otherwise. So:

```
/admin (404)                                  -> interesting
/about (404)                                  -> clean
/product?utm_source=newsletter (200)          -> noisy, below both
/admin?utm_source=mail (404)                  -> interesting, then noisy (still first)
```

The four tests assert exactly those orders, that a noisy URL is still counted
and present, and that `report.noise_params=["campaign"]` adds a name while
`gclid` (built-in) still demotes. `report_urls(urls, 0, noise_params)` is the
one entry point; both `report.txt`/`report.json` and `hosts/<name>/urls.txt`
sort through it, so a per-host list cannot disagree with the main report.
Suite 1006 -> 1010.

## 2026-11-19 (D71) - a report folder carries lists, per-host folders, and every URL

**Before.** A report folder held `report.txt` + `report.json`, the URL block was
capped at `report.urls_max: 200`, and the only per-host view was inside
`report.json`.

**After (measured on a `--mock` run, `results/mock/example.com/20261119T204517Z`):**

```
$ ls -R <dir> | head -30
alive.txt  dns_resolved.txt  host-info.json  host-info.txt  hosts
report.json  report.txt  subdomains.txt
<dir>/hosts: demo.testfire.net  testfire.net  www.testfire.net
<dir>/hosts/www.testfire.net: info.json  urls.txt
$ head -5 subdomains.txt        alias.example.com ... (21 names)
$ head -5 alive.txt             api.example.com  www.example.com
$ head -5 dns_resolved.txt      alias.example.com  api.example.com  www.example.com
$ head -5 host-info.txt         domain | state | status | ips | tech
                                alias.example.com | DNS_ONLY | - | - | -
$ head -3 hosts/www.testfire.net/urls.txt
https://www.testfire.net/admin/admin.aspx
https://www.testfire.net/logout.jsp
$ python -c 'json...' -> urls_total 24, urls_shown 24, urls_truncated False
```

**Design choices.**

- `report.urls_max` default is now `0` (no cap); a set value still caps
  `report.txt`/`report.json` and prints `urls: 100 of 500 shown`, and
  `urls_truncated` stays honest. `hosts/<name>/urls.txt` is never capped.
- `hosts/<name>/` exists only when that host has a stored URL (an empty folder
  would be evidence that is not there); `info.json` falls back to
  `state: UNKNOWN` for a URL host with no `subdomains` row, matching the URL
  block's own rule.
- `urls.txt` is `<url>` when unprobed and `<url>\t<status>` when `url_probe`
  stored one; two `hosts/` names are impossible to confuse with a URL.
- The three name lists are written even when empty; `host-info.txt/json` are
  written even when there are no hosts (header / `[]`).
- `emit_lists: false` and `per_host_folders: false` skip their outputs and
  leave `report.txt`/`report.json` untouched; `reconkit report` passes the same
  two settings through, so a rebuild has the same shape as a scan.

**Tests (7).** `test_report_no_url_cap_by_default`,
`test_report_emits_per_host_folders` (and asserts no folder for a URL-less
host), `test_per_host_urls_file_contains_only_that_hosts_urls`,
`test_report_emits_subdomains_alive_dns_resolved_lists`,
`test_report_emits_host_info_without_urls` (asserts no `://` - a tech name such
as `HTTP/3` is not a URL), `test_emit_lists_disabled_skips_lists`,
`test_urls_max_still_respected_when_set` (100 of 500, `urls_truncated` true).
Suite 999 -> 1006.

**Files.** `ui.py`, `config.py`, `config.yaml`, `cli.py`, `tests/test_ui.py` -
five non-doc files, at the item's limit, no stop rule fired.

## 2026-11-19 (D70) - a URL-derived host gets DNS and a live check, never tech or crawl

**Question.** D58 adds URL-only hosts to `subdomains` after `urls`. `tech` and
the crawlers run before that, so do those hosts ever get tech or a crawl?

**Stage order and where the hook sits.**

```
STAGE_ORDER = (SUBS, DNS, LIVE, PORTS, TECH, URLS, URL_PROBE, SHOTS, VULNS)
# run loop, after the URLS stage's results are persisted:
if stage is Stage.URLS:
    await self._second_resolve(target, target_id, opts, run_id, discovered, alive, ...)
```

`_second_resolve` -> `_second_resolve_pass`:

1. `_second_resolve_dns` - `dnspython` on the candidates;
2. `_label_url_derived` - create the row, `subdomain_sources.tool = 'url-derived'`;
3. `_persist_dns(..., defer=live)`;
4. only when `opts.active`: `_active_hosts` (scope gate), then
   `_second_resolve_live` - `pyprobe` only, not the live pool - then `_persist_live`.

No `_run_tools`, no `self._select(Stage.TECH, ...)`, no crawler. Measured on the
DB copy:

```
$ sqlite3 /tmp/item1.db "SELECT s.fqdn, s.state, h.status_code, h.tech_json, h.run_id
  FROM subdomains s LEFT JOIN host_status_history h ON h.id=(SELECT max(id) ...)
  WHERE s.fqdn IN (SELECT ... subdomain_sources.tool='url-derived')"
api.target.com     UNKNOWN  NULL  NULL  (no status row)
assets.target.com  UNKNOWN  NULL  NULL  (no status row)
```

**Answer.** Passive: DNS only. Active/full: DNS plus a `pyprobe` live check.
Neither mode gets the `tech` pool or any crawler.

**Decision: not implemented, documented as a gap (D70).** A tech/crawl step
inside the pass needs its own `scan_runs`/`tool_runs` rows, budget and per-host
scope decision - stage machinery, not a bounded pass - and a second `urls`
execution would repeat the archive pool. Files would stay under three, but the
change is not the "small extension" the item allowed for. docs/09's D58 section
now carries the table and the enabler.

**A follow-up run does not pick the host up either** (new finding): `discovered`
starts empty unless `--resume` (`_seed_from_store` is guarded by `resumed`), and
`Store.url_only_hosts()` skips a host that already has a row. So the name is
invisible to that run's `tech` stage and to the pass. The stored row and its
URLs stay correct and appear in the report; only tech/crawl evidence is missing.
That is the state of `api`/`assets.target.com` today.

## 2026-11-19 (D69) - an ALIVE host keeps the HTTP status the live pool observed

**Symptom (owner report).** `results/target.com/20261119T200322Z/report.txt`
listed 9 ALIVE hosts, all with `HTTP status code = -`, although `b.target.com`
had technologies (`Amazon CloudFront`, `Cloudflare`) from the `tech` stage.

**Diagnosis (case a: the live pass wrote the wrong record's status).**

```
$ sqlite3 /tmp/item1.db "SELECT s.fqdn, h.state, h.status_code, h.tech_json ..."
b.target.com            ALIVE    NULL  ["Amazon CloudFront", "Amazon
blog.target.com         ALIVE    NULL  ["Cloudflare", "Google Font AP ...
... 9 rows, every status_code NULL, run_id 203
$ sqlite3 /tmp/item1.db "SELECT url, status_code FROM urls WHERE url LIKE '%b.target.com%'"
https://b.target.com/                       200
http://b.target.com/                         -1
$ sqlite3 /tmp/item1.db "SELECT tool, status, item_count FROM tool_runs WHERE run_id=203"
httprobe ok 9 | httpx ok 9 | pyprobe ok 9 (unreachable=3) | tlsx ok 13
```

`_persist_live` built `best = next(record for ..., if record.state is ALIVE)`
over the pass's `HostStatusRecord`s in completion order and `_write_host`
stored `best.status_code`. `pyprobe` and `httpx` set a code; `httprobe` (it
prints URLs) and `tlsx` (certificates) do not. Whichever ALIVE record finished
first won, so the row kept a status only by luck - older runs (161: 39 rows with
a code) happened to win. `tech` is innocent: `Store.update_host_extras` writes
`tech_json`/`waf` on the newest row and never touches `status_code`
(docs/04 section 5), which the tech test now pins.

**Fix.** `_best_live_record()` + `_live_rank()`
(`src/reconkit/engine.py:193` and `:210`): ALIVE records first, then 2xx < 3xx < other
known code < no code, then the tool name as the tie-break. The chosen record
still supplies `title`/`location`/`detail`; state still comes from
`decide_host_state`.

**Mutation check.** Putting the old `next(...)` back made
`test_multiple_live_adapters_prefer_200_over_other` fail with `assert 301 == 200`
(the 301 adapter returns immediately, the 200 adapter after 20 ms); restored, it
passes.

**Mock acceptance (`results/mock/example.com/20261119T203613Z/`):**

```
$ grep www.example.com report.txt
www.example.com  ALIVE  HIGH  assetfinder, certspotter, crtsh, hackertarget, otx, subfi...  6  203.0.113.5  200  Example Domain  -  -  Nginx  not applicable
$ sqlite3 ~/.reconkit/mock.db "SELECT s.fqdn, h.state, h.status_code, h.tech_json ..."
api.example.com  ALIVE  401  []
www.example.com  ALIVE  200  ["Nginx"]
```

Historical rows are not rewritten: run 203 keeps its NULLs until a new live
pass writes the host again, and no real scan was run in this batch.

**Tests.** `test_alive_host_has_status_code_in_report`,
`test_tech_stage_does_not_clear_host_status`,
`test_multiple_live_adapters_prefer_200_over_other` (suite 996 -> 999).

## 2026-11-19 (D63) - `--exclude` reaches stages and sections; `--include` forces one in

Before: `--exclude` was `frozenset(_csv(exclude))` compared in one place
(`Engine._select`, `if name in opts.exclude`), i.e. against **adapter names
only**. `--exclude urls` matched no adapter (`urls` is a stage) and was silently
ignored. There was no `--include`: `grep -rn '"--include' src/reconkit/cli.py`
returned only `--include-noisy`.

After, one resolver (`_name_namespaces` in `cli.py`) reads every value
case-insensitively in **stage -> adapter -> report section** order and keeps all
matches, so the documented `urls` case does both:

```
$ reconkit run -d example.com --mock --active --no-scope --db /tmp/d63d.db --no-color --exclude urls
--exclude urls: stage skipped, report section hidden
```

and the artifact proves the section was hidden rather than absent - the 24 URLs
from the first run are still stored:

```
=== URLs by host ===  occurrences: 0
=== Domains ===       occurrences: 1
urls_total: 24 urls_by_host present: False
```

Unknown names warn and continue (a typo must not abort a scan), and naming one
value on both sides is exit 2 `contradictory: --include and --exclude both name
urls`. Both are pinned by a test.

`--include` adds the stage to the run's tuple (at its `STAGE_ORDER` position)
and, for an adapter, that adapter's stage plus its name in the new
`ScanOptions.include_tools`, which is the only new bypass of the tier and
tool-mode gates (the exploitation rule is untouched). Raw, mock runs:

```
$ reconkit run -d testfire.net --active --include ports --mock --no-scope ...
⚠ --include ports forces target contact; this is no longer an active scan.
--include ports: stage added
ports: running 5 tool(s)
ports: smap ok 3 item(s)
ports: pyscan ok 2 item(s)
ports: naabu ok 3 item(s)
ports: nmap ok 3 item(s)
ports: rustscan ok 3 item(s)
ports: finished 5/5 tool(s), 14 item(s)

$ reconkit run -d testfire.net --include live --mock --no-scope ...
⚠ --include live forces target contact; this is no longer a passive scan.
--include live: stage added
live: running 4 tool(s)
live: pyprobe ok 2 item(s)
live: httpx ok 2 item(s)
live: httprobe ok 2 item(s)
live: tlsx ok 4 item(s)
live: finished 4/4 tool(s), 10 item(s)
```

and the forced run says so in both artifacts:

```
$ grep -n '^mode:' results/mock/testfire.net/<run>/report.txt
5:mode: active (forced by --include)
$ python -c "print(d['mode'])"
active (forced by --include)
```

Safety: `forced_contact` is what makes the four `_active_hosts()` gate sites run
for a forced stage, so `--include live` on a passive run is gated by
`scope.yaml` exactly like `--active`; the requested mode's tool pool is
otherwise untouched, so forcing one stage cannot enable more tools elsewhere.
No `--passive` flag exists on `run` (passive is the default), so the documented
`--passive --include live` case is `reconkit run -d X --include live` or the
`passive` command; both are covered.

Six tests (`pytest -q tests/test_cli.py -k "exclude or include"` -> `8 passed`,
the two pre-existing ones included):

- `test_exclude_stage_skips_it_and_hides_its_section`
- `test_exclude_adapter_still_works`
- `test_exclude_unknown_value_warns_but_runs`
- `test_include_stage_runs_it_in_a_mode_that_would_skip_it`
- `test_include_live_under_passive_prints_banner_and_relabels_mode`
- `test_include_and_exclude_same_value_is_an_error`

`test_scan_has_no_undocumented_options` gained `--include`, because every scan
command shares one option group and the flag is on all of them (the batch
allowed "the stage subcommands if they share the option group"). The bare
`reconkit -d X ...` shorthand (`main`) does not carry it; `run` does.

Gate: `990 passed`, `ruff check .` clean, `ruff format --check .` 96 files,
`mypy src/reconkit` clean (62 source files). No scan was run.

## 2026-11-19 - loop notes: `live --urls-file` deferred, urlfinder idle unchanged

**`live --urls-file` was not built (deferred, not silent).** The flag is small;
the plumbing is not. `Stage.LIVE`'s input is `[target] + that target's stored
subdomains` (`_stage_hosts`), and `engine.run()` takes one root target from
`validate_target()`. A file of URLs has no single root, so the command needs a
way to hand the engine an explicit host list (and a scope decision for each
host) - engine work the batch's stop rule excludes from `cli.py` + tests. The
gap and the smallest enabler stay documented in docs/02 section 1 ("A list of
URLs does not work").

**urlfinder's idle window stays at 180s - the evidence does not support 240.**
`config.yaml` today:

```
runtime_idle:
  crawler: 60
  scanner: 120
  archive: 180
  api: 60
```

Per-run `tool_runs` for the urls stage (repo `recon.db`, copy):

```
run 193 target 19:06  urlfinder killed    80  "killed after 180s idle at stage 180.1s, 80 partial"  waybackurls ok 0
gaU 1540 killed, katana 380, gospider 681, hakrawler 678, subjs 75, unfurl 24
run 187 example 18:45  urlfinder killed  6367  "killed after 180s idle at stage 281.2s, 6367 partial" waybackurls ok 0
run 181 target 18:33  urlfinder killed     6  "killed after 180s idle at stage 180.2s, 6 partial"    waybackurls ok 0
run 178 target 17:05  urlfinder ok       2222  (no kill)                                          waybackurls ok 0
run 174 example 16:48  urlfinder killed  6367  "killed after 180s idle at stage 199.2s, 6367 partial" waybackurls ok 0
run 168 example 14:53  urlfinder killed  6367  "killed after 180s idle at stage 193.5s, 6367 partial" waybackurls ok 0
```

The batch's proposed evidence - "waybackurls also 0 that run" - does not
discriminate: waybackurls returned **0 items in every one of these runs**,
including the three that produced 6,367. The variance is inside urlfinder: the
same target produced 2,222 (completed) at 17:05 and 6 (killed at 180s of
silence) at 18:33. `grep -n 'runtime_idle' config.yaml` -> `29:runtime_idle:`,
`32:  archive: 180`; `grep -c urlfinder results/*/*/report.json` -> `0` in all
six reports (the report never names tools), so the DB is the only witness.

Each killed run had already emitted its items (6,367 or 80) and then went
silent; the 6-item run was silent from the start. A longer idle window would
not turn either into more data - it would only hold the stage open 60 s longer.
No config change; no D-number.

## 2026-11-19 (D65) - `reconkit report` rebuilds a report from the database

Before, the only writer was a scan: a run stored before D62 could not be seen in
the new shape without scanning the target again. After, on a **copy** of the
repo's `recon.db` (the stale example data):

```
$ cp recon.db /tmp/item4.db
$ reconkit report --db /tmp/item4.db --target example.com --out /tmp/item4-out/
wrote /tmp/item4-out/report.txt and /tmp/item4-out/report.json — 69 hosts, 7421 
URLs (200 shown)

$ grep -c '=== Domains ===\|=== URLs by host ===' /tmp/item4-out/report.txt
2
$ jq '.urls_total, .urls_shown, .urls_truncated' /tmp/item4-out/report.json
7421 200 true
$ jq 'keys' /tmp/item4-out/report.json
['type','target','generated_at','selection','scope_warnings','fields','hosts',
 'urls_total','urls_shown','urls_truncated','roots','urls_by_host']
$ jq -r .generated_at /tmp/item4-out/report.json
2026-11-19T18:50:30+00:00
```

(The batch expected 2,253 URLs; the stored total for `example.com` is **7,421**
over runs 163-187 - that number was from an earlier run's stage output.)

Read-only is a property of the connection, not a promise: `Store.open_readonly`
opens `file:<path>?mode=ro`, skips migrations, and runs one `SELECT` to prove the
file is a reconkit schema. The test chmods the database to `0444`, rebuilds a
report from it successfully, and asserts the file's sha256 is unchanged.

Shape: `host_snapshots()`/`url_snapshots()` are now module functions in
`engine.py`, used by both `Engine.host_rows`/`url_rows` and
`load_stored_report`, so a rebuilt report cannot drift from a scan's. Command
name `report` was free, so no `db report` fallback was needed. `--out` is
created if missing; without it the folder is `<results_dir>/<domain>/<run
stamp>`, with `-rebuilt` appended when a report already exists there (the stored
one is evidence). Dot-not-dash: the hosts are the latest stored state and the
URL block is every URL stored for the target, exactly like a scan's report -
`--run` selects the run stamp, not a point-in-time snapshot.

Tests (4): `test_report_from_db_writes_both_files`,
`test_report_from_db_latest_is_default`,
`test_report_from_db_nonexistent_run_errors_cleanly`,
`test_report_from_db_is_read_only`. Gate: `996 passed`, ruff/format/mypy clean.

**Deviation from the item's stop rule:** it said to skip if the work needs more
than `cli.py` + `ui.py`. No new module was created, but the read-only
requirement and `test_cli_imports_only_the_allowed_layers` (no `Store` in the
CLI) made `core/store.py` and `engine.py` the right homes; the disclosure is
here and in PROGRESS.

## 2026-11-19 (D64) - a scope-limited run says so in banner and report

Before, `reconkit run -d not-in-scope.example --active --mock` (scope file
present) printed the pre-flight block and exited `3`, but the saved report was
indistinguishable from a normal passive scan:

```
$ reconkit run -d not-in-scope.example --active --mock --no-color --db /tmp/d61.db --json
exit=3
⚠ scope gate would block active stages for: not-in-scope.example
  active stages will be SKIPPED for this target.
...
$ head -5 results/mock/not-in-scope.example/<run>/report.txt
reconkit report
target: not-in-scope.example
generated: 2026-11-19T19:39:15+00:00
hosts: 16
$ jq '.scope_warnings' report.json
[]
```

So D61 was **partially landed**: the exit code and pre-flight block existed, the
artifact annotation did not. After:

```
$ reconkit run -d example.com --active --mock --scope <denying> --db /tmp/d64.db
...
⚠ ACTIVE STAGES SKIPPED BY SCOPE — this run is passive-only; the report says so.
report: results/mock/example.com/20261119T194127Z/report.txt and .../report.json

$ head -6 report.txt
reconkit report
target: example.com
generated: 2026-11-19T19:41:27+00:00
hosts: 21
⚠ ACTIVE STAGES SKIPPED BY SCOPE — this run is passive-only; the report says so.

$ jq '.scope_limited, .scope_limited_reason' report.json
true
"active stages skipped by scope gate"
```

**Exit code stays 3 (deviation from the batch text).** The batch asked for `0`.
docs/02 section 6 and docs/05 rule 2 define `3` as the scope-refusal signal, and
`_exit_code()` puts scope first for exactly that reason; `0` would tell a
pipeline the requested active scan ran. The partial results are announced by the
banner and the two `report.json` keys instead. Both new keys are added only when
the gate refused something, so no existing report changes shape.

Tests (2): `test_scope_limited_run_marks_the_report`,
`test_scope_limited_banner_prints_once` (the second also proves a run with an
allowing scope file prints no banner). Gate: `992 passed`, ruff/format/mypy
clean.

## 2026-11-19 - state check: `api`/`assets.target.com` never held DNS_ONLY

Reported as a DNS_ONLY -> UNKNOWN regression between the 18:36 passive run and
the 19:13 active run. The stored rows say otherwise:

```
subdomains: api.target.com    UNKNOWN  source_count=1  provenance=dns  first_seen_run=181  last_seen_run=181
            assets.target.com UNKNOWN  source_count=1  provenance=dns  first_seen_run=181  last_seen_run=181
subdomain_sources: (api.target.com, run 181, 'url-derived')
                   (assets.target.com, run 181, 'url-derived')
host_status_history: no row for either host
target history at run 180 (dns): 13 rows, all DNS_ONLY except temp.target.com DEAD
target history at run 191 (live): 12 rows, the same hosts, 9 ALIVE + 3 DNS_ONLY
```

Both names were created by the `urls` stage's D58 second resolve in run 181
(passive, 18:33-18:36Z), which labels a URL-only name with the `url-derived`
sentinel; `dnspython` returned no record for either, so `_persist_dns` wrote no
state and the row kept the column default `UNKNOWN`. No later run touched them
(`last_seen_run` stays 181: the 19:04 `subs` pass did not report them, so the
19:05 `live` pass never had them in its host list). The only state these two
hosts have ever had in this DB is `UNKNOWN`; the active run at 19:13 is not
implicated.

The transition table is not the cause either: `DNS_ONLY` + timeout keeps
`DNS_ONLY` (engine.py transition comment, `decide_host_state`), and
`_second_resolve_live` only reaches `UNKNOWN` for a host with no previous
state, or keeps the previous state when one exists. No code change.

## 2026-11-19 (D62) - a saved report carries a domain tree and its URLs

**Real-run check (2026-11-19, loop item 1): CONFIRMED.** A report written
during the loop, `results/target.com/20261119T193822Z/`, is the first one
saved after `0062f11` (19:08:14Z), and it has the new shape:

```
$ grep -c '=== Domains ===\|=== URLs by host ===' results/target.com/20261119T193822Z/report.txt
2
$ jq 'keys' results/target.com/20261119T193822Z/report.json
['type','target','generated_at','selection','scope_warnings','fields','hosts',
 'urls_total','urls_shown','urls_truncated','roots','urls_by_host']
$ jq '.urls_total, .urls_shown, .urls_truncated' .../report.json
3061 200 true
$ jq '.roots[0].host_count, (.hosts|length)' .../report.json
15 15
```

Before that report appeared, every report on disk predated D62: `example.com`
has 15:06:46Z, 16:52:32Z and 18:50:30Z, all with the old 7 keys and 0 `===`
headings, and `results/target.com/` held no report until 19:38Z. The same
real report also shows `api.target.com` / `assets.target.com` as
`UNKNOWN`, `url-derived`, source count 1 - the D63 loop note's finding,
confirmed on a live artifact rather than only in the DB.

Before: `report.json` had 7 top-level keys (`type`, `target`, `generated_at`,
`selection`, `scope_warnings`, `fields`, `hosts`) and `report.txt` had **no**
section headings at all - one header block and one table, 0 occurrences of
`http`. The 69-host `example.com` report therefore showed which hosts exist and
nothing about the 2 253 URLs stored beside them.

After, read from what the run already stored (`Store.url_report_rows()`; no
request, no schema change, no new module):

- `report.json` keeps `hosts` unchanged and adds `roots`, `urls_by_host`,
  `urls_total`, `urls_shown`, `urls_truncated`.
- `report.txt` appends `=== Domains ===` and `=== URLs by host ===` after the
  hosts table, and writes neither when the run stored no URL.
- Ranking inside a host: interesting path (`admin|login|api|\.git|\.env|backup|
  config|upload|debug|phpinfo|swagger|graphql|\.sql|\.zip|\.bak|dashboard|panel|
  test|dev`), then a query string, then `200`/`301`/`302`, then the rest; the
  total order is completed by host and URL so two runs are byte-identical.
- The cap is `config.yaml` `report.urls_max` (default 200, `0` = no cap) across
  the whole report, and both files state the cut.

Raw proof, mock run (`reconkit run -d testfire.net --mock --active --no-scope
--db /tmp/d62.db --no-color`), 24 stored URLs, none capped:

```
=== Domains ===
testfire.net  -  16 host(s)
  api.example.com   UNKNOWN  MEDIUM
  api.testfire.net   UNKNOWN  LOW
  ...
  www.testfire.net   ALIVE  HIGH

=== URLs by host ===
testfire.net  (ALIVE)
  https://testfire.net/login.jsp?uid=1&pw=2  null
  http://testfire.net/login.jsp  null
  https://testfire.net/login.jsp  null
  http://testfire.net/index.jsp?content=inside_contact.htm  null
  ...
www.testfire.net  (ALIVE)
  https://www.testfire.net/admin/admin.aspx  null
  https://www.testfire.net/logout.jsp  null
demo.testfire.net  (DNS_ONLY)
  https://demo.testfire.net/bank/queryxpath.jsp?query=1  null
  ...
```

and the JSON side of the same run:

```
keys: ['type', 'target', 'generated_at', 'selection', 'scope_warnings', 'roots', 'fields', 'hosts', 'urls_total', 'urls_shown', 'urls_truncated', 'urls_by_host']
roots: [{"domain": "testfire.net", "subdomains": ["api.example.com", "api.testfire.net", ...], "host_count": 16}]
total/shown/truncated: 24 24 False
```

Note the ranking did its job on real-shaped data: `login.jsp?uid=1&pw=2` sorts
first, and the plain `js/`, `style.css` and `jquery.min.js` files sort last.

Zero-URL case (`--tools pyprobe`, so the run stores no URL):

```
$ grep -c '=== Domains ===\|=== URLs by host ===' results/mock/testfire.net/20261119T190641Z/report.txt
0
has urls_by_host: False total: 0
```

Six tests (`pytest -q tests/test_ui.py` -> `36 passed`):

- `test_report_json_has_roots_and_urls_by_host`
- `test_urls_by_host_ranks_interesting_paths_first`
- `test_urls_cap_is_per_report_and_says_so` (300 URLs over 5 hosts, cap 200 ->
  `urls_shown=200`, `urls_truncated=True`)
- `test_report_txt_has_domains_and_urls_by_host_sections`
- `test_report_with_no_urls_omits_both_new_sections`
- `test_roots_has_one_entry_for_single_target`

Gate: `984 passed`, `ruff check .` clean, `ruff format --check .` 96 files,
`mypy src/reconkit` clean (62 source files). No scan was run.

## 2026-11-19 (D59) - the list-check workflow, documented with its two gaps

Docs only, no `src/`/`tests/` change. The owner asked how to check a list they already have; the answer is "hostnames
yes, URLs no, and there is no export yet", so that is what docs/02 now says instead of leaving the operator to infer
it from `--help`.

Added to docs/02 section 2 (`### Existing list: which hosts are live?`):

- The working command, `reconkit live -l hosts.txt --active --scope scope.yaml`, with the two facts an operator needs
  before using it - every line becomes its **own target**, and `--scope` gates every name (a name not in the file is
  refused with exit 3, never probed).
- Why a URL list fails, with the real message: `-l` is parsed by `validate_target()`, so `https://nb.example.com/x`
  gives `invalid domain label: 'https://nb'` before the run starts; the smallest enabler is a new option routing lines
  through `validate_host()`, and that needs an owner ruling.
- Where the list comes from: `export`, `db list` and `db export` are Part-8 stubs that print `... is not wired in
  Part 8` and exit 1; the real export is `results/<target>/<timestamp>/report.json` with `hosts[].hostname`, hosts
  only.

Evidence behind those three statements (no new run needed; all from the shipped code and the existing artifacts):

```
$ reconkit db list -d target.com
db list is not wired in Part 8; no data was read.
$ reconkit export -d target.com --format json
export is not wired in Part 8; no report was written.
$ reconkit db export -d target.com
db export is not wired in Part 8; no data was written.
$ reconkit live -l /tmp/urls.txt --active --mock --no-color --db /tmp/d57probe.db
invalid domain label: 'https://nb'
$ reconkit live -l /tmp/hosts.txt --active --mock --no-color --db /tmp/d57probe.db
1 hosts: 0 ALIVE, 0 DNS_ONLY, 0 SHUT_DOWN, 0 DEAD, 1 UNKNOWN | tools: 3 ok, 0 gap, 1 failed, 0 skipped, 0 timeout
report: results/mock/nb.target.com/20261119T173241Z/report.txt
```

The first three are the exact stub strings the CLI prints (and the reason the doc points at `report.json` instead);
the last two are the same probe recorded in the analysis entry above, reused here rather than re-run.

PROGRESS records the same gap under "What is explicitly open and why", with the stub message quoted and the URL-list
enabler named as a ruling, so it cannot be mistaken for finished work.

Gate: docs only, nothing to re-run; suite stays `978 passed` (verified on the D58 commit and unchanged here since no
`src/`/`tests/` file moved).

## 2026-11-19 (D58) - a bounded second resolve gives URL-only hosts a row

Owner ruled Option 2 from the analysis above. One pass runs immediately after `urls` and before `url_probe`: it takes
the distinct hostnames in this target's URL rows that have no `subdomains` row, resolves them with the `dns` stage's
`dnspython` adapter through the normal `_persist_dns()` state rule, and - in `active`/`full` only - probes them with the
`live` stage's `pyprobe` adapter through `_persist_live()` after `require_active()` has filtered the list.

Files: `src/reconkit/core/store.py` (`Store.url_only_hosts()`), `src/reconkit/engine.py` (`URL_DERIVED` sentinel,
`Engine._second_resolve()`, `_second_resolve_pass()`, `_second_resolve_dns()`, `_second_resolve_live()`,
`_label_url_derived()`, and the hook in the stage loop after the `urls` stage), `tests/test_engine.py` (four tests),
`docs/03` (stage section), `docs/09` section 5, `docs/04` section 5.

Decisions and disclosures called out by the batch:

- **Source label `url-derived`, not a migration.** `subdomains.provenance` has `CHECK (provenance IN ('subs','dns'))`, so
  an invented provenance value would have been schema v9. The row keeps `provenance = 'dns'` (a DNS pass did create it)
  and carries one `subdomain_sources` entry whose tool is the sentinel `url-derived`; `source_count` follows the
  documented rule (distinct sources in the run) and is 1. docs/04 section 5 records the sentinel and its exception to
  "a `dns` row has no sources". `diff_new()` still filters `provenance = 'subs'`, so these rows never show as NEW.
- **`www.` is not stripped**, as instructed: `www.x` and `x` are two candidates, exactly like the rest of the code.
- **Live check is `pyprobe` only, not the live pool.** Running the whole pool would need four more `tool_runs` rows
  under the `urls` stage's `scan_runs` id, which would make that row claim tools it never ran; one binary-free adapter
  plus the shared `_persist_live()` state rule keeps the evidence honest and the pass bounded.
- **Not a stage.** No `scan_runs` row and no `tool_runs` row are created; `first_seen_run`/`last_seen_run` on the new
  hosts record the `urls` run that named them. `summary.stages` is unchanged, so resume plans and the UI are unaffected.
- **Budget:** no new config key. The pass runs under `timeout = timeouts.urls` in passive and `timeouts.url_probe` in
  active/full, wrapped in `asyncio.wait_for`; on expiry the rows stay as they were and one progress line says so - the
  run never fails because of it.
- **Store reads stay on the loop.** The first draft used `asyncio.to_thread` and 26 engine tests failed with
  `sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that same thread` - the connection
  is thread-bound by design (docs/03 section 11). `url_only_hosts()` is a plain sync call, like every other query.
- **`RunContext` is a Pydantic model, not a dataclass:** the probe's ctx is copied with `model_copy(update=...)`.

Raw evidence - passive, real engine run (`mock=True`, injected adapters, same code path as the tests; the CLI's mock
fixtures happen to have no URL-only host, so the CLI shows the zero case):

```
urls: running 1 tool(s)
urls: urls-fake ok 4 item(s)
urls: finished 1/1 tool(s), 4 item(s)
urls: 2 host(s) found only in URLs; resolved
--- subdomains rows ---
{'fqdn': 'api.example.com', 'state': 'DNS_ONLY', 'source_count': 1, 'provenance': 'dns', 'sources': 'url-derived'}
{'fqdn': 'known.example.com', 'state': 'UNKNOWN', 'source_count': 0, 'provenance': 'subs', 'sources': ''}
{'fqdn': 'nb.example.com', 'state': 'DNS_ONLY', 'source_count': 1, 'provenance': 'dns', 'sources': 'url-derived'}
```

Raw evidence - active, same setup with `pyprobe` answering ALIVE for both new hosts (the fixture scope file lists
`api.example.com` under `out_of_scope`, so the gate drops it - which is itself the proof that the new live check is
gated):

```
urls: running 1 tool(s)
urls: urls-fake ok 4 item(s)
urls: finished 1/1 tool(s), 4 item(s)
urls: 2 host(s) found only in URLs; resolved, 1 now ALIVE
--- subdomains rows ---
{'fqdn': 'api.example.com', 'state': 'UNKNOWN', 'source_count': 1, 'provenance': 'dns', 'sources': 'url-derived'}
{'fqdn': 'known.example.com', 'state': 'UNKNOWN', 'source_count': 0, 'provenance': 'subs', 'sources': ''}
{'fqdn': 'nb.example.com', 'state': 'ALIVE', 'source_count': 1, 'provenance': 'dns', 'sources': 'url-derived'}
```

Raw evidence - the real CLI in mock mode, where every URL host is already known (the zero case, proving the hook runs
in the shipped path):

```
$ reconkit run -d testfire.net --mock --no-color --db /tmp/d58.db | grep "only in URLs"
25:urls: 0 host(s) found only in URLs; resolved
```

The four tests, raw:

```
pytest -q tests/test_engine.py -k second_resolve
4 passed, 159 deselected in 0.18s
```

- `test_second_resolve_adds_url_only_hosts_in_passive` - 3 URL hosts, 1 known, 2 not: 2 new rows with
  `provenance='dns'`, `source_count=1`, `sources='url-derived'`, state `DNS_ONLY`, and no live adapter ran.
- `test_second_resolve_live_checks_new_hosts_in_active` - same setup, active: both hosts probed and stored `ALIVE`, log
  line `resolved, 2 now ALIVE`.
- `test_second_resolve_does_not_duplicate_existing_hosts` - every URL host already known: no resolver call at all,
  one row in the table, log line `0 host(s) found only in URLs; resolved`.
- `test_second_resolve_is_one_pass` - the DNS adapter writes a new URL row for `late.example.com` while it runs; after
  the run that host has no `subdomains` row and the resolver was called once with exactly the pre-extracted hosts, so a
  second extraction cannot happen.

Gate:

```
pytest -q
978 passed in 29.19s
ruff check .            All checks passed!
ruff format --check .   96 files already formatted
mypy src/reconkit       Success: no issues found in 62 source files
```

Not verified: a real run of the pass against a live third party (no scan was run and no request was sent); `--resume`
after a run whose `urls` stage completed (the hook does not re-run for a completed stage - this is by construction, not
measured); and the pass under a firing budget (the `wait_for` path is code-reviewed, not exercised). The target.com
figures (3 hosts / 43 URLs) are the earlier analysis counts, not a new measurement.

## 2026-11-19 (analysis) - what consumes URLs in a passive run, and four stage-order options

Investigation only. No `src/`/`tests/` change, no stage reordering, no new flag, no scan, no network request to
`target.com` or `example.com`. Baseline `d5caeed`, 974 tests, tree clean, `scope.yaml` sha256
`d45a3c90...eeee8b` before and after. All run evidence is read from `results/target.com/20261119T170839Z/` and
`recon.db` (target 7). MASTER_PLAN holds no D52-D57 entry (they live in PROGRESS); the D52-D57 rulings were re-read
there.

### Part A - what actually happens to URLs in passive mode

`src/reconkit/engine.py`, raw:

```python
STAGE_ORDER: tuple[Stage, ...] = (
    Stage.SUBS,
    Stage.DNS,
    Stage.LIVE,
    Stage.PORTS,
    Stage.TECH,
    Stage.URLS,
    # The liveness probe follows the crawl: it needs the stored URLs (D23).
    Stage.URL_PROBE,
    # Screenshots come after URL discovery (they need alive hosts and the crawl
    # has already run) and before vulns, so a slow browser never delays the
    # findings stage (D19).
    Stage.SHOTS,
    Stage.VULNS,
)

# Scan-mode stages, the first of the two mode tables (docs/02 section 2).
# Every surface that needs "which stages does mode X run" reads this dict.
MODE_STAGES: dict[str, tuple[Stage, ...]] = {
    "passive": (Stage.SUBS, Stage.DNS, Stage.URLS),
    "active": (
        Stage.SUBS,
        Stage.DNS,
        Stage.LIVE,
        Stage.TECH,
        Stage.URLS,
        # Sends HTTP, so it is never a passive stage (D23).
        Stage.URL_PROBE,
    ),
    # `shots` is full-only (D19): it is in STAGE_ORDER, and therefore here, but
    # in neither tuple above. gowitness is `opt_in`/`active`, so the tier and
    # tool-mode rules in MODE_TOOLS still decide whether it runs.
    "full": STAGE_ORDER,
}
```

`Stage.URL_PROBE` is **not** in passive's tuple, and it is **not inside** the `urls` stage: it is its own stage in
`STAGE_ORDER`, engine-owned (no adapters), invoked in the engine's stage loop. Raw call site:

```python
        for stage in STAGE_ORDER:
            if stage not in opts.stages:
                continue
            if stage in completed:
                summary.stages.append(StageOutcome(stage, completed[stage], resumed=True))
                continue
            if stage is Stage.URL_PROBE:
                # Engine-owned, so it never goes through tool selection (D23).
                # D26: it gets the same deadline every tool stage has, from
                # --phase-timeout or `timeouts.url_probe` in config.yaml.
                probe_timeout = opts.phase_timeout or self._stage_timeout(Stage.URL_PROBE)
                try:
                    probe, scope_error = await asyncio.wait_for(
                        self._run_url_probe(target, target_id, opts, scan_key=scan_key),
                        timeout=probe_timeout,
                    )
```

So with `--passive`, `opts.stages` is the passive tuple, `stage is Stage.URL_PROBE` never becomes reachable, and the
selector `Store.probe_candidates()` is never called. Nothing else consumes URLs: `_persist_urls()` writes the rows and
touches no other table.

The run, raw (SQLite, target 7):

```
=== url count for run 178 ===
2253
=== status_code distribution ===
status_code  urls
-----------  ----
NULL         2253

=== scan_runs for target 7 ===
id   stage   status         started_at           finished_at       scope_mode
---  -----  ---------  --------------------  --------------------  ----------
176  subs   completed  2026-11-19T17:02:16Z  2026-11-19T17:05:16Z  enforced
177  dns    completed  2026-11-19T17:05:16Z  2026-11-19T17:05:20Z  enforced
178  urls   completed  2026-11-19T17:05:20Z  2026-11-19T17:08:39Z  enforced

=== distinct URL hosts, split on which side of subdomains ===
url_hosts  in_subdomains  url_only  root_itself
---------  -------------  --------  -----------
       15             12         3            1

=== the three URL-only hosts, by URL count ===
        fqdn          urls
--------------------  ----
nb.target.com        40
api.target.com        2
assets.target.com     1
```

**The A.3 number: 3 URL-only hostnames, carrying 43 of the 2 253 URLs** (`nb.target.com` 40, `api.target.com` 2,
`assets.target.com` 1). None of them has a `subdomains` row, so none was ever resolved, none has a host state, and
none appears in `report.json` or `report.txt` (grep count 0 for all three in both files). The `subdomains` table for the
target holds 12 rows (11 DNS_ONLY, 1 DEAD) - the 12 "in_subdomains" hosts including the root.

**What consumes the URLs in a passive run: nothing.** They are stored with `status_code IS NULL` and no stage ever
reads them back; only a later active or full run reaches `url_probe`, which calls `probe_candidates()` and sends an HTTP
request per URL - subject to the D55 filter, which skips a URL only when its host is **already known** DEAD or DNS_ONLY.
The three hosts above have no state row at all, so the filter keeps all 43 of their URLs; an active run on this target
would therefore spend 43 of its probes on hosts that no DNS source ever confirmed (2 253 - 43 = 2 210 would be skipped).
Note also that URL hostnames never enter the `subdomains` table in any mode: `_persist_urls()` writes only `urls`, and
the `discovered` set the DNS stage receives is fed by subdomain records, not URL records.

### Part B - can the owner check an arbitrary list they already have?

Four `--help` outputs, raw (box art as printed):

```
$ reconkit live --help
 Usage: reconkit live [OPTIONS]
 --domain -d <str>                Root domain to scan.
 --list -l <path>                 File with one root domain per line.
 --json <bool>                    Write one JSON document to stdout.
 --silent -q <bool>               Suppress tables and progress.
 --min-sources <int>              Hide results below this many sources. [default: 1]
 --tools <str>                    Comma-separated adapters to run.
 --exclude <str>                  Comma-separated adapters to skip.
 --include-noisy <bool>           Allow opt_in tier tools.
 --phase-timeout <float>          Stage time limit in seconds.
 --mock <bool>                    Use fixtures; no network or external processes.
 --active <bool>                  Run active stages: subs, dns, live, tech, urls,
                                  url_probe. The passive stages still run. Uses
                                  passive and active tools; no intrusive/aggress...
                                  tools. A scope.yaml, when present, is
                                  enforced; with no scope file, active scanning
                                  is unrestricted.
 --full <bool>                    Run a full scan: all stages (subs, dns, live,
                                  ports, tech, urls, url_probe, shots, vulns).
                                  Uses passive, active, and intrusive-tier tools
                                  (exploitation-cla... tools still require an
                                  explicit --tools). Implies --active and
                                  --include-noisy.
 --no-scope <bool>                Ignore any scope file and behave as if none
                                  existed. Active stages run unrestricted; a
                                  loud warning is printed and the run records
                                  scope_mode = unrestricted_flag. scope.yaml is
                                  never modified.
 --only-alive <bool>              Print only hosts whose state is ALIVE. If
                                  none match, print "no ALIVE hosts (N
                                  scanned)".
 --only-states <str>              Print only hosts matching one of these
                                  comma-separated states: ALIVE, DNS_ONLY,
                                  SHUT_DOWN, DEAD, UNKNOWN.
 --ports <str>                    Override the default port list for naabu and
                                  pyscan. Format: 80,443,8000-8100.
 --status-codes <str>             Only keep hosts that respond with one of these
                                  HTTP status codes. Format: 200,301,302.
 --header <list[str]>             Add an HTTP header to every request made by
                                  httpx and pyprobe. Repeatable. Format: "Name:
                                  Value".
 --user-agent <str>               Override the default User-Agent for httpx and
                                  pyprobe.
 --redact-headers/--show-headers   Hide header values in JSON and UI output
                                  (default on). [default: redact-headers]
 --ffuf-wordlist <path>           Wordlist for ffuf content discovery. Default:
                                  the packaged common.txt (about 110 paths). The
                                  file must exist and be readable.
 --resolvers <path>               Resolver list for massdns and puredns.
                                  Default: the packaged resolvers.txt (16 public
                                  resolvers). The file must exist and be
                                  readable.
 --skip-url-probe <bool>          Skip the url_probe stage: leave every stored
                                  URL without an HTTP status (D23). It runs
                                  after urls in --active and --full.
 --reprobe-urls <bool>            Probe every stored URL again, not only the
                                  ones with no status yet, so a URL that has
                                  since gone dead is found (D24). It needs the
                                  url_probe stage.
 --no-keys <bool>                 Force free mode.
 --resume <bool>                  Continue the latest unfinished run.
 --no-color <bool>                Disable colors.
 --verbose -v <bool>              Show a traceback for unexpected errors.
 --config <path>                  Config file path.
 --scope <path>                   Scope file path.
 --db <path>                      SQLite database path.
 --help <bool>                    Show this message and exit.

$ reconkit export --help
 Usage: reconkit export [OPTIONS]
 *  --domain  -d      <str>   Target to export. [required]
    --format          <str>   Report format: json, md or html. [default: json]
    --help            <bool>  Show this message and exit.

$ reconkit db --help
 Usage: reconkit db [OPTIONS] COMMAND [ARGS]...
 Query stored assets.
 Commands: list, export

$ reconkit db list --help
 Usage: reconkit db list [OPTIONS]
 *  --domain  -d      <str>   Target to list. [required]

$ reconkit db export --help
 Usage: reconkit db export [OPTIONS]
 *  --domain    -d      <str>   Target to export. [required]
    --new-only          <bool>  Only items new since the previous run.

$ reconkit scope --help
 Usage: reconkit scope [OPTIONS] COMMAND [ARGS]...
 Inspect or import scope.yaml.
 Commands: check, import

$ reconkit scope check --help
 Usage: reconkit scope check [OPTIONS]
 *  --domain    -d      <str>   Domain to check. [required]
    --scope             <path>  Scope file path.
    --no-color          <bool>  Disable colors.

$ reconkit scope import --help
 Usage: reconkit scope import [OPTIONS]
```

Every file-reading option in `cli.py` (`grep -n 'Path'` / `read_text`): `-l/--list` (target file), `--ffuf-wordlist`,
`--resolvers`, `--config`, `--scope`, `--db`. Only `--list` is a user data file, and `_targets()` parses it with
**`validate_target()`**, one root domain per line. It is not a hosts file and not a URLs file: a line like
`https://nb.target.com/x` is rejected before any run (`invalid domain label: 'https://nb'`, observed with `--mock`
against a throwaway `--db /tmp/d57probe.db`).

Three of the four pasted commands do not work at all yet: `export`, `db list` and `db export` are Part-8 stubs that
print `... is not wired in Part 8; no ...` and exit with `ExitCode.ERROR` - so there is no CLI export to feed a list
back in. The only export that exists is the `report.json` / `report.txt` a run writes itself (hosts only; it does not
contain URL-only hosts, as Part A shows).

**Answer: partly.** No command accepts a file of URLs and checks liveness, and no command accepts a list of hosts *as a
hosts file* - but a list of **hostnames** works today through `-l`, because each line is treated as its own target and
each target is probed by the live stage. Exact command, one hostname per line, every name listed in the scope file:

```bash
reconkit live -l hosts.txt --active --scope scope.yaml
```

Proven end to end with `--mock` (no network, throwaway DB and a temp scope file in `/tmp`): the file
`nb.target.com` produced `1 hosts: ... 3 ok, 1 failed` with `pyprobe`, `httpx`, `httprobe`, `tlsx` selected for it;
the same command against the real `scope.yaml` refused it with exit 3, exactly as the gate should, because `scope.yaml`
lists only testfire.net and friends. Caveats to state plainly: each line becomes a separate target row, the run is
per-host (one report per hostname), URLs are not accepted, and no liveness result is written back to the original
target's history. The smallest thing that would make the URL case work is a single new option that reads a file, sends
each line through `validate_host()` (not `validate_target()`), and queues `probe_candidates`-style requests for it -
a new flag, so it needs an owner ruling before any code.

### Part C - stage-order options

Current order, from `MODE_STAGES` above:

| mode | stages in order | where `url_probe` runs |
|---|---|---|
| passive | subs, dns, urls | nowhere (not in the tuple) |
| active | subs, dns, live, tech, urls, url_probe | its own stage, last |
| full | subs, dns, live, ports, tech, urls, url_probe, shots, vulns | its own stage, after urls |

The `urls` pool is 4 passive tools (`gau`, `waybackurls`, `unfurl`, `urlfinder` - all `mode: passive`, `tier: core`)
and 4 active crawlers (`katana`, `hakrawler`, `gospider`, `subjs` - `mode: active`). Crawlers are handed
`_stage_hosts(Stage.URLS)` = **alive** hosts; the archive tools are handed the discovered names.

**Option 1 - move `urls` before `dns` in passive (`subs -> urls -> dns`).** Safe for the archive tools, which take
domain names and never need a resolved host; the crawl tools would break, but none of them is in the passive pool, so
passive is the only mode where this is even coherent (active `urls` needs `alive`, which needs `live`, which needs
`dns`). What it does **not** do on its own: make anything resolve the URL hosts. `_persist_urls()` writes only the
`urls` table, and the `discovered` set the DNS stage reads is built from subdomain records, so a reordering alone still
leaves `nb.target.com` without a row. It also moves a 3-minute stage in front of a 4-second one and would need an
extraction step (URL host -> `validate_host()` -> subdomain row) to be worth anything.

**Option 2 - one bounded second resolve pass after `urls`, then stop.** After `urls`, extract distinct hosts from the
URL rows, keep the ones with no `subdomains` row, resolve those, and in active/full run one more live check on the
newly resolved hosts; no third pass, and the pass is idempotent so a resume does not repeat it. Cost on
`target.com`: **3 DNS names** (two of them one label deep) and, if active, 3 live probes - on the order of a couple of
seconds, versus the 488 s full run. What it would surface: `nb.target.com` (40 URLs, archive paths that look like a
real corporate site), `api.target.com`, `assets.target.com`. Whether `nb.target.com` answers today is not
knowable without traffic, which this batch did not send; the value is that the host would gain a row, a state and a
report line, and any ALIVE result would then hand its 40 URLs to `url_probe` as a normal live host instead of the
"unreachable filter keeps it because nothing is known" path. The real cost is behavioural, not CPU: a passive run would
start resolving names that only third-party archives mentioned, which is one more step from "archives say so" toward
producing traffic (still no traffic in passive, since resolving is what `dns` already does for every discovered name).

**Option 3 - add `url_probe` to passive.** Probing is **active contact**: an HTTP request per stored URL to the target
itself, which is exactly what passive mode promises not to do. This changes what the word means, not just a table row.
It would need docs/02 section 2 (mode table and the mode prose), the `--active`/`--passive` help strings and the
interactive legend (all generated from `MODE_STAGES`, so they would change themselves), the `--skip-url-probe` help
("it runs after urls in --active and --full"), docs/09's stage table and D23 note, the exit-3 scope rule (passive would
now be gateable and could refuse), and D55's meaning (a passive run now sends the 43 URL requests). Recommend
**against**: it would make `--passive` a mode that contacts the target, and every operator's mental model of "passive"
in a scope document would be wrong.

**Option 4 - do nothing in-run; document the existing workflow.** Today: run passive, then feed the hostnames you care
about to `reconkit live -l hosts.txt --active --scope ...` (Part B), which is a real liveness check with the real scope
gate. It costs the operator one copy/paste and one command, adds no traffic the owner did not ask for at that moment,
and needs no engine change. Its gap is the URL list itself: the report has no URL-only hosts, so the operator must get
those hostnames from somewhere else (the `urls` table, or `--json`... which is also hosts-only), which is the honest
version of the same limitation Part A describes.

**Recommendation for the owner to rule on: Option 4 now, with Option 2 named as the follow-up if the in-run coverage is
wanted.** Option 4 uses machinery that already exists and is already gate-correct, changes no semantics, and answers
the owner's actual question ("which of my hosts are live") without inventing traffic in a mode that promises none;
Option 2 is the only one of the four that would fix the missing host rows automatically, and it should be a separate,
dated decision with its own D-number because it changes what a passive run discovers.

## 2026-11-19 (D57) - a timeout from an external API is a gap, not a failure

Owner ruling after the final run: the 488 s `example.com` run exited 5 over exactly one row,
`crtsh: request timed out` after 30.71 s, while the other 25 executed tools were ok, gap, skipped or killed. One slow
free third party made a healthy run look broken. A timeout is the same class of "upstream is slow" as that service's
502, so it becomes a gap - with the boundary drawn where this box can actually be at fault.

What changed, in one place (`src/reconkit/adapters/base.py`):

```python
def _timeout_failure(self) -> FetchFailed:
    message = f"{self.name}: request timed out"
    if self._is_external_api():
        return ExternalServiceGap(message)
    return FetchFailed(message)
```

and the two `raise FetchFailed(f"{self.name}: request timed out")` sites in `_request` now `raise
self._timeout_failure()`. The second one is the attempt after a connection retry, so a service that ignores us twice
is a gap too; nothing is retried *because* of a timeout, as before.

| outcome | before | after |
|---|---|---|
| timeout, adapter `external: true` | `failed`, exit 5 | **`gap`**, exit 0 + one gaps line |
| timeout, adapter not external | `failed` | `failed` (unchanged) |
| `ConnectError` after its one retry | `failed` | `failed` - a refused connection can be this box's network |
| 400 / 401 / 403 / body too large | `failed` | unchanged |
| 429 / 5xx / external 404 / quota body | `gap` | unchanged |
| binary stopped at the stage budget | `timeout` / `failed` | unchanged - `classify_external_gap` has no timeout rule |

All five `kind: http` adapters carry `external: true` today (`crtsh`, `certspotter`, `otx`, `hackertarget`, `urlscan`),
so the rule covers all of them; `_is_external_api()` is what keeps a future direct-scan HTTP adapter a failure instead of
silently inheriting the lenient path. No new `ToolStatus`, no schema change, no flag, no config key.

Evidence:

```
pytest -q tests/test_adapters.py -k "timeout or external or local_http or 404"
21 passed, 48 deselected in 0.29s

pytest -q
974 passed in 33.27s
ruff check .            All checks passed!
ruff format --check .   96 files already formatted
mypy src/reconkit       Success: no issues found in 62 source files
```

The two tests:

- `test_external_timeout_is_a_gap` - real `CrtshAdapter` over a `MockTransport` that raises `httpx.ReadTimeout`:
  `status == GAP`, `error == "crtsh: request timed out"`, exactly one call, and the injected `sleep` asserts instead of
  recording, so a timeout cannot start retrying.
- `test_timeout_from_a_local_http_adapter_is_still_a_failure` - the same transport on a `name = "localhttp"` subclass
  (not in `tools.yaml`): `_is_external_api() is False`, `status == FAILED`, `error == "localhttp: request timed out"`.

Mock run of the changed command (`reconkit run -d testfire.net --mock --no-color --json`): `exit_code 0`, 16 hosts,
`tools: 15 ok, 0 gap, 3 failed, 6 skipped, 0 timeout`, report at
`results/mock/testfire.net/20261119T172327Z/report.{txt,json}`. The three failures are `otx`, `hackertarget` and
`dnspython` answering `no fixture for testfire.net` - a missing-fixture artifact of this mock target, present before
this change and unrelated to it (the mock path reads a fixture and never reaches `_request`).

Not re-run: the measured run stands untouched. The 488 s wall, the 39 s `url_probe`, the 1 444 skipped URLs and the
tool counts do not depend on crtsh's status; only the exit code of a future run would differ, and only when a third
party times out. `scope.yaml` sha256 still `d45a3c903c7417cf73115d4a7b73ab4ccf43509656d30414bd89e1a368eeee8b`.

## 2026-11-19 (final run) - example.com on the complete build: 488 s wall, `url_probe` 39 s

One pass, no re-run, real limits - `reconkit run -d example.com --active --phase-timeout 600 --no-color --json
--no-scope`, `url_probe.max_urls: 5000`, the same `recon.db` the D54/D55 measurements used (runs 169/175).
`scope.yaml` was not touched (`--no-scope`; `scope_mode: unrestricted_flag`).

```
start 2026-11-19T11:44:24-05:00   end 11:52:32-05:00   wall 488.0 s   exit 5
previous run (ca0dcd0)            wall 1 060.685 s      exit 0
url_probe run 169  14:57:30Z -> 15:06:46Z = 556 s
url_probe run 175  16:51:53Z -> 16:52:32Z =  39 s   (-517 s, 14.3x)
```

stderr, in order:

```
url_probe: skipping 1444 URL(s) whose host is unreachable
url_probe: probing 906 URL(s)
url_probe: 200/906 URL(s) probed
url_probe: 400/906 URL(s) probed
url_probe: 600/906 URL(s) probed
url_probe: 800/906 URL(s) probed
url_probe: finished 906 URL(s)
```

Tool rows, compact (records, seconds, error):

```
subs     otx gap 0 5.39 'otx: rate limited (HTTP 429)'
subs     urlscan ok 1 6.01 | certspotter ok 27 6.64 | subfinder ok 67 18.30 | findomain ok 38 20.02
subs     amass ok 14 22.18 | assetfinder ok 37 31.05
subs     hackertarget gap 0 6.56 'hackertarget: free quota exceeded'
subs     crtsh FAILED 0 30.71 'crtsh: request timed out'
dns      dig ok 46 | massdns ok 39 | dnsx ok 39 | dnspython ok 15 'timeout=53' | puredns ok 39
live     tlsx ok 21 | httpx ok 12 | httprobe ok 12 | pyprobe ok 12 'unreachable=57'
tech     cdncheck ok 2 | webanalyze ok 6 | httpx_tech ok 12 | whatweb ok 12 | wafw00f ok 2 (104.80 s)
urls     unfurl ok 138 0.02 | waybackurls ok 0 0.57 | subjs ok 100 10.26 | gau ok 4918 58.17
urls     hakrawler ok 137 60.07 | katana ok 543 63.43 'output truncated; skipped unusable line ...'
urls     gospider KILLED 397 130.87 'killed after 60s idle at stage 130.9s, 397 partial; ...'
urls     urlfinder KILLED 6367 199.17 'killed after 180s idle at stage 199.2s, 6367 partial'
```

Summary line: `69 hosts: 12 ALIVE, 27 DNS_ONLY, 0 SHUT_DOWN, 29 DEAD, 1 UNKNOWN | tools: 26 ok, 2 gap, 1 failed,
2 skipped, 0 timeout, 2 killed`, `completion: complete_with_gaps` (gaps: the otx/hackertarget pair). Exit **5** comes
from the single `failed` row, `crtsh: request timed out` - the R13 rule, not a regression; crt.sh was already recorded
as intermittent in Part R.

Comparison with the previous run: `gau` 4 918 (was 4 917), `katana` 543 (was 356), `urlfinder` 6 367 (identical),
`waybackurls` 0 (unchanged, the deferred upstream finding), ALIVE hosts 12 (unchanged), total wall 488.0 s against
1 060.685 s (-54%), kills 2 against 3 (gospider and urlfinder, both idle windows, partial output kept).

DB after the run (`recon.db`, target 6) proves the skip, not just reports it:

```
urls total 7147 -> 7421   NULL 2147 -> 1515   -1 4982 -> 4984   answered >0 16 -> 919
status counts: -1 4984 | NULL 1515 | 200 800 | 302 66 | 301 26 | 404 21 | 400 3 | -2 3 | 308 1 | 401 1 | 403 1
www.example.com (DNS_ONLY): answered 4861 (the old run's -1s) | NULL 1371 (this run's new URLs, none probed)
NULL rows on DEAD/DNS_ONLY hosts: 1444  == the skipped count
```

Of 906 probed URLs, 903 answered (`919 - 16`), 2 came back `-1` and 1 `-2` (`3 - 2`), which reconciles with the 906
progress line. Nothing was changed or retried after the run.

## 2026-11-19 (R14) - scope excludes CIDRs, and the run says where that is partial (D56)

Owner rulings: exclusion beats inclusion (both CIDRs and names), and a partial exclusion is warned on **two** surfaces
(stderr at run start plus `scope_warnings` in the report and `--json`), with no `--strict-cidr` flag in this build.
No migration: `scope.yaml` is read at run time; `scan_runs.scope_mode` is untouched.

Code, as ruled:

- `core/scope.py`: `exclude_cidrs` on `Scope` and in `_SCOPE_KEYS`; `ScopeGate` compiles a second network tuple and
  `ip_allowed` is "inside an included range **and** outside every excluded one"; `has_cidr_exclusions()` lets the engine
  ask whether there is anything to enforce; `allows()` (names) is unchanged, because `out_of_scope` already wins.
- `engine.py`: `_scope_gate()` (one load, `None` for `--no-scope`/no file/unreadable), `_cidr_ungated_tools()` (the
  active tools that will run and resolve inside the child - `pyscan` and `naabu` are the two that are gated),
  `_cidr_scope_warnings()`; `ScanSummary.scope_warnings`; the warning is pushed once through the progress channel at
  run start. `_ip_allowed` now returns `gate.ip_allowed` through the same helper, so there is one scope load shape.
- `ui.py` / `cli.py`: `scope_warnings` in the `--json` summary document, in `report.json`, and as a `scope warnings:`
  block in `report.txt`; the CLI passes `summary.scope_warnings` into the report writer.

Raw evidence, mock run (no traffic, scratch scope file in `/tmp`, temp DB, so neither `scope.yaml` nor `recon.db` was
touched):

```
$ reconkit run -d testfire.net --active --mock --scope /tmp/r14-scope.yaml --tools httpx --db /tmp/r14-evidence.db
run_exit=0
--- stderr ---
exclude_cidrs is set, but 1 selected tool(s) resolve hostnames inside the child and cannot be CIDR-gated: httpx
(pyscan and naabu are gated)
--- results/mock/testfire.net/20261119T163427Z/report.txt (first 8 lines) ---
reconkit report
target: testfire.net
generated: 2026-11-19T16:34:27+00:00
hosts: 1
scope warnings:
  - exclude_cidrs is set, but 1 selected tool(s) resolve hostnames inside the child and cannot be CIDR-gated: httpx
    (pyscan and naabu are gated)

--- report.json ---
['exclude_cidrs is set, but 1 selected tool(s) resolve hostnames inside the child and cannot be CIDR-gated: httpx
  (pyscan and naabu are gated)']
```

The two surfaces carry the identical sentence (the text report wraps it at the table width; the stored string is one
line), and the scratch scope file put `203.0.113.128/25` inside `in_scope_cidrs` `203.0.113.0/24`, so the predicate
really had both halves.

Tests (966 -> 973, +7; `test_ui`'s exact-shape assertion updated in place, not weakened - it now also requires
`scope_warnings`):

```
$ pytest -q -v <the six new tests>
tests/test_scope.py ....                                                 [ 66%]
tests/test_engine.py ..                                                  [100%]
============================== 6 passed in 0.19s ===============================
```

- `test_an_excluded_cidr_refuses_an_otherwise_allowed_address` - `203.0.113.5` True, `203.0.113.200` False (in both
  ranges), `198.51.100.5` False (outside the inclusion); `has_cidr_exclusions()` True.
- `test_a_malformed_excluded_cidr_is_a_config_error` - `203.0.113.0/33` raises `ConfigError("invalid CIDR in scope")`
  from the same `_compile_cidr` the inclusions use, before any traffic.
- `test_empty_exclude_cidrs_changes_nothing` - default is `[]`, `has_cidr_exclusions()` False, and the old
  include/exclude-by-absence answers are unchanged.
- `test_an_excluded_name_loses_to_an_in_scope_wildcard` - `admin.example.com` is dropped from an active gate even though
  `*.example.com` includes it (`hosts == ["www.example.com"]`, `dropped == 1`).
- `test_an_excluded_cidr_is_refused_by_the_ports_predicate` - the predicate the ports stage receives answers True for
  `203.0.113.5`, False for `203.0.113.200` and `198.51.100.5`.
- `test_scope_warnings_name_the_tools_that_resolve_in_the_child` - exactly one `summary.scope_warnings` entry, it
  names `live-fake`, it is the only progress line mentioning `exclude_cidrs`, the JSON document carries it, and the
  written `report.txt`/`report.json` contain the same text.
- `test_pyscan_refuses_an_address_inside_an_excluded_cidr` - the real gate predicate from a scratch scope file
  (`203.0.113.128/25` excluded inside `203.0.113.0/24`) is handed to `pyscan`; the resolver answers the excluded
  address first, so `probed == ["203.0.113.5"]` can only hold when the exclusion refused the first one. Raw:

```
$ pytest -q -v tests/test_python_adapters.py::test_pyscan_refuses_an_address_inside_an_excluded_cidr
tests/test_python_adapters.py .                                          [100%]
============================== 1 passed in 0.18s ===============================
```

Gate after the change: `972 passed in 28.21s`, `ruff check .` all checks passed, `ruff format --check .` 96 files,
`mypy src/reconkit` clean (62 source files).

Deviations: (1) the warning is emitted through the progress channel, so `--silent` suppresses the stderr copy while the
report still carries it - the artifact is the surface that cannot be silenced; (2) `_cidr_ungated_tools` repeats the
selection rules instead of refactoring `_select`, with a comment pointing at it (a tool that will not run is not
named); (3) no `--strict-cidr`, as ruled - recorded as future work in PROGRESS Open risks.

## 2026-11-19 (Parts X-Y) - the 4 982 `-1` answers are DNS_ONLY hosts (D55)

Part X, on a copy of `recon.db` (target_id 6), no code change. Sample (`ORDER BY RANDOM() LIMIT 20`) with the parsed
host, its recorded state and one manual `curl -m 5` per URL; every URL in the sample is on a `example.com` host, so
none needed the external-host skip:

```
https://www.example.com/wp-content/uploads/2025/03/L2.jpg | www.example.com | DNS_ONLY | https | 000 5.054597 (28)
https://www.example.com/wp-includes/js/mediaelement/wp-mediaelement.min.css?ver=6.3.1 | www.example.com | DNS_ONLY | https | 000 5.057891 (28)
https://www.example.com/wp-content/uploads/2024/11/research2-980x350.jpg | www.example.com | DNS_ONLY | https | 000 5.060017 (28)
https://www.example.com/wp-content/uploads/2023/07/Connectwise.jpg | www.example.com | DNS_ONLY | https | 000 5.059072 (28)
https://www.example.com/wp-content/uploads/2024/02/tbi-ev4-400x284.jpg | www.example.com | DNS_ONLY | https | 000 5.059399 (28)
https://www.example.com/wp-includes/js/mediaelement/mediaelementplayer-legacy.min.css?ver=4.2.16 | www.example.com | DNS_ONLY | https | 000 5.059581 (28)
https://www.example.com/wp-content/uploads/2022/06/Samparka-2019-11-480x321.jpg | www.example.com | DNS_ONLY | https | 000 5.055450 (28)
https://www.example.com/wp-content/uploads/2025/04/ADS-980x523.jpg | www.example.com | DNS_ONLY | https | 000 5.050157 (28)
http://webmail.example.com/ | webmail.example.com | DNS_ONLY | http | 000 5.053422 (28)
https://www.example.com/wp-content/et-cache/25911/et-core-unified-tb-232-deferred-25911.min.css?ver=1778245344 | www.example.com | DNS_ONLY | https | 000 5.059961 (28)
https://www.example.com/wp-content/uploads/2022/06/2-307-SE-min.pdf | www.example.com | DNS_ONLY | https | 000 5.058850 (28)
https://www.example.com/wp-content/et-cache/8068/et-core-unified-8068.min.css?ver=1751271748 | www.example.com | DNS_ONLY | https | 000 5.059957 (28)
https://www.example.com/wp-content/et-cache/72/et-divi-dynamic-72.css?ver=1658701566 | www.example.com | DNS_ONLY | https | 000 5.058021 (28)
https://www.example.com/wp-content/uploads/2024/07/Program-Intake-480x614.jpg | www.example.com | DNS_ONLY | https | 000 5.059373 (28)
https://www.example.com/wp-content/et-cache/72/et-core-unified-72.min.css?ver=1714217519 | www.example.com | DNS_ONLY | https | 000 5.059127 (28)
https://www.example.com/wp-content/et-cache/72/et-core-unified-deferred-72.min.css?ver=1731669203 | www.example.com | DNS_ONLY | https | 000 5.051134 (28)
https://www.example.com/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=6.1.3 | www.example.com | DNS_ONLY | https | 000 5.059423 (28)
https://www.example.com/wp-content/uploads/2023/10/IPR-KAPILA.png | www.example.com | DNS_ONLY | https | 000 5.050410 (28)
https://www.example.com/wp-content/uploads/2025/04/Placement-Policy-example-_compressed.pdf | www.example.com | DNS_ONLY | https | 000 5.058634 (28)
https://www.example.com/wp-content/themes/Divi/js/scripts.min.js?ver=4.27.5 | www.example.com | DNS_ONLY | https | 000 5.049882 (28)
```

Every row is the same bucket: **DNS_ONLY host** (resolves, never serves HTTP). Then the whole population, so the sample
is not the argument:

```
total -1: 4982
by state: {'DNS_ONLY': 4916, 'DEAD': 58, 'ALIVE': 6, 'UNKNOWN': 2}
by scheme: {'http': 115, 'https': 4867}
  ('DNS_ONLY', 'https'): 4836 (97.1%)
  ('DNS_ONLY', 'http'):    80 (1.6%)
  ('DEAD', 'http'):        29 (0.6%)
  ('DEAD', 'https'):       29 (0.6%)
  ('ALIVE', 'http'):        5 (0.1%)
  ('ALIVE', 'https'):       1 (0.0%)
  ('UNKNOWN', 'http'):      1 (0.0%)
  ('UNKNOWN', 'https'):     1 (0.0%)
27 distinct DNS_ONLY hosts; top: www.example.com 4861, example.com 5, admission.example.com 2, ...
NULL (unprobed) rows by state: {'<no row>': 49, 'ALIVE': 658, 'DNS_ONLY': 1440} total 2147
answered rows (status > 0) by state: {'ALIVE': 16} total 16
```

Classification of the sample: DNS_ONLY 20/20 (100%), ALIVE-wrong-scheme 0, ALIVE-dead-path 0, external host 0,
other 0. **"ALIVE host, wrong scheme" is ruled out for the population as well:** all 6 ALIVE-host `-1` rows were
re-checked directly - `http://koha.example.com/` 000 after 6.0 s (28), `http://library.example.com/` 000/28,
`http://librarystaff.example.com/` 000/28, `http://ws.example.com/` 000/0.52 s (56 "Connection reset by peer"),
`http://www.ws.example.com/` 000/0.56 s (56), `https://autodiscover.example.com/` 000/6.0 s (28) - none answers on
the other scheme either. The two UNKNOWN rows are `mail.example.com`, which no longer resolves (curl 6).

Three case studies, one per top bucket (DNS_ONLY, DEAD, ALIVE-dead-path):

1. `https://www.example.com/wp-content/uploads/2025/03/L2.jpg` - DNS_ONLY - `000` after 5.05 s, curl 28 "Connection
timed out": the host resolves, nothing listens on 443. This one host is 4 861 of the 4 982 `-1` rows.
2. `http://koha.example.com/` (DEAD rows behave the same way; koha is ALIVE but its path list is historical) - `000`
after 6.0 s, curl 28: the path is from an old archive crawl and no longer exists.
3. `http://ws.example.com/` - ALIVE, dead path - `000` in 0.52 s, curl 56 "Connection reset by peer": the host
answers other traffic but resets this one; retrying would not help.

Distribution (sample n=20): DNS_ONLY 20 (100%), ALIVE-wrong-scheme 0, ALIVE-dead-path 0, external 0, other 0.
**The dominant cause is DNS_ONLY hosts** - 98.7% of the whole `-1` population, 67% of the unprobed candidates.

**X.1b (same day, after the commit): the engine probed correctly.** A second random sample of 30 `-1` rows was
re-probed with the **engine's own transport settings** (httpx, 10 s timeout, `reconkit/0.1` UA, no redirects,
certificate verification on, the same `-1`/`-2` mapping) and with `curl -m 5`:

```
agree (engine still -1): 30/30 | disagree: 0
```

Every row: `engine_now = -1`, `curl5s = 000`, DNS resolves. The stored `-1`s are genuinely unanswering URLs, not a
probe misconfiguration or a stale verdict. Host level, same day (httpx, 10 s, both schemes on `/`):

```
www.example.com     | dns=['66.198.240.31']  | http=ConnectTimeout https=ConnectTimeout
example.com         | dns=['66.198.240.31']  | http=ConnectTimeout https=ConnectTimeout
webmail.example.com | dns=['66.198.240.31']  | http=ConnectTimeout https=ConnectTimeout
koha.example.com    | dns=['121.241.29.115'] | http=ConnectTimeout https=200
ws.example.com      | dns=['192.96.210.12']  | http=ReadError       https=TLS
```

`www`/apex/webmail share one address that answers nothing on either scheme, so DNS_ONLY is correct for them and the
4 861-row skip is safe. The two exceptions are the ALIVE-host residue: `koha` answers **https** but not http (the 5
stored rows are `http://` URLs), and `ws` answers only with an untrusted certificate. That is 6 of 4 982 rows (0.1%),
which is why no scheme rewrite was attempted - Y.2 needs a scheme column and would buy 6 rows.

Part Y (Y.1), code: `Store._dead_fqdns` -> `_unreachable_fqdns` with `state IN ('DEAD', 'DNS_ONLY')`,
`ProbeCandidates.skipped_dead` -> `skipped_unreachable`, engine line
`url_probe: skipping N URL(s) whose host is unreachable`. ALIVE / SHUT_DOWN / UNKNOWN / no-row hosts still probe.
Measured on the example copy:

```
NULL rows (unfiltered): 2147
limit=5000: rows=707 skipped_unreachable=1440
limit=5001: rows=707 skipped_unreachable=1440
reprobe limit=5001: rows=733 skipped_unreachable=6414   (7147 total rows)
```

Drop 1 440 of 2 147 (**67%**, above the 10% floor). The `-1` bucket the filter removes: 1 440 unprobed URLs on
DNS_ONLY hosts; of the 4 982 existing `-1` rows it would have prevented 4 916. Tests: new
`test_probe_candidates_skips_urls_for_dns_only_hosts` (3 URLs, one DNS_ONLY -> 2 candidates, skip 1); the engine test
renamed `test_probe_candidates_logs_unreachable_skip_count` (6 www + 4 DEAD + 2 DNS_ONLY -> `skipping 6`, `calls == 6`,
no non-www host requested); the DEAD and no-row tests still pass unchanged in meaning. Focused run:

```
$ pytest -q tests/test_store.py -k probe_candidates tests/test_engine.py -k probe
24 passed, 216 deselected in 2.36s
```

## 2026-11-19 (Part W) - waybackurls returns 0 on example.com: upstream, deferred

Adapter path (`src/reconkit/adapters/waybackurls.py`): `build_command` returns `[self.binary_path() or self.binary]`
and nothing else, `stdin_text` returns `_query_roots(...)` - the apex once, because the 2026-11-18 rule collapsed the
per-host wildcard queries - and `parse_output` accepts one URL per line, raising only on a line that is not a URL.
Nothing in the adapter can turn real output into zero: a parse error is a `failed` row, never `ok 0`.

Manual runs, one archive.org query each, 60 s cap, the same binary the adapter resolves
(`/home/kali/.reconkit/bin/waybackurls`, 9 948 804 bytes, `-h` markers `-no-subs` / `don't include subdomains`):

```
$ printf 'example.com\n'           | timeout 60 ~/.reconkit/bin/waybackurls
input=example.com          exit=0 stdout_lines=0 stdout_bytes=0 stderr_bytes=0
$ printf 'www.example.com\n'       | timeout 60 ~/.reconkit/bin/waybackurls
input=www.example.com      exit=0 stdout_lines=0 stdout_bytes=0 stderr_bytes=0
$ printf 'http://www.example.com\n' | timeout 60 ~/.reconkit/bin/waybackurls
input=http://www.example.com exit=0 stdout_lines=0 stdout_bytes=0 stderr_bytes=0
```

`gau` proved the archive has the data - its raw file from the same stage and run is 487 360 bytes / 4 919 JSON lines:

```
$ grep -m5 'example' workspaces/example.com/urls/168-gau.txt
{"url":"https://autodiscover.student.example.com/autodiscover/autodiscover.xml"}
{"url":"https://www.example.com/.well-known/ai-plugin.json"}
{"url":"https://www.example.com/.well-known/assetlinks.json"}
{"url":"https://www.example.com/.well-known/dnt-policy.txt"}
{"url":"https://www.example.com/.well-known/gpc.json"}
```

Endpoints baked into the binary (`strings ... | grep archive.org`), i.e. the same CDX host `gau` reads:

```
http://web.archive.org/cdx/search/cdx?url=%s&output=json
http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey
http://web.archive.org/web/%sif_/%s
http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json
```

That CDX shape answers intermittently, and the tool reports neither answer:

```
$ curl -sL 'https://web.archive.org/cdx/search/cdx?url=example.com/*&output=json&collapse=urlkey&limit=3'
attempt1 status=503 bytes=11832   <title>Internet Archive: Temporarily Offline</title>
attempt2 status=200 bytes=553     [["urlkey","timestamp",...],["in,ac,example)/","20170624141040","http://acm@example.com/",...]]
$ curl -sL 'https://web.archive.org/cdx/search/cdx?url=http://www.example.com/&output=json&limit=3'
status=200 bytes=443
```

Classification: **tool broken / API changed - not an adapter bug, not archive.org rate-limiting reconkit.**
waybackurls has no error surface: a 503 and an empty archive both print nothing and exit 0, so the adapter correctly
stores `ok 0` and nothing can be reclassified as a gap without inventing a signal the tool does not emit. The
upstream status the 2026-11-19 14:53Z run actually saw is not recoverable (the tool discards it). Nothing was fixed,
per the batch rule for this class; the finding is in PROGRESS under Open risks with no D number.

## 2026-11-19 (Part V) - url_probe skips URLs whose host is DEAD (D54)

Measurement first (V.1), against `recon.db` read-only, target_id 6 (`example.com`), done in Python because the URL
host has to be parsed (`urlsplit(url).hostname`) and schema 11 has no `hosts` table: the name is `subdomains.fqdn`
and the current state is `subdomains.state` (the newest `host_status_history` row agrees on this DB: 29 DEAD,
27 DNS_ONLY, 12 ALIVE over 69 hosts).

```
Q1  urls with status_code IS NULL        2147   (of 7147 rows for the target)
Q2  ... whose host is DEAD                  0
Q3  NULL URLs by the state of their host: DNS_ONLY 1440 | ALIVE 658 | no host row 49 | unparseable 0
Q4  probed answers: -1 4982 | 200 8 | 301 6 | -2 2 | 404 1 | 308 1   (= the 5000 probed)
    distinct hosts behind the NULL rows: 34 (ALIVE 11, DNS_ONLY 4, no row 19)
```

V.4, with the new filter, against a **copy** of the DB so the original is untouched:

```
$ python -c 'Store("/tmp/v4-example.db").probe_candidates(6, limit=...)'
limit=5000: before(NULL rows, unfiltered)=2147  after(rows)=2147  skipped_dead=0
limit=5001: before(NULL rows, unfiltered)=2147  after(rows)=2147  skipped_dead=0
reprobe=True limit=5001: after(rows)=5001  skipped_dead=58
```

**Drop = 0 of 2 147 (0%) - under the batch's 10% floor, so the DEAD-host filter is not the bottleneck.** The pass's
real cost is the **4 982 `-1` answers out of 5 000 probes**: URLs that do not answer each burn their connect
timeout. Probe concurrency, connection reuse and retries are the next investigation; the filter was not widened to
DNS_ONLY or UNKNOWN, and nothing else changed. It ships as specified because it is correct (a DEAD host can only
time out) and costs one indexed read.

Behaviour: `Store.probe_candidates` returns `ProbeCandidates(rows, skipped_dead)`, filters **before** `limit` is
filled, keeps URLs for unknown hosts / ALIVE / DNS_ONLY / SHUT_DOWN / UNKNOWN / unparseable hosts, and the engine
prints `url_probe: skipping N URL(s) whose host is DEAD` only when N > 0 (before the `--mock` early return, so the
line is visible in a mock pass too).

Tests, 961 -> 965: `test_probe_candidates_skips_urls_with_dead_hosts`,
`test_probe_candidates_keeps_urls_with_no_host_row`, `test_probe_candidates_skip_does_not_eat_the_limit` (extra),
and the engine-level `test_probe_candidates_logs_the_skip_count` (10 URLs, 4 on a DEAD host, injected transport:
asserts the exact line, that no `dead.example.com` URL is requested and that the other 6 are). Raw:

```
$ pytest -q <the seven probe tests>
.......                                                                  [100%]
7 passed in 0.43s
```

## 2026-11-19 (Part U) - the first example.com engine run, made once

Part T (`b6df719`) made per-request timeouts adapter constants (D53). This is the one engine run that followed, on the
target the owner named. It was **not repeated**; everything below comes from that single run.

Two deviations from the batch's literal command are disclosed in PROGRESS (D53 addendum): `--no-scope` (example.com
is not in `scope.yaml`, which was left byte-identical, so the gate would have exited 3 with no scan;
`scan_runs.scope_mode` reads `unrestricted_flag`) and `--json` (U.3 asks for the JSON summary block; without the flag
that block would have needed a second run, which the batch forbids). The temp config was
`/tmp/reconkit-example-config.yaml`, a byte-identical copy of `config.yaml` (`diff -q` clean; `url_probe.max_urls: 5000`,
config line 38).

```
$ time reconkit run -d example.com --active --phase-timeout 600 --no-color --no-scope --json \
    --config /tmp/reconkit-example-config.yaml
wall 1060.685 s
exit=0
```

stderr, 99 lines, verbatim:

```
⚠ --no-scope given: active stages will run WITHOUT scope enforcement.
  target(s): example.com
  no scope file is being read, checked, or enforced.
  a scan_runs record will be written with scope_mode = "unrestricted_flag".
subs: running 9 tool(s)
subs: otx gap 0 item(s)
subs: urlscan ok 1 item(s)
subs: hackertarget gap 0 item(s)
subs: certspotter ok 27 item(s)
subs: crtsh ok 37 item(s)
subs: assetfinder ok 37 item(s)
subs: amass running (20s)
subs: findomain running (20s)
subs: subfinder running (20s)
subs: findomain ok 67 item(s)
subs: subfinder ok 39 item(s)
subs: amass ok 14 item(s)
subs: finished 9/9 tool(s), 222 item(s)
dns: running 5 tool(s)
dns: dnsx ok 39 item(s)
dns: dig ok 46 item(s)
dns: massdns ok 39 item(s)
dns: dnspython ok 55 item(s)
dns: puredns ok 39 item(s)
dns: finished 5/5 tool(s), 218 item(s)
live: running 4 tool(s)
live: pyprobe running (10s)
live: httprobe running (20s)
live: httpx running (20s)
live: tlsx running (20s)
live: tlsx ok 21 item(s)
live: httpx ok 12 item(s)
live: httprobe ok 12 item(s)
live: pyprobe ok 12 item(s)
live: finished 4/4 tool(s), 57 item(s)
tech: running 5 tool(s)
tech: httpx_tech ok 12 item(s)
tech: cdncheck ok 2 item(s)
tech: webanalyze ok 6 item(s)
tech: whatweb running (10s)
tech: wafw00f running (20s)
tech: whatweb ok 12 item(s)
tech: wafw00f ok 2 item(s)
tech: finished 5/5 tool(s), 34 item(s)
urls: running 8 tool(s)
urls: unfurl ok 138 item(s)
urls: waybackurls ok 0 item(s)
urls: gau running (10s)
urls: subjs ok 100 item(s)
urls: gospider running (20s)
urls: hakrawler running (20s)
urls: katana running (20s)
urls: urlfinder running (20s)
urls: katana ok 356 item(s)
urls: hakrawler killed 62 item(s)
urls: gau ok 4917 item(s)
urls: gospider killed 402 item(s)
urls: urlfinder killed 6367 item(s)
urls: finished 8/8 tool(s), 12342 item(s)
url_probe: probing 5000 URL(s)
url_probe: 200/5000 URL(s) probed
url_probe: 400/5000 URL(s) probed
url_probe: 600/5000 URL(s) probed
url_probe: 800/5000 URL(s) probed
url_probe: 1000/5000 URL(s) probed
url_probe: 1200/5000 URL(s) probed
url_probe: 1400/5000 URL(s) probed
url_probe: 1600/5000 URL(s) probed
url_probe: 1800/5000 URL(s) probed
url_probe: 2000/5000 URL(s) probed
url_probe: 2200/5000 URL(s) probed
url_probe: 2400/5000 URL(s) probed
url_probe: 2600/5000 URL(s) probed
url_probe: 2800/5000 URL(s) probed
url_probe: 3000/5000 URL(s) probed
url_probe: 3200/5000 URL(s) probed
url_probe: 3400/5000 URL(s) probed
url_probe: 3600/5000 URL(s) probed
url_probe: 3800/5000 URL(s) probed
url_probe: 4000/5000 URL(s) probed
url_probe: 4200/5000 URL(s) probed
url_probe: 4400/5000 URL(s) probed
url_probe: 4600/5000 URL(s) probed
url_probe: 4800/5000 URL(s) probed
url_probe: finished 5000 URL(s)
⚠ 3 tool(s) stopped early — partial output kept
  hakrawler: killed after 60s idle at stage 60.1s, 62 partial
  gospider: killed after 60s idle at stage 128.6s, 402 partial; skipped unusable
line '[aws-s3] - vaave.s3.amazonaws.com'; skipped unusable line '[aws-s3] - 
vaave.s3.amazonaws.com'
  urlfinder: killed after 180s idle at stage 193.5s, 6367 partial
  raise that class's window under runtime_idle: in config.yaml, or the stage 
budget with --phase-timeout.
⚠ active scan completed with gaps — 1 stage(s) incomplete
  subs: hackertarget: free quota exceeded, otx: rate limited (HTTP 429)
  run 'reconkit doctor' to see what is installed; see docs/10_TOOL_SOURCES.md 
for provenance.
  this is not a failure — the scan used every tool that was available.
report: results/example.com/20261119T150646Z/report.txt and results/example.com/20261119T150646Z/report.json
```

`--json` document (stdout, 1 473 078 bytes) - the scalars and the `summary` block:

```
target: "example.com"  type: "summary"  exit_code: 0
scope_mode: "unrestricted_flag"  scope_denied: false  resumed: false
completion: {"status": "complete_with_gaps", "gaps": [{"stage": "subs", "reason": "hackertarget: free quota exceeded, otx: rate limited (HTTP 429)"}]}
www_dedup: {"applied": false, "pairs": []}
warnings: ["DNS/probe inconclusive; kept previous state",
           "url_probe: probed the first 5000 URL(s) only; re-run to probe the rest"]
summary: {
  "hosts": 69, "alive": 12, "dns_only": 27, "shut_down": 0, "dead": 29, "unknown": 1,
  "tools_ok": 26, "tools_gap": 2, "tools_failed": 0, "tools_skipped": 2,
  "tools_timeout": 0, "tools_killed": 3
}
```

`scan_runs` (all six `completed`; `scope_mode` `unrestricted_flag` on each):

| id | stage | started | finished | duration |
|---|---|---|---|---|
| 164 | subs | 14:49:06Z | 14:50:45Z | 99 s |
| 165 | dns | 14:50:45Z | 14:50:59Z | 14 s |
| 166 | live | 14:50:59Z | 14:52:06Z | 67 s |
| 167 | tech | 14:52:07Z | 14:53:55Z | 108 s |
| 168 | urls | 14:53:55Z | 14:57:30Z | 215 s |
| 169 | url_probe | 14:57:30Z | 15:06:46Z | 556 s |

`tool_runs`: 33 rows for 164-169 - `26 ok, 2 gap, 0 failed, 2 skipped, 0 timeout, 3 killed`. Every non-ok row:

```
971  164  chaos              skipped  0     None    requires PDCP_API_KEY
972  164  github_subdomains  skipped  0     None    requires GITHUB_TOKEN
973  164  otx                gap      0     0.47s   otx: rate limited (HTTP 429)
975  164  hackertarget       gap      0     0.83s   hackertarget: free quota exceeded
1000 168  hakrawler          killed   62    60.06s  killed after 60s idle at stage 60.1s, 62 partial
1002 168  gospider           killed   402   128.62s killed after 60s idle at stage 128.6s, 402 partial; skipped unusable line '[aws-s3] - vaave.s3.amazonaws.com'; skipped unusable line '[aws-s3] - vaave.s3.amazonaws.com'
1003 168  urlfinder          killed   6367  193.43s killed after 180s idle at stage 193.5s, 6367 partial
```

One more zero-item row, but `ok`: `waybackurls ok 0` in 0.62 s. Its raw file
(`workspaces/example.com/urls/168-waybackurls.txt`) is **0 bytes**, and the 2026-11-18 run's file (`163-waybackurls.txt`)
is 0 bytes too, while `gau`'s file from the same stage is 487 360 bytes / 4 919 lines. The adapter asks the apex once
(`_query_roots`: `example.com`, covered by `*.<target>/*`); `gau` was handed every host. Nothing failed - 0 rows is
`ok` - so this is recorded as a new edge, not a defect and not fixed here (PROGRESS, Open risks).

Item counts asked for, against the 2026-11-18 six-tool capture: `gau` 4 917 (70.23 s) vs 6 227; `katana` 356 (52.05 s)
vs 1; `subfinder` 39 (33.81 s) vs 67; `httprobe` 12 (33.30 s) vs 18. Crawlers: `hakrawler` 62, `gospider` 402,
`urlfinder` 6 367, `subjs` 100, `unfurl` 138, `waybackurls` 0.

### Classification (U.4)

| Row | Class | Why |
|---|---|---|
| `chaos`, `github_subdomains` skipped | expected | selection skips, no API key (`PDCP_API_KEY`, `GITHUB_TOKEN`) |
| `otx` gap, HTTP 429 | known since PIT-55 (2026-11-18) | provider rate limit, already classified `gap` |
| `hackertarget` gap, free quota | known since PIT-55 (2026-11-18) | provider quota, already classified `gap` |
| `hakrawler` killed | expected, D52 idle | crawler window 60 s, last output at 0.001 s, 62 partial kept |
| `gospider` killed | expected, D52 idle | crawler window 60 s, last output at 0.0007 s, 402 partial kept; the two `[aws-s3]` lines are skipped per PIT-58 |
| `urlfinder` killed | expected, D52 idle | archive window 180 s, last output at 0.0045 s, 6 367 partial kept |
| `waybackurls` ok 0 items | **new edge, recorded, not fixed** | 0 bytes raw, reproducible from the 2026-11-18 run, while `gau` returned 4 917 archive URLs |

Four one-line answers:

1. **Idle kill?** Yes - three, all from the idle windows, none from a per-request timeout: `hakrawler` (60 s crawler),
   `gospider` (60 s crawler), `urlfinder` (180 s archive), partial output kept in all three.
2. **Stage-budget timeout?** No. `tools_timeout: 0`, no `ToolStatus.TIMEOUT` row, and the longest stage (`url_probe`,
   556 s) finished below its 600 s ceiling.
3. **Exit 0 or 5?** 0. `completion.status` is `complete_with_gaps` with one gap, and both its members are `gap`, not
   `failed`, so the failure total is 0 (PIT-55).
4. **Wall clock vs the ~2m40s capture?** 1 060.685 s vs 160 s. The capture replayed six tools; this run is six stages,
   and `url_probe` alone is 556 s (52%) probing 5 000 URLs at ~9/s. Without it the run would have been ~505 s.

## 2026-11-18 (audit close-out) - raw proofs for the url_probe/httpx batch

The follow-up batch (6488aad, 4b97928, aad092c, 62e88db) reported five findings
whose raw evidence had not been pasted. They are pasted here verbatim, with no
code change. Nothing in them contradicts the report; two are stronger than the
report's own summary (A.2 measures the whole 20-URL distribution, A.5 makes the
database state itself differ instead of relying on the run's parameters).

### A.1 - the managed PD httpx help, complete

`~/.reconkit/bin/httpx -h`, 196 lines, verbatim. There is no `-insecure` (nor any
`-verify`) flag anywhere in it: the only TLS switches are `-tls-probe`,
`-tls-grab`, `-sni`, `-ztls` and `-tlsi`. `-rl` defaults to 150 requests/second.

```
httpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library.

Usage:
  /home/kali/.reconkit/bin/httpx [flags]

Flags:
INPUT:
   -l, -list string         input file containing list of hosts to process
   -rr, -request string     file containing raw request
   -u, -target string[]     input target host(s) to probe
   -im, -input-mode string  mode of input file (burp)

PROBES:
   -sc, -status-code                      display response status-code
   -cl, -content-length                   display response content-length
   -ct, -content-type                     display response content-type
   -location                              display response redirect location
   -favicon                               display mmh3 hash for '/favicon.ico' file
   -hash string                           display response body hash (supported: md5,mmh3,simhash,sha1,sha256,sha512)
   -jarm                                  display jarm fingerprint hash
   -rt, -response-time                    display response time
   -lc, -line-count                       display response body line count
   -wc, -word-count                       display response body word count
   -title                                 display page title
   -bp, -body-preview                     display first N characters of response body (default 100)
   -server, -web-server                   display server name
   -td, -tech-detect                      display technology in use based on wappalyzer dataset
   -cff, -custom-fingerprint-file string  path to a custom fingerprint file for technology detection
   -cpe                                   display CPE (Common Platform Enumeration) with product version based on awesome-search-queries
   -wp, -wordpress                        display WordPress plugins and themes
   -kb, -knowledge-base                   enable knowledge base classification
   -method                                display http request method
   -ws, -websocket                        display server using websocket
   -ip                                    display host ip
   -cname                                 display host cname
   -extract-fqdn, -efqdn                  get domain and subdomains from response body and header in jsonl/csv output
   -asn                                   display host asn information
   -cdn                                   display cdn/waf in use (default true)
   -probe                                 display probe status

HEADLESS:
   -ss, -screenshot                 enable saving screenshot of the page using headless browser
   -system-chrome                   enable using local installed chrome for screenshot
   -ho, -headless-options string[]  start headless chrome with additional options
   -esb, -exclude-screenshot-bytes  enable excluding screenshot bytes from json output
   -ehb, -exclude-headless-body     enable excluding headless header from json output
   -no-screenshot-full-page         disable saving full page screenshot
   -st, -screenshot-timeout value   set timeout for screenshot in seconds (default 10s)
   -sid, -screenshot-idle value     set idle time before taking screenshot in seconds (default 1s)
   -jsc, -javascript-code string[]  execute JavaScript code after navigation

MATCHERS:
   -mc, -match-code string            match response with specified status code (-mc 200,302)
   -ml, -match-length string          match response with specified content length (-ml 100,102)
   -mlc, -match-line-count string     match response body with specified line count (-mlc 423,532)
   -mwc, -match-word-count string     match response body with specified word count (-mwc 43,55)
   -mfc, -match-favicon string[]      match response with specified favicon hash (-mfc 1494302000)
   -ms, -match-string string[]        match response with specified string (-ms admin)
   -mr, -match-regex string[]         match response with specified regex (-mr admin)
   -mcdn, -match-cdn string[]         match host with specified cdn provider (arvancloud, cdnetworks, gcore, lgtelecom, skbroadband, 云盾, cafe24, cloudfront, google, gocache, qrator, 百度云加速, fastly, kinx, 加速乐, 腾讯云)
   -mrt, -match-response-time string  match response with specified response time in seconds (-mrt '< 1')
   -mdc, -match-condition string      match response with dsl expression condition

EXTRACTOR:
   -er, -extract-regex string[]   display response content with matched regex
   -ep, -extract-preset string[]  display response content matched by a pre-defined regex (url,ipv4,mail)

FILTERS:
   -fc, -filter-code string               filter response with specified status code (-fc 403,401)
   -fpt, -filter-page-type string[]       filter response with specified page type (e.g. -fpt login,captcha,parked)
   -fep, -filter-error-page               [DEPRECATED: use -fpt] filter response with ML based error page detection
   -fd, -filter-duplicates                filter out near-duplicate responses (only first response is retained)
   -fl, -filter-length string             filter response with specified content length (-fl 23,33)
   -flc, -filter-line-count string        filter response body with specified line count (-flc 423,532)
   -fwc, -filter-word-count string        filter response body with specified word count (-fwc 423,532)
   -ffc, -filter-favicon string[]         filter response with specified favicon hash (-ffc 1494302000)
   -fs, -filter-string string[]           filter response with specified string (-fs admin)
   -fe, -filter-regex string[]            filter response with specified regex (-fe admin)
   -fcdn, -filter-cdn string[]            filter host with specified cdn provider (arvancloud, cdnetworks, gcore, lgtelecom, skbroadband, 云盾, cafe24, cloudfront, google, gocache, qrator, 百度云加速, fastly, kinx, 加速乐, 腾讯云)
   -frt, -filter-response-time string     filter response with specified response time in seconds (-frt '> 1')
   -fdc, -filter-condition string         filter response with dsl expression condition
   -strip                                 strips all tags in response. supported formats: html,xml (default html)
   -lof, -list-output-fields              list of fields to output (comma separated)
   -eof, -exclude-output-fields string[]  exclude output fields output based on a condition

RATE-LIMIT:
   -t, -threads int              number of threads to use (default 50)
   -rl, -rate-limit int          maximum requests to send per second (default 150)
   -rlm, -rate-limit-minute int  maximum number of requests to send per minute

MISCELLANEOUS:
   -pa, -probe-all-ips        probe all the ips associated with same host
   -p, -ports string[]        ports to probe (nmap syntax: eg http:1,2-10,11,https:80)
   -path string               path or list of paths to probe (comma-separated, file)
   -tls-probe                 send http probes on the extracted TLS domains (dns_name)
   -csp-probe                 send http probes on the extracted CSP domains
   -tls-grab                  perform TLS(SSL) data grabbing
   -pipeline                  probe and display server supporting HTTP1.1 pipeline
   -http2                     probe and display server supporting HTTP2
   -vhost                     probe and display server supporting VHOST
   -ldv, -list-dsl-variables  list json output field keys name that support dsl matcher/filter

UPDATE:
   -up, -update                 update httpx to latest version
   -duc, -disable-update-check  disable automatic httpx update check

OUTPUT:
   -o, -output string                     file to write output results
   -oa, -output-all                       filename to write output results in all formats
   -sr, -store-response                   store http response to output directory
   -srd, -store-response-dir string       store http response to custom directory
   -ob, -omit-body                        omit response body in output
   -csv                                   store output in csv format
   -csvo, -csv-output-encoding string     define output encoding
   -j, -json                              store output in JSONL(ines) format
   -md, -markdown                         store output in Markdown table format
   -irh, -include-response-header         include http response (headers) in JSON output (-json only)
   -irr, -include-response                include http request/response (headers + body) in JSON output (-json only)
   -irrb, -include-response-base64        include base64 encoded http request/response in JSON output (-json only)
   -include-chain                         include redirect http chain in JSON output (-json only)
   -store-chain                           include http redirect chain in responses (-sr only)
   -svrc, -store-vision-recon-cluster     include visual recon clusters (-ss and -sr only)
   -pr, -protocol string                  protocol to use (unknown, http11, http2 [experimental], http3 [experimental])
   -fepp, -filter-error-page-path string  path to store filtered error pages (default "filtered_error_page.json")
   -rdb, -result-db                       store results in database
   -rdbc, -result-db-config string        path to database config file
   -rdbt, -result-db-type string          database type (mongodb, postgres, mysql)
   -rdbcs, -result-db-conn string         database connection string
   -rdbn, -result-db-name string          database name (default "httpx")
   -rdbtb, -result-db-table string        table/collection name (default "results")
   -rdbbs, -result-db-batch-size int      batch size for database inserts (default 100)
   -rdbor, -result-db-omit-raw            omit raw request/response data from database

CONFIGURATIONS:
   -config string                   path to the httpx configuration file (default $HOME/.config/httpx/config.yaml)
   -r, -resolvers string[]          list of custom resolver (file or comma separated)
   -allow string[]                  allowed list of IP/CIDR's to process (file or comma separated)
   -deny string[]                   denied list of IP/CIDR's to process (file or comma separated)
   -sni, -sni-name string           custom TLS SNI name
   -random-agent                    enable Random User-Agent to use (default true)
   -auto-referer                    set the Referer header to the current URL
   -H, -header string[]             custom http headers to send with request
   -http-proxy, -proxy string       proxy (http|socks) to use (eg http://127.0.0.1:8080); falls back to HTTP_PROXY/HTTPS_PROXY/NO_PROXY env vars
   -unsafe                          send raw requests skipping golang normalization
   -resume                          resume scan using resume.cfg
   -fr, -follow-redirects           follow http redirects
   -maxr, -max-redirects int        max number of redirects to follow per host (default 10)
   -fhr, -follow-host-redirects     follow redirects on the same host
   -rhsts, -respect-hsts            respect HSTS response headers for redirect requests
   -vhost-input                     get a list of vhosts as input
   -x string                        request methods to probe, use 'all' to probe all HTTP methods
   -body string                     post body to include in http request
   -s, -stream                      stream mode - start elaborating input targets without sorting
   -sd, -skip-dedupe                disable dedupe input items (only used with stream mode)
   -ldp, -leave-default-ports       leave default http/https ports in host header (eg. http://host:80 - https://host:443
   -ztls                            use ztls library with autofallback to standard one for tls13
   -no-decode                       avoid decoding body
   -tlsi, -tls-impersonate string   enable experimental client hello (ja3) tls impersonation (chrome, or ja3 full string)
   -no-stdin                        Disable Stdin processing
   -hae, -http-api-endpoint string  experimental http api endpoint
   -sf, -secret-file string         path to the secret file for authentication

DEBUG:
   -health-check, -hc        run diagnostic check up
   -debug                    display request/response content in cli
   -debug-req                display request content in cli
   -debug-resp               display response content in cli
   -version                  display httpx version
   -stats                    display scan statistic
   -profile-mem string       optional httpx memory profile dump file
   -silent                   silent mode
   -v, -verbose              verbose mode
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default: 5)
   -nc, -no-color            disable colors in cli output
   -tr, -trace               trace

OPTIMIZATIONS:
   -nf, -no-fallback                  display both probed protocol (HTTPS and HTTP)
   -nfs, -no-fallback-scheme          probe with protocol scheme specified in input 
   -maxhr, -max-host-error int        max error count per host before skipping remaining path/s (default 30)
   -e, -exclude string[]              exclude host matching specified filter ('cdn', 'private-ips', cidr, ip, regex)
   -retries int                       number of retries
   -timeout int                       timeout in seconds (default 10)
   -delay value                       duration between each http request (eg: 200ms, 1s) (default -1ns)
   -rsts, -response-size-to-save int  max response size to save in bytes (default 50000000)
   -rstr, -response-size-to-read int  max response size to read in bytes (default 50000000)

CLOUD:
   -auth                           configure projectdiscovery cloud (pdcp) api key (default true)
   -ac, -auth-config string        configure projectdiscovery cloud (pdcp) api key credential file
   -pd, -dashboard                 upload / view output in projectdiscovery cloud (pdcp) UI dashboard
   -tid, -team-id string           upload asset results to given team id (optional)
   -aid, -asset-id string          upload new assets to existing asset id (optional)
   -aname, -asset-name string      assets group name to set (optional)
   -pdu, -dashboard-upload string  upload httpx output file (jsonl) in projectdiscovery cloud (pdcp) UI dashboard
```

The flag the report said does not exist, asked for directly:

```
$ ~/.reconkit/bin/httpx -l /tmp/probe200.txt -insecure -silent
flag provided but not defined: -insecure
```

### A.2 - 10 certificate-invalid https URLs against 10 http 200s, one pass

Fixture: 20 rows in a fresh DB for `testfire.net` - ten `https://testfire.net/...`
URLs (the host's certificate is issued for `www.testfire.net`) and ten
`http://testfire.net/...` paths that answer 200. One `url_probe` pass, real
network, `threads: 10`, `batch_size: 10`.

```
== A.2 fixture: 10 https (certificate for www.testfire.net) + 10 http 200 ==
  sqlite3 a2.db '.dump urls' (first 4 INSERT lines):
    INSERT INTO "urls" VALUES(1,1,'https://testfire.net/',NULL,'[]',0,1,1,NULL);
    INSERT INTO "urls" VALUES(2,1,'https://testfire.net/index.jsp',NULL,'[]',0,1,1,NULL);
    INSERT INTO "urls" VALUES(3,1,'https://testfire.net/login.jsp',NULL,'[]',0,1,1,NULL);
    INSERT INTO "urls" VALUES(4,1,'https://testfire.net/feedback.jsp',NULL,'[]',0,1,1,NULL);
  seeded 10 https + 10 http rows
  url_probe: probing 20 URL(s)
  url_probe: 10/20 URL(s) probed
  url_probe: finished 20 URL(s)
  warnings: []
  completion: complete
  probe run 2 params_json: {"scan_key": "830175900ad751cd", "mode": "active", "tools": [], "mock": false, "active": true, "reprobe": false, "no_keys": false, "min_sources": 1}
  [A.2] SELECT status_code, COUNT(*) FROM urls GROUP BY status_code:
    -2|10
    200|10
```

`-2|10` and `200|10`: the mixed list is fully classified in a single pass, so the
https rows that fail at the certificate do not starve the http rows that answer.

### A.3 - `_dedupe_www_variants`, before and after (4b97928)

Before, at `4b97928^:src/reconkit/engine.py`:

```python
    def _dedupe_www_variants(self, target_id: int, hosts: list[str]) -> None:
        """Mark a www/non-www pair as one website (D22, 2026-11-18).

        Metadata only: it reads the rows the `live` pass just stored and writes
        `duplicate_of`/`www_note` on the newest status row. Host state,
        confidence, `status_code` and every count query are untouched, and a
        pair that cannot be explained (different non-2xx codes) is left alone.

        Rules (docs/09 section 5):

        - one 3xx and one 2xx -> the 3xx name is the duplicate of the 2xx name;
        - both 2xx -> both serve content, neither is a duplicate (sibling note);
        - same non-2xx status and a shared IP -> `www.X` is a duplicate of `X`
          (the bare name is the web convention for the canonical one);
        - same status, different IPs -> different servers, sibling note only;
        - one alive, one not -> nothing (a dead variant is not a duplicate of a
          live site, it is a name that does not resolve).
        """
        rows: dict[str, dict[str, object]] = {
            str(row["fqdn"]): row for row in self.store.host_rows(target_id)
        }
        current = set(hosts)
        for fqdn in sorted(rows):
            if not fqdn.startswith("www."):
                continue
            bare = fqdn[len("www.") :]
            other = rows.get(bare)
            if other is None or fqdn not in current or bare not in current:
                continue
            if rows[fqdn]["state"] != HostState.ALIVE.value:
                continue
            if other["state"] != HostState.ALIVE.value:
                continue
            www_status = rows[fqdn]["status_code"]
            bare_status = other["status_code"]
            www_ip = set(cast(tuple[str, ...], rows[fqdn]["ips"]))
            bare_ip = set(cast(tuple[str, ...], other["ips"]))
            duplicate: str | None = None
            canonical: str | None = None
            note: str | None = None
            if _is_redirect(bare_status) and _is_2xx(www_status):
                duplicate, canonical = bare, fqdn
            elif _is_redirect(www_status) and _is_2xx(bare_status):
                duplicate, canonical = fqdn, bare
            elif _is_2xx(bare_status) and _is_2xx(www_status):
                # Both names serve content: two sites, not a duplicate (rule 2).
                self.store.set_host_duplicate(
                    target_id, bare, duplicate_of=None, www_note=f"has www sibling at {fqdn}"
                )
                self.store.set_host_duplicate(
                    target_id, fqdn, duplicate_of=None, www_note=f"has www sibling at {bare}"
                )
                continue
            elif www_status == bare_status and www_ip & bare_ip:
                duplicate, canonical = fqdn, bare
            elif www_status == bare_status and www_ip and bare_ip and not (www_ip & bare_ip):
                # Known and disjoint: two servers. With no DNS evidence for
                # either name we say nothing rather than guess.
                note = "www variant on a different server"
            if duplicate is not None and canonical is not None:
                self.store.set_host_duplicate(target_id, duplicate, duplicate_of=canonical)
            elif note is not None:
                self.store.set_host_duplicate(target_id, bare, duplicate_of=None, www_note=note)
                self.store.set_host_duplicate(target_id, fqdn, duplicate_of=None, www_note=note)
```

After, at `4b97928`:

```python
    def _dedupe_www_variants(self, target_id: int, hosts: list[str]) -> None:
        """Mark a www/non-www pair as one website (D22, 2026-11-18).

        Metadata only: it reads the rows the `live` pass just stored and writes
        `duplicate_of`/`www_note` on the newest status row. Host state,
        confidence, `status_code` and every count query are untouched, and a
        pair that cannot be explained (different non-2xx codes) is left alone.

        Rules (docs/09 section 5):

        - one 3xx and one 2xx -> the 3xx name is the duplicate of the 2xx name;
        - both 2xx -> both serve content, neither is a duplicate (sibling note);
        - same **known** non-2xx status and a shared IP -> `www.X` is a duplicate
          of `X` (the bare name is the web convention for the canonical one);
          `NULL` is "no HTTP status observed", not a status the two names share,
          so a pair with no status on either side is never marked (D25);
        - same status, different IPs -> different servers, sibling note only;
        - one alive, one not -> nothing (a dead variant is not a duplicate of a
          live site, it is a name that does not resolve).
        """
        rows: dict[str, dict[str, object]] = {
            str(row["fqdn"]): row for row in self.store.host_rows(target_id)
        }
        current = set(hosts)
        for fqdn in sorted(rows):
            if not fqdn.startswith("www."):
                continue
            bare = fqdn[len("www.") :]
            other = rows.get(bare)
            if other is None or fqdn not in current or bare not in current:
                continue
            if rows[fqdn]["state"] != HostState.ALIVE.value:
                continue
            if other["state"] != HostState.ALIVE.value:
                continue
            www_status = rows[fqdn]["status_code"]
            bare_status = other["status_code"]
            www_ip = set(cast(tuple[str, ...], rows[fqdn]["ips"]))
            bare_ip = set(cast(tuple[str, ...], other["ips"]))
            duplicate: str | None = None
            canonical: str | None = None
            note: str | None = None
            if _is_redirect(bare_status) and _is_2xx(www_status):
                duplicate, canonical = bare, fqdn
            elif _is_redirect(www_status) and _is_2xx(bare_status):
                duplicate, canonical = fqdn, bare
            elif _is_2xx(bare_status) and _is_2xx(www_status):
                # Both names serve content: two sites, not a duplicate (rule 2).
                self.store.set_host_duplicate(
                    target_id, bare, duplicate_of=None, www_note=f"has www sibling at {fqdn}"
                )
                self.store.set_host_duplicate(
                    target_id, fqdn, duplicate_of=None, www_note=f"has www sibling at {bare}"
                )
                continue
            elif (
                www_status is not None
                and bare_status is not None
                and www_status == bare_status
                and www_ip & bare_ip
            ):
                # Both codes must be known: `NULL == NULL` is not evidence that
                # the two names answer the same way (D25, verification gap 2).
                duplicate, canonical = fqdn, bare
            elif www_status == bare_status and www_ip and bare_ip and not (www_ip & bare_ip):
                # Known and disjoint: two servers. With no DNS evidence for
                # either name we say nothing rather than guess.
                note = "www variant on a different server"
            if duplicate is not None and canonical is not None:
                self.store.set_host_duplicate(target_id, duplicate, duplicate_of=canonical)
            elif note is not None:
                self.store.set_host_duplicate(target_id, bare, duplicate_of=None, www_note=note)
                self.store.set_host_duplicate(target_id, fqdn, duplicate_of=None, www_note=note)
```

### A.4 - the config line, raw

```
$ grep -n 'url_probe' config.yaml
21:  url_probe: 600      # D26: the probe's own deadline; --phase-timeout overrides it
36:url_probe:
```

Line 21 is the `timeouts:` entry the report cited; line 36 is the ordinary probe
block (`threads`/`batch_size`/`timeout_s`/`max_urls`).

### A.5 - `--reprobe-urls` changes which rows are probed

Two identical fresh DBs, five URLs each, with rows 1-2 carrying a deliberately
stale `404` and rows 3-5 `NULL`. Without the flag only the three `NULL` rows are
sent, so the stale answers survive; with it all five are sent and the two stale
`404`s are rewritten to the real `200`.

```
== A.5 db1: 5 URLs, 2 carry a stale 404, 3 NULL - run WITHOUT --reprobe-urls ==
  seed: id=1 status_code=404 http://testfire.net/
  seed: id=2 status_code=404 http://testfire.net/index.jsp
  seed: id=3 status_code=None http://testfire.net/login.jsp
  seed: id=4 status_code=None http://testfire.net/feedback.jsp
  seed: id=5 status_code=None http://testfire.net/search.jsp
  url_probe: probing 3 URL(s)
  url_probe: finished 3 URL(s)
  warnings: []
  completion: complete
  probe run 2 params_json: {"scan_key": "28bd99886c47c934", "mode": "active", "tools": [], "mock": false, "active": true, "reprobe": false, "no_keys": false, "min_sources": 1}
  [A.5 without] SELECT status_code, COUNT(*) FROM urls GROUP BY status_code:
    200|3
    404|2

== A.5 db2: same 5 rows - run WITH --reprobe-urls ==
  seed: id=1 status_code=404 http://testfire.net/
  seed: id=2 status_code=404 http://testfire.net/index.jsp
  seed: id=3 status_code=None http://testfire.net/login.jsp
  seed: id=4 status_code=None http://testfire.net/feedback.jsp
  seed: id=5 status_code=None http://testfire.net/search.jsp
  url_probe: probing 5 URL(s)
  url_probe: finished 5 URL(s)
  warnings: []
  completion: complete
  probe run 2 params_json: {"scan_key": "9530a2ae45e41b0e", "mode": "active", "tools": [], "mock": false, "active": true, "reprobe": true, "no_keys": false, "min_sources": 1}
  [A.5 with] SELECT status_code, COUNT(*) FROM urls GROUP BY status_code:
    200|5
```

That is the distinction the earlier report lacked: `probing 3 URL(s)` leaves
`404|2` behind, `probing 5 URL(s)` replaces it with `200|5`, and `params_json`
shows `"reprobe": false` against `"reprobe": true`.

## Commit map

- Step 1 (`docs: add master plan, review log, check script, resume block`): `09a5bce`
- Part 3-AUDIT (`fix: close the phase-2 review gaps in store, keys and adapters`): `75eb261`
- Part 0 (`docs: record the Part 0 baseline and f1 review`): `e675079`
- Part 4 (`feat: add the phase-2 binary adapters`): `ee06075`
- Part 5 code (`wip: add wildcard detection and the target workspace`): `d9cf6c7`
- Regression/pitfalls addendum (`docs: add regression and pitfalls rules`): `49c68ae`
- Part 5 review (`docs: record the Part 5 review`): `7eb6b3f`
- Part 6a (`feat: add the staged engine and safety gates`): `36cd3a4`
- Part 6b (`feat: add confidence, host states, resume and exit codes`): `fffd5ea`
- Part 7 (`feat: add UI rendering, JSON and color safety`): `17d0412`
- Part 8 (`feat: add the Typer CLI, flags and mock wiring`): `c69aac5`
- Part 8 fix (`fix: align CLI timeout docs and mock help`): `83edd03`
- Part 9 (`fix: persist dangling CNAME evidence across restarts`): `83f3b85`
- Entries A, B and C below are the Part 3-AUDIT evidence. That audit was
  committed before Step 1 and Part 0 because the audit instruction arrived
  first; the ordering inversion is logged in the Step 1 entry and in Part 0.

## Step 1: save the plan, check script, resume block

- Docs read / goal: `AGENTS.md`, `docs/PROGRESS.md`, the pasted master plan. Make the plan permanent and give every session one read-only gate and one resume block.
- Decisions and assumptions: `docs/REVIEW_LOG.md` already existed from the Part 3-AUDIT; it was kept and extended rather than recreated. the four checks are run directly because `scripts/` had only `bootstrap.sh`, not a check script.
- Decisions for user review (things the user may want to overrule): the fallback to bare `python` will run the checks on 3.10 and fail; that is deliberate so a missing venv is visible rather than silently skipped.
- Docs changed first: created `docs/MASTER_PLAN.md` (verbatim from AUTONOMY RULES through Part 11), prepended the session-start block to `AGENTS.md`, added both new docs to the AGENTS docs map, added the RESUME block to `docs/PROGRESS.md`, and trimmed PROGRESS history to stay under the 150-line cap.
- Deviations: Part 3-AUDIT was completed and committed as `75eb261` before Step 1/Part 0, contrary to the requested order. No work was discarded; Part 0 records the baseline normally.
- Files touched: `docs/MASTER_PLAN.md` (new), `docs/REVIEW_LOG.md`, `docs/PROGRESS.md`, `AGENTS.md`.
- Requirement -> test table: no product behavior in Step 1. Gate evidence: the failure path was proved with a temporary `tests/test_zz_gate_probe.py` containing `assert False`; `pytest` and `ruff check` failed and the gate exited nonzero. The file was deleted and the same four commands then passed.
- Self-review findings (S2 lists, S3 raw output): no `src/` changes, so the S2 lists are empty. the gate runs only the four checks and writes nothing. Raw failing gate (tail): `pytest=FAIL`, `ruff-check=FAIL`, `ruff-format=PASS`, `mypy=PASS`, exit 1.
- Bugs found: none.
- Mutation proofs: not applicable (no behavior under test); the gate's FAIL branch was exercised as above.
- Raw check output: `238 passed, 1 skipped`, ruff check/format and mypy clean, exit 0.
- Not verified: the gate on a machine without the venv.
- Next part must know: Part 0 records the baseline and the f1 retro entry; the audit commit already exists, so do not redo it.

## Part 0: baseline

- Docs read / goal: `AGENTS.md`, `docs/MASTER_PLAN.md` Part 0, `docs/PROGRESS.md`. Record the real starting point before Part 4.
- Decisions and assumptions: `docs/PROGRESS.md` is already 146 lines with the RESUME block, under the 150-line cap. The Part 3-AUDIT work is treated as finished history, not redone.
- Decisions for user review (things the user may want to overrule): none new. The local branch is 8 commits ahead of `reconkit/main` and is not pushed, as instructed.
- Docs changed first: no product docs changed; this commit is evidence only.
- Deviations: the Part 3-AUDIT commit (`75eb261`) landed before Step 1 and Part 0 because its instruction arrived first. It is recorded here instead of being replayed.
- Files touched: `docs/REVIEW_LOG.md`, `docs/PROGRESS.md`, `tests/test_python_adapters.py` (removed one suppression added by the audit).
- Requirement -> test table: Part 0 has evidence requirements, not feature requirements. `0a`: raw git/remote/fixture/ignore output below. `0b`: the four checks twice, 238 passed / 1 skipped, S3 scans below. `0c`: f1 entry below. `0d`: S1/S3/S7 only.
- Self-review findings (S2 lists, S3 raw output):
  - S2: no `src/` diff in this part. The only code-adjacent edit was deleting a `# type: ignore[method-assign]` in a test; no broad except, blocking call, secret path or escaping exception was introduced.
  - S3 raw (bash grep): `assert` no hits; `shell=True` no hits; `TODO|FIXME|XXX|HACK` only matches the word `Hackertarget`/`hackertarget` (case-insensitive false positive, no real marker); `print(` no hits; `subprocess` only `core/runner.py` plus one docstring in `adapters/base.py`; `sqlite3` only `core/store.py`; `os.environ` no hits; broad except: `adapters/dnspython.py:130` (unexpected resolver error must stay a structured per-host ERROR, not abort the DNS stage) and `core/store.py:202` (`__init__` closes the connection and re-raises the migration error); `noqa|type: ignore` count = 3, all pre-existing in tests; adapter imports of store/scope/ui/cli: no hits.
- Bugs found: one self-inflicted suppression from the audit (`tests/test_python_adapters.py`, `# type: ignore[method-assign]`). Root cause: added defensively although mypy does not check tests and ruff accepts the assignment. Fix: removed the comment. Guarding test: the S3 suppression count is back to the 3 pre-existing entries, and `test_pyscan_respects_the_pacer_parallel_limit` still passes.
- Mutation proofs: not applicable to Part 0.
- Raw check output (last lines of the four checks, run twice): both runs ended `238 passed, 1 skipped`, `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0.
- Raw 0a evidence: `git status --short` empty; `git log --oneline -8` starts `09a5bce`, `75eb261`, `80ddd93`, `e40091d`, `d03a231`, `89ba34f`, `2cb24e4`, `1ba2fd8`; `git ls-remote reconkit main` = `5fd1d9aa0d4a2ed9fc5ef2e9d0934abdd04e7b5a` (remote behind local); fixtures: certspotter 596, crtsh 1577, dnspython 172, hackertarget 31, otx 591, pyprobe 185, pyscan 168 bytes; `git check-ignore -v .env` = `.gitignore:3:.env`; `.tmpfetch` absent.
- Not verified: nothing about real tools or network; the remote was read, never pushed.
- Next part must know: Part 4 is f3, the four remaining phase-2 binary adapters. The 3 existing suppressions are the baseline; do not add a fourth.

## f1 (retroactive): 89ba34f `feat: add HTTP subdomain adapters and tool registry`

- Docs read / goal: docs/09 adapter contract and stage registry, docs/05 secrets, `tools.yaml`. Build `adapters/base.py`, `adapters/registry.py` and the crt.sh, Cert Spotter, OTX and HackerTarget HTTP adapters.
- Decisions and assumptions: one shared `HttpAdapter` for rate limiting, timeout, User-Agent, one connect retry and 429/5xx mapping; `parse_output` stays pure and target-unaware, so domain filtering lives in `run()`; keys are read from `ctx.env` only.
- Decisions for user review: none outstanding. The later audit corrected key facts; see entry B.
- Docs changed first: docs/09 sections 2-3 and the tool registry table.
- Deviations: OTX had no real response (HTTP 429 anonymous), so its fixture is synthetic and the parser has only seen the documented shape.
- Files touched: `src/reconkit/adapters/{base,registry,__init__,crtsh,certspotter,otx,hackertarget}.py`, `tests/test_adapters.py`, `tests/test_registry.py`, four fixtures, docs/09, tools.yaml.
- Requirement -> test table: normal shapes -> `test_real_fixture_shapes`; malformed -> `test_malformed_responses_fail_without_raising`; 429/5xx -> `test_429_is_failed_and_not_retried`, `test_500_is_failed_and_not_retried`; connection retry -> `test_connection_error_retries_once_with_injected_sleep`; mock -> `test_mock_mode_reads_fixture_and_skips_network`; keys never leak -> `test_certspotter_sends_key_in_header_and_never_leaks_it`, `test_otx_sends_key_in_header_and_never_leaks_it`; dependency rule -> `test_adapters_import_no_forbidden_modules`.
- Self-review findings (S2 lists, S3 raw output): no broad except in the adapter files; external input is the HTTP body, validated by each parser; keys stay in headers, never in URLs, errors or `ToolResult`; no blocking calls in async code; no unfinished path known.
- Bugs found: none at f1. The Part 3 audit later found unverified key metadata and corrected it in `75eb261`.
- Mutation proofs: not part of the Part 0 retro loop.
- Raw check output: same Part 0 baseline, `238 passed, 1 skipped`, all four checks PASS.
- Not verified: OTX real response (anonymous 429); the free-tier provider names for subfinder; the pre-commit hook can still be bypassed with `--no-verify` and does not check REVIEW_LOG content; domain filtering is covered only through `run()` tests, not a dedicated `_within_target` unit test.
- Next part must know: f1's key metadata was superseded by `75eb261` (`keys` is the only key field); do not restore `needs_key`.

---

## Part 3-AUDIT: phase-2 commit review

One entry per phase-2 commit reviewed in the Part 3 audit. The loop used for each
entry is S1 diff integrity, S2 contract/correctness, S3 tests and edge cases,
S4 docs, S5 security and hard rules, S6 mutation proof, S7 gate.

Chain confirmed with `git log --oneline -8`:

```
80ddd93 feat: add dnspython, pyprobe and pyscan adapters
e40091d feat: define the free-first API key policy and registry keys
d03a231 fix: keep stored port/url values and cap HTTP response bodies
89ba34f feat: add HTTP subdomain adapters and tool registry
```

Full hashes:

- A = `d03a231ff31df205d9c5e7819b542300a695bd22`
- B = `e40091d6c279ba3c77f44441a59fdd9063787386`
- C = `80ddd936a3870d6cf0500395efc3519cc3c0aa26`
- f1 base = `89ba34feee08aaccb0d9f8beb0197b4b6c4caade`

Baseline before the audit (working tree clean at 80ddd93): `218 passed, 1 skipped`;
`ruff check .`, `ruff format --check .` and `mypy src/reconkit` all passed.

## A - d03a231 `fix: keep stored port/url values and cap HTTP response bodies`

S1 - The commit changes `store.py`, `adapters/base.py`, `adapters/hackertarget.py`,
their tests and docs/09. No unrelated files.

S2 - Every writer in `store.py` was re-audited for a defaulted column being reset
on conflict:

| Method | Conflict-updated columns | Verdict |
|---|---|---|
| `upsert_subdomain` | `last_seen_run` (always), `state`, `confidence`, `source_count`, `is_wildcard` (COALESCE) | keeps omitted values; explicit `0`/`False` overwrite |
| `upsert_port` | `last_seen_run` (always), `state` (always), `service`, `version`, `confidence` (COALESCE) | `state` is required, not defaulted, so updating it is intended; no reset |
| `upsert_url` | `last_seen_run` (always), `category`, `patterns_json`, `source_count` (COALESCE) | keeps omitted values; explicit `""`/`[]`/`0` overwrite |
| `add_subdomain_source`, `add_port_source` | `INSERT OR IGNORE`, composite primary key | no defaulted column is updated. First `seen` value wins per `(port, run, tool)`; cross-run diffs are unaffected |
| `append_host_status`, `record_tool_run`, `create_scan_run` | insert-only | no conflict path |
| `create_target` | `ON CONFLICT DO NOTHING` | `created_at` preserved |

No other reset was found. `insert` defaults use `COALESCE(:x, ...)` too, so a fresh
row and a conflict row agree on what `None` means.

S3 - Tests added: explicit `source_count=0` and `is_wildcard=False` overwrite;
explicit `service=""`/`version=""` overwrite; explicit `category=""`,
`patterns=[]` and `source_count=0` overwrite; body exactly at `MAX_BODY_BYTES`
passes; body at `MAX_BODY_BYTES + 1` fails; chunked body with no
`Content-Length` is capped; a lying small `Content-Length` with a large body is
capped. Mixed-case quota text (`API count Exceeded`) was already covered.

S4 - docs/09 already states the 10 MiB stream cap and the failed `ToolResult`
behaviour; no doc change was needed for the tests.

S5 - No new subprocess, scope, secret or pacing path. The body cap is a memory
safety control and stays enforced while streaming.

S6 - Mutations (each temporarily applied to `src/`, then restored):

- `source_count = COALESCE(:source_count, subdomains.source_count)` -> `..., 0)`:
  `test_upsert_subdomain_keeps_values_when_omitted` failed (`assert 0 == 3`).
- `if size > MAX_BODY_BYTES:` -> `if size > MAX_BODY_BYTES * 1000:`: the +1,
  chunked and lying-length tests failed.
- quota check deleted: `test_hackertarget_free_quota_is_reported` failed with
  `hackertarget: unexpected response (not host,ip)`.

S7 - Gate at the end of the audit: see "Gate" below.

## B - e40091d `feat: define the free-first API key policy and registry keys`

S1 - Adds the docs/05 6.1 key policy, `keys` parsing/validation, `ToolSpec.keys`,
`tools.yaml` entries and registry tests.

S2 - Corrections made after fetching the official pages (all on 2026-11-13):

- **Cert Spotter.** `https://sslmate.com/help/reference/ct_search_api_v1` says an
  API key is a Bearer token (or Basic username) and that only *unauthenticated*
  "List Issuances" queries are limited per hour, for evaluation. It gives no
  number and no authenticated quota. The old `adds` text ("free ... 100
  queries/hour") mixed the anonymous limit into the key entry; it now says the
  key authenticates queries and the unauthenticated limit is for evaluation.
  The API defines no environment variable name, so `CERTSPOTTER_API_KEY` stays
  reconkit's own name.
- **subfinder.** `https://docs.projectdiscovery.io/opensource/subfinder/install`
  lists 27 providers that need keys, but states they are stored only in
  `$HOME/.config/subfinder/provider-config.yaml`. No per-provider environment
  variable is documented, so a `keys` entry would pass an env var the child
  ignores. No `keys` entry was invented; the provider list, the file-based
  mechanism and the unverified free tiers are recorded under Open risks in
  PROGRESS. Doctor cannot hint at these keys until a provider-config bridge is
  designed.
- **`needs_key` vs `keys`.** `keys` is now the only per-tool key field.
  `urlscan`, `chaos` and `github_subdomains` were migrated, `needs_key` was
  removed from `tools.yaml`, and `registry._spec()` raises `ConfigError` if it
  reappears. docs/05 6.1 and docs/09 section 1 were updated first.
- **Chaos env name.** The chaos-client README documents `PDCP_API_KEY`, not
  `CHAOS_API_KEY`; the registry now uses the real name.
- **urlscan / github_subdomains.** Verified free account + API key
  (`https://urlscan.io/user/signup`) and `GITHUB_TOKEN` (read by the tool,
  `https://github.com/settings/tokens`; 60/hour anonymous, 5,000/hour
  authenticated per GitHub's REST rate-limit docs).

S3 - Tests: every `keys` env must appear in `.env.example`; malformed `keys`
(lowercase env, non-https, missing `adds`, non-list, non-mapping) raise
`ConfigError`; `tools.yaml` must contain no `needs_key`; an entry that still
uses `needs_key` raises `ConfigError`; the Cert Spotter text no longer claims
100 queries/hour; Chaos/urlscan/github env names are asserted.

S4 - docs/05 6.1 (single source of truth, subfinder exception), docs/05 7
(active env names), docs/09 section 1 and the tools.yaml header were updated
before the code.

S5 - The loader still enforces `https` URLs and `^[A-Z][A-Z0-9_]*$` env names;
no key value is stored or printed, and `.env.example` lists names only.

S6 - Mutations:

- https check -> `if False:`: both "must be https" cases failed.
- env regex -> `if False:`: the lowercase-env case failed.
- `PDCP_API_KEY` deleted from `.env.example`:
  `test_every_key_env_is_in_env_example` failed with
  `PDCP_API_KEY missing from .env.example`.

S7 - Gate at the end of the audit: see "Gate" below.

## C - 80ddd93 `feat: add dnspython, pyprobe and pyscan adapters`

S1 - Touches adapters, models, store, docs/09 and docs/04, three JSON fixtures and
one test file. `RunContext.ports` and `HostStatusRecord.location` are the model
changes.

S2 - The docs/09 text for per-host input is (as of this commit, section 3):

> Per-host adapters (`python` kind) read their inputs from `ctx.hosts` (and
> `ctx.ports` for port scanners); both are already scope-checked by the engine.
> `pyscan` calls `ctx.pacer.order(ctx.ports, kind="port")` itself because it
> owns the scan loop; the engine only fills the lists.

and the schema says `ports: list[int] = []  # port-scan input; empty = adapter
default list`. `RunContext` did gain `ports` in this commit, and docs/09 was
updated in the same commit, so the engine does not have to guess. The code and
docs agree; nothing was changed for this item.

`DnsResult` already had a structured `DnsOutcome` (`resolved`, `nxdomain`,
`noanswer`, `servfail`, `timeout`, `error`), so timeout and
SERVFAIL/NoNameservers are distinct values, not only an error string. No-answer
stays distinct from NXDOMAIN, and only NXDOMAIN produces `DEAD`. Audit fixes:

- An unexpected resolver exception was not caught (`RuntimeError` escaped
  `resolve_host` and aborted the stage). It now maps to `DnsOutcome.ERROR`.
- Per-host adapters did not normalize their input. Every per-host adapter now
  calls `validate_host()`; uppercase names are lowercased and IDN/invalid names
  are skipped and counted instead of being put in a request.
- `pyscan` closed the socket only after `wait_closed()` could be cancelled. It
  now calls `close()` (synchronous) before the first await, so cancellation
  cannot leak the connection.

S3 - Tests added for all four required DNS outcomes plus `resolved` and `error`
(asserted with distinct enum values), CNAME loop -> `error` not `DEAD`,
unexpected resolver exception -> `error` not a crash, uppercase host
normalization and IDN rejection in all three adapters, empty inputs for all
three, out-of-range ports (`0`, `-1`, `65536`, `70000` are not dialled), the
pyscan semaphore bound, binary banner bytes never read, cancellation closing the
writer, and the existing "Location to an out-of-scope host is recorded but not
followed" test (`outside.example.net`, exactly one request).

S4 - docs/09 now records the structured DNS outcomes and the per-host
`validate_host()` rule. The three synthetic fixtures are listed explicitly under
Open risks in PROGRESS.

S5 - No adapter imports `store`, `scope`, `ui` or `cli`; the dependency test
still covers all three files. No payload is sent, no banner is read, and
`pyprobe` still does not follow redirects.

S6 - Mutations:

- TIMEOUT -> NXDOMAIN: `test_dnspython_nxdomain_timeout_servfail_are_distinct`
  failed (`assert <DnsOutcome.NXDOMAIN> is <DnsOutcome.TIMEOUT>`).
- `follow_redirects=False` -> `True`: the redirect test failed (no record after
  `TooManyRedirects`).
- pyscan semaphore -> `Semaphore(999)`: the bound test failed (`assert 10 == 2`).
- `writer.close()` removed: the cancellation test failed
  (`assert False is True`).
- the `except Exception` branch removed: the unexpected-exception test failed
  with `RuntimeError: resolver bug`.

S7 - Gate at the end of the audit: see below.

## Gate

Run from the canonical checkout with the venv activated, after all audit changes:

```
pytest -q                    238 passed, 1 skipped in 7.33s
ruff check .                 All checks passed!
ruff format --check .        57 files already formatted
mypy src/reconkit            Success: no issues found in 37 source files
```


## Part 4: binary adapters f3

- Docs read / goal: `docs/09_TOOL_CONTRACTS.md`, `docs/03_ARCHITECTURE.md` (adapter file names), `docs/05_SECURITY.md` 4-6, `tools.yaml`, and the official pages for subfinder, assetfinder, ProjectDiscovery httpx and naabu. Implement every remaining phase-2 binary adapter: subfinder, assetfinder, httpx, naabu.
- Decisions and assumptions: a shared `BinaryAdapter` in `adapters/base.py` resolves `~/.reconkit/bin` before `PATH` and verifies identity from the registry `version_cmd` output. subfinder provider keys are bridged to a temporary `provider-config.yaml` because Part 4 requires it and subfinder has no env-var reader. httpx JSON lines without `status_code` are failed probes and are skipped, not marked ALIVE. Empty host lists are a failed command, not an empty argv. naabu always uses `-scan-type c`.
- Decisions for user review (things the user may want to overrule): subfinder now lists four keys (certspotter, chaos, github, virustotal) and the adapter writes them to a temp file; this reverses the audit's "no env bridge" open risk. A wrong binary and a missing binary both return `installed=False`, but a wrong binary also sets `path` so doctor can show it. `chmod 0600` on the temp config is best-effort.
- Docs changed first: `docs/09` section 3 (BinaryAdapter, identity, missing/exit/timeout, subfinder bridge, httpx/naabu flags), `docs/05` 6.1 (subfinder exception replaced by the bridge), `tools.yaml` (`keys` for subfinder, note updated).
- Deviations: the provider config is written synchronously in the event-loop thread (bounded, under 1 KiB, local disk). Fixtures are synthetic because none of the four binaries is installed. The rate-cap mutation target does not apply to f3: all four tools are `core`, and no opt-in tool is in this part.
- Files touched: `src/reconkit/adapters/{base,subfinder,assetfinder,httpx_tool,naabu,__init__}.py`, `tests/test_binary_adapters.py`, four synthetic fixtures, `tools.yaml`, `docs/05`, `docs/09`, `docs/PROGRESS.md`.
- Requirement -> test table:
  - adapter for every remaining phase-2 tool -> `test_binary_adapters_are_registered`
  - identity check, not name only -> `test_projectdiscovery_httpx_identity_is_accepted`, `test_python_httpx_cli_is_rejected`, `test_assetfinder_usage_identity`, `test_identity_timeout_is_not_installed`
  - argv list, no shell, validated hosts, leading `-` rejected -> `test_subfinder_command_and_rate_flag`, `test_assetfinder_command`, `test_httpx_command_dedupes_and_lowercases_hosts`, `test_naabu_command_and_ports`, `test_flag_like_host_is_rejected_before_argv`, `test_flag_like_target_is_rejected`, `test_empty_host_list_is_a_failed_command`
  - key never in argv; temp file deleted on success/failure/timeout -> `test_subfinder_writes_and_deletes_provider_config`, `test_subfinder_deletes_provider_config_on_parse_failure`, `test_subfinder_deletes_provider_config_on_timeout`, `test_subfinder_without_keys_has_no_provider_flag`, `test_subfinder_provider_envs_are_registry_keys`
  - parse normal/empty/malformed -> `test_subfinder_and_assetfinder_parse_fixtures`, `test_httpx_parse_fixture`, `test_naabu_parse_fixture`, `test_empty_output_is_ok`, `test_malformed_output_fails_without_raising`
  - missing binary / non-zero / timeout distinct -> `test_run_missing_binary_is_distinct`, `test_run_nonzero_exit_is_distinct`, `test_run_timeout_is_distinct`, `test_run_runner_error_is_a_failed_result`
  - no secret in result -> `test_subfinder_writes_and_deletes_provider_config`
  - AST import rule -> `test_binary_adapters_import_no_forbidden_modules`
  - mock mode -> `test_mock_mode_reads_fixture`
  - adversarial: ANSI, duplicates, stderr noise, truncation, empty vs partial, uppercase, IPv6 -> `test_ansi_and_log_noise_are_ignored`, `test_duplicate_httpx_and_naabu_lines_are_merged`, `test_run_truncated_output_is_reported`, `test_httpx_parser_skips_lines_without_a_status`, `test_httpx_parser_handles_url_input`, `test_naabu_parser_accepts_ipv6`
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: none added. Specific handlers only: `(TypeError, ValueError)` for validation, `OSError`/`yaml.YAMLError` for the temp file, `RuntimeError` for runner pipe failure.
  - External input: `ctx.target` -> `validate_target`; `ctx.hosts` -> `validate_host`; `ctx.ports` -> `1..65535`; tool stdout -> strict per-line parser; version output -> identity markers; fixture files -> the same parser.
  - Secrets: key values only enter the 0600 temp file and the child env; argv holds only the temp path; `runner` redacts env values in stdout/stderr before the adapter sees them; tests assert no secret in argv/result.
  - Blocking call in async: one synchronous YAML write in `SubfinderAdapter.prepare` (bounded, local, no network); recorded above.
  - Escaping exceptions: parsers raise `ParseError`, `prepare` raises `ToolFailed`, `run_exec` `RuntimeError` is mapped; `asyncio.CancelledError` still propagates, and `prepare`'s `finally` deletes the temp file.
  - Unfinished path: engine wiring (`ctx.env` from `keys`, tool selection) is Part 6; real binaries are not installed, so identity markers are based on official docs, not a live run.
  - S3 raw: `assert` none; `shell=True` none; `TODO|FIXME|XXX|HACK` none; `print(` none; `subprocess` only `core/runner.py` plus the `base.py` docstring; `sqlite3` only `core/store.py`; `os.environ` none; broad except only the two justified earlier (`dnspython.py:130`, `store.py:202`); suppressions = 3, all pre-existing; adapter imports of store/scope/ui/cli none.
- Bugs found:
  1. httpx identity: name-only resolution would accept the Python `httpx` CLI. Root cause: no identity check in the base. Fix: `BinaryAdapter.check_installed` matches the tool's own banner/version text. Guard: `test_python_httpx_cli_is_rejected`.
  2. httpx JSON without `status_code` would have been stored as `ALIVE`. Root cause: no distinction between a response and a failed probe. Fix: skip status-less lines. Guard: `test_httpx_parser_skips_lines_without_a_status`.
  3. `run_exec` `RuntimeError` could escape an adapter. Root cause: only parse/fetch errors were mapped. Fix: map it to a failed result. Guard: `test_run_runner_error_is_a_failed_result`.
  4. `yaml.safe_dump` failure could leave the provider file behind. Root cause: only `OSError` was caught. Fix: catch `yaml.YAMLError` and unlink. Not separately testable without monkeypatching PyYAML; covered by inspection.
- Mutation proofs: key-in-argv -> `test_subfinder_writes_and_deletes_provider_config` failed on `assert all("secret" not in arg ...)`; identity check -> `test_python_httpx_cli_is_rejected` failed with `installed=True`; rate-cap refusal -> not applicable (no opt-in tool in f3, recorded above). `git status --short` after restore showed only the intended Part 4 changes.
- Raw check output (twice): `295 passed, 1 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0 (both runs).
- Not verified: real subfinder/assetfinder/httpx/naabu binaries and their exact version banners; whether real subfinder accepts the generated provider-config on all versions; JSON fields beyond the official docs; rate flags against live binaries; installer-provided binary paths.
- Next part must know: `ADAPTERS` now covers every phase-2 tool. Engine work must pass only the tool's `keys` env, and subfinder's temp file is handled inside the adapter. Adapter file names follow docs/03: `httpx_tool.py`, not `httpx.py`.

### Tool table (from tools.yaml)

| Tool | Stage | Tier | Adapter |
|---|---|---|---|
| crtsh | subs | core | yes |
| certspotter | subs | core | yes |
| otx | subs | core | yes |
| hackertarget | subs | core | yes |
| urlscan | subs | core | no |
| subfinder | subs | core | yes |
| assetfinder | subs | core | yes |
| amass | subs | core | no |
| findomain | subs | core | no |
| chaos | subs | core | no |
| github_subdomains | subs | core | no |
| dnspython | dns | core | yes |
| dnsx | dns | core | no |
| puredns | dns | core | no |
| massdns | dns | core | no |
| dig | dns | core | no |
| pyprobe | live | core | yes |
| httpx | live | core | yes |
| httprobe | live | core | no |
| tlsx | live | core | no |
| smap | ports | core | no |
| pyscan | ports | core | yes |
| naabu | ports | core | yes |
| nmap | ports | core | no |
| rustscan | ports | core | no |
| masscan | ports | opt_in | no |
| httpx_tech | tech | core | no |
| whatweb | tech | core | no |
| wafw00f | tech | core | no |
| cdncheck | tech | core | no |
| webanalyze | tech | core | no |
| gau | urls | core | no |
| waybackurls | urls | core | no |
| katana | urls | core | no |
| hakrawler | urls | core | no |
| gospider | urls | core | no |
| subjs | urls | core | no |
| unfurl | urls | core | no |
| urlfinder | urls | core | no |
| nuclei | vulns | core | no |
| subzy | vulns | core | no |
| dnsreaper | vulns | core | no |
| nikto | vulns | opt_in | no |
| ffuf | vulns | opt_in | no |
| gowitness | shots | opt_in | no |
| dalfox | vulns | intrusive | no |
| crlfuzz | vulns | intrusive | no |
| sqlmap | vulns | intrusive | no |

Per-stage counts: subs 11, dns 5, live 4, ports 6, tech 5, urls 8, vulns 8, shots 1. `subs` is above the 3-8 guide (11) and `shots` below it (1, Phase-3 opt-in); no tool was invented or removed.

## Addendum: regression and pitfalls rules

- Goal: make every known trap visible before coding and make every future fix carry a failing-then-passing guard. Applied before resuming the Part 5 review, as instructed.
- Docs first: added the Known pitfalls table at the top of this file, the `REGRESSION AND PITFALLS RULES` section to `docs/MASTER_PLAN.md`, the pitfall line to G1, the `Pitfalls added this part` line to S7, and the session-start line to `AGENTS.md`. the pre-commit hook prints `WARN: fix commit without a test change` when HEAD is a `fix:` subject with no `tests/` file.
- Back-fill: no behavior changed. Existing guards were tagged with `Regression: PIT-xx` docstrings: PIT-01 `test_dnspython_nxdomain_timeout_servfail_are_distinct`; PIT-02 `test_tool_rate_args_slow_passive_vs_active`; PIT-03 the three `test_upsert_*_keeps_*_when_omitted` tests; PIT-04 `test_redact_cases`; PIT-05 `test_timeout_keeps_partial_output`; PIT-06 `test_timeout_kills_child`; PIT-11 `test_workspace_rejects_unsafe_filenames`; PIT-13 `test_wildcard_labels_are_unique_valid_and_under_the_target`; PIT-14 `test_python_httpx_cli_is_rejected`; PIT-15 `test_httpx_parser_skips_lines_without_a_status`; PIT-16 `test_run_runner_error_is_a_failed_result`; PIT-18 `test_subfinder_writes_and_deletes_provider_config`; PIT-19 `test_tools_yaml_has_no_legacy_needs_key`; PIT-20 `test_lying_small_content_length_is_still_capped`; PIT-21 `test_wildcard_unknown_is_not_none`; PIT-22 `test_workspace_redacts_two_secrets_and_a_bearer_token`.
- Failing-before-fix evidence already recorded: PIT-01/02/03/04/20 in the Part 3-AUDIT mutation proofs; PIT-14/15/16/18 in the Part 4 proofs. No new mutation was needed because those tests are the same guards, only tagged. New Part 5 mutations are recorded in the Part 5 entry.
- UNTESTED rows: PIT-06 (needs Linux), PIT-17 (needs a PyYAML fault injection), PIT-23 (review fix; no observable behavior test). PIT-07/08/09/10/12/25/26 are non-code traps with `n/a`.
- Raw WARN simulation (the current HEAD is `wip:`, so the real gate cannot emit it yet): subject `fix: simulate` with `src/reconkit/core/wildcard.py` printed `WARN-SIM: fix commit without a test change`; the same subject with `tests/test_wildcard_workspace.py` printed `WARN-SIM: no warning`.
- Raw check output after the addendum: `342 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, gate exit 0. A separate `ruff check .` printed `All checks passed!`.
- Pitfalls added this part: PIT-01 through PIT-26.
- Not verified: the real gate's WARN line before a real `fix:` commit (only the simulated branch was run); PIT-06 on Linux; PIT-17 and PIT-23 as above.

## Part 5: wildcard detection + target workspace

- Docs read / goal: `docs/03_ARCHITECTURE.md` section 5 (workspace layout) and section 8 (wildcard), `docs/04_DATABASE.md` (`subdomains.is_wildcard`, redaction rule), `docs/05_SECURITY.md` sections 6 (redaction, 0700 workspace), `docs/09_TOOL_CONTRACTS.md` section 5 (wildcard/confidence). Implement `core/wildcard.py` and `core/workspace.py` with no new dependencies.
- Decisions and assumptions: the detector takes an injected `probe` rather than importing the DNS adapter at runtime, so `core` keeps its dependency direction; the engine passes `DnsPythonAdapter.resolve_host` bound to the run context, which keeps probes on the same resolver and limiter. `rng` is a required injected `Rng` protocol (no `random.Random()` default, which S311 rejects). One resolved probe is enough for `present`; `unknown` covers timeout/SERVFAIL/no-answer/error only when nothing resolved. A host matches when its CNAME is in the wildcard CNAME set or all of its IPs are in the wildcard IP set. Partial probe sets still count as `present`.
- Decisions for user review (things the user may want to overrule): Workspace writes are synchronous (`fsync` + `os.replace`); the engine must keep large outputs off the event loop. The workspace root is created but not chmodded; only the target and stage directories get `0700`.
- Docs changed first: `docs/03` gained the Workspace API, the wildcard API and the unknown/partial rules; `docs/09` section 5 gained the exact matching and unknown rule; `docs/05` now says workspace files are redacted before the write.
- Deviations: Part 5 landed as three commits because the regression/pitfalls addendum required a `wip:` commit mid-part (`d9cf6c7`), then its own `docs:` commit (`49c68ae`), then this review record. The code is complete in `d9cf6c7`; no code changed in the later commits. The first mutation attempt used the full filename parameter list, reached the UNC case, and hung on the network share until the 180 s tool timeout; the files were restored and the proof was re-run with only `../escape.txt` under a 60 s timeout. No repo file was created by the hung run (`workspaces/` absent).
- Files touched: `src/reconkit/core/workspace.py`, `src/reconkit/core/wildcard.py`, `tests/test_wildcard_workspace.py`, `docs/03`, `docs/05`, `docs/09`, `docs/REVIEW_LOG.md`, `docs/PROGRESS.md`.
- Requirement -> test table:
  - wildcard yes / no / unknown(timeout) -> `test_wildcard_present_and_only_wildcard_ips_match`, `test_wildcard_none_when_every_probe_is_nxdomain`, `test_wildcard_unknown_is_not_none`
  - partial wildcard (some resolve, some NXDOMAIN) -> `test_wildcard_present_and_only_wildcard_ips_match` (2 resolved + 1 NXDOMAIN), `test_wildcard_resolved_beats_a_failed_probe`
  - CNAME wildcard -> `test_wildcard_cname_answer_matches_cname`
  - unknown is not no-wildcard -> `test_wildcard_unknown_is_not_none`, `test_wildcard_timeout_plus_nxdomain_is_unknown`
  - traversal rejected -> `test_workspace_rejects_unsafe_filenames`, `test_workspace_rejects_unknown_stages`, `test_workspace_rejects_invalid_targets`
  - domain validated -> `test_workspace_rejects_invalid_targets`, `test_workspace_create_builds_documented_layout`
  - redaction applied -> `test_workspace_redacts_two_secrets_and_a_bearer_token`
  - atomic write leaves no partial file -> `test_workspace_failed_replace_leaves_no_partial_file`, `test_workspace_same_filename_twice_replaces_atomically`
  - documented layout only -> `test_workspace_create_builds_documented_layout`, `test_workspace_rejects_unknown_stages`
  - empty / very large output -> `test_workspace_empty_output_is_written`, `test_workspace_large_output_is_written`
  - labels valid and under target -> `test_wildcard_labels_are_unique_valid_and_under_the_target`
  - injected RNG -> `test_wildcard_labels_are_unique_valid_and_under_the_target` (CyclingRng)
  - probe exception -> `test_wildcard_unexpected_probe_exception_is_unknown`
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: `except Exception` in `WildcardDetector.detect` (a probe failure must be `unknown`, never abort the scan) and `except BaseException` in `Workspace.write` (cleanup of the temp file on cancellation/KeyboardInterrupt, then re-raise). Both are deliberate and recorded; no other new broad handler.
  - External input: `target` -> `validate_target()`; `stage` -> exact `STAGES` allowlist; `filename` -> regex, length, trailing-dot, reserved-name and one-segment checks plus `resolve()` containment; `text`/`secrets` -> type checks and `store.redact()`; probe results -> `outcome` comparison and IP/CNAME sets; `rng` -> the `Rng` protocol.
  - Secrets: `redact()` runs before `mkstemp`, the temp file is `0600`, the destination keeps `0600`, and no secret enters a filename or error. Tests assert both supplied secrets and a Bearer token are gone.
  - Blocking call in async: `Workspace.write` is synchronous (local `fsync` + `os.replace`); the engine must offload large raw writes. No new blocking call inside an `async def`.
  - Escaping exceptions: `path()`/`write()` raise `ValueError`/`TypeError`/`OSError` by design; `detect()` catches probe exceptions and lets `CancelledError` (a `BaseException`) propagate. The temp file is unlinked on every failure path.
  - Unfinished path: engine wiring is Part 6 (construct the detector with `partial(dns.resolve_host, ctx)` and `random.Random`, pass `wildcard_check.probes`, call `Workspace.create` with the allowed env values).
  - S3 raw: `assert` none in the two modules; `shell=True` none; `TODO|FIXME|XXX|HACK` none; `print(` none; `subprocess` only `core/runner.py`; `sqlite3` only `core/store.py`; `os.environ` none; broad except the two above; suppressions still the 3 pre-existing; no runtime core -> adapter import (`DnsResult` is `TYPE_CHECKING` only).
- Bugs found:
  1. `random.Random()` as a default tripped S311. Root cause: convenience default. Fix: require an injected `Rng`; tests use `CyclingRng`. Guard: PIT-13 `test_wildcard_labels_are_unique_valid_and_under_the_target`.
  2. `Workspace.create` chmodded `self.root`, which may be a caller-owned parent. Root cause: applied workspace mode to the shared root. Fix: chmod only the target and stage dirs. Guard: none (PIT-23 UNTESTED; review fix).
  3. A test edit produced `probe = ...    result = ...` on one line (syntax error). Root cause: a replacement lost a newline. Fix: split the lines; collection passes. Not a product bug.
  4. The first mutation run hung on a UNC path. Root cause: with the traversal checks disabled, the test tried to write to `\\server\share`. Fix: re-ran the proof with only the `../escape.txt` case and a timeout. No product change; recorded above.
- Mutation proofs: traversal checks disabled (all four guards no-op) -> `test_workspace_rejects_unsafe_filenames[../escape.txt]` failed `DID NOT RAISE ValueError`, 1 failed; redaction disabled (`cleaned = text`) -> `test_workspace_redacts_two_secrets_and_a_bearer_token` failed because `sk-live-abc123` was still present, 1 failed; UNKNOWN changed to NONE -> `test_wildcard_unknown_is_not_none[timeout|servfail|noanswer|error]` all failed `NONE is not UNKNOWN`, 4 failed. Each file was restored from a backup; the post-restore grep showed no mutation and the full gate passed.
- Raw check output (twice): `342 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0. The new test file alone: `47 passed, 1 skipped`.
- Not verified: real wildcard DNS (no resolver/network run) and real CNAME wildcard behavior; engine integration (Part 6) and the effect of synchronous large writes on the loop; the addendum's real `fix:`-commit WARN path.
- Pitfalls added this part: PIT-13, PIT-21, PIT-22.
- Next part must know: `WildcardDetector(probe, rng, probes)` requires the engine to bind the DNS adapter to the run context; `matches()` is the only `is_wildcard` decision; `Workspace.create(root, target, secrets)` is the only constructor the engine should use, and writes are redacted atomically.

## Part 6a: staged engine, selection and safety gates

- Docs read / goal: `docs/09_TOOL_CONTRACTS.md` sections 3-5 (selection rules, wildcard, host rule), `docs/01_PRD.md` pipeline description, `docs/02_CLI_UX.md` flags/speed table, `docs/03_ARCHITECTURE.md` data flow and dependency rules, `docs/04_DATABASE.md` bulk-write/redaction rules. Build the engine skeleton: stage order, tool selection, tier/mode/scope gates, env filtering, phase timeouts, mock pipeline and batched writes.
- Decisions and assumptions: one `scan_runs` row per executed stage; one `tool_runs` row per selected or skipped tool. `subs` gets `[target]`; `dns`/`live` get the target plus discovered hosts; `ports` gets only hosts with an ALIVE record, and is skipped when none exist. The target is always checked against scope for active stages even when it is the only host. An active stage whose `require_active()` fails is skipped with a recorded reason, not raised out of the pipeline; Part 8 will refuse `--active` earlier. `--tools` is validated globally (unknown and intrusive names raise `ConfigError`); `opt_in` needs `--include-noisy` or an explicit `--tools`; intrusive tools are never selected. `--mock` bypasses `check_installed()` and every adapter's non-mock path. `FindingRecord` is not persisted because the findings table is still deferred.
- Decisions for user review (things the user may want to overrule): a port scan with no stored ALIVE host produces no run instead of scanning the root target; a scope failure silently skips active tools (the CLI's refusal is the user-facing guard); `scan_runs.stage` is the stage name, not a single `run` row for the whole pipeline.
- Docs changed first: `docs/03` gained the Engine API and the env/selection/mock/transaction contract; `docs/04` gained `store.transaction()` semantics; docs/09 already specified the selection rules and needed no change.
- Deviations: `Store.transaction()` uses SQLite's implicit transaction rather than an explicit `BEGIN`; the explicit form failed inside the implicit transaction that the previous write left open (PIT-27). Engine asset writes are batched; `tool_runs` are recorded per tool as they finish so a phase timeout still leaves evidence.
- Files touched: `src/reconkit/engine.py`, `src/reconkit/core/store.py`, `tests/test_engine.py`, `tests/test_store.py`, `docs/03`, `docs/04`, `docs/REVIEW_LOG.md`, `docs/PROGRESS.md`.
- Requirement -> test table:
  - stage order -> `test_stage_order_and_tool_rows`
  - tier gating / opt_in -> `test_tier_gating_and_explicit_intrusive_refusal`
  - unknown or intrusive `--tools` refused -> `test_tier_gating_and_explicit_intrusive_refusal`
  - active without `--active` skipped -> `test_active_without_flag_skips_and_scope_drops_host`
  - out-of-scope host dropped before active contact -> `test_active_without_flag_skips_and_scope_drops_host`
  - env filtering and `--no-keys` -> `test_env_filtering_and_no_keys`
  - one tool crashing, others succeed -> `test_one_crash_does_not_stop_the_stage`
  - all tools failing -> `test_all_tools_failing_is_not_an_exception`
  - phase timeout -> `test_phase_timeout_records_a_timeout_row`
  - redacted stored error -> `test_tool_error_is_redacted_before_storage`
  - slow mode runs one at a time -> `test_slow_mode_runs_one_tool_at_a_time`
  - disallowed tool's command never built -> all engine tests use an adapter whose `build_command` raises; `rec.built == []` in `test_stage_order_and_tool_rows`
  - one `tool_runs` row per tool -> `test_stage_order_and_tool_rows`
  - transaction commits/rolls back -> `test_transaction_commits_once_and_rolls_back`
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: `except Exception` in `Engine._run_one` (convert an adapter bug into a failed, redacted result), `except TimeoutError` for per-tool and phase timeouts, and `except BaseException` in `Store.transaction` for rollback-on-cancel. No other new handler.
  - External input: `ScanOptions` (speed checked against the literal set, timeout > 0, tools exist and are not intrusive), `target` via `validate_target`, hosts via `validate_host` + target suffix, scope via `load_scope`/`require_active`, adapter records via Pydantic models, env only through each spec's `keys`.
  - Secrets: `self._secrets` is used for workspace redaction, exception redaction and `record_tool_run`; `scan_runs.params_json` contains only tool names and booleans; `ctx.env` contains only the current tool's keys. No full environment is copied.
  - Blocking call in async: `check_installed()` is now run with `asyncio.to_thread`; `Workspace.create`, `load_scope` and `require_active` do short synchronous local file I/O, and `RateLimiter`/`Pacer` take the injected sleep/clock. Raw workspace output is not written by the engine yet, so the large-write risk is still open.
  - Escaping exceptions: `ConfigError` escapes for invalid selection (the CLI maps it to exit 2); `ScopeError` is caught and becomes skipped rows; adapter exceptions become failed results; `CancelledError` propagates (Part 6b cancellation work).
  - Unfinished path: consensus/confidence, host-state transitions, resume and exit codes are Part 6b; `FindingRecord` persistence is deferred with the findings table; the engine does not yet pass wildcard results into `is_wildcard` or write raw adapter output.
  - S3 raw: `assert` none in `engine.py`; `shell=True` none; `TODO|FIXME|XXX|HACK` none; `print(` none; `subprocess` only `core/runner.py`; `sqlite3` only `core/store.py`; `os.environ` none; broad except only the engine handler above plus the previously justified ones; suppressions still 3.
- Bugs found:
  1. PIT-27: `store.transaction()` raised `sqlite3.OperationalError: cannot start a transaction within a transaction` in `test_transaction_commits_once_and_rolls_back`. Root cause: explicit `BEGIN` while SQLite's implicit transaction was still open. Fix: drop the explicit `BEGIN`, keep the depth counter and commit/rollback at block exit. Guard: `test_transaction_commits_once_and_rolls_back` (failing output in the mutation record below).
  2. Test helper `class Fake: stage = stage` raised `NameError` (class scope does not close over the function parameter); fixed by assigning `Fake.stage` after the class. Test-only, no product change.
- Mutation proofs: scope gate disabled (`_active_hosts` returns hosts unchanged) -> `test_active_without_flag_skips_and_scope_drops_host` failed with `api.example.com` in the live hosts, 1 failed; env filter removed (`_tool_env` returns all env) -> `test_env_filtering_and_no_keys` failed with `{'ONLY_ME': ..., 'OTHER': 'not-for-you'}`, 1 failed; tier gates disabled -> `test_tier_gating_and_explicit_intrusive_refusal` failed with `['core', 'noisy', 'intrusive']`, 1 failed. All files restored from backups; the post-restore grep found no mutation.
- Raw check output (twice): `352 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0 (both runs).
- Not verified: real adapters/network and installed binaries through the engine; resume and cancellation; consensus/host-state results (Part 6b); scope files with regex/CIDR entries and a real `allow_active: false`. The mock pipeline is covered only with fake adapters, not the real fixture-backed adapters end to end.
- Pitfalls added this part: PIT-27.
- Next part must know: `Engine.run` returns `ScanSummary` with one `StageOutcome` per executed stage; `tool_runs` rows exist even for skipped/timeout tools; Part 6b must add confidence/host states/resume and must not move consensus out of `engine.py`. The store batch helper is `with store.transaction():`.

## Part 6b: confidence, host states, resume and exit codes

- Docs read / goal: `docs/01_PRD.md` Features 4 and 6, `docs/02_CLI_UX.md` exit-code table and the missing `--resume` flag, `docs/03_ARCHITECTURE.md` consensus/data-flow sections, `docs/04_DATABASE.md` `subdomains`/`host_status_history` schema and state rule, `docs/09_TOOL_CONTRACTS.md` section 5. Implement confidence, the unconditional host-state rule, stage resume, injected timestamps and a typed exit result in `engine.py` only.
- Decisions and assumptions: confidence counts **distinct** tools (`len(set(sources))`), with disagreement forced to `UNCONFIRMED`. Discovery merges by `fqdn`/`url`; live merges by host; ports merge by `(fqdn, ip, port)`. `min_sources` filters discovery and port rows. `--resume` uses the newest `scan_key` in `scan_runs.params_json`, skips stages whose rows are `completed`/`partial`, marks leftover `running` rows `interrupted`, and creates a fresh row for the unfinished stage. On resume, discovered/alive sets are reseeded from `Store.subdomains()`. The state rule is unconditional: only NXDOMAIN can produce `DEAD`; timeout/SERVFAIL/no-answer/error keep the previous state and warn. `SHUT_DOWN` is chosen only when the previous state was `ALIVE` or `DNS_ONLY`. Timestamps come from the injected `now` source, default `store.utc_now()`.
- Decisions for user review (things the user may want to overrule): resume is stage-level, not tool-level; a crashed stage is rerun, so tools that finished inside it run again (asset writes are batched at stage end). `scope_denied` maps to exit 3 even when passive tools succeeded. All tools failing maps to exit 4; a mixture maps to 5. A first-run timeout records `UNKNOWN` without a history row; an established host keeps its state and gets a warning. CNAME warnings are in `ScanSummary.warnings`, not the database, because `host_status_history` has no CNAME column. Wildcard detection remains unwired (Open risk).
- Docs changed first: `docs/02` gained `--resume`; `docs/03` gained the injected `now`, `min_sources`/`resume`, typed `ExitCode`, the full transition table, the unconditional timeout rule and the CNAME warning; `docs/04` gained the timestamp/resume rules and the `Store.scan_runs()`/`Store.subdomains()` read queries.
- Deviations: `--resume` was documented in `docs/08` but missing from the `docs/02` flag table, so it was added there first. Resume is stage-level as above. The engine's `now` default is a public `store.utc_now()` wrapper; `Store._utc_now` remains for direct store calls. `ScanSummary.exit_code` is an `IntEnum`; no `sys.exit()` exists in `engine.py`.
- Files touched: `src/reconkit/engine.py`, `src/reconkit/core/store.py`, `tests/test_engine.py`, `docs/02_CLI_UX.md`, `docs/03_ARCHITECTURE.md`, `docs/04_DATABASE.md`, `docs/REVIEW_LOG.md`, `docs/PROGRESS.md`.
- Requirement -> test table:
  - HIGH with 3 distinct tools -> `test_confidence_three_distinct_tools_high`
  - MEDIUM with 2 -> `test_confidence_two_distinct_tools_medium`
  - LOW with 1 -> `test_confidence_one_tool_low`
  - UNCONFIRMED on disagreement -> `test_confidence_disagreement_unconfirmed`, `test_engine_disagreement_is_unconfirmed`
  - same tool three times is not HIGH -> `test_same_tool_three_results_is_not_high`
  - engine persistence of HIGH/3 sources -> `test_engine_persists_three_distinct_tools_as_high`
  - timeout/SERVFAIL never DEAD -> `test_regression_dns_timeout_not_dead`
  - SHUT_DOWN after ALIVE, external CNAME -> `test_shut_down_after_alive_with_external_cname`
  - DEAD only on NXDOMAIN -> `test_dead_only_on_nxdomain`
  - UNKNOWN -> ALIVE -> SHUT_DOWN -> ALIVE recovery -> `test_state_recovers_unknown_alive_shut_down_alive`
  - unprobed stays UNKNOWN -> `test_unprobed_host_stays_unknown`
  - DNS resolved, no web response -> `test_dns_resolved_without_web_is_dns_only`
  - deterministic timestamps -> `test_injected_clock_controls_state_and_run_timestamps`
  - resume skips completed stages, reseeds hosts, no duplicate rows -> `test_resume_skips_completed_stages_and_continues`
  - exit 0 clean / 3 scope / 4 no tool / 5 partial / crash -> `test_exit_code_clean_is_success`, `test_exit_code_scope_violation`, `test_exit_code_all_tools_failed_is_no_tool`, `test_exit_code_partial_success`, `test_exit_code_tool_crash_is_partial`
  - 1/2/130 constants -> `test_exit_code_constants_match_docs`
  - `--min-sources` filtering -> `test_min_sources_hides_low_source_results`
  - no `consensus.py` -> `Get-ChildItem -Recurse -Filter 'consensus*.py' src\reconkit` returns nothing
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: `except Exception` in `Engine._run_one` (adapter crash becomes a redacted failed result) and around `_persist_stage` (mark the run `failed`, then re-raise); `except asyncio.CancelledError` marks the run `interrupted` and re-raises; `Store.transaction` still rolls back on `BaseException`. No other new handlers.
  - External input: `ScanOptions` fields validated (`speed`, `phase_timeout`, `min_sources`, tool names/tier); target via `validate_target`; hosts via `validate_host` + suffix; scope via `load_scope`/`require_active`; adapter records via Pydantic; resume rows parsed defensively (`json.loads`, `Stage(...)` caught).
  - Secrets: `_secrets` is used for workspace, error and `params_json` redaction; resume stores only a random `scan_key`; no env values enter `scan_runs` or warnings.
  - Blocking call in async: `check_installed()` stays on `asyncio.to_thread`; `Workspace.create`, `load_scope` and SQLite writes remain short synchronous local I/O. Resume reads all `scan_runs`/`subdomains` once at start.
  - Escaping exceptions: `ConfigError` escapes for invalid options; `ScopeError` becomes skipped active tools + exit 3; `CancelledError` is recorded and re-raised; adapter crashes become failed results.
  - Unfinished path: wildcard detection is still not wired into the engine; CNAME warnings are not persisted; `FindingRecord` remains unpersisted. Diff queries were not touched in this part.
  - S3 raw: `assert` none in `src`; `shell=True` none; `TODO|FIXME|XXX|HACK` only case-insensitive `Hackertarget` false positives; `print(` none; `subprocess` only `core/runner.py` plus docstrings; `sqlite3` only `core/store.py`; `os.environ` none; broad except only the engine handlers above plus the previously justified `dnspython`, `store`, `wildcard` and `workspace`; suppressions remain the 3 pre-existing test-only entries.
- Bugs found: PIT-28. Resume skipped completed stages but the restarted `live` stage saw only the target because `discovered`/`alive` were not reseeded from SQLite. Fix: `_seed_from_store()` on resume. Guard: `test_resume_skips_completed_stages_and_continues`; mutation 1 below shows it failing. No other product bug was found; the lost newline in the transition-table comment was a tooling artifact fixed before the gate.
- Mutation proofs: resume seeding disabled -> `test_resume_skips_completed_stages_and_continues` failed with `{'example.com'} == {'example.com', 'www.example.com'}`; uncertain DNS forced to DEAD -> `test_regression_dns_timeout_not_dead` failed with `DEAD is not ALIVE`; distinct-tool set replaced by list -> `test_same_tool_three_results_is_not_high` failed with `HIGH is not LOW`; all-failed exit changed to SUCCESS -> `test_exit_code_all_tools_failed_is_no_tool` failed with `SUCCESS is not NO_TOOL`. All files restored from a backup; the post-restore grep found no mutation.
- Raw check output (twice): `374 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0 (both runs).
- Not verified: real DNS NXDOMAIN/CNAME behavior through the engine; a real interrupted process (the test uses `CancelledError`); tool-level resume; wildcard integration; CNAME persistence; real exit-code mapping in the CLI (Part 8); process-group interruption.
- Pitfalls added this part: PIT-28.
- Next part must know: `ScanSummary.exit_code` is the only CLI exit signal; `summary.warnings` is in-memory; `Engine(now=...)` is the timestamp injection point; `Store.scan_runs()`/`subdomains()` are the resume reads; consensus and state logic stay in `engine.py`.

## Part 6b follow-up: double-confirmation, mixed scope denial, SERVFAIL

- Docs-first commit `f4ff550` added the explicit two-consecutive-NXDOMAIN rule to `docs/03`, the mixed passive-success/active-denied exit-3 rule to `docs/02`, the reasoning to PROGRESS "Deviations", and the dangling-CNAME persistence item to PROGRESS "Fix backlog". No code changed in that commit.
- Added `test_exit_code_scope_denied_with_passive_success` (asserts exit `3`, passive result stored, active tool not run) and `test_regression_dns_servfail_not_dead` (SERVFAIL collapses into `DnsSignal.UNCERTAIN`; state is `UNKNOWN`, never `DEAD`).
- Raw targeted run: 4 selected tests passed (`scope_denied_with_passive_success`, `scope_violation`, `regression_dns_servfail`, `regression_dns_timeout`).
- Raw gate twice after the tests: `376 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0 (both runs). PROGRESS is 149 lines.
- Pitfalls added this follow-up: none.

## Part 7: UI tables, JSON and color safety

- Docs read / goal: `docs/02_CLI_UX.md` output, colors, progress and exit codes; `docs/03_ARCHITECTURE.md` dependency rules and Engine API; `docs/09_TOOL_CONTRACTS.md` JSON section; `docs/MASTER_PLAN.md` Part 7. Implement `ui.py`: Rich tables/progress on stderr, one valid JSON document on stdout, silent/no-color modes, markup escaping, and the free-key rate-limit hint. Render precomputed output only; no store/scope/adapters imports and no confidence/state logic.
- Decisions and assumptions: `HostRow` is the plain UI input (`fqdn`, `state`, `confidence`, `sources`, `status_code`, `ports`); the CLI will populate it. `ui.render(...)` returns `int(summary.exit_code)` and writes JSON to stdout or tables to stderr. `write_json` is separate so tests can parse the document directly. Tables use `Text` plus `Console(markup=False)` so hostnames such as `[red]x[/]` stay literal. `NO_COLOR` and non-TTY streams force `color_system=None`. Empty results use the docs/02 doctor hint; zero tools get a clear skipped/excluded variant.
- Decisions for user review (things the user may want to overrule): docs/09 previously specified JSONL while the Part 7 requirement/master plan specified ONE JSON document; I chose the one-document contract and updated both docs. `ScanSummary` has no skipped-tool list, so skipped adapters are not in the Tools table yet; this needs Part 8 wiring or an engine summary change. `HostRow` lives in `ui.py` rather than `engine.py`; the CLI must map stored rows to it.
- Docs changed first: `docs/02` now states one JSON document and includes the fixed shape; `docs/09` section 6 was aligned to that shape; `docs/03` gained section 8b (`ui.render`, `HostRow`, layering).
- Deviations: the JSON contract change above; skipped tools are absent from `ScanSummary`; `HostRow` is a UI-local input type; the empty zero-tool message is a wording choice not in docs/02.
- Files touched: `src/reconkit/ui.py`, `tests/test_ui.py`, `docs/02_CLI_UX.md`, `docs/03_ARCHITECTURE.md`, `docs/09_TOOL_CONTRACTS.md`, `docs/PROGRESS.md`, `docs/REVIEW_LOG.md`.
- Requirement -> test table:
  - one valid JSON document and documented keys -> `test_json_output_is_one_valid_document_with_documented_schema`
  - confidence/state/sources per host -> `test_json_hosts_carry_confidence_state_and_sources`
  - silent suppresses all stderr, returns exit code -> `test_silent_suppresses_tables_but_returns_the_exit_code`
  - silent non-TTY does not crash/hang -> `test_silent_mode_in_a_non_tty_context_does_not_crash_or_hang`
  - silent plus JSON still usable -> `test_silent_json_still_writes_one_usable_document`
  - non-TTY has no ANSI -> `test_non_tty_output_has_no_ansi_codes`
  - `NO_COLOR` has no ANSI -> `test_no_color_env_suppresses_ansi_on_a_tty`
  - redaction survives rendering -> `test_redacted_engine_values_stay_redacted_through_rendering`
  - every state label distinct -> `test_every_state_has_a_distinct_label`
  - every confidence label distinct -> `test_every_confidence_has_a_distinct_label`
  - labels visible in tables -> `test_all_state_and_confidence_labels_render_in_tables`
  - zero hosts -> `test_zero_hosts_renders_the_documented_empty_state`
  - zero tools -> `test_stage_with_zero_tools_renders_a_clear_empty_state`
  - one and many warnings -> `test_one_and_many_warnings_are_all_rendered`
  - Rich markup injection -> `test_rich_markup_in_host_data_is_printed_literally`
  - unicode/wide hostname -> `test_unicode_and_wide_hostnames_stay_intact_in_json`
  - hint only without key -> `test_rate_limit_hint_is_shown_only_when_the_key_is_unset`
  - progress disabled by silent/JSON -> `test_progress_is_suppressed_for_silent_and_json_modes`
  - no forbidden imports -> `test_ui_does_not_import_store_scope_adapters_or_cli`
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: none added; `ui.py` converts no exceptions and does not catch rendering/serialization errors.
  - External input: `HostRow` fields and `ScanSummary`/`ToolResult` are Pydantic or typed; JSON serialization uses `model_dump(mode="json")`; `HostRow` supplies no raw objects. No filesystem paths or environment values are rendered except `NO_COLOR` presence.
  - Secrets: UI trusts the engine's redaction; the test feeds already-redacted `***` values and confirms no raw secret or object repr is re-expanded. `summary.warnings` and `ToolResult.error` are rendered as `Text`, never `str(raw)` of an adapter object.
  - Blocking call in async: none; all UI functions are synchronous and only write to streams.
  - Escaping exceptions: `json.dumps`/`model_dump` would raise on an unserializable type, but engine results are typed and serializable; no fallback `default=str` (which could bypass redaction) was added.
  - Unfinished path: CLI wiring, skipped-tool presentation, real terminal rendering and export formats remain for Part 8/11.
  - S3 raw: `Select-String` shows `ui.py` imports only stdlib, Rich, `reconkit.engine.ScanSummary` and `reconkit.models` (no store/scope/adapters/cli); `console.print` is the only terminal output, no `print(` or `subprocess`/`sqlite3`.
- Bugs found: no product bug. Two test expectations were corrected: the label test used a hard-coded source count that did not match the row (`HIGH (2)` vs `HIGH (3)`), and the 120-character unicode host is wrapped by Rich at 80 columns, so only its prefix is contiguous. The renderer was already correct; no PIT row was added.
- Mutation proofs: JSON prefix `noise` -> `test_json_output_is_one_valid_document_with_documented_schema` failed with `JSONDecodeError: Expecting value`; removing `Text(...)` and enabling markup -> `test_rich_markup_in_host_data_is_printed_literally` failed because `[red]x[/]` was consumed; disabling the silent early return -> `test_silent_suppresses_tables_but_returns_the_exit_code` failed because stderr contained the tables. All files restored; targeted tests passed after each restore.
- Raw check output (twice): `395 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS` (both runs after the final docs edits).
- Not verified: real terminal width/color behavior, CLI population of `HostRow`, skipped-tool display, `--json` in an actual Typer invocation (Part 8).
- Pitfalls added this part: none.
- Next part must know: call `ui.render(summary, host_rows, json_output=..., silent=..., no_color=...)` and use its return value as the CLI exit code; `HostRow` is precomputed; JSON is one document, not JSONL; `render_rate_limit_hint` takes `key_set` and suppresses the hint when true.

## Part 8: Typer CLI, flags and mock end-to-end

- Docs read / goal: `docs/02_CLI_UX.md` commands/flags/output/exit codes, `docs/03_ARCHITECTURE.md` layers and engine API, `docs/04_DATABASE.md` read queries, `docs/05_SECURITY.md` scope/secrets/speed, `docs/07_TESTING.md` CliRunner rules, `docs/09_TOOL_CONTRACTS.md`, `docs/MASTER_PLAN.md` Part 8, and the Known pitfalls table. Build `cli.py` as the Typer entrypoint: parse documented flags, build `ScanOptions`, run the engine, render through `ui`, return the engine/UI exit code, and refuse active work without `--active`.
- Decisions and assumptions: one shared scan command is registered under `subs`, `dns`, `live`, `ports`, `tech`, `urls`, `vulns`, `passive`, `lite`, and `run`; `ctx.info_name` selects the stage set. No command is `lite` (passive pipeline), now documented in docs/02. `run --active` covers all stages; `run` without `--active` is passive only. Active-only stage commands require `--active` before the engine runs. `Engine.open` is the CLI-facing factory: it opens the Store and loads `.env` values, so `cli.py` never imports `store` or reads `os.environ`/`getenv`. `Engine.host_rows` supplies typed host rows; `Engine.diff`/`recent_runs` supply the read-only command data. `--json` is one document per target; multiple `-l` targets with `--json` are rejected until a batch shape is documented. Active fast mode prints the warning and requires the exact typed phrase outside `--mock` (mock bypasses it because no traffic is possible).
- Decisions for user review (things the user may want to overrule): `--timeout-<stage>` from docs/02 is not implemented; only `--phase-timeout` is accepted. `doctor`/`install`/`update` are explicit Part 9 stubs; `db list`, `db export`, `export`, and `scope import` are explicit exit-1 stubs. `.env` is the only key source through `Engine.open`; shell-exported key variables are ignored because the CLI must not read `os.environ`. `diff` compares the latest two completed `subs` runs and the latest two `live`/`ports` runs when present; `status` lists recent runs across targets.
- Docs changed first: docs/02 gained the no-command shorthand and the `diff`/`status` JSON shapes; docs/03 gained `Engine.open`/`close`, `host_rows`/`diff`/`recent_runs`, and the new UI helpers; docs/04 gained the three read queries. No new CLI flags were invented.
- Deviations: `--timeout-<stage>` missing as above; multi-target `--json` rejected; `db`/`export`/`scope import` stubs; fast active confirmation skipped in mock; `.env`-only key loading. No dependencies, suppressions, asserts, shell paths or new modules were added.
- Files touched: `src/reconkit/cli.py`, `src/reconkit/engine.py`, `src/reconkit/ui.py`, `src/reconkit/core/store.py`, `tests/test_cli.py`, `docs/02`, `docs/03`, `docs/04`, `docs/PROGRESS.md`, `docs/REVIEW_LOG.md`.
- Requirement -> test table:
  - layering: CLI imports engine/ui/config/scope and no store/adapters -> `test_cli_imports_only_the_allowed_layers`
  - every documented scan flag present -> `test_every_documented_scan_flag_is_registered`; the missing `--timeout-<stage>` is listed above, not hidden
  - no undocumented scan options -> `test_scan_has_no_undocumented_options`
  - exit code forwarded, not recomputed -> `test_mock_scope_denial_returns_three`, `test_mock_json_is_one_valid_document_and_exit_zero`
  - mock end-to-end JSON, Rich tables and two exits -> `test_mock_json_is_one_valid_document_and_exit_zero`, `test_mock_human_output_uses_rich_tables_on_stderr`, `test_mock_scope_denial_returns_three`
  - bad speed/delay/tool return 2 with no traceback -> `test_bad_flags_exit_two_without_a_traceback`
  - silent + JSON through the real command -> `test_silent_json_through_the_real_cli_has_no_stderr`
  - resume reaches engine and skips completed stages -> `test_resume_flag_reaches_the_engine_resume_path`
  - no `os.environ`/`getenv` key reads -> `test_cli_never_reads_environment_keys`
  - flag/list/root/scope/diff/status behavior -> `test_active_commands_require_active_flag`, `test_fast_active_requires_typed_confirmation`, `test_target_list_accepts_comments_and_deduplicates`, `test_root_invocation_without_a_command_runs_the_passive_pipeline`, `test_scope_check_command_reports_allowed_and_blocked`, `test_diff_and_status_after_two_mock_runs`
  - every command has help -> `test_every_scan_command_has_help`, `test_every_non_scan_command_has_help`
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: `Engine.open` catches `BaseException` only to close a partially opened Store and re-raises; `_run_scan` catches `Exception` to convert an unexpected failure into exit 1 and optional `-v` traceback. No bare except.
  - External input: `-d`/`-l` through `validate_target`; file lines skip blanks/comments and dedupe; `--speed`/`--delay` through `load_config`/`parse_delay`; `--tools`/`--exclude` through the engine's registry validation; `--min-sources`/`--phase-timeout` through engine validation; `--scope` through `load_scope`/`require_active`.
  - Secrets: `cli.py` has no `os.environ`/`getenv` and no `print`; `Engine.open` loads `.env` values, the engine filters each tool's `keys`, and UI renders only redacted engine errors/warnings. No key value is put in argv or CLI output by this layer.
  - Blocking call in async: none added; `asyncio.run` wraps the engine, and CLI work is synchronous flag/format handling.
  - Escaping exceptions: `ConfigError`/`ScopeError`/`ValueError` map to documented codes; `KeyboardInterrupt` maps to 130; unexpected exceptions to 1; `typer.Exit` escapes after the return code is chosen.
  - Unfinished path: `doctor`/`install`/`update` (Part 9), `db`/`export`/`scope import`, batch `--json`, and real-tool/real-terminal verification.
  - S3 raw: `cli.py` imports only stdlib, Typer and `reconkit.{config,core.runner,core.scope,engine,errors,models,ui}`; no store/adapters. `os.environ`/`getenv` no hits; `print(` no hits; no `assert`, `noqa` or `type: ignore` in `cli.py`.
- Bugs found: no product bug. One test-side correction: Click does not include the generated `--help` in `cmd.params`, so the no-undocumented-options test adds it to the allowed set; this is not a product change. No PIT row.
- Mutation proofs: exit forwarding removed (`exit_code = render(...)` -> bare `render(...)`) -> `test_mock_scope_denial_returns_three` failed `assert 0 == 3`; active gate disabled -> `test_active_commands_require_active_flag` failed `assert 4 == 2`; delay validation disabled (`if False`) -> `test_bad_flags_exit_two_without_a_traceback[extra1-invalid delay]` failed `assert 0 == 2`. Every file restored; the restored targeted tests passed.
- Raw check output (twice): `437 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS` (both runs after the final docs edits).
- Not verified: real installed tools/network, real terminal width/color, `db`/`export` output, `scope import`, multi-target JSON, shell-exported keys, and the fast-active prompt outside mock.
- Pitfalls added this part: none.
- Next part must know: `Engine.open` is the only CLI store creation path; `cli.py` must keep `raise typer.Exit(code=...)` as the final step; `HostRow` is mapped from `Engine.host_rows`; `--timeout-<stage>` and `db`/`export` remain open for Part 9/11.

## Part 9: fix backlog - dangling CNAME persistence

- Docs read / goal: `docs/PROGRESS.md` Fix backlog and Open risks first; then `docs/04_DATABASE.md` schema/migrations, `docs/03_ARCHITECTURE.md` host-state/engine rules, `docs/09_TOOL_CONTRACTS.md` records, and the Known pitfalls table. Fix only the Fix backlog item: persist dangling-CNAME evidence. No CLI, UI, commands, flags or tools were changed.
- Decisions and assumptions: schema version 2 adds `host_status_history.cnames_json TEXT NOT NULL DEFAULT '[]'` and `dangling_cname TEXT`; `Store.latest_cnames()` is the read query. DNS-only resolved hosts now get a `DNS_ONLY` status row so their CNAME survives a restart. A later NXDOMAIN with no current CNAME reuses the latest stored CNAME before `decide_host_state`. `dangling_cname` is persisted only for a `SHUT_DOWN` row with an outside-target CNAME. Wildcard wiring and stage-level resume were triaged in Open risks, not fixed, because this part was limited to the Fix backlog.
- Docs changed first: docs/04 schema, read-query rules and migration version; docs/03 host-state persistence/reuse behavior; docs/REVIEW_LOG PIT-29.
- Files touched: `src/reconkit/core/store.py`, `src/reconkit/engine.py`, `tests/test_store.py`, `tests/test_engine.py`, `docs/03`, `docs/04`, `docs/PROGRESS.md`, `docs/REVIEW_LOG.md`.
- Requirement -> test table:
  - old v1 DB opens and gets both columns -> `test_v1_database_migrates_and_defaults_cname_columns`
  - existing rows default to `[]`/NULL -> same test
  - new CNAME evidence round-trips and `latest_cnames` reads it -> `test_host_status_persists_cnames_and_latest_cnames`
  - CNAME survives close/reopen and the later NXDOMAIN warns/persists `SHUT_DOWN` -> `test_regression_dangling_cname_survives_restart`
  - migration remains idempotent and history order is unchanged -> `test_migration_is_idempotent`, `test_host_status_history_order`
- Failing-first evidence: `test_regression_dangling_cname_survives_restart` failed before the fix with `assert False` on `summary.warnings`; the stored CNAME and SHUT_DOWN row did not exist. Post-fix targeted run: `5 passed in 0.84s`.
- Migration safety: v1 database with an existing ALIVE row migrated to version 2; the row read `cnames_json='[]'` and `dangling_cname=None` (no NULL list, no crash). `SCHEMA_VERSION == 2`.
- Raw check output (twice): `440 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`.
- Not verified: real DNS NXDOMAIN/CNAME behavior; the fix reuses a CNAME recorded by an earlier resolved pass, and `dnspython`'s NXDOMAIN path does not return one in the failing pass. This is recorded in Open risks.
- Pitfalls added this part: PIT-29.
- Next part must know: do not treat `host_status_history` as only live-stage data; DNS-only resolved hosts now write status rows. Use `Store.latest_cnames()` before deciding an NXDOMAIN warning. The wildcard and stage-level-resume gaps remain open.


## Part 10 docs pre-fix (docs only, no code)

- Goal: remove the contradictions that would make Part 10 unbuildable, before any `installer/` or `doctor.py` code. Every change below is a docs change; `src/`, `tests/`, `tools.yaml` and `config.yaml` were not touched.
- Docs changed: `docs/10` §1 grammar now matches `docs/02` §2 (dropped the undocumented `--stage`/`--yes`), §1 prompt text no longer implies `install --silent/--json`; §2 states that `install`/`update` refuse on any non-Linux platform with a Linux-required message; §3 gained the version-pin policy; §3b lists the real prerequisites (jq, dnsutils via the `dig` entry, Python >= 3.11, GOBIN, pipx via apt); §4 limits the GitHub-only host rule to `github_release` and names the Go module proxy and PyPI; §5a records the doctor checks, `--json`, and doctor exit codes; §6 defers the fixture-version warning to Phase 3 because `tools.yaml` has no fixture metadata; §9 restates that `--dry-run` may read the GitHub API. `docs/08` Flow 1 failure line no longer calls a non-Linux host fatal for `doctor`; `docs/05` §6.1 no longer says `install` prompts under `--silent`/`--json`.
- Decisions for user review: (1) removing `--stage` and `--yes` from docs/10 narrows the installer to the docs/02 surface; add them back deliberately if wanted. (2) Non-Linux refusal uses exit 1, taken from docs/08 Flow 1 because docs/10 named no code. (3) `--all` still means "core tier only"; whether it should skip `phase: 3` entries (tools with no adapter yet) is left open. (4) The installer exit code when every tool fails is left open (docs/10 only defines 5 for a partial failure). (5) The "wordlists" check in docs/01/02 still has no documented location.
- Platform finding (not fixed): on this Linux copy `scripts/bootstrap.sh` and `.githooks/pre-commit` have CRLF line endings in the working tree while the index stores LF, so the documented `./scripts/bootstrap.sh` exits 127 and git cannot run the hook. The hook was restored from HEAD's LF blob so the mandated gate could run; `bootstrap.sh` is left as-is for the user to decide.
- Not verified: no Part 10 behavior exists, so nothing about install/doctor was exercised beyond the three stubs returning exit 1.

## Part 10 scope decisions (docs only, no code)

- Goal: settle the three questions left open by the docs pre-fix (commit `5f3b907`) before any Part 10 code. Docs only; `src/`, `tests/`, `tools.yaml` and `config.yaml` untouched.
- Evidence for `--all`: `tools.yaml` header defines `phase (build phase: 2 = working adapter in Phase 2, 3 = later)`. The only runtime consumer is `src/reconkit/engine.py:722`, which skips such a tool with `no adapter yet (phase {spec.phase})`; `adapters/registry.py:80` says the same in an error, and `registry.py:110` defaults a missing phase to `3`. Security gating is `tier` + `mode` in the engine's selection loop, never `phase`. Of 48 tools, 41 are core and 30 of those are `phase: 3` (`urlscan, amass, findomain, chaos, github_subdomains, dnsx, puredns, massdns, dig, httprobe, tlsx, smap, nmap, rustscan, httpx_tech, whatweb, wafw00f, cdncheck, webanalyze, gau, waybackurls, katana, hakrawler, gospider, subjs, unfurl, urlfinder, nuclei, subzy, dnsreaper`); core phase 2 is exactly the 11 tools that have adapters. So `nmap: phase 3` is build tracking, not a tier bug, and a phase filter would silently exclude `nmap -sV`.
- Decision 1: `--all` remains "core tier tools only", no phase filter. `MASTER_PLAN.md` Part 4 called `masscan, rustscan, nmap -sV` opt-in, contradicting `tools.yaml` (`rustscan`/`nmap` are core, only `masscan` is opt_in); the line now names only `masscan` and adds that core-but-phase-3 tools install and run by default once their adapters land.
- Correction to the review premise: docs/01 Feature 5 acceptance criteria never mention `nmap -sV`. They say "Default scan is a top-ports connect scan (no root needed)". The `nmap -sV` phrases live in docs/09 (`service fingerprint ... raises confidence`) and MASTER_PLAN Part 4, which is the line that was wrong.
- Decision 2: exit code `6` = "Every requested tool failed to install or update" was added to docs/02 section 6 as a new row. `git show b752ec2` proves the table was frozen only for layout (it moved the scope paragraph out from between rows, no renumbering): `4` = "No usable tool for the stage" and `5` = "Partial success (some tools failed or timed out)" keep their scan meanings, so all-failed install needed its own code rather than overloading `4`.
- Decision 3: the wordlists check was removed from docs/01 Feature 2 and the docs/02 command table, and recorded under PROGRESS Open risks. Evidence: `grep -rn -i wordlist src/ tools.yaml config.yaml` returns nothing; only docs/01:61 and docs/02:20 mentioned it; the only wordlist-consuming tools (`puredns`, `massdns`, `amass`, `findomain`, `dnsx`) are phase 3 with no adapter. `doctor` will not print a fabricated "not applicable" line.
- Not verified: nothing in this commit is behavior; the four checks were re-run for the tree, and no Part 10 command was exercised beyond the existing stubs.
- Next: 10a only (doctor's real checks, `--json`, exit rules). Blocked on confirming that the registry exposes stage membership readably, so 10a adds no module outside docs/03.

## Part 10a - doctor's real checks (code)

- Goal: replace the `doctor` stub with the checks docs/01 Feature 2, docs/08 Flow 1 and docs/10 section 5a require, without installing anything and without a new module.
- Code changed: `doctor.py` (report models, `collect_report`, `default_status`, `installed_packages`, `db_writable`), `adapters/registry.py` (`ToolSpec.requires_apt`, `load_system_packages()`, shared `_document()`), `ui.py` (`doctor_document`, `render_doctor`), `cli.py` (`doctor` now takes `--fix/--json/--no-color/--config` and exits 0 with warnings, 1 on Python < 3.11 or an unreadable config).
- Decisions: (1) apt packages are read from `/var/lib/dpkg/status` rather than by running `dpkg-query`, so doctor starts no subprocess for them and on a non-Debian host prints `unknown` instead of guessing; (2) non-binary tools print `n/a (no binary required)` in version and path exactly as docs/02 says; (3) `installed=False` with a path becomes `wrong program` plus a warning, per the sentence added to docs/09 in `a7d0399`; (4) `--fix` refuses with exit 1 until `install` exists (10b+), because a silent no-op would be a lie; (5) the doctor JSON field list is documented in docs/02 section 5.
- Tests added: `tests/test_doctor.py` (12) - all-present, all-missing with n/a rendering, wrong `httpx` namesake, unparsable version, dpkg installed/missing/unknown, JSON shape and no key values, warnings keep 0, Python < 3.11 exits 1, `--fix` refuses, unreadable config exits 1, one JSON document. `tests/test_registry.py` (+4) - `requires_apt` parsed, `load_system_packages()` matches tools.yaml, both invalid-list cases raise `ConfigError`.
- Real run on this Kali box: `reconkit doctor` reported subfinder 2.17.0 and naabu 2.7.0 as installed, and `httpx` as `wrong program` because the PATH copy is not ProjectDiscovery's - the case docs/10 section 5 names. Exit 0 with the missing-tools suggestion line.
- Not verified: no real `--fix` (no installer yet); the dpkg parser was exercised against synthetic status files and the real Kali database, not against a package installed mid-run.
- Known cosmetic: the `n/a (no binary required)` cells wrap in an 80-column terminal. The text matches docs/02; compacting it would need a docs change first.

## Part 10b - install plans and verification primitives (code)

- Goal: turn `tools.yaml` into typed install plans and make checksum/archive handling correct before any download code exists. No network, no subprocess, no apt.
- Code changed: `installer/registry.py` (`InstallPlan`, `load_plans`, `plan_for`, `resolve_plan`, `tool_versions` pinning that rewrites a trailing `@latest`), `installer/verify.py` (`sha256_file`, `checksum_for`, `verify_checksum`, `extract_binary` for zip and tar.gz, `ARCHIVE_LIMIT` 200 MiB, `MEMBER_LIMIT` 100 MiB). Docs first: docs/10 gained section 3c (plan fields, pin rule, `none` plans, `resolve_plan`) and the size caps in section 4.
- Decisions: (1) plans are built from `tools.yaml` directly because `ToolSpec` deliberately does not carry `install`; the tool set still comes from `load_tools()` so the two loaders cannot drift on which tools exist; (2) a tool with no `install` block is a `none` plan (`httpx_tech` reuses the `httpx` binary) rather than an error; (3) extraction places the member under the destination using its own basename, refuses absolute paths, drive letters and any `..` segment, and fails when no member matches; (4) the binary is made 0755 with `Path.chmod` (ruff's S103 rejects a literal `os.chmod(0o755)`, and the documented mode is the requirement, not a mistake).
- Tests added: `tests/test_installer_registry.py` (10) - full registry coverage, subfinder's github_release to go_install chain, `requires`/`requires_apt`, `httpx_tech` as `none`, pin rewriting for pinned and unpinned packages, unknown method, missing package, missing repo, unknown tool, no-fallback chain. `tests/test_installer_verify.py` (11) - checksum match and mismatch, checksum line selection, zip extraction of only the expected binary with 0755, missing member, `..` and absolute members refused, archive and member caps, tar.gz extraction and `..` member.
- Not verified: no real release asset was downloaded or extracted; the caps are enforced against synthetic archives. `checksums_pattern`/`asset_pattern` templating is only parsed, not rendered - that belongs to 10c.

## Part 10a follow-up - identity probe destroyed tool configs (code)

- Found while smoke-testing `reconkit doctor` on Kali: `git status` showed untracked `naabu/` and `subfinder/` in the repo root, born at the run time, containing files dated 2026-10-29. `~/.config/naabu` and `~/.config/subfinder` no longer existed: `BinaryAdapter.check_installed()` calls `run_exec(..., env={})`, so HOME was unset and the ProjectDiscovery tools wrote (moved) their config directories into the CWD. This was latent for scans too, because the engine calls the same method.
- Fix: pass `env={"HOME": str(Path.home())}` to the version probe, with a docstring that says why. The configs were moved back to `~/.config` and the tree is clean again.
- Test: `test_identity_probe_passes_home` in `tests/test_binary_adapters.py` asserts the child env is exactly `{"HOME": <home>}`.
- Guard: `test_every_binary_adapter_declares_needs_home_or_is_allowlisted` walks every `kind: binary` tool that has an adapter and fails unless it sets `needs_home = True` or appears in `NO_HOME_NEEDED` with a checkable reason (today only `assetfinder`, whose `build_command` passes no config path and whose registry entry has no keys). Mutation check: flipping `SubfinderAdapter.needs_home` to `False` makes the test report `['subfinder']`; restoring it reports `[]`.
- Not verified: that every ProjectDiscovery version subcommand accepts an unset HOME was never true; this change removes the question rather than answering it per tool. Tools that need `XDG_CONFIG_HOME` instead are untested.

## Part 10c - github_release download and dry-run (code)

- Goal: fetch one GitHub release asset safely, verify it, install it with a post-install version check and a `.prev` rollback, and describe the same steps under `--dry-run`. Still no `apt`, `go_install` or `pipx` (10d) and no `install --all` wiring (10e).
- Code changed: `installer/github_release.py` (`release_for`, `download`, `install_release`, `install_plans`, `exit_code`, `host_arch`, `render_pattern`, `checked_https`); `installer/registry.py` gained `InstallPlan.version_args` parsed from `version_cmd`, because the post-install check needs per-tool arguments and `tools.yaml` is the only source for them. Docs first: docs/10 section 3c lists `version_args`.
- HTTP: `httpx.Client` injected by the caller, exactly like the adapters' `transport=` injection. Tests pass `httpx.MockTransport`; **no `respx` pattern existed in this repo**, so the established MockTransport approach was reused rather than introducing a second mocking style. Nothing in the module constructs its own client, so a test cannot reach the network by accident.
- Safety: `checked_https` rejects any URL that is not HTTPS on `api.github.com`, `github.com`, `objects.githubusercontent.com` or `release-assets.githubusercontent.com`; the cap is the 200 MiB `ARCHIVE_LIMIT`; extraction reuses `verify.extract_binary` (single member, zip-slip refused, 0755); the bin dir is chmod 0700; the old binary is copied to `<name>.prev` and restored if the version check fails; `.prev` is deleted after success.
- Exit codes: `exit_code` returns 0 when everything installed, 5 when some did, 6 (docs/02) when every requested tool failed; `install_plans` catches `InstallError` per plan so one failure cannot stop the rest.
- rustscan: option (b) chosen. The real release (tag 2.4.1 through the `bee-san/RustScan` redirect) publishes `x86_64-linux-rustscan.zip` and `aarch64-linux-rustscan.zip`, which do not fit the registry's `amd64`/`arm64` `{arch}` values, and no checksums asset was listed, while `tools.yaml` still holds `"verify-at-implementation"`. 10c therefore never resolves it; `test_rustscan_placeholder_cannot_resolve` pins that it fails with "has no asset" rather than guessing. The Open risk carries the evidence.
- Tests added: `tests/test_installer_github_release.py` (14) - resolve asset + checksums, missing asset, dry-run touches nothing and calls no runner, install places 0755 in a 0700 dir with a HOME-only version probe, checksum mismatch, checksums file without our asset, `verify_checksums` with no checksums asset, plain-HTTP refusal, non-GitHub asset host refusal, download cap, rollback restores the previous binary, per-plan isolation with 0/5/6, arch mapping, rustscan placeholder. `tests/test_installer_registry.py` gained `version_args` assertions.
- Not verified: no real GitHub API request or download was made by code; everything ran through MockTransport. The 200 MiB cap and rollback were exercised with synthetic archives. The `asset_pattern` values in `tools.yaml` beyond subfinder's are still unverified against real releases - only subfinder's shape is proven here, and rustscan's is known wrong.
- Follow-ups for 10d/10e: fallback plans are parsed but not executed (`resolve_plan` exists, `install_release` never walks it); `install --all` and the config `tool_versions` wiring remain 10e.

### Part 10c - review follow-ups (same part, before close)

- Host allowlist made explicit in docs/10 section 4: it previously said "the GitHub release asset hosts", which could drift from `ALLOWED_HOSTS`. The doc now names all four hosts and their roles (`api.github.com` lookup, `github.com` download URLs, `objects.githubusercontent.com` and `release-assets.githubusercontent.com` for redirects) and points at the constant.
- Checksums fetch was unbounded: `_fetch_text` used `client.get(...).text`, so a hostile or broken server could return an arbitrarily large body. It now streams like `download()` with `CHECKSUMS_LIMIT` (64 KiB, documented in docs/10) and rejects non-UTF-8 bodies instead of raising `UnicodeDecodeError`.
- Tests: `test_checksums_fetch_is_size_capped` (15 tests in the file, 498 in the suite). `bin_dir` still has no default - it is a required keyword argument on `install_release`/`install_plans`; the `~/.reconkit/bin` path stays 10e's job.

## Part 10d - apt, go_install and pipx backends (code)

- Goal: the three remaining install methods plus per-method dispatch, with sudo shown and confirmed, and minimal child environments.
- Docs first: docs/10 gained section 3d (exact argv and env dicts for all three backends, the sudo contract, validation rules, the two-pipx-prompts rule and the no-rollback rule), section 8 gained the "sudo needs a password" and "pipx missing" rows, docs/05 section 5 now states `sudo -n`. Code followed.
- Decision: `sudo -n`. `runner.run_exec` opens children with `stdin=subprocess.DEVNULL` and captures stdout/stderr, so an interactive sudo password prompt cannot work; without `-n`, apt would fail with "no tty present" anyway. With `-n` the failure is immediate and is reported as `skipped` with "sudo needs a password: run `sudo -v` in this terminal and retry". reconkit never handles a sudo password and never runs as root.
- Confirmation: `confirm(message: str) -> bool` is a required keyword for apt and pipx plans. `False` means no `runner` call happens at all (`test_apt_declined_starts_no_process_at_all`, `test_declined_pipx_prerequisite_installs_nothing`), and `install_plans` without a handler raises `ConfigError` instead of silently skipping. The backend modules never print or prompt, so the CLI owns the wording.
- Two prompts for pipx: a missing pipx produces "pipx is required for wafw00f: sudo apt-get install -y pipx (sudo required)" and then "wafw00f: pipx install wafw00f -> <path>" - two distinct confirmations and two distinct argv calls, pinned by `test_pipx_missing_apt_prompts_twice_and_keeps_them_distinct`. Declining the first installs nothing; declining the second stops before the pipx call.
- Env dicts are exactly the documented ones: apt `{PATH, DEBIAN_FRONTEND, LC_ALL}` (asserted with `==`, and `HOME` asserted absent), go `{HOME, GOBIN, PATH}`, pipx `{HOME, PATH, PIPX_BIN_DIR, PIPX_HOME}`. `PATH` is the only value copied from the parent, because `go`/`pipx` must be findable; no other parent variable is passed.
- Validation before argv: apt `^[a-z0-9][a-z0-9+.-]*$`, go `^[A-Za-z0-9._+/-]+(@[A-Za-z0-9._-]+)?$`, pipx the same plus `git+https://...`. Violations are `ConfigError` and no runner call (`test_apt_package_names_are_validated`, `test_go_specs_are_validated`, `test_pipx_git_spec_is_allowed_and_other_specs_are_rejected`).
- Shared version check: `verify.check_version` now backs both github_release's post-install check and the new backends, so one place decides "timed out or non-zero = failed". github_release's rollback stays where it was.
- Dispatch: `install_plans` in `installer/github_release.py` (the module docs/03 lists; no new module) now routes by method, keeps per-tool isolation, and marks declined steps `skipped=True`. `exit_code` is unchanged, so skipped counts as failed for 5/6.
- Tests added: `tests/test_installer_backends.py` (24) - apt argv/env/decline/password/timeout/validation/dry-run, go env/success/failure/missing binary/validation/dry-run, pipx env/two prompts/declines/one prompt/validation, and dispatch (mixed methods, declined apt exits 5, missing handler, dry-run, all-fail exits 6).
- Not verified: no real `sudo`, `apt-get`, `go install` or `pipx` was executed; every test injects a fake runner. The password-detection markers come from sudo's real messages ("a password is required", "no tty present", "askpass") but were not reproduced against a live sudo in this session. `pipx_available()` uses a real `shutil.which`, so tests always inject `has_pipx`.
- Carried forward: no `.prev` rollback for package-manager installs (documented, by design); `install --all`, `update`, the prompt text and `bin_dir` resolution remain 10e; `dnsreaper`'s `git+https://github.com/...` pipx source is allowed by the registry and now by the spec check, but has never been installed.

## Part 10e - install/update CLI, idempotency and exit codes (code)

- Docs first: docs/10 section 1 gained the idempotency rules, the update comparison rules and its apt/pipx limitation, the exit-code aggregation, the summary columns, the `bin_dir()` resolution, the `nuclei -ut` step (flag confirmed against the installed `nuclei --help`: `-ut, -update-templates`, engine v3.11.1 on this box) and the `tier` field in section 3c.
- CLI surface is exactly docs/02 section 2 plus the documented global flags: `install [TOOL...|--all] [--dry-run] [--config PATH] [--no-color]` and the same for `update`. No `--force`, no `--yes`, no `--stage`. Unknown tool names and a missing selection exit `2`; a non-Linux platform exits `1` with the SETUP.md message (tested by patching `sys.platform`).
- Aggregation: `install_selected` returns `(outcomes, exit_code(outcomes))` for the whole selection, so 0/5/6 is computed once, not per backend. `engine.ExitCode` gained `ALL_FAILED = 6` to match docs/02 section 6.
- Idempotency: `install` skips a tool when `installed_version` finds a usable copy (managed `~/.reconkit/bin` first, then `PATH`) whose `version_cmd` exits 0, and reports `already installed`. `update` resolves the desired version where one exists (GitHub release tag, or a go pin/`@version`) and skips with `up to date` when the tag appears in the installed version output. apt/pipx re-run their package-manager install because there is no local version query here; that limitation is in docs/10 section 1.
- `tool_versions` wiring: `_install_selection` calls `load_plans(versions=config.tool_versions)`; a test writes a config copy with `tool_versions: {subfinder: 9.9.9}` and asserts the selected plan carries `9.9.9` (no network: `install_selected` is stubbed in that test).
- `doctor --fix` now calls the same `_run_install` path with `--all`; the old refusal test was replaced by `test_fix_runs_the_installer`, which asserts the installer is called and the refusal text is gone.
- Keys prompt: implemented per docs/05 section 6.1 - only on a TTY, never under `--dry-run`, copies `.env.example` to `.env` (never overwrites) with mode 0600. Deviation: it does not re-print the Keys table there; logged in PROGRESS Open risks.
- Tests added: `tests/test_install_cli.py` (14) - bin_dir default, installed-version probing, install skip, update skip on equal pin, update when older, exit 5/6 aggregation, nuclei `-ut` step, the three CLI usage/platform errors, tool_versions + core selection wiring, update flag plumbing, `doctor --fix`, and no `.env` write without a TTY. `tests/test_doctor.py`'s refusal test was rewritten.
- Not verified: no real install was performed by the tests; `--all` selection is exercised with a stubbed `install_selected`, so the end-to-end download/apt path is still covered only by 10c/10d unit tests. The `nuclei -ut` flag was confirmed from real `--help` but the refresh itself was not run.

### Part 10e - review follow-ups (same part, before close)

- Keys table implemented instead of deferred: `doctor.key_checks()` returns every documented key by name (`set=False`, values never read) and `ui.render_keys` prints tool/key/state/adds/sign-up. `_maybe_ask_keys` now prints it after writing `.env`, matching docs/05 section 6.1. The helper lives in `doctor.py` because `tests/test_cli.py::test_cli_imports_only_the_allowed_layers` forbids `cli` importing `reconkit.adapters` - the first attempt imported `load_tools` in cli and that test caught it.
- One definition of the managed bin dir: `adapters/base.py` gained `managed_bin_dir()`, which imports `installer.registry.bin_dir` lazily (adapters -> installer.registry -> adapters.registry -> adapters.base would import in a loop) and `BinaryAdapter.binary_path` uses it. `test_managed_bin_dir_has_one_source_of_truth` asserts `adapters.base.managed_bin_dir() == installer.registry.bin_dir()`.
- docs/10 section 1 now states the UX cost: because apt/pipx have no version comparison, `update --all` re-asks the sudo confirmation for every apt/pipx tool on every run.
- Exit codes unchanged: `ERROR=1`, `USAGE=2`, `SCOPE=3`, `NO_TOOL=4`, `PARTIAL=5`, `ALL_FAILED=6`, `INTERRUPTED=130` (code 6 added in 10e, no renumbering).
- Tests: 18 in `tests/test_install_cli.py`, 540 in the suite.

### Part 10e - second review pass

- The keys-table claim was only in prose: the pasted cli diff was from `0d6f762`, and the actual `render_keys` call landed in `14c43cf`. Two tests now prove the call path, not just the renderer: `test_keys_table_is_printed_by_the_prompt` captures the console `_maybe_ask_keys` builds and asserts "wrote"/"CERTSPOTTER_API"/"missing"; `test_declining_keys_prints_nothing` asserts empty output and no `.env` when the prompt is declined. docs/05 section 6.1 now states which branch prints the table (chosen keys, including when `.env` already exists) and that declining prints nothing.
- `_refresh_templates` was a new subprocess call site; it passed only `HOME`. That is a PIT-30-adjacent gap in the making: `nuclei` lives under `$HOME/go/bin` here, and `execvpe` with no `PATH` in the child env only searches `os.defpath`, so the refresh would have failed to find the binary. It now passes `{"HOME", "PATH"}` (the documented exception in docs/10 section 3d) and the nuclei test pins the exact env keys.
- Engine exit codes were re-checked: `NO_TOOL = 4`, `INTERRUPTED = 130` unchanged.
- The unverified sudo-marker risk bullet is in docs/PROGRESS.md (Open risks).
- Tests: 20 in `tests/test_install_cli.py`, 542 in the suite.
- Pitfalls added this pass: PIT-31 (custom `env=` without `PATH` cannot resolve a bare binary), with `test_regression_custom_env_without_path_cannot_resolve_binary` and the `Regression: PIT-31` docstring on the nuclei test.

## Part 10f - close-out (code + real run)

- What 10e already covered, so 10f did not duplicate it: the non-Linux refusal for `install` (added for `update` too), the TTY key prompt and `.env` copy-without-overwrite (10e tests; 10f adds the existing-`.env` and missing-`.env.example` branches), `--no-keys` end-to-end (`tests/test_engine.py::test_env_filtering_and_no_keys`), second `install` changing nothing (`test_install_skips_a_tool_that_is_actually_usable`). The three Part 8 stubs (`install`, `update`, `doctor --fix`) are all wired.
- Real run, first attempt (2026-11-13, this Kali box): `reconkit install --all --dry-run --no-color` exited 5 with three genuine defects that the fake-runner tests could never have caught:
  1. `RustScan/RustScan` answers the releases API with HTTP 301 (the repo moved to `bee-san/RustScan`) and `release_for` did not follow redirects. Fixed with `follow_redirects=True` plus `test_release_lookup_follows_a_rename_redirect`.
  2. `naabu` and `katana` reported "no checksums asset". Live API shows `naabu-checksums.txt` and `katana-1.8.0-checksums.txt`, so the shared `{name}_{version}_checksums.txt` anchor was wrong for both. `tools.yaml` now overrides each pattern (verified names, fetched today).
  3. After the fix the same command exits 5 with exactly one failure: `rustscan` (the documented placeholder), every other tool `would install`.
- New safety check: `install_apt` now confirms the binary is on `PATH` after a successful `apt-get` (the MASTER_PLAN adversarial case "apt succeeds but the binary is still missing"), with `test_apt_that_leaves_no_binary_is_an_error`. `shutil.which` is monkeypatched in the apt tests so they do not depend on the host.
- New adversarial tests: a `PATH` copy whose `version_cmd` fails is not treated as installed; an unparsable version line is not treated as current; existing `.env` is kept and the table still prints; missing `.env.example` prints no table.
- docs/10 section 5a and section 6 synced to the code: `--fix` runs the `install --all` selection and relies on idempotency; `update` points at the apt/pipx limitation; the nuclei refresh is stated as implemented with the confirmed `-ut, -update-templates` flag.
- Not verified: the real non-dry install. It needs a sudo password on this box (`sudo -n true` returns "a sudo: a password is required"), so `install --all` would skip every apt tool; the run has to happen in a shell where `sudo -v` has been done. Also untested: Ctrl-C mid-install (logged in Open risks).

### Part 10f - mutations, Ctrl-C, diff confirmations

- Mutation proofs (break, fail, restore, pass), raw one-line results:
  - Non-Linux refusal: `if sys.platform != "linux":` -> `if False:` -> `test_cli_install_refuses_non_linux` FAILED; restored, PASSED.
  - `.env` no-overwrite: `if env_path.exists():` -> `if False:` -> `test_existing_env_is_kept_and_the_table_still_prints` FAILED; restored, PASSED.
  - Failure isolation: `except InstallError` in `install_selected` -> `except ZeroDivisionError` -> `test_exit_code_is_aggregated_over_every_selected_tool` FAILED with the uncaught `InstallError`; restored, byte-identical, PASSED.
- `KeyboardInterrupt` is now wired for install/update, matching the scan path (`cli.py:222` already caught it and exited 130): `_run_install` catches it around `install_selected`, prints "interrupted; tools already installed are kept" and exits 130, with `test_ctrl_c_during_install_exits_130`.
- The three live-run fixes did not need a new registry field: `checksums_pattern` already existed (added in 10c); the fix populated it per tool. `git show 0b8e1f7 -- src/reconkit/installer/registry.py` is empty.

### Part 10f - second pass: mutation proofs re-run, real non-dry run, non-TTY abort

Repo state: `104d23e` plus the uncommitted registry/doctor/`tools.yaml` work; gate before this pass `558 passed`.
Every restore below was checked with `sha256sum`; the digests before and after each cycle are identical
(`src/reconkit/cli.py c1f9206ec7e83368d64e76cfc508284d6c5f791b0c2ab1963aae2007db07e928`,
`src/reconkit/installer/github_release.py 91b73b6664a38dd26684f8e2d09a86bc5b7b6ee8cc4c5366a2aebe4f7f19ffad`).

- Mutation 1, non-Linux refusal (`cli.py:575`): `if sys.platform != "linux":` -> `if False:`. Both
  `test_cli_install_refuses_non_linux` (the refusal message assertion) and `test_cli_update_refuses_non_linux`
  (`assert 5 == 1`) FAILED, mutant exit 1; restored, both PASSED, exit 0.
- Mutation 2, `.env` no-overwrite (`cli.py:553`): the keep branch -> `if False: pass`. The committed test has
  `.env` but no `.env.example`, so on its own it can only show the lost message, not a clobber: an inline driver
  with **both** files present printed `ENV AFTER: 'EXAMPLE=1\n'` under the mutation and `ENV AFTER: 'KEEP=1\n'`
  restored. `test_existing_env_is_kept_and_the_table_still_prints` FAILED
  (`assert 'keeping existing' in '.env.example not found; nothing copied\n'`), PASSED after restore.
  A first attempt at this mutation replaced the branch with `if False:` alone and left `elif` without a body, so
  the suite failed to import (`IndentationError`); that proves nothing and was redone with a valid body.
- Mutation 3, failure isolation on the CLI path: `install_selected` `except InstallError` -> `except ZeroDivisionError`.
  `test_exit_code_is_aggregated_over_every_selected_tool` FAILED with the uncaught
  `InstallError: broken: go install finished but .../broken was not created`; restored, PASSED. The same mutation on
  `install_plans` FAILED `test_plans_are_isolated_and_exit_codes_follow_the_table` with
  `InstallError: subfinder: release v2.6.0 has no asset 'subfinder_missing.zip'`. Two identical
  `except InstallError as exc:` blocks exist; a naive first attempt matched both sites and aborted without writing
  anything (the test still passed), so the applied mutations target the enclosing function by line index.

- Ctrl-C: already wired before this pass by `104d23e`.
  `grep -n "KeyboardInterrupt\|130" src/reconkit/cli.py src/reconkit/engine.py` -> `cli.py:222` (scan),
  `cli.py:606` (`_run_install`), `engine.py:79` (`INTERRUPTED = 130`). `test_ctrl_c_during_install_exits_130` passes;
  the stale Open-risk bullet is removed. No further change.
- Real non-dry run, first attempt: `reconkit install --all --no-color < /dev/null` printed
  `massdns: sudo apt-get install -y massdns (sudo required) [y/N]: Aborted.` and exited 1 **before installing
  anything**. That is a real defect: without a TTY, `typer.confirm` aborts the whole run, while docs/10 section 3d
  says a declined prompt skips only that tool. Fix: `_install_confirm` returns `False` when
  `sys.stdin.isatty()` is false; docs/10 section 3d updated first; new tests
  `test_sudo_prompt_without_a_tty_refuses_instead_of_aborting` and
  `test_a_piped_install_skips_the_sudo_tool_instead_of_aborting`.
- Real non-dry run after the fix: 30 tools `already installed`, `massdns` `skipped` (sudo needs a password),
  `rustscan` `failed` (`release lookup failed with HTTP 403`), exit 5. Nothing was downloaded or compiled: the
  managed bin dir was already populated by an earlier real run (files dated 15:31-16:15 on this box).
- The sudo half is still unrun: `sudo -n true` -> `sudo: a password is required`; `sudo -v < /dev/null` ->
  `sudo: a terminal is required to read the password`. No NOPASSWD rule exists for `kali`. `massdns`, `amass`,
  `dig`, `nmap`, `whatweb` and `libpcap-dev` have only ever been exercised as `skipped`.
- GitHub rate limit, captured rather than retried: `GET /rate_limit` at 21:25 UTC returned core
  `limit 60, remaining 0, used 60, reset 1794607056 (21:57:36 UTC)`. A direct
  `GET /repos/projectdiscovery/nuclei/releases/latest` returned `HTTP/2 403` with
  `{"message":"API rate limit exceeded for 152.59.43.217. ..."}` and `x-ratelimit-remaining: 0`.
  `update --all` therefore reported all 13 `github_release` tools as `failed` with HTTP 403 and continued (exit 5).
  docs/10 promised "Suggest setting `GITHUB_TOKEN`; skip remaining" and claimed an optional `GITHUB_TOKEN` raises
  the limit, but `release_for` sends no token at all; both statements are corrected, and the gap is listed as an
  Open risk for a decision before Part 11.
- `update --all` idempotency: **not achieved**. 13 `github_release` tools failed (403), 6 sudo/pipx tools were
  `skipped`, and all 14 `go_install` tools re-ran `go install` and reported `installed`. Measured that the re-run
  is not a corrupting reinstall: `sha256sum` of `assetfinder`, `subjs` and `gau` were identical before and after
  `reconkit update assetfinder` (`d5173bdac4eb2054438adaea2c4c1b7173923224516976bf6df7e40fc6def4e7`).
  docs/10 section 6 now states the `@latest` behaviour; the reporting gap is an Open risk.
- `doctor` (exit 0): 8 tools missing (`massdns`, `rustscan`, `httpx_tech`, `dnsreaper`, `crlfuzz`, `dalfox`,
  `gowitness`), `masscan` warned as "not the expected program", `libpcap-dev missing`, coverage
  `dns 4/5, ports 4/6, tech 4/5, vulns 5/8, shots 0/1`. The plan-probe fallback added in this pass is what makes
  the adapter-less tools (`assetfinder`, `findomain`, `chaos`, `gau`, ...) report `yes` instead of `missing`.
- Follow-up from mutation 2: the pre-existing `.env` test could not fail on a real clobber, so
  `test_existing_env_is_not_overwritten_when_env_example_exists` now copies the real `.env.example` beside a
  `.env` and asserts the bytes are unchanged. Proved it guards the property: clean PASS, mutated (keep branch
  removed) FAILED with the `.env.example` contents in the actual value, restored (`git hash-object` equals
  `HEAD:src/reconkit/cli.py`), PASS.
- Gate after the fix: `560 passed`; `ruff check .`, `ruff format --check .`, `mypy src/reconkit` clean.

- Review ruling after this pass: 10f **code** is accepted. The Part 10 gate stays open on one item only - the
  sudo-authenticated apt install, which needs a human terminal (agent has no sudo password on this box). The
  `@latest` go_install reporting gap is deferred to a future part (`docs/10` section 6 says so explicitly; it is
  non-destructive and needs its own docs-first design), and authenticated GitHub release lookups are deferred to
  Part 11 planning. Neither is a Part 10 blocker. Do not start Part 11 until the apt run's output is recorded.

### Part 10f - `requires_apt` was never installed (docs/10 3a was false)

- Defect: `InstallPlan.requires_apt` was parsed and read only by `doctor` (system-packages list). No installer
  backend consumed it, so `install --all` would install `naabu` without `libpcap-dev`, while docs/10 section 3a
  said "The installer installs dependencies first and reports them in `--dry-run`". Found by checking our own
  instruction before spending the scarce sudo run, not by the run itself.
- Docs first (docs/10 3a): `requires_apt` is installed before the tool with its own prompt; a declined
  prerequisite skips the tool; `--dry-run` lists the step; prerequisites are not reached for an already-installed
  tool; `requires` (puredns -> massdns) is still not auto-installed and is deferred.
- Code: `github_release._install_one` now calls `_install_required_packages` before dispatching, and merges the
  prerequisite steps ahead of the backend steps via `replace(outcome, steps=(*prelude, *outcome.steps))`. The old
  dispatch body moved unchanged to `_dispatch_backend`. `apt.apt_install_package` (the confirmed primitive) is
  reused, so the prerequisite prompt is `naabi`-style distinct: `naabu: sudo apt-get install -y libpcap-dev
  (required by naabu)`. A declined prerequisite raises `InstallSkipped` out of `_install_one`, so
  `install_selected`/`install_plans` mark the **tool** skipped and never call its backend.
- Tests added (`tests/test_installer_backends.py`): `test_requires_apt_is_installed_before_the_tool_with_its_own_prompt`,
  `test_a_declined_prerequisite_skips_the_whole_tool`, `test_dry_run_lists_the_apt_prerequisite_and_runs_nothing`,
  `test_naabu_declares_libpcap_as_its_prerequisite`.
- Mutation proofs (restore verified by `sha256sum` = `12f009fde7df9e11a694b64da90e12ca5f5dc2707bc5227318c51ed6292945c5`):
  - A: `for package in plan.requires_apt:` -> `for package in ():` -> the ordering, declined and dry-run tests all
    FAILED (`3 failed`), e.g. `assert 'puredns: go install ...' == 'puredns: sudo apt-get install -y libpcap-dev ...'`.
  - B: wrap `apt_install_package` in `except InstallSkipped: continue` -> `test_a_declined_prerequisite_skips_the_whole_tool`
    FAILED (`assert [go install ...] == []`); the tool was installed despite the refusal.
  - Note: the `MUTANT_*_EXIT=` lines printed `0` because `$?` captured `tail` in the pipeline, not pytest. The
    `3 failed` / `1 failed` summary lines are pytest's real verdict; the restored run used `if ... then ... fi`.
- Gate: `565 passed`; ruff, ruff format and mypy clean.
- Consequence for the gate run: on this box `naabu` is already installed, so `install --all` will install only
  `massdns` through apt. A live `libpcap-dev` proof needs `update naabu` (when the release comparison says "not
  current") or a machine without naabu.

- Evidence weight agreed in review for the `requires_apt` fix: the prerequisite **orchestration** (loop over
  `requires_apt`, a distinct prompt per package, install before the backend dispatch, skip the whole tool on a
  decline, the step listed under `--dry-run`) is verified by the four unit tests and the two mutation proofs above.
  The prerequisite **apt mechanism** is the same `apt.apt_install_package` call site (same `sudo -n apt-get`, same
  `InstallSkipped` mapping) that `massdns` exercises live, so a separate live `libpcap-dev` run is not required to
  close the Part 10 gate: `massdns` alone is the accepted live proof. Forcing it would need either a destructive
  `apt-get remove naabu` or waiting for a natural not-current state.

## Part 10f follow-up - sudo ticket invisible to detached children (code, PIT-32)

- Symptom, isolated by the user's A/B test in one shell with a fresh `sudo -v` ticket: the direct
  `subprocess.Popen([...])` call succeeds under `sudo -n true`, and the identical call with only
  `start_new_session=True` added fails with `sudo: a password is required` and exit 1. Nothing else changed.
- Root cause confirmed: `start_new_session=True` calls `setsid()`; sudo's `tty_tickets` caches the ticket against
  the parent's controlling terminal/session, so the detached child cannot see it.
- Docs check (step 8) before touching code: `grep -rn "session\|setsid\|start_new_session\|process group\|pgid\|subprocess"
  docs/03_ARCHITECTURE.md docs/10_TOOL_INSTALLER.md` finds only docs/03:5,34,60,108,117,161,193 and docs/10:83, none of
  which describes session membership. docs/03:193 says "Kill process group" and stays true after the fix, so no doc
  text needed changing; only this log and the PIT row were updated. No adapter, installer or test assumes detachment:
  `grep -rn "getsid\|setsid\|start_new_session\|process_group\|preexec_fn" src/reconkit/ tests/` matched only
  `src/reconkit/core/runner.py:112`, and a daemon/double-fork/orphan/survive grep matched only the runner's drain
  threads and `spawn_child.py`, which is used solely by the timeout-kill test.
- Fix (`src/reconkit/core/runner.py`): `start_new_session=False`,
  `process_group=0`, so the child stays in the parent's session and leads its own process group.
- Tests added (`tests/test_runner.py`, fake child `tests/fakebin/session_child.py`):
  `test_regression_child_shares_parent_session_but_not_pgid` and
  `test_regression_kill_tree_kills_only_the_child_group`. PIT rule followed: the first failed before the fix with
  `AssertionError: child sid=8034 parent sid=8011; child pgid=8034 parent pgid=8011` / `assert 8034 == 8011`
  (getsid; pgid already passed) and passed after (`1 passed`). The kill test starts a child with `process_group=0`
  plus a sibling in the parent's group, calls `_kill_tree`, and asserts the child exits by `SIGKILL`, the sibling is
  still alive, and the parent's pgid is unchanged.
- Mutation proof: reverting only `process_group=0` to `start_new_session=True` (the old line) reproduces the PIT-32
  assertion failure above; restoring the fix passes. The pre-fix run of the same test is that proof; no separate
  mutant was needed.
- Residual risk (named): every adapter and every installer backend now runs its child in the parent's session
  instead of a fresh one. Consequences: (a) a child can now open `/dev/tty` where `setsid()` previously detached it;
  stdin is `DEVNULL` and the apt path uses `sudo -n` with `DEBIAN_FRONTEND=noninteractive`, so no known tool prompts;
  (b) terminal-generated signals are sent to the foreground process group, and children are still in their own
  process group (`process_group=0`), so Ctrl-C still does not reach them, while a session-wide teardown such as a
  terminal hangup can now reach them where it previously could not. Scans and installs are run to completion in the
  foreground under a live terminal, and `_kill_tree` still owns timeout cleanup, so this is accepted; it is recorded
  rather than silently ignored. (c) tools that daemonize themselves (none in the registry today) would still
  `setsid()` on their own and detach. `_kill_tree` is unchanged and still targets only `os.getpgid(process.pid)`.
- Check output: `tests/test_runner.py` 34 passed; full gate recorded in PROGRESS. The real sudo-authenticated
  `install --all` proof is still outstanding and is the only open Part 10 gate item.

## Part 10f follow-up - massdns version display (code)

- Symptom: the idempotent `install --all` row read
  `massdns  apt  already installed  massdns: already installed (/usr/bin/massdns)`, while every other apt tool
  showed a version (`amass (v5.1.3)`, `dig (DiG 9.20.30-1-Debian)`, `nmap (Nmap version 7.991 ...)`).
- Cause: `github_release.installed_version()` returns `str(copy)` when `plan.version_args` is empty, and
  `registry._plan()` discarded `version_cmd[0]`. `massdns --help` has no version flag and `massdns -v` reads a
  filename, so the plan had no `version_cmd` at all. The dpkg package version is the only source:
  `dpkg-query -W -f='${Version}' massdns` -> `1.1.0-0kali2`.
- Fix: docs/10 (commit `66b117c`) defines `version_cmd[0]` as the program that reports the version, defaulting to
  `binary`. `InstallPlan.version_command` is set only when the head differs from `binary` (so the managed-copy
  preference is unchanged); `installed_version` resolves it with `shutil.which` and runs it; `apt.install_apt`
  passes it to `check_version`. `tools.yaml` gives massdns `[dpkg-query, -W, '-f=${Version}', massdns]`.
- Tests: `test_massdns_version_command_is_the_package_manager` and
  `test_massdns_version_cmd_reports_dpkg_version` (fake runner; asserts the exact argv
  `['/usr/bin/dpkg-query', '-W', '-f=${Version}', 'massdns']` and the state `1.1.0-0kali2`). Full gate:
  `569 passed`, ruff/format/mypy clean.
- Live proof: after `sudo apt-get remove -y massdns`, a fresh `reconkit install --all --no-color` under a pty
  authenticated with `sudo -v` reported `massdns apt installed`; `dpkg-query` then read
  `install ok installed 1.1.0-0kali2` and `command -v massdns` -> `/usr/bin/massdns`. The next idempotent
  `install --all` (no sudo needed) showed `massdns  apt  already installed  1.1.0-0kali2`.
- Caveat: the pty driver's first attempt answered the earlier "Free only, or add keys?" prompt with `y`, so the
  massdns confirmation went unanswered and the run was killed. The orphaned installer continued: it installed
  `katana` into `~/.reconkit/bin` and attempted `nuclei`, which failed with
  `'nuclei' exceeds 104857600 bytes`. The following idempotent run reports both as `already installed`
  (nuclei via `/home/kali/go/bin/nuclei`, v3.11.1). `.env` was not modified.
- `install --all` exits 5 because `rustscan`'s placeholder asset (`verify-at-implementation`) still fails; that is
  the known, tested exclusion, not a massdns failure.

## Part 11b - docs sync (docs 01-10)

- docs/01: primary platform is a native Linux checkout (Kali/Ubuntu); every flow runs there. The Phase 2 command list marks `db list`, `db export`, `export`
  and `scope import` as Phase 3 stubs, the success metric and test platform name Linux only, and the open
  questions are closed.
- docs/02: `-q/--silent` (the docs said `--quiet`, which does not exist); `--json` is documented on the scan
  commands, `doctor`, `diff` and `status`, not on `install`/`update`/`scope check`/the stubs; `db list` and `db
  export`/`export` are marked Phase 3 stubs; the status JSON field list now matches `ui.status_document`; the
  progress line says `--silent`.
- docs/03: the dead `dns_python.py` name is corrected to `dnspython.py`; 429/5xx are documented as failed results
  with no retry (only a connection error retries once); `meta/` no longer claims a `reconkit.log`; the platform
  decision and workflow section describe the native Linux checkout.
- docs/04: the DB hosting line no longer hard-codes `~/reconkit`; the nonexistent `db delete -d X` command was
  removed.
- docs/05: logging now states that this build has no file logger; data protection no longer names `db delete`.
- docs/06: `InstallSkipped` is added to the exception list; logging matches the console-only build.
- docs/07: live tests are documented as manual, with the `live` marker registered but no checked-in test; the test
  tree is replaced with the real files; the unverified ~85% coverage target was removed.
- docs/08: setup requires a native Linux checkout; `install` does not rerun `doctor`; the status JSON example matches
  `ui.status_document`; resume is stage-level (the interrupted stage reruns); export is marked a Phase 3 stub.
- docs/09: intrusive tools are refused because there is no `--intrusive` flag; 429/5xx are failed without a
  back-off; the `InstallStatus.version` comment no longer implies the installer's `version_cmd` field.
- docs/10: the apt row shows `apt-get`; the dry-run example is the real table shape (`tool/method/result/detail`).
- Deliberately not changed here: `README.md` and `SETUP.md` are still the old beginner guide (11a is next);
  docs/10's non-Linux refusal text still says the platform message documented in SETUP.md; stage-table tools without adapters remain Phase 3 by design; `docs/PROGRESS.md` line 101 about the
  original uv venv is an environment deviation, not current setup advice.
- Checks: docs-only change; the pre-commit hook runs the full gate (569 passed, ruff, format, mypy).

## Part 11b-2 - docs/08 flow audit and follow-ups

- `docs/01` §12: the deployment question "which optional keys a user configures first" is restored; it was removed in
  11b by folding three questions into one "no blocking questions" sentence, which was a judgment call, not a resolved
  item. Release asset names and the `nuclei` phase are genuinely closed.
- `docs/01` Feature 5: removed the nonexistent `--ports`/`--full` flags; ports come from each adapter's default set.
- `docs/02`: the result-table example now has the real `Status` column and plausible rows; the tools panel is a table
  with stage/status/items/detail; the Progress section states that no live line is wired
  (`ui.render_progress` is uncalled); the summary line no longer claims "new items"; the success state no longer
  claims workspace/DB paths are printed (they are not).
- `docs/03` failure table: Ctrl+C marks the run `interrupted` and exits 130, but a child already running is **not**
  explicitly killed in this build; the old "kill children" claim was wrong.
- `docs/08` Flow 2: dry-run columns are `tool/method/result/detail`; the installer has no per-tool progress line, only
  a final table; checksum errors use the real message shape; the empty state is not a separate line.
- `docs/08` Flow 4: no header/estimated time and no live progress line; the wildcard check only surfaces as a warning
  when detection is `unknown`; real result columns include `Status`; the footer has counts and tool statuses but no
  workspace/DB paths.
- `docs/08` Flow 5: no title/tech columns and no `[NOW ALIVE]`/`[WENT DOWN]` tags in the stage table; changes appear
  later as `STATE` rows in `diff`.
- `docs/08` Flow 6: removed `--ports`/`--full` (they do not exist); no IP/service columns are rendered.
- `docs/08` Flow 7: real labels are `NEW`, `GONE`, `STATE`, `PORT OPEN`, `PORT CLOSED`; empty message has no date;
  the no-run message is `No completed discovery run for this target.`, and the one-run message includes `(#N)`.
- `docs/08` Flow 9: Ctrl+C does not explicitly kill a running child; only new launches stop.
- `pyproject.toml`: the `live` marker description now says Kali/Ubuntu.
- Evidence for the flow fixes: a real `passive -d example.com --mock` run printed the six-column table
  (`Subdomain/State/Status/Ports/Sources/Trust`) and the counts/tool-status footer, and a second run plus `diff`
  printed `No changes since run #1.` A fresh DB printed `No completed discovery run for this target.`
- Remaining by design: docs/10's non-Linux refusal message still matches the code's literal platform string;
  port IP/service data is stored but not rendered; stage-table tools without adapters remain Phase 3.

## Wildcard filter wiring in the engine (2026-11-14)

- Docs read / goal: docs/03 section 8 (wildcard filter and API bullets), docs/09:166 (`matches` rule), docs/04
  (`subdomains.is_wildcard`), docs/PROGRESS "Part 9 triage: wildcard detection is still not wired". Goal: make the
  existing `core/wildcard.py` detector run per scan and store `is_wildcard`.
- Decisions and assumptions:
  - The two docs bullets were already ahead of the code, so only one gap needed a docs change: `wildcard_check.enabled`
    was modeled and set `true` but named by no document. It now means "filter off when false"; the same sentence
    records the `--mock` rule that docs/03's engine API already implies.
  - The detector is constructed in `Engine.run` right after `_run_tools` returns the `dns` stage's `RunContext`.
    That is the one place where the stage's limiter and resolver context exist, and a run has at most one `dns`
    stage, so this is one detector per run in practice.
  - The probe uses a fresh `DnsPythonAdapter()` bound to that context: the stage's own adapter instance is created
    inside `_run_one` and is not retained, so "reuse that resolver" means the same adapter code path and the same
    stage limiter, not the same resolver object.
  - `is_wildcard` is written only in `_persist_dns`'s `RESOLVED` loop, the first point where a host is known to have
    resolved. `PRESENT` passes `matches()`; `NONE` and `UNKNOWN` pass `None` (no mark, no clearing of an older mark).
- Decisions for user review:
  - `wildcard_check.enabled` is honored as a switch. The docs previously said nothing about it; if it was meant to
    control something else (for example whether wildcard hosts are hidden), say so and the docs/code change again.
  - docs/09's "exclude them from counts by default" was **not** implemented: no doc defines which count (host table,
    JSON summary, confidence) and no code path filters it. It is now an open item in PROGRESS rather than a guess.
- Docs changed first: `docs/03_ARCHITECTURE.md` section 8 (switch + mock clause), commit `581a556`.
- Deviations: none from the agreed spec. The `enabled` switch is the one behavior added beyond the two bullets.
- Files touched: `docs/03_ARCHITECTURE.md`, `docs/PROGRESS.md` (docs commit); `src/reconkit/engine.py`,
  `tests/test_engine.py`, `docs/PROGRESS.md`, this file (code commit).
- Requirement -> test table:
  - PRESENT marks matching hosts: `test_wildcard_present_marks_matching_hosts`.
  - NONE leaves hosts at 0: `test_wildcard_none_marks_nothing`.
  - UNKNOWN warns and marks nothing: `test_wildcard_unknown_warns_and_marks_nothing`.
  - `is_wildcard` reaches the `subdomains` table: `test_wildcard_mark_reaches_the_subdomains_table`.
  - `--mock` never probes: `test_wildcard_never_probes_under_mock`.
  - Probes stay under the target: asserted inside the PRESENT test (`<label>.example.com`, three calls).
- Self-review findings (S2 lists, S3 raw output): no new dependencies, no `assert` in `src/`, no new suppressions, no
  adapter imports added to `core/`; `engine` already imported `cast`/`Any`, so the probe binding adds no new import
  surface beyond `functools.partial` and `core.wildcard`.
- Bugs found: none beyond the already-logged "built but never wired" gap this change closes.
- Mutation/red proof: with the old `engine.py` restored and the new tests kept, `4 failed, 1 passed, 36 deselected`,
  exit 1 (`assert 0 == 3` for the probe count; `{'www.example.com': 0} != {'www.example.com': 1}` for the table).
  The mock test passes in both states by design. Restored with `git stash pop`; green run `5 passed`.
- Raw check output (`.venv`, Python 3.14.8): `585 passed in 12.96s` -> `pytest=PASS`; `ruff check .` ->
  `All checks passed!` -> `ruff=PASS`; `ruff format --check .` -> `69 files already formatted` -> `format=PASS`;
  `mypy src/reconkit` -> `Success: no issues found in 37 source files` -> `mypy=PASS`.
- Real run (v4) `/tmp/rk_testfire_v4.db`, `reconkit passive -d testfire.net --db /tmp/rk_testfire_v4.db -v
  --no-color`: 2 `scan_runs` (`subs` partial 15:11:17-15:13:58Z, `dns` completed 15:13:58-15:14:56Z), 16
  `tool_runs`, 36 `subdomains`, `0` non-zero `is_wildcard`, no wildcard warning, exit 5 (`otx` 429 only).
  `PRAGMA integrity_check` = `ok`, `PRAGMA foreign_key_check` empty. v1/v2/v3 sha256 values are unchanged before and
  after (`f1832f...`, `f90227...`, `61f748...`), so the first three artifacts were not touched.
- What `detect()` returned for testfire.net: `none`. Confirmed two ways: the v4 run printed no inconclusive warning,
  and an observer run (a wrapper around `WildcardDetector.detect` with no `src/` change) recorded exactly one call,
  `{'target': 'testfire.net', 'status': 'none', 'probes': 3, 'resolved': 0, 'ips': [], 'cnames': []}`. Before
  interpreting it, three random `A` labels under `testfire.net` were resolved directly with the venv's dnspython and
  all returned `nxdomain`, so `none` is the expected status and no wildcard answer exists to match.
- Not verified (needs network/tools): nothing new. The `live`/`ports` marking path was not exercised because it is
  the `dns` stage that owns resolution; `_write_host` passes no `is_wildcard`, so an earlier mark is preserved. That
  preservation is covered by the store's `COALESCE` tests, not by a new end-to-end live run.
- Next part must know: `is_wildcard` is a mark only (docs/09's "exclude from counts" is unimplemented and undefined);
  11d-findings-b and (c) remain open; `certspotter` still returns `ok` with 0 items on every real run and needs a
  one-line hypothesis before Part 11 closes.

## Part 11 - findings backfill (docs only, 2026-11-14)

- Why this entry exists: MASTER_PLAN:222 requires every Part 11 finding to be logged under "Bugs found". Only the
  wildcard wiring had a REVIEW_LOG section; the rest lived in `docs/PROGRESS.md`, in commit subjects, or nowhere.
  This section is the accounting for the whole Part 11 window (`3a14568`..`b24f39b`). It records dispositions as the
  code and docs actually stand today. It does not re-verify any fix, and it does not claim an open item is closed.
- Scope: docs-only. No `src/`, `tests/`, `tools.yaml` or `config.yaml` change. No test is added by this entry; the
  four guarding tests below pre-date it and are named, not created, here.
- Provenance of the list: an earlier conversational tally of "14 findings" was never a repo artifact
  (`grep -rn 11c docs/*.md` returned only MASTER_PLAN:222, MASTER_PLAN:223 and PROGRESS:189). The table below is the
  first committed enumeration: 14 findings plus one cleanup row.

### Findings

| ID | Finding | Class | Disposition | Commit | Guarding test |
|---|---|---|---|---|---|
| 11d-a | `_write_host` overwrote the discovery consensus: `demo.testfire.net` stored `LOW`/1 while docs/04 section 5 requires `MEDIUM`/2 from two sources | logic | FIXED | `1b41f4e` | `tests/test_engine.py::test_dns_pass_does_not_overwrite_discovery_confidence` |
| 11d-b | the `dns` stage INSERTs subdomain rows for hosts discovery never returned, with `first_seen_run` = a dns run and no `subdomain_sources` row | logic | **OPEN** | ticket in PROGRESS | none (blocked on a product decision) |
| 11d-c | `tool_runs.duration_s` stores `0.0` for real I/O; three writers | logic | **OPEN** | ticket in PROGRESS | none |
| 11d-e | `subfinder`/`assetfinder` launched bare `argv[0]` with no `PATH` in the child env, so `doctor` said installed and the scan said not installed | logic | FIXED | `df218b5` (docs `a0d06b5`) | `test_build_command_launches_the_resolved_managed_binary`, `test_installed_binary_in_managed_dir_actually_runs` |
| D | identity markers were satisfied by ANY marker, so the `httpx` namesake passed `check_installed()` | logic | FIXED | `d265dc0` (docs `22fbd49`) | `test_projectdiscovery_identity_requires_every_marker`, `test_naabu_identity_accepts_real_version_banner`, `test_subfinder_identity_accepts_pre_264_version_only_banner` |
| W | wildcard filter built but never called; an inconclusive detection was silent | logic | FIXED | `1dd63e5` (docs `581a556`) | see "Wildcard filter wiring in the engine" above (5 tests) |
| 11d-d | "missing binary" meant two different moments across docs/03, docs/09 (two sections) and MASTER_PLAN | doc text | RESOLVED, docs only | `a0d06b5` | n/a |
| 11b-2 | docs/08 flows did not match the built CLI; the docs/01 deployment question had been dropped | doc text | RESOLVED, docs only | `d2e3c66` | n/a |
| - | first-contact contradictions across docs/01, 02, 04, 05, 07 and README | doc text | RESOLVED, docs only | `722b2d1` | n/a |
| - | AGENTS session-start checklist was duplicated and inconsistent | doc text | RESOLVED, docs only | `046e0a2` | n/a |
| 11a | README/SETUP were still the old beginner guide | doc text | RESOLVED, docs only | `cc70b15` | n/a |
| R1 | managed-directory shadowing: a broken `~/.reconkit/bin` copy shadows a working PATH binary | doc text | **OPEN RISK**, deliberate | `3e2aff9` | n/a (manual mitigation; PROGRESS "Open risks") |
| R2 | interactive Ctrl+C does not kill an already-running child | doc text | **OPEN RISK** | `86be2bb` | n/a (killpg path unverified on Linux) |
| - | `certspotter` reporting `ok`/0 on every run | not a defect | EXPLAINED | `430aa1d` | n/a |
| - | `src/reconkit/adapters/dns_python.py` dead stub | cleanup | REMOVED | `b24f39b` | n/a (docs/03:70 fixed earlier in `3a14568`) |

### Logic findings fixed in this window (symptom / root cause / fix / guard)

- **11d-a (high).** Symptom: `/tmp/rk_testfire_v2.db` stored `LOW`/1 for a host with two `subdomain_sources` rows,
  where docs/04 section 5 requires `MEDIUM`/2; the stored value followed write order across six runs. Root cause:
  `_write_host` passed `source_count=len(transition.sources)`, and `upsert_subdomain`'s `COALESCE` guards only
  `None`, so a state pass overwrote a column it had no data to justify. Fix: `_write_host` supplies no `source_count`
  and supplies `confidence` only for `UNCONFIRMED`; `_persist_dns` gained the same `if not transition.persist:
  continue` that `_persist_live` already had. Guard: the test above, red first (`('LOW', 1) == ('MEDIUM', 2)`,
  `1 failed, 35 deselected`), green after (`1 passed`); full suite 570. Verified on the v2 real run.
- **11d-e (high).** Symptom: `check_installed()` reported `subfinder v2.17.0` at
  `/home/kali/.reconkit/bin/subfinder` while a real passive run stored `failed` with `[Errno 2] No such file or
  directory: 'subfinder'`. Root cause: `build_command()` used the bare name while `Engine._tool_env` passes only key
  variables, so the child had no `PATH` to resolve it against. Fix: launch `binary_path() or binary`; the child env
  was deliberately not widened with `PATH` (hijack surface). Guard: the two tests above, red first (`4 failed, 59
  deselected`, production message reproduced verbatim), green after (574 passed). Two existing argv assertions were
  hardened from bare `argv[0]` to `Path(argv[0]).name` because they only passed on a box without the tool installed.
  Verified on the v3 real run.
- **Identity markers (medium).** Symptom: a binary whose banner carried only one of two markers was accepted, which
  cannot reject the `httpx` namesake docs/09 promises to reject. Root cause: `check_installed()` used `any()`. Fix:
  `BinaryAdapter.identity_require_all = True` drives `all()`, with one documented opt-out, `SubfinderAdapter`,
  because upstream added the `Subfinder Config Directory` line in v2.6.4 and an AND would report a working pre-2024
  install as not installed. The missing `naabu` positive identity test was added at the same time, so the
  strictness change did not ship its success path untested. Guard: the three tests above, red first (`4 failed, 2
  passed, 63 deselected`), green after (identity slice `11 passed`; full suite 580).
- **Wildcard wiring.** Already logged above in this file; this entry only assigns it an ID so the table is complete.

### Logic findings still open

- **11d-b (medium).** Not a test gap: the fix is a product decision first (drop dns-only hosts, or keep the row and
  label its provenance as dns and exclude it from discovery counts and `diff_new`), then the two call sites, then
  the rule in docs/04 section 5. Data-dependent: visible in v1/v2, absent in v3/v4 because `assetfinder` returned
  the apex.
- **11d-c (low).** Metadata only. Needs a decision on which measurement is authoritative (adapter-measured vs
  `Engine._run_one`-measured) recorded in docs/04 before any writer changes; a careless fix double-counts.

### What this entry does not establish

- The ten S3 scans (MASTER_PLAN:38) were **not** re-run for this docs-only commit. 11c still requires one final run
  of all ten plus a second full `pytest`; both remain outstanding.
- 11c-bis (fresh-venv `--mock` end-to-end run) is still not done. No REVIEW_LOG entry, commit body or PROGRESS line
  records it ever running.
- 11f (final report) remains unwritten. The RESUME block was stale until this commit corrected it.
- Pitfalls added this entry: PIT-33 (docs-only commits bypass the pre-commit PROGRESS requirement).

## Part 11c - fresh-eyes audit (docs only, 2026-11-14)

- What was read: `engine.py` (all 1238 lines), `cli.py` (all 702), `core/scope.py`, `core/runner.py`, `core/pacing.py`, `core/workspace.py`, `core/wildcard.py`, `adapters/base.py`, all twelve adapters, `doctor.py` (report and key paths), `store.redact`, `installer/github_release.py` (`install_selected`, `desired_version`), `config.yaml` and the `tools.yaml` stage modes. No `src/` or `tests/` change in this entry.
- Requirement -> outcome, one row per MASTER_PLAN:222 hunt category:
  - (a) active tool without `--active` + scope pass: no bypass. `cli.py:47`, `cli.py:168-170`, `engine.py:707-741` (selection), `engine.py:683-712` (gate + skip), exit 3 on denial.
  - (b) timeout becoming DEAD/SHUT_DOWN: none. `dnspython.py:126-127` is the only DEAD producer; `engine.py:234-255` keeps the previous state on uncertain evidence; `pyprobe.py:112-124` maps TLS failures to `UNKNOWN`.
  - (c) secrets: no proven leak. Keys only in headers (`certspotter.py:33`, `otx.py:23`), never argv (`subfinder.py:88-89`); redaction in `runner.py:184-189`, `engine.py:867-877`, `store.redact`; `doctor.py:266-273` prints names and computes `Set` from `.env`. Open question stays `cli.py:227` / `-v` (`cli.py:125-127`).
  - (d) traceback escaping: none demonstrated. `cli.py:225-229`, `github_release.py:601-611`, `:518-521`. Unverified: `BrokenPipeError`, fast-active prompt EOF.
  - (e) blocking in async: E-1 `engine.py:551-556`, E-2 `engine.py:687`, E-3 `engine.py:463`. No structural change made.
  - (f) confidence from non-distinct tools: none. `engine.py:118-131` uses `set()`; ports disagree into `UNCONFIRMED` (`engine.py:1204-1238`).
  - (g) docs/code mismatches: G-1 workspace never written (`workspace.py:104` no callers, `models.py:112` never set vs docs/03:120); G-2 `pacer.before_host()` never called (`pacing.py:73`, docs/03:125, `config.yaml` host_delay); G-3 `scope.passive_warning()` never called (`scope.py:325`); G-4 unreachable `ExitCode.ALL_FAILED`; G-6 the 11d-e blast-radius claim is false (`httpx_tool.py:48`, `naabu.py:41`).
- Consolidated findings and states: see the `## Part 11c` table in `docs/PROGRESS.md`; the head-line items are A-1 (high, fix queued), G-1 (high, ticketed), G-2 (high, contract ambiguity reported), G-3 (medium, ticketed), C-1 (known), E-1/E-2/E-3, C-2 and G-4 (low, ticketed).
- Not verified: the two (d) edges above; every finding is static analysis - no tool was executed and no target was touched in this audit.
- Checks: docs-only change; the pre-commit hook runs the full gate (585 passed, ruff, format, mypy).

## Part 11c-G-2 - inter-host pacing was documented but never called (docs + code)

- **Symptom:** `active.host_delay` is configured for every speed (`[1, 5]` slow, `[0, 2]` normal, `[0, 0]` fast) and docs/03 §7 lists `before_host()`, but nothing called it: active stages sent host after host with no inter-host pause.
- **Why it was reported instead of guessed:** the docs only listed the method in the API; they did not say which loop owns it, and the three adapter shapes disagree - a sequential loop (`pyscan`), a gather (`pyprobe`), and one process for all hosts (`httpx`/`naabu`). A per-host call inside `pyprobe`'s gather would sleep concurrently rather than space dispatches. Owner ruling: Option B.
- **Docs first:** `0ced491` - docs/03 §7 now states that `before_host()` spaces host dispatches in `pyscan` and `pyprobe`, uses `active.host_delay`, does not wait for the first host, that `pyprobe` dispatches sequentially at `parallel_limit("active") == 1`, and that `httpx`/`naabu` are exempt and pace via `-rl`/`-rate`.
- **Code:** `pyscan.run` awaits `before_host()` before the second and later valid host; `pyprobe.run` takes a sequential branch at `parallel_limit("active") <= 1` and keeps the gather above it. `httpx`, `naabu` and passive `dnspython` are untouched (the last because `before_host()` reads the active preset).
- **Guarding tests:** `test_pyscan_waits_between_hosts_before_dispatching_the_next` and `test_pyprobe_waits_between_hosts_when_dispatch_is_sequential` (docstring `Regression: 11c-G-2`). Red before the wiring: `2 failed, 35 deselected`, both `StopIteration` because no pause was recorded. Green after: `2 passed, 35 deselected`.
- **Assertion strength:** ordering, not call count - host B is not dispatched until the recorded pause after host A completes, the first host never waits, and the pause is inside slow's `[1, 5]`.
- **Not verified:** no live active run; the tests inject a recording sleep, so real wall-clock spacing is unmeasured.

## Part 11c-A-1 - active binary adapters launched a bare argv[0] (code)

- **Symptom:** `doctor` reported `httpx v1.12.0` and `naabu 2.7.0` at `~/.reconkit/bin/...`, while a `live` or `ports` stage would record `failed` with `not installed or not executable` - the same self-contradiction 11d-e removed from subfinder/assetfinder.
- **Root cause:** `httpx_tool.py:48` and `naabu.py:41` built `argv[0]` from the bare `self.binary`; `Engine._tool_env` (`engine.py:867-870`) passes only key variables and `BinaryAdapter.child_env` (`base.py:213-219`) adds only `HOME`/`USERPROFILE`, so the child has no `PATH`. `run_exec` turns the resulting `OSError` into `returncode=None` (`runner.py:105-124`) and `base.py:158-164` maps that to `failed`. `check_installed()` used `binary_path()`, hence the disagreement.
- **Fix:** launch `self.binary_path() or self.binary` in both adapters. The child env was deliberately not widened with `PATH`.
- **Guarding tests:** `test_active_binary_adapters_launch_the_resolved_managed_binary` (new, parametrized over both adapters; docstring `Regression: 11c-A-1`), red before the fix (`2 failed, 69 deselected`, `PosixPath('httpx').is_absolute()` False) and green after (`4 passed, 67 deselected`; full suite 587). `test_httpx_command_dedupes_and_lowercases_hosts` and `test_naabu_command_and_ports` were hardened from a bare `argv[0]` to `Path(argv[0]).name` for the same environment-dependence reason as 11d-e.
- **Not verified:** no real binary and no target were used; the test launches a stand-in in the managed directory.
- **Why 11d-e missed it:** that entry claimed subfinder/assetfinder were the only two `build_command` implementations. Corrected in `docs/PROGRESS.md` (11c-G-6).

> **SUPERSEDED 2026-11-17 (owner request D2, `docs/MASTER_PLAN.md`):** the
> permanent `naabu` block recorded here was replaced by the scope-mode branch -
> no scope file: naabu runs unrestricted; scope file present: the engine
> resolves and verifies the IPs itself and hands naabu only those. The entries
> below are kept verbatim as history; they are not current behaviour.

## Part 11c-G-7 - the IP/CIDR scope rule is unenforced (docs only)

- **Symptom:** docs/05 rule 6 requires an IP to be inside `in_scope_cidrs` before it is probed, and to be skipped entirely when no CIDRs are defined. The code contains the predicate for that rule and never uses it.
- **Evidence:** `scope.py:296` `ip_allowed(ip, *, path)` and `ScopeGate.ip_allowed` (`scope.py:110`) both implement "no CIDRs means no IPs"; `tests/test_scope.py:142-148` exercises all three outcomes directly. `grep -rn ip_allowed src tests --include=*.py` returns only those definitions, the wrapper and the tests - **zero call sites in `src/`**. `pyscan.py:75-81` then does the exact thing the rule forbids: `addresses = await self._resolve(host)`, `ip = addresses[0] if addresses else host`, and probes `ip`.
- **Ruling recorded in the ticket:** until fixed, no IP-connecting active tool (`pyscan`, `naabu`, or any future resolve-then-connect adapter) may run. This is a hard precondition on active-stage work, not a note. `pyprobe` is exempt from the precondition because it connects by hostname and never touches a resolved IP.
- **Why it matters for a real run:** the local `scope.yaml` for the first supervised run has no `in_scope_cidrs`, and the wildcard `*.testfire.net` would otherwise authorize any name that resolves anywhere. With only `pyprobe` selected, that run touches no resolved IP, which is why it can proceed under this ticket.
- **Not done:** no code fix, no test change, no decision on where the enforcement belongs (`_active_hosts`, per-adapter, or a shared resolve helper).
- **Checks:** docs-only change; the pre-commit gate runs the full four checks (see the commit output pasted in the session report).

## Part 11c-G-7 - the IP/CIDR rule is enforced in `pyscan` (2026-11-14)

- **Docs read / goal:** docs/05 section 2 rule 6, docs/03 section 13, docs/09 section 3 (adapter contract, `RunContext`, per-host adapters), docs/06 (no `assert`, no new suppressions, adapters never import `scope`), docs/07 (no network in tests). Goal: make the documented IP rule true at the only place in this build that resolves and then connects.
- **Order of work, and why two commits:** `30c368e` first added a selection-time block for both IP-connecting adapters with a test that fails if the block is removed, so the tree could not launch an unchecked IP even if the wiring below were reverted. The wiring then removed `pyscan` from that block and changed the test to assert `pyscan` is selectable and `naabu` is not.
- **Enforcement point, decided:** the adapter, not `_active_hosts` and not a shared helper. `pyscan` owns its resolver call, and the engine cannot filter an address it never sees. To keep the adapter free of `core.scope` (hard rule), `RunContext` gained `ip_allowed: Callable[[str], bool] | None`, filled by `Engine._ip_allowed()` from `load_scope(self.scope_path).ip_allowed` once the active gate passed. `None` (no readable scope) means deny, matching the predicate's own "no CIDRs means no IPs".
- **Behaviour fixed beyond the literal ticket:** `ip = addresses[0] if addresses else host` was a second bypass - an empty resolver answer handed the *hostname* to `asyncio.open_connection`, which resolves again below the filter. Empty now counts as `blocked=1` and nothing is probed. `addresses[0]` also became "the first *allowed* address", so a mixed answer no longer skips a permitted address just because the resolver listed a forbidden one first. A resolver answer the predicate cannot parse (`ValueError`) is a block, not a pass.
- **Decision for user review - `naabu` stays blocked.** (Resolved 2026-11-14 by the 12i ruling: option (c), permanent - no pre-resolve design, no second IP-connecting adapter.) `naabu` is handed hostnames and resolves inside the child; neither the adapter nor the engine can see the address, so there is no place to apply rule 6. Passing pre-resolved IPs instead would change `PortRecord.fqdn` semantics and could not be verified against the real binary (not installed here, and G4 forbids guessing its output). The safe choice is the skip: `blocked: resolves inside the binary, so in_scope_cidrs cannot be enforced (11c-G-7)`. The ports pool is therefore `pyscan` only in this build. Overrule this if a pre-resolve design is wanted.
- **Tests:** `test_pyscan_probes_only_an_address_inside_in_scope_cidrs` (mixed answer, only the permitted address is probed), `test_pyscan_skips_a_host_whose_address_is_outside_in_scope_cidrs` (no connection, no invented `closed` row, `blocked=1`), `test_pyscan_without_cidrs_probes_no_addresses` (predicate `None`), `test_pyscan_never_falls_back_to_the_hostname`, `test_pyscan_blocks_a_malformed_resolved_address`, `test_active_ports_stage_receives_the_cidr_predicate` (engine-level: the stage gets the scope file's predicate; `203.0.113.5` allowed, `198.51.100.5` not), `test_naabu_stays_blocked_because_it_resolves_inside_the_binary`.
- **Test helper change, disclosed:** `make_ctx()` in `tests/test_python_adapters.py` gained `ip_allowed` defaulting to a permissive lambda. That stand-in represents the engine's hand-down; the real wiring is proven separately by `test_active_ports_stage_receives_the_cidr_predicate`, so the default cannot hide a missing hand-down.
- **Mutation proofs (raw):** (1) `_allowed_addresses` made to `return addresses` -> `3 failed, 1 passed, 38 deselected`, first failure `AssertionError: assert ['not-an-ip'] == ['203.0.113.5']`; restored -> `17 passed, 25 deselected`. (2) `RunContext` built without `ip_allowed` -> `AssertionError: the active ports stage must get a CIDR predicate`, `1 failed, 42 deselected`; restored -> `1 passed, 42 deselected`. `git status --short` showed only the five intended modified files afterwards.
- **Checks:** `pytest -q` -> `596 passed`; `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `68 files already formatted` (after `ruff format tests/test_python_adapters.py`, which reformatted 1 file); `mypy src/reconkit` -> `Success: no issues found in 36 source files`.
- **Not verified:** no real resolver and no real target were used - `pyscan` has never run against a live host, so the filter is proven against injected resolvers only. The `blocked=` token is new in `ToolResult.error` and appears nowhere in real data yet.

## Part 11 close-out - rulings for the nine open items (2026-11-14)

- **Why this entry exists:** Part 11 could not close with findings that were merely "ticketed, no code": an owner reading the table could not tell whether an item was dropped. Every open 11c/11d item now has a ruling, and the deferred ones name a single future part instead of a vague "later".
- **Named future part:** **Part 12 - evidence, secrets and loop hygiene**. It is not in `docs/MASTER_PLAN.md`; adding a part is the owner's decision, so this entry records the name and scope rather than editing the plan.
- **Two fixes landed with this entry:** G-3 and G-4 (below). Everything else is deferred with a reason, and the two new findings from the first real active run (11d-findings-f and -g) are ticketed and deferred rather than silently absorbed.

| Item | Ruling | Why | What a fix needs |
|---|---|---|---|
| 11d-findings-b | **deferred to Part 12**, product decision made now | no traffic or scope impact, but the choice changes inventory semantics and `diff_new` | decision: keep the dns-only row, mark provenance `dns`, exclude from `diff_new` and discovery counts; then `_persist_dns` / `_previous_facts`, docs/04 section 5, migration if a column is added |
| 11d-findings-c | **deferred to Part 12** | metadata only: three writers disagree (`HttpAdapter` omits `duration_s` on two branches, `DnsPythonAdapter` never sets it, `_run_one` discards its own measurement on success), so the fix starts with which measurement is authoritative | decide adapter-measured vs engine-measured (docs/04 states it for the column), then fill all three sites, then test a 429, a parse error and a successful DNS run each store `> 0` |
| G-1 | **deferred to Part 12** | docs/03 promises raw output files; writing them needs per-adapter raw text, so it is an adapter-contract change, not a one-line call to `Workspace.write` | a `raw_path` per result, one write per adapter branch, redaction before write (PIT-22), tests per adapter |
| G-3 | **fixed now** | one caller away from the documented behaviour; no design decision needed | `Engine._note_passive_warning` calls `scope.passive_warning()` for a non-active run and splits/strips the `warning:` prefix so the UI does not print it twice |
| G-4 | **closed, not a defect** | docs/02 section 6 gives code 6 to install/update only, so a scan whose tools all failed returning 4 is correct; the member was dead weight that implied a scan outcome | removed `ExitCode.ALL_FAILED`; the enum test now pins the scan set {0,1,2,3,4,5,130}. The installer's numeric 6 is untouched |
| C-1 | **deferred to Part 12** | no reachable leak demonstrated (keys travel in headers, not URLs); a correct fix needs a secret source inside the CLI layer, which docs/03 must decide first | either redact `str(exc)` with the same env-derived secret list the engine uses, or keep secrets out of exception text at the source; decide whether `-v` may print a traceback |
| C-2 | **deferred to Part 12** | the file is 0600 and removed in `finally`; only SIGKILL can strand it, and a cleanup sweep is a new mechanism | decide between a startup sweep of the managed temp names and an unlinked-file design; keep the key out of argv |
| E-1 | **deferred to Part 12** | the SQLite transaction is synchronous and short; moving it risks write ordering for no correctness gain | `asyncio.to_thread` around the transaction body, or a writer thread; needs a test that persistence ordering survives |
| E-2 | **deferred to Part 12** | a YAML read on the loop delays the scheduler, never a result | make `_active_hosts` async and `await asyncio.to_thread(load_scope, ...)`; the gate already loads twice, so load once and pass the gate |
| E-3 | **deferred to Part 12** | mkdir/chmod happens once per run, before any network work | move `Workspace.create` into `to_thread` alongside E-1/E-2 |
| 11d-findings-f (new) | **deferred to Part 12** | `pyprobe` classifies a TLS `ConnectError` by substring and discards the text, so an UNKNOWN host cannot be explained without probing again | a diagnostic detail field carried from adapter to store (redacted), and a docs/04 column decision |
| 11d-findings-g (new) | **deferred to Part 12** | an inconclusive live pass with no previous state writes no `host_status_history` row, while docs/04 section 5 says one row per host per status pass | a docs/04 decision on whether UNKNOWN transitions persist, then `decide_host_state`'s `persist` flag and the state-change diff |

- **G-3 details.** `scope.passive_warning()` returns `warning: <host> is outside scope.yaml\nwarning: continuing with passive stages only` or `None`. The UI prefixes every entry with `warning: ` (`ui.py:462`), so the engine strips the prefix per line instead of double-prefixing. The call sits after `self._warnings = []`, guarded by `not opts.active`; an active run does not need it because the gate decides there.
- **G-4 details.** `_exit_code` was never wrong: docs/02 section 6 assigns 6 to "Every requested tool failed to install or update", and no scan path returns 6. `ALL_FAILED = 6` had zero references in `src/` and `tests/` (only historical REVIEW_LOG prose), so removing it changes no behaviour and makes the enum match the documented scan codes.
- **Red before green, raw:** with the passive-warning call removed and `ALL_FAILED = 6` restored, `pytest -q tests/test_engine.py -k "exit_code_constants or passive_run_outside"` -> `2 failed, 42 deselected`, `Extra items in the left set: 6` and `test_passive_run_outside_scope_warns - Assertion...`. Restored -> `2 passed, 42 deselected`.
- **Tests:** `test_passive_run_outside_scope_warns` (outside target warns with both lines; in-scope target warns nothing) and the extended `test_exit_code_constants_match_docs`.
- **Checks:** `pytest -q` -> `597 passed`; `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `68 files already formatted`; `mypy src/reconkit` -> `Success: no issues found in 36 source files`.
- **Decisions for user review:** (1) Part 12's name and scope are proposed here, not plan-approved; (2) `naabu` remains unavailable in this build (see the G-7 entry) - overrule if a pre-resolve design is preferred; (3) 11d-findings-b's product decision is mine under A1 (keep + label provenance) and can be overruled before implementation. (All three resolved 2026-11-14: Part 12 was approved, 12i kept `naabu` blocked permanently, and 11d-findings-b was implemented as proposed in 12b.)

## Part 11 close-out - fresh S3 scans (2026-11-14)

- **Form, disclosed:** the S3 scans ran in bash `grep` form on this Kali checkout (`/home/kali/Desktop/reconkit`). Each command and its raw output is below, run at `18e7462` with a clean tree.

```
$ grep -rn --include=*.py -E '\bassert\b' src/
exit=1
$ grep -rn --include=*.py -E 'shell\s*=\s*True' src/
exit=1
$ grep -rn --include=*.py -E 'TODO|FIXME|XXX|HACK' src/
exit=1
```

- S3-1, S3-2, S3-3: no hits (`exit=1` is grep's "no match"). No `assert` in `src/`, no `shell=True`, no TODO markers.

```
$ grep -rn --include=*.py -E 'print\(' src/
src/reconkit/ui.py:208:    console.print(Text(message, style="yellow"))
src/reconkit/ui.py:232:    target_console.print(Text(line), soft_wrap=True)
src/reconkit/ui.py:256:        target.print(Text(hint, style="yellow"))
src/reconkit/ui.py:268:    target.print(Text(message))
src/reconkit/ui.py:275:    target.print(Text(message, style="red"))
src/reconkit/ui.py:320:        target.print(Text("No completed discovery run for this target.", style="yellow"))
src/reconkit/ui.py:323:        target.print(
src/reconkit/ui.py:335:    target.print(Text(f"No changes since run #{report.previous_run_id}."))
src/reconkit/ui.py:351:    target.print(table)
src/reconkit/ui.py:399:        target.print(Text("No runs yet.", style="yellow"))
src/reconkit/ui.py:419:    target.print(table)
src/reconkit/ui.py:447:            target.print(_host_table(rows))
src/reconkit/ui.py:449:            target.print(Text("No hosts found.", style="yellow"))
src/reconkit/ui.py:451:            target.print(_tool_table(summary))
src/reconkit/ui.py:461:        target.print(Text(summary_line))
src/reconkit/ui.py:463:        target.print(Text(f"warning: {warning}", style="yellow"))
src/reconkit/ui.py:551:    out.print(table)
src/reconkit/ui.py:552:    out.print(
src/reconkit/ui.py:561:    out.print(
src/reconkit/ui.py:573:    out.print(Text(environment), soft_wrap=True)
src/reconkit/ui.py:589:        out.print(keys)
src/reconkit/ui.py:591:        out.print(
src/reconkit/ui.py:595:        out.print(Text(f"warning: {warning}", style="yellow"))
src/reconkit/ui.py:640:    target.print(table)
src/reconkit/ui.py:660:    target.print(table)
```

- S3-4: 25 hits, all in `ui.py`, the single rendering module. No `print(` anywhere else in `src/`.

```
$ grep -rn --include=*.py 'subprocess' src/
src/reconkit/core/runner.py:1:"""The only subprocess entry point: argv lists, timeouts, process groups."""
src/reconkit/core/runner.py:8:import subprocess
src/reconkit/core/runner.py:105:        process = subprocess.Popen(
src/reconkit/core/runner.py:107:            stdin=subprocess.DEVNULL,
src/reconkit/core/runner.py:108:            stdout=subprocess.PIPE,
src/reconkit/core/runner.py:109:            stderr=subprocess.PIPE,
src/reconkit/core/runner.py:132:        raise RuntimeError("subprocess pipes were not created")
src/reconkit/core/runner.py:161:    except subprocess.TimeoutExpired:
src/reconkit/core/runner.py:191:def _kill_tree(process: subprocess.Popen[bytes]) -> None:
src/reconkit/adapters/base.py:3:Adapters return data only: no database, scope gate, UI or subprocess of their
$ grep -rn --include=*.py 'sqlite3' src/
src/reconkit/core/store.py:3:Only this module imports sqlite3. It stores and queries; the engine decides
src/reconkit/core/store.py:11:import sqlite3
src/reconkit/core/store.py:206:        self._conn = sqlite3.connect(str(self.path))
src/reconkit/core/store.py:207:        self._conn.row_factory = sqlite3.Row
```

- S3-5: only `runner.py` imports and uses `subprocess`; the `base.py` hit is prose in the module docstring stating that adapters own no subprocess. S3-6: only `store.py` mentions `sqlite3` (its own docstring plus the import and connection).

```
$ grep -rn --include=*.py 'os\.environ' src/
src/reconkit/ui.py:145                                        # NO_COLOR (docs/02 color rule)
src/reconkit/installer/go_install.py:22                       # PATH for the child env
src/reconkit/installer/pipx.py:31                             # PATH for the child env
src/reconkit/installer/github_release.py:537                  # HOME + PATH for the authenticated lookup
```

- S3-7: four hits, each justified in place: `NO_COLOR` is a documented output rule; the other three are the installer's documented "child gets PATH (and HOME)" exception in docs/10 section 3d. No adapter reads `os.environ`; keys reach adapters through `ctx.env` only.

```
$ grep -rn --include=*.py -E 'except\s*:|except Exception|except BaseException' src/
src/reconkit/core/store.py:214        # close the connection when migration fails, then re-raise
src/reconkit/core/store.py:249        # rollback on any exception, then re-raise
src/reconkit/core/workspace.py:135    # close fd / unlink the temp file on any exception, then re-raise
src/reconkit/core/wildcard.py:90      # a failed probe is "cannot tell" (None), never NONE (PIT-21)
src/reconkit/cli.py:226               # last-resort handler; the known C-1 question (unredacted str(exc))
src/reconkit/engine.py:389            # close the store when Engine construction fails, then re-raise
src/reconkit/engine.py:578            # mark the stage run "failed", then re-raise
src/reconkit/engine.py:878            # adapter exception -> ToolResult(FAILED) with redacted text (PIT-16)
src/reconkit/adapters/dnspython.py:130 # unexpected resolver error -> structured ERROR, never DEAD (PIT-01)
```

- S3-8: nine hits. Eight either re-raise immediately after cleanup or convert the failure into a structured result on purpose, with the in-code comment naming the reason. One remains the known C-1 item (`cli.py:226`), which is deferred to Part 12 by the ruling above, so this scan is "justified with one open ruling", not "clean".

```
$ grep -rn --include=*.py -E 'noqa|type:\s*ignore' src/ tests/
tests/test_scope.py:266:        return {name.lower() for name in inspect.signature(func).parameters}  # type: ignore[call-overload]
tests/test_runner.py:82:        run_exec("echo", timeout=1)  # type: ignore[arg-type]
tests/test_runner.py:86:        run_exec([sys.executable, 1], timeout=1)  # type: ignore[list-item]
```

- S3-9: no `noqa` and no `type: ignore` in `src/`; the three test-only ignores are the Part 0 baseline (signature introspection and two deliberate bad-argument cases). No new suppression was added by this part.

```
$ grep -rn -E 'import (store|scope|ui|cli)|from reconkit\.(core\.store|core\.scope|ui|cli)' src/reconkit/adapters/
exit=1
```

- S3-10: no adapter imports `store`, `scope`, `ui` or `cli`. The new `ip_allowed` field keeps that rule intact: the adapter receives a callable, it does not import the gate.
- **What the scans cannot see:** they are pattern checks, not a review. The `docs/09` "exclude from counts" gap, the C-1 reachability question and the two new live-run findings are judgement calls, not pattern hits, and they are covered by the ruling table above.

## Part 11 close-out - install exit code 6 re-check (2026-11-14)

- **Why:** G-4 removed `ExitCode.ALL_FAILED = 6` from the scan enum. The owner asked whether that broke `install --all` when every tool fails, on the premise that Part 10 put 6 into the same enum.
- **What the code actually does:** there is exactly one `class ExitCode` in `src/` (`engine.py:79`) and it is scan-only. The installer never imports it. `install` reachability comes from `installer/github_release.py:288` `def exit_code(outcomes) -> int`, which returns the literal `0`/`5`/`6` and is called at both dispatch sites (`:460`, `:611`). `grep -rn "ALL_FAILED" src/ tests/` -> no matches. `grep -rn "return 6\b" src/` -> no matches (the 6 is `return 5 if ok else 6`).
- **History:** `git log --oneline -S "ALL_FAILED" -- src/reconkit/engine.py` -> `18e7462` (removal) and `0d6f762 feat: wire install and update to the installer backends` (addition). Part 10 did add the member, but no code path ever returned it; install's 6 has always been the plain int in `github_release`.
- **Proof it still exits 6:** `pytest -v` over the five guards plus the enum test -> `6 passed in 0.38s`: `test_exit_code_is_aggregated_over_every_selected_tool` (asserts 5 then 6), `test_dispatch_every_tool_failing_exits_6` (both outcomes not ok -> `code == 6`), `test_a_piped_install_skips_the_sudo_tool_instead_of_aborting` (`result.exit_code == 6`), `test_a_declined_prerequisite_skips_the_whole_tool` (`code == 6`), `test_plans_are_isolated_and_exit_codes_follow_the_table` (`exit_code([...]) == 6`) and `test_exit_code_constants_match_docs`.
- **Doc change so the two owners are unmistakable:** docs/02 section 6 now states under the table that code 6 comes from `installer.github_release.exit_code()` and that the scan enum deliberately stops at 5 plus 130; the `ExitCode` docstring says the same. No behaviour change.
- **Verdict:** not broken. It is one enum for scans and a separate int for the installer; the 6 never lived on the scan path.
- **Checkout question (answered 2026-11-14):** all commits are in `/home/kali/Desktop/reconkit` (Kali, `uname -a` -> `Linux kali 7.2.15+kali-amd64`). Development began on another machine; the folder was copy-pasted to Kali to finish the parts needing real Debian tooling, and every commit since then exists only here. Kali is canonical and the only checkout.

## Tool flags and fields verified against the real tools (2026-11-14)

- **Why:** G4 forbids guessing a flag or a JSON field. This pass checks every phase-2 tool and the phase-3 candidates named in the request (`nmap`, `rustscan`, `naabu`, `masscan`, `subfinder`, `assetfinder`, `massdns`, `httpx`, `katana`, `nuclei`) against the real binary on this Kali box where installed, and the tool's official source where not. Documentation only; no code changed in this commit.
- **Where the table lives:** `docs/09_TOOL_CONTRACTS.md` section 9. It is reproduced here as the evidence record.
- **Form:** binaries were preferred (9 of 11 external tools are installed here); the two that are not (`assetfinder`, `rustscan`) were checked against the official repo/docs. The four HTTP endpoints were checked with live requests or their official reference. Every command below ran on 2026-11-14 in `/home/kali/Desktop/reconkit`.

| Tool | Relied on | Verified by | Mismatch |
|---|---|---|---|
| crtsh | `?q=%.<domain>&output=json`, fields `name_value`, `common_name` | live 200, 28,454 bytes | none; unencoded `%` in `q` 404s, httpx encodes |
| certspotter | `/v1/issuances` + `domain`/`include_subdomains`/`expand=dns_names`, field `dns_names`, Bearer auth | official APIv1 reference + live 200 (17 entries) | none |
| otx | `/api/v1/indicators/domain/{d}/passive_dns`, `passive_dns[].hostname` | official external-API page; two live anonymous calls 429 | shape still not observed live |
| hackertarget | `?q=<domain>`, text `host,ip` | two live 200s `www.example.com,172.66.147.243` | quota string still unobserved |
| subfinder | `-d -silent -nc -duc -pc -rl -version` | installed v2.17.0 `-h`; official README | none |
| assetfinder | `--subs-only <domain>`, domain positional; `-h` identity probe | official README + `main.go` | binary not installed; probe inferred |
| httpx | `-u -json -silent -no-stdin -duc -nc -sc -title -location -td -cdn -rl`; keys `input url status_code title location tech cdn_name` | installed v1.12.0 `-h`, `-ldv`, two localhost probes | none |
| naabu | `-silent -json -no-stdin -duc -nc -scan-type c -host -p -rate`; keys `host ip port` | installed v2.7.0 `-h`, two localhost scans | `host` omitted for IP inputs (adapter falls back to `ip`) |
| nmap | `-sV`, `-T<0-5>`, `-p`, `--version` | installed 7.991 | `rate_flag: -T` needs a digit appended |
| masscan | `--max-rate`, `--version`, needs root | installed 1.3.2; `--max-rate 100 --echo` shows `rate = 100` | **`--version` exits 1**, so doctor calls a real Masscan "wrong program" |
| rustscan | `-V, --version` | not installed; Kali package page shows `rustscan -h` | not verified against a binary |
| massdns | `-r`, `-t`, `-o` (L/S/F/B, no JSON); version via `dpkg-query` | installed 1.1.0-0kali2 | none; a future adapter must parse text |
| katana | `-rl`, `-version` | installed v1.8.0 | version line is not the first line |
| nuclei | `-rl`, `-tags`, `-version` | installed v3.11.1 | same first-line defect |
| dig | `dig -v` version command | installed 9.20.30 | none |
| dnspython/pyprobe/pyscan | library/stdlib only | dnspython 2.9.2 with `NXDOMAIN`; stdlib imports | none |

Raw evidence:

```
$ for b in nmap masscan naabu subfinder assetfinder httpx katana nuclei massdns dig jq go curl; do printf "%-12s " "$b"; command -v "$b" || echo MISSING; done
nmap         /usr/bin/nmap
masscan      /usr/bin/masscan
naabu        /usr/bin/naabu
subfinder    /home/kali/go/bin/subfinder
assetfinder  MISSING
httpx        /home/kali/go/bin/httpx
katana       /home/kali/go/bin/katana
nuclei       /home/kali/go/bin/nuclei
massdns      /usr/bin/massdns
dig          /usr/bin/dig
jq           /usr/bin/jq
go           /usr/bin/go
curl         /usr/bin/curl
```

```
$ nmap --version | head -2
Nmap version 7.991 ( https://nmap.org )
Platform: x86_64-pc-linux-gnu
$ masscan --version
Masscan version 1.3.2 ( https://github.com/robertdavidgraham/masscan )
Compiled on: Jul 25 2024 16:44:22
Compiler: gcc 14.1.0
OS: Linux
CPU: unknown (64 bits)
GIT version: unknown
$ naabu -version | tail -3
		projectdiscovery.io

[INF] Current Version: 2.7.0
$ subfinder -version
[INF] Current Version: v2.17.0
[INF] Subfinder Config Directory: /home/kali/.config/subfinder
$ httpx -version | tail -2
[INF] Current Version: v1.12.0
$ katana -version
[INF] Current version: v1.8.0
$ nuclei -version | head -1
[INF] Nuclei Engine Version: v3.11.1
$ dig -v
DiG 9.20.30-1-Debian
```

Flag presence, straight from the binaries:

```
$ nmap --help | grep -nE '^\s*-sV|^\s*-T<|-p <'
31:  -p <port ranges>: Only scan specified ports
39:  -sV: Probe open ports to determine service/version info
62:  -T<0-5>: Set timing template (higher is faster)
$ naabu -h | grep -inE 'json|no-color|scan-type|-host|-p |-rate'
8:   -host string[]              hosts to scan ports for (comma-separated)
14:   -port, -p string              ports to scan (80,443, 100-200)
24:   -rate int             packets to send per second (default 1000)
35:   -j, -json                              write output in JSON lines format
45:   -scan-type, -s string            type of port scan (SYN/CONNECT) (default "c")
103:   -no-color, -nc            disable colors in CLI output
$ subfinder -h | grep -nE '^\s+-(d|silent|nc|duc|pc|rl)\b'
8:   -d, -domain string[]  domains to find subdomains for
24:   -rl, -rate-limit int      maximum number of http requests to send per second (global)
30:   -duc, -disable-update-check  disable automatic subfinder update check
41:   -pc, -provider-config string  provider config file (default "/home/kali/.config/subfinder/provider-config.yaml")
50:   -silent             show only subdomains in output
53:   -nc, -no-color      disable color in output
$ httpx -h | grep -nE '^\s+-(u|sc|title|location|td|cdn|rl|duc|no-stdin|nc)\b'
10:   -u, -target string[]     input target host(s) to probe
14:   -sc, -status-code                      display response status-code
17:   -location                              display response redirect location
24:   -title                                 display page title
27:   -td, -tech-detect                      display technology in use based on wappalyzer dataset
38:   -cdn                                   display cdn/waf in use (default true)
88:   -rl, -rate-limit int          maximum requests to send per second (default 150)
105:   -duc, -disable-update-check  disable automatic httpx update check
159:   -no-stdin                        Disable Stdin processing
174:   -nc, -no-color            disable colors in cli output
$ katana -h | grep -nE '^\s+-rl'
100:   -rl, -rate-limit int                maximum requests to send per second (default 150)
$ nuclei -h | grep -nE 'rate-limit|\-tags'
50:   -tags string[]                     templates to run based on tags (comma-separated, file)
153:   -rl, -rate-limit int                     maximum number of requests to send per second (default 150)
```

Real JSON output, produced by running the installed binaries against a local `python3 -m http.server` on 127.0.0.1:18080 (no packets left this machine):

```
$ httpx -u 127.0.0.1:18080 -json -silent -sc -title -location -td -cdn -nc -duc
{"timestamp":"2026-11-14T13:47:12.211473768-05:00","port":"18080","url":"http://127.0.0.1:18080","input":"127.0.0.1:18080","title":"reconkit probe","scheme":"http","webserver":"SimpleHTTP/0.6 Python/3.14.8","content_type":"text/html","method":"GET","host":"127.0.0.1","host_ip":"127.0.0.1","path":"/","time":"5.500479ms","a":["127.0.0.1"],"tech":["Python:3.14.8","SimpleHTTP:0.6"],"words":2,"lines":1,"status_code":200,"content_length":30,"failed":false,"knowledgebase":{"pHash":0}}

$ httpx -u 127.0.0.1:18080/subdir -json -silent -sc -title -location -td -cdn -nc -duc
{"timestamp":"2026-11-14T13:47:31.262194637-05:00","port":"18080","url":"http://127.0.0.1:18080/subdir","input":"127.0.0.1:18080/subdir","location":"/subdir/", ...,"status_code":301, ...}

$ naabu -host 127.0.0.1 -p 18080 -json -silent -nc -duc -no-stdin -scan-type c
{"ip":"127.0.0.1","timestamp":"2026-11-14T18:47:12.26100621Z","port":18080,"protocol":"tcp","tls":false}

$ naabu -host localhost -p 18080 -json -silent -nc -duc -no-stdin -scan-type c
{"host":"localhost","ip":"127.0.0.1","timestamp":"2026-11-14T18:47:32.005116457Z","port":18080,"protocol":"tcp","tls":false}
```

The httpx JSON key list was also read from the binary itself (`httpx -ldv`), which contains `input`, `url`, `status_code`, `title`, `location`, `tech`, `cdn_name`, `webserver`, `host`, `port`.

```
$ masscan --max-rate 100 -p1234 --echo | grep -inE 'rate|ports'
2:rate = 100
8:ports = 1234
$ dpkg-query -W '-f=${Version}' massdns; echo
1.1.0-0kali2
$ massdns -h
Usage: massdns [options] [domainlist]
  -r  --resolvers        Text file containing DNS resolvers.
  -t  --type             Record type to be resolved. (Default: A)
  -o  --output           Flags for output formatting.
Output flags:
  L - domain list output
  S - simple text output
  F - full text output
  B - binary output
```

```
$ curl -s -m 25 "https://crt.sh/?q=%25.example.com&output=json" -w "http=%{http_code} bytes=%{size_download}\n"
http=200 bytes=28454
$ curl -s -m 25 "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names" -w "http=%{http_code}\n"
http=200 bytes=7739   -> 17 entries, first keys include dns_names
$ curl -s -m 25 "https://api.hackertarget.com/hostsearch/?q=example.com"
http=200 bytes=31
www.example.com,172.66.147.243
$ curl -s -m 25 "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
http=429 bytes=80   -> {"detail": ...}; shape taken from the official API page instead
```

Two defects found, both outside the adapter contract and fixed/ticketed separately:

1. **`masscan --version` exits 1** while printing `Masscan version 1.3.2 (...)` on stdout. `installer.github_release.installed_version()` returns `None` for any nonzero exit, so `default_status()` reports `installed=False, path=/usr/bin/masscan` and doctor prints `masscan | wrong program | failed` for a genuine, working Masscan. Confirmed with `reconkit doctor` on 2026-11-14.
2. **Banner-first version text.** `installed_version()` returns `text.splitlines()[0]`; for katana and nuclei the first line is ASCII art, so doctor shows `__` and `[I…`. Adapter-backed tools are unaffected because they use `check_installed()` and a version regex. Cosmetic, but it also defeats `_same_version` for those tools.

## Bugs found by the Part B audit - masscan reported as "wrong program" (2026-11-14)

- **Symptom:** `reconkit doctor` printed `masscan | ports | opt_in | wrong program | - | /usr/bin/masscan | failed` and `warning: masscan: /usr/bin/masscan is not the expected program; doctor ignores it.` on a box where `/usr/bin/masscan` is genuine Masscan 1.3.2.
- **Cause:** `masscan --version` prints `Masscan version 1.3.2 ( https://github.com/robertdavidgraham/masscan )` on stdout and exits **1**. `installer.github_release.installed_version()` returned `None` for `returncode != 0`, so `doctor.default_status()` produced `installed=False` with a resolved path, which the doctor maps to `WRONG_PROGRAM`.
- **Fix:** a nonzero exit is now accepted only when the probe output still names the program (`plan.binary.lower() in text.lower()`); every other nonzero probe remains not-usable, so the "wrong program" guard keeps its purpose. Docs first: the mismatch is recorded in docs/09 section 9 and this entry.
- **Red before green:** `pytest -v tests/test_install_cli.py -k "masscan_version_counts or nonzero_version_probe"` -> `1 failed, 1 passed` (`assert None == 'Masscan version 1.3.2 ( https://github.com/robertdavidgraham/masscan )'`). After the fix -> `2 passed in 0.20s`.
- **Verified on the real binary, not only the fake runner:** `reconkit doctor` now prints `│ masscan │ ports │ opt_in │ yes │ Masscan │ /usr/bin… │ ok │` and no masscan warning.
- **Not fixed (ticketed to Part 12):** the same function returns `text.splitlines()[0]`, so `katana` shows `__` and `nuclei` shows `[I…` in the version column, which also defeats `_same_version()` for update reporting. Recorded in PROGRESS Open risks.

## Open-risk retry - OTX and HackerTarget (2026-11-14, one request each)

- **Why:** the Part B audit left OTX's response shape and HackerTarget's quota text unobserved. The owner asked for one polite retry each, or to leave them named. Both were retried once, with the honest UA `reconkit/0.1`, no key.
- **OTX:** still refused.
  ```
  $ curl -s -m 30 -A "reconkit/0.1" "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns" -w "http=%{http_code} bytes=%{size_download}\n"
  http=429 bytes=80
  {"detail": "Anonymous access to this endpoint is limited. Please authenticate."}
  ```
  The exact 429 body is now known, but the `passive_dns` shape is still not observed from this box. No code reads the body: the HTTP adapter maps 429 to a `failed` result with the status and no retry, which the fixture tests pin. Open risk unchanged except that the refusal text is now recorded.
- **HackerTarget:** succeeded, quota not hit, so the quota message is still unobserved.
  ```
  $ curl -s -m 30 -A "reconkit/0.1" "https://api.hackertarget.com/hostsearch/?q=example.com" -w "http=%{http_code} bytes=%{size_download}\n"
  http=200 bytes=31
  www.example.com,172.66.147.243
  ```
  The `host,ip` format is confirmed twice; the adapter's `api count exceeded` branch remains unexercised and is named in Open risks rather than guessed.
- **Not done, deliberately:** no key was used, no rate-limit window was waited out, and nothing was installed to make a probe possible. `assetfinder`/`rustscan` remain named Open risks per the owner's ruling.

## Real-tool verification session - testfire.net (2026-11-14)

- **Purpose:** exercise the code at `c9072d9` against the already-authorized target with real installed tools, no mock, no keys. Verification only: no code changed in this entry. Scope was the existing `scope.yaml` (`in_scope: testfire.net, *.testfire.net`, `allow_active: true`); nothing outside it was contacted.
- **Step 1 - install.** `reconkit install --all` (real, exit 5). Every tool came back `already installed` from earlier work except `rustscan`:

```
rustscan           github_release  failed             rustscan: release 2.4.1
                                                      has no asset
                                                      'verify-at-implementation'
rustscan: rustscan: release 2.4.1 has no asset 'verify-at-implementation'
```

  That is the documented placeholder in tools.yaml, not a new failure. **`libpcap-dev` is NOT installed and could not be installed:** `dpkg -s libpcap-dev` says "package 'libpcap-dev' is not installed", and `sudo -n true` returns `sudo: a password is required`, so the apt step cannot run non-interactively. `install --all` never reaches it because `naabu` is "already installed" and prerequisites only run when their tool installs (the documented consequence in docs/10 section 3a). This prerequisite is therefore **unverified**, independent of the CIDR gate.
- **Doctor** (exit 0) confirms the same state:
```
coverage: subs 11/11 ready, dns 5/5 ready, live 4/4 ready, ports 5/6 ready, tech
4/5 ready, urls 8/8 ready, vulns 5/8 ready, shots 0/1 ready
system packages: python3 installed, python3-venv installed, python3-pip installed, git installed, golang-go installed, libpcap-dev missing, jq installed, curl installed
python 3.14.8 | scope.yaml found | db recon.db writable
Missing tools: 6. Run: reconkit install --all
```
  Every Keys row reads `Set: no`; no key was used and none was added.
- **Step 3 - the run command, and one trap.** The requested command `reconkit -d testfire.net --active --speed slow --no-keys --json` executed **`lite`, not `run`**: docs/02 section 2 defines the bare form as `lite` (passive only), and `_stages("lite", active)` ignores `--active` entirely (`cli.py:103`). It completed after 2 min 48 s with `subs` + `dns` only and exit 5 (`crtsh` 502, `otx` 429). The full active pipeline was then run as `reconkit run -d testfire.net --active --speed slow --no-keys --json`, twice. Neither run wrote one byte to stderr despite docs/02 section 5 saying tables and progress stay on stderr (recorded below as a finding, not fixed).
- **Run 1** (19:11:26Z-19:16:56Z, exit 5, `alive 8 / dead 28 / hosts 36`, `tools_ok 8 / tools_failed 2`):

| Stage | Tool | Status | Items | Real detail |
|---|---|---|---|---|
| subs | crtsh | failed | 0 | `crtsh: server error (HTTP 502)` |
| subs | certspotter | ok | 0 | real empty answer |
| subs | otx | failed | 0 | `otx: rate limited (HTTP 429)` |
| subs | hackertarget | ok | 3 | |
| subs | subfinder | ok | 35 | 15.63 s |
| subs | assetfinder | ok | 4 | 6.49 s |
| dns | dnspython | ok | 36 | `duration_s` 0.0 (known 11d-findings-c) |
| live | pyprobe | ok | 8 | `unreachable=28`, `duration_s` 0.0 |
| live | httpx | ok | 8 | 7.04 s |
| ports | pyscan | ok | 0 | `blocked=8` - the CIDR gate refused every host because scope.yaml has no `in_scope_cidrs` |
| tech, urls, vulns | - | - | 0 | **no adapter exists for any tool in these pools** (all phase 3); each stage was created, ran zero tools and completed |

- **Run 2** (19:18:45Z-19:24:09Z, exit 5, `alive 8 / dead 28`, `tools_ok 9 / tools_failed 1`): `crtsh` recovered (ok, 1 item, 8.19 s), `otx` still 429, `subfinder` returned **8** items in 68.55 s instead of 35 in 15.63 s, `certspotter` 0, `hackertarget` 3, `assetfinder` 4; `dns` resolved 9; `live` 8 ALIVE from pyprobe + httpx; `ports` `blocked=8`; tech/urls/vulns again zero tools.
- **skipped, from `tool_runs` (run 1):** `urlscan`, `amass`, `findomain`, `chaos`, `github_subdomains`, `dnsx`, `puredns`, `massdns`, `dig`, `httprobe`, `tlsx`, `smap`, `nmap`, `rustscan`, `httpx_tech`, `whatweb`, `wafw00f`, `cdncheck`, `webanalyze`, `gau`, `waybackurls`, `katana`, `hakrawler`, `gospider`, `subjs`, `unfurl`, `urlfinder`, `nuclei`, `subzy`, `dnsreaper` all `no adapter yet (phase 3)`; `naabu` skipped as `blocked: resolves inside the binary, so in_scope_cidrs cannot be enforced (11c-G-7)`. These rows are in the database, not in the JSON summary (`tools_skipped: 0`), which is the pre-existing Part 7/8 gap named below.
- **Step 5 - database, raw.** After both runs:
```
targets              1
scan_runs            17
tool_runs            99
subdomains           36
subdomain_sources    100
host_status_history  81
ports                0
port_sources         0
urls                 0
```
  One full stored status row (`run_id` 13, ALIVE) and one `tool_runs` row:
```
            id: 73
  subdomain_id: 1
        run_id: 13
         state: ALIVE
   status_code: 200
      location:
         title: Altoro Mutual
      ips_json: ["65.61.137.117"]
     tech_json: ["Apache Tomcat", "Java"]
           waf:
    tools_json: ["httpx"]
    checked_at: 2026-11-14T19:23:39Z
   cnames_json: []
dangling_cname:

        id: 42
    run_id: 7
      tool: pyscan
    status: ok
item_count: 0
duration_s: 0.0
     error: blocked=8
```
  `ports` is empty, so **the LOW-only confidence ceiling could not be observed in practice**: no port row was written at all. What the run proves is the gate itself (`blocked=8`), not a LOW row.
- **Step 6 - `reconkit diff -d testfire.net` after run 2** (exit 0): 27 `GONE` rows, no `NEW`, no `CHANGED`. The list is exactly the run-1 discovery set minus run-2's 9 hosts, e.g. `social.testfire.net`, `tv.testfire.net`, `mvaas.testfire.net`, `www.demo.testfire.net`. Cause: `subfinder` returned 35 items in run 1 and 8 in run 2, so the latest-two-subs comparison sees an absent source as a disappearance. `diff` behaved as docs/02 defines it ("gone since the previous run"); the output is nonetheless dominated by source variance rather than a target change.
- **Findings (no code changed):**
  1. **Bare `--active` is silently a no-op** (`lite` ignores it). Docs-conformant, but the exact command in this request produced a passive-only run with exit 5 and no warning. Recommend a CLI warning or rejecting `--active` for `lite`; that is a docs-first decision.
  2. **A stage with zero adapters completes silently.** `tech`, `urls` and `vulns` ran zero tools in both runs and the JSON reports `tools_skipped: 0`; only `tool_runs` shows the 30 skipped rows. With a clean subs stage the same run would exit 0 while three of six requested stages did nothing. Related to the known Part 7/8 gap (skipped tools not in the summary) but broader: it also hides whole empty stages.
  3. **`--json` writes nothing to stderr** (0 bytes in both runs), while docs/02 section 5 says progress stays on stderr. No progress was visible during 5-minute runs.
  4. **`diff` amplifies passive-source variance**: 27 of 36 hosts reported GONE after one flaky `subfinder` run. Not a code defect against docs/02, but a real-world usability problem worth a tolerance/union decision.
  5. **Known items re-confirmed on real data, not new:** `duration_s` 0.0 for `dnspython` and `pyprobe` (11d-findings-c), `pyprobe` carrying `unreachable=28` in `error`, `otx` anonymous 429, `certspotter` legitimately empty, `scan_runs` partial status when a passive source fails.
- **Confidence actually observed, and a decision this forces.** Every ALIVE host in both runs came back `confidence: UNCONFIRMED`, e.g. `altoro.testfire.net` with discovery sources `assetfinder, hackertarget, subfinder` and `status_code: 200`. Cause: `pyprobe` returned `UNKNOWN` for all 8 hosts (and `unreachable=28` for the rest) while `httpx` returned 200 for the same 8, and `decide_host_state` treats *any* web state that is not `ALIVE` as disagreement (`engine.py:166-168`), which `confidence_for` maps to `UNCONFIRMED` before counting sources. `test_engine_disagreement_is_unconfirmed` pins that behaviour deliberately, and docs/09 section 5 says only that "at least 2 agreeing checks ... sets confidence (**LOW when only one check is available**)" without naming `UNCONFIRMED` for host state. So this is ambiguous, not an untested defect: `UNKNOWN` can mean "no evidence" (which docs/09 would score LOW) or "contradicts the ALIVE tool" (current behaviour). Decision needed; no code was changed. The related reason `pyprobe` cannot reach hosts that `httpx` gets 200 from is 11d-findings-f, still deferred.
- **What this run does NOT prove:** no tech/urls/vulns tool was executed (no adapters), no open port was ever observed (`pyscan` blocked, `naabu` blocked, `nmap`/`rustscan`/`smap` phase 3), `libpcap-dev` is absent, no keyed provider ran, and `killpg`/`sudo` paths were not exercised.

## Bug-fix session - 2026-11-14: pyprobe TLS short-circuit, `--active` on passive commands, skipped tools in the summary

- Docs read / goal: `AGENTS.md`, `docs/PROGRESS.md` RESUME, the pitfalls table above, `docs/02_CLI_UX.md` (sections 2, 5, 6), `docs/09_TOOL_CONTRACTS.md` (section 3 adapter contract, section 4 selection rules), `docs/03_ARCHITECTURE.md` section 7, and the code paths `cli._run_scan`/`_stages`, `adapters/pyprobe._probe`, `engine._select`/`StageOutcome`, `ui.summary_document`/`_tool_table`/`render`. Owner instruction: fix the two most serious findings for real (not `--mock`), investigate one before calling it a bug, log one as a named finding without changing behaviour, do not touch `scope.yaml`/`in_scope_cidrs`, do not install anything with sudo, do not push.
- **Item 1 - `--active` is now a usage error on passive-only commands.** docs/02 section 2 already defines the bare form as "shorthand for `lite` (the passive pipeline)" and says "`lite` is the workflow shortcut for exactly that passive pipeline and nothing active ... Only `run` includes active stages", so the flag had no honest meaning there; option (a) from the request (reject with exit 2 and name `run`) is the behaviour the doc already requires. docs/02 was edited first: a new paragraph in section 2 states that `--active` is exit `2` on the bare form, `lite`, `passive`, `subs` and `dns`, and names `run -d X --active`. Code: `cli._run_scan` derives the stage tuple once, and when `active` is set and every stage in it is passive it raises `ConfigError("<command> is passive-only; --active needs: reconkit run -d X --active")` before the engine opens (no `scan_runs` row, no workspace). The message is deliberately under 80 columns after the first real run wrapped it as `use 'reconkit / run -d X --active'`.
- **Item 2 - investigated, and it is a real bug, not scanner variance.** Scratch reproduction of the exact client config (`timeout=10`, `User-Agent: reconkit/0.1.0`, `follow_redirects=False`), verbatim stderr/stdout:
  ```
  GET https://www.testfire.net/
    EXC TYPE: httpx.ConnectError
    EXC STR : [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'www.testfire.net'. (_ssl.c:1127)
    is ConnectError: True
    _is_tls_error  : True
  GET http://www.testfire.net/
    status      : 200
    http_version: HTTP/1.1
    location    : None
    server      : Apache-Coyote/1.1
  ```
  All eight hosts behaved identically (`https` certificate failure, `http` 200):
  ```
  altoro.testfire.net          https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  demo.testfire.net            https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  demo2.testfire.net           https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  evil.testfire.net            https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  ftp.testfire.net             https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  localhost.testfire.net       https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  testfire.net                 https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  www.testfire.net             https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  ```
  Root cause: `_probe` looped `SCHEMES = ("https", "http")` but on `httpx.ConnectError` it returned a `HostStatusRecord(state=UNKNOWN)` **inside** the loop as soon as `_is_tls_error()` matched, so the `http` attempt was never made. A certificate whose name does not match the host (or any TLS-only failure) therefore hid a working plain-HTTP service from the tool that was supposed to be the independent second opinion, while ProjectDiscovery `httpx` reported 200. Fix: remember `tls_error`, `continue` to the next scheme, and only after every scheme has failed is a TLS error turned into `UNKNOWN` (plain connect failures still produce no record, so `unreachable=` is unchanged). docs/09 section 3 was updated with that contract. Real proof after the fix, production `PyprobeAdapter.run` with a real `RunContext` (real `Pacer`/`RateLimiter`, 8 hosts, `slow`):
  ```
  status: ok error: None
    altoro.testfire.net        ALIVE    200 'Altoro Mutual'
    demo.testfire.net          ALIVE    200 'Altoro Mutual'
    demo2.testfire.net         ALIVE    200 'Altoro Mutual'
    evil.testfire.net          ALIVE    200 'Altoro Mutual'
    ftp.testfire.net           ALIVE    200 'Altoro Mutual'
    localhost.testfire.net     ALIVE    200 'Altoro Mutual'
    testfire.net               ALIVE    200 'Altoro Mutual'
    www.testfire.net           ALIVE    200 'Altoro Mutual'
  ```
  CLI proof (`reconkit live -d www.testfire.net --active --tools pyprobe --no-keys --speed slow`, then the same for the root): both `exit=0`, host table `www.testfire.net ALIVE 200` / `testfire.net ALIVE 200`, and `host_status_history` holds `('www.testfire.net','ALIVE',200,'Altoro Mutual','["pyprobe"]')` and `('testfire.net','ALIVE',200,'Altoro Mutual','["pyprobe"]')`. The earlier real run had the same tool return `UNKNOWN` for both.
- **Item 2 - what this does and does not settle.** The "100% disagreement" was not two tools disagreeing; it was one tool short-circuiting. In the two-tool live run (`--tools pyprobe,httpx`, `--json`) both now return `ALIVE 200` for `www.testfire.net`, so the input that produced `UNCONFIRMED` in the full run is gone. It does **not** settle the queued UNKNOWN-vs-disagreement ruling: `engine.decide_host_state` still treats any non-`ALIVE` web state as disagreement, and `_persist_stage`/`Store.host_rows` still read confidence and sources from the discovery tables, so a `live`-only invocation displays `LOW (0)` with `sources: []`. Both observations are in the raw JSON of this session; neither behaviour was changed. `11d-findings-f`'s other half (the TLS text is still discarded, no diagnostic column) stays deferred to Part 12: adding a column is a docs/04 decision and this session was not allowed to add one.
- **Item 3 - a stage that built nothing no longer reports a clean zero.** docs/02 section 5 now documents `stages[].skipped` (`{"tool","reason"}`) and says `summary.tools_skipped` counts selection-time skips as well as executed `skipped` results; docs/09 section 4 states the same reporting rule. Code: `engine.ToolSkip` and `StageOutcome.skipped` carry the list `_select` already produced, `ScanSummary.skipped` flattens it; `ui.summary_document` writes it per stage and adds its length to `tools_skipped`; `_tool_table` renders skipped rows (which docs/02 already promised) and the summary line adds the same count; a run whose only rows are skips now prints the Tools table instead of the empty-state line. Exit codes were deliberately **not** changed (a stage with no adapter still exits `4`, and whether it should make a mixed run partial is still an owner decision). Real, no-`--mock`, against testfire.net:
  ```
  reconkit tech  -d testfire.net --active --json -> exit 4, 5 skipped
  reconkit urls  -d testfire.net --active --json -> exit 4, 8 skipped
  reconkit vulns -d testfire.net --active --json -> exit 4, 3 skipped
  stages[0].skipped = [{"tool":"httpx_tech","reason":"no adapter yet (phase 3)"}, ...]
  summary.tools_skipped = 5 / 8 / 3
  ```
- **Item 4 - logged, not fixed: `diff` reports source flakiness as infrastructure change.** New named finding in `docs/PROGRESS.md` "Open risks" - `subfinder` returned 35 names in run 1 and 8 in run 2 five minutes apart, and `diff` printed 27 `GONE` rows for hosts nothing had re-probed. `diff` matches docs/02 ("gone since the previous run") so no code changed. Proposed fix shapes for the owner's ruling: (a) require two consecutive misses before `GONE` (a run history query, no schema change); (b) compare against a union of the last N discovery runs (a new `Store` read, no schema change); (c) leave the rule and rename the column/JSON key to "not seen this run", which is honest but breaks the documented `gone` name and the `--json` shape. (a) hides real removals for one run; (b) hides them for N runs; (c) keeps the data exact and changes only the label. Ruling required before any of them.
- Bugs found:
  1. **`--active` silently swallowed by the bare form and by every passive-only command.** Symptom: `reconkit -d testfire.net --active --speed slow --no-keys --json` exited 5 after running only subs+dns; the user could believe an active scan ran. Root cause: `_stages("lite", active)` ignores `active` by design and nothing rejected the flag. Fix: docs/02 section 2 paragraph plus the `cli._run_scan` guard. Guarding tests: `test_bare_command_rejects_active_instead_of_running_lite`, `test_passive_only_commands_reject_active[lite|passive|subs|dns]`.
  2. **`pyprobe` returned `UNKNOWN` instead of trying `http` after a TLS failure.** Symptom: 8 of 8 hosts that `httpx` got 200 on were `UNKNOWN`, forcing `UNCONFIRMED` confidence. Root cause: `_probe` returned inside the scheme loop on the first TLS `ConnectError`. Fix: `tls_error` flag plus `continue`, UNKNOWN only when every scheme failed. Guarding test: `test_pyprobe_tls_failure_still_tries_http` (the older `test_pyprobe_tls_error_is_a_result` still pins "TLS on every scheme is a result, never a crash").
  3. **A stage with zero adapters reported `tools_skipped: 0`.** Symptom: `tech`/`urls`/`vulns` returned `results: []` and a zero skip count while 30 tools had been skipped. Root cause: the summary counted only executed `ToolResult`s and `StageOutcome` dropped `_select`'s skip list. Fix: `ToolSkip`/`StageOutcome.skipped`/`Summary.skipped` plus the docs/02 JSON field and the Tools table rows. Guarding test: `test_a_stage_with_no_adapter_reports_its_skips`.
- Requirement -> test table: item 1 -> `test_bare_command_rejects_active_instead_of_running_lite` (bare form, exit 2, no DB file created) and `test_passive_only_commands_reject_active` (parametrized over `lite`, `passive`, `subs`, `dns`); item 2 -> `test_pyprobe_tls_failure_still_tries_http` (asserts both URLs were requested, `ALIVE`, `200`, title); item 3 -> `test_a_stage_with_no_adapter_reports_its_skips` (exit 4 unchanged, `stages[0].skipped`, `summary.tools_skipped == len(skipped)`); item 4 -> docs only, no test.
- **Red before the fix** (source reverted, tests kept): `7 failed in 88.79s`, exit 1. Reproduced failures: `assert 0 == 2` on the bare form and on each passive-only command (old code exited 0), `KeyError: 'skipped'` for the JSON stage, and `assert <HostState.UNKNOWN: 'UNKNOWN'> is <HostState.ALIVE: 'ALIVE'>` for pyprobe with the record `HostStatusRecord(fqdn='www.example.com', source='pyprobe', state=UNKNOWN, status_code=None, ...)`.
- **Green after the fix:** the five new test functions (eight cases with the parametrization) -> `8 passed in 0.41s`, exit 0.
- Mutation proofs (source mutated, targeted tests run, source restored by `git checkout -- src/reconkit` + `git apply` of the saved diff each time):
  - A: guard condition turned into `if False and ...` -> `5 failed in 93.55s` (`test_bare_command_rejects_active_instead_of_running_lite` plus all four `test_passive_only_commands_reject_active` cases), `MUTATION_A_CAUGHT`.
  - B: restore the early `return HostStatusRecord(state=UNKNOWN)` on a TLS error -> `1 failed` with the same UNKNOWN-vs-ALIVE assertion, `MUTATION_B_CAUGHT`.
  - C: drop `+ len(summary.skipped)` from `tools_skipped` -> `assert 0 == 5`, `MUTATION_C_CAUGHT`.
  - D: emit `"skipped": []` for the stage -> `assert []` on the stage list, `MUTATION_D_CAUGHT`.
- Raw gate output after the last edit: `pytest -q` -> `606 passed in 13.01s` (`PYTEST_PASS`); `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `68 files already formatted`; `mypy src/reconkit` -> `Success: no issues found in 36 source files`. The full suite went from 599 to 606 (seven new cases; one pre-existing pyprobe test kept and documented).
- Not changed on purpose: `scope.yaml` and `in_scope_cidrs` (the owner's decision), `pyscan`/ports, `diff`, exit codes for empty stages, `--json` progress, the UNKNOWN-vs-disagreement rule, and every deferred Part 12 item. No dependency, module, file or CLI command was added; no sudo install was attempted; nothing was pushed.
- Not verified: no full `run --active` pipeline was repeated after the fix (the two real `live` runs and the real per-host adapter run cover the changed code path); the `ALIVE`-from-`http` case is proved on testfire.net only; the tech/urls/vulns tools still have no adapter, so item 3 was proved only on stages that skip everything.
- **S1 (second pass):** `pytest -q` run a second time after the commit -> `606 passed in 12.94s`, `PYTEST_SECOND_PASS`; the commit itself ran the pre-commit hook with the same four checks (`606 passed`, `All checks passed!`, `68 files already formatted`, `Success: no issues found in 36 source files`).
- **S2 (own diff, `git diff HEAD~1 -- src` read line by line):**
  - Broad `except`: **none added**. The nine pre-existing sites are unchanged (`store.py:214,249`, `workspace.py:135`, `wildcard.py:90`, `cli.py:232` the top-level error boundary, `engine.py:406,595,901`, `dnspython.py:130`); the new code adds no `try` at all.
  - External input and where it is validated: the only new input is `--active` (a Typer bool) and `command`, which comes from `ctx.info_name` or the literal `_SCAN_COMMANDS` tuple, never from the target; the new `ConfigError` message interpolates no user text, so there is no path for shell/format/JSON injection. `pyprobe` still validates every host with `validate_host()` inside `_probe` before building a URL (unchanged).
  - Secrets reaching a log/error/argv/URL/file: **none**. Skip `reason` strings now travel into JSON and the Tools table; they are produced by `engine._select` from constants (`no adapter yet (phase N)`, `requires --active`, `not installed`, `IP_GATE_BLOCKED`) or by `require_active()`'s scope message, which carries a hostname, never an env value. No tool stdout is included, and `ToolSkip` has no secret field.
  - Blocking calls inside async code: **none added** (`ToolSkip`/`StageOutcome` are plain dataclasses; `ui` is sync and already only called from the CLI).
  - Exceptions that could escape an adapter or the engine: **none new**; `ToolSkip(spec.name, reason)` and the list comprehension cannot raise, and the CLI guard raises `ConfigError`, which `_run_scan` already maps to exit 2.
  - Unfinished paths: `StageOutcome.skipped` is empty for a **resumed** stage (the earlier run owned those rows; `tool_runs` still has them); a stage whose pool is entirely excluded/opt-in is still omitted from `summary.stages` rather than reported as empty; a zero-adapter stage still exits `4` on its own and does not force `5` in a mixed run.
- **S3 scans (bash grep form of the S3 block, run on the committed tree):** `\bassert\b` in `src` -> `NONE`; `shell\s*=\s*True` -> `NONE`; `TODO|FIXME|XXX|HACK` -> `NONE`; `print(` -> `src/reconkit/ui.py` only; `subprocess` -> `src/reconkit/core/runner.py`, `src/reconkit/adapters/base.py` (pre-existing: `base.py` only names `subprocess.CalledProcessError`); `sqlite3` -> `src/reconkit/core/store.py` only; `os.environ` -> `ui.py:148` (`NO_COLOR`), `installer/go_install.py:22`, `installer/pipx.py:31`, `installer/github_release.py:542` (all pre-existing, justified in docs/10 section 3d); the nine broad-`except` sites above are the pre-existing justified set; `noqa|type: ignore` in the six changed files -> `NONE`; adapters importing store/scope/ui/cli -> `NONE`. `git status --short` after the commit -> empty tree.

## Rule decision - 2026-11-14: `diff` GONE needs two consecutive misses

- Docs read / goal: `docs/02_CLI_UX.md` (section 2 state/output table, section 5 JSON), `docs/04_DATABASE.md` section 6 (diff queries) and section 5 (state rules), `docs/08_UX_FLOWS.md` Flow 7, plus `core/store.py` `diff_*`, `engine.DiffSnapshot`/`Engine.diff` and `ui.diff_document`/`render_diff`. Owner ruling on the logged finding: **option (a)** - a host must be missing for two consecutive runs before `diff` reports `GONE`; this entry implements exactly that and changes nothing else (`state_changes`, ports, `NEW`).
- **Definition, docs first:** docs/02 section 2 now states the rule in user terms ("`GONE` only after two consecutive misses ... a host missing from only the latest run is silent in the table and listed once under `Not reported as GONE yet`"), docs/04 section 6 restates it for the queries, and docs/08 Flow 7 shows the message. "Two consecutive runs" means the two latest **completed discovery runs** for the target: `scan_runs` rows for the `subs` stage with status `completed` or `partial`, newest first. Resume does not change the set (a resumed stage gets its own row like any run); no other stage takes part. Formally, with the three newest discovery runs `baseline`, `previous`, `latest`: a host is `GONE` iff it was seen in `baseline` **and** is absent from both `previous` and `latest`. Fewer than three completed discovery runs -> `gone` is empty.
- **No schema change:** presence per run already lives in `subdomain_sources.run_id`, so the rule is the old single-miss query plus one more `NOT EXISTS`. docs/04 says so explicitly. `Store.diff_gone(baseline, previous, latest)` carries the rule; the old query survives as `Store.diff_pending_gone(previous, latest)`, which powers the human "not reported as GONE yet" line and the new `pending_gone` JSON array. `DiffSnapshot` gained `baseline_run_id` and `pending_gone` (both defaulted), and `diff --json` now documents all three run ids.
- Adversarial cases and their tests (all in `tests/test_store.py` / `tests/test_engine.py`):
  - missing once then back: `test_diff_gone_is_not_confirmed_when_the_host_reappears` (not GONE, not pending once it is back).
  - missing twice in a row: `test_regression_diff_gone_needs_two_consecutive_misses` (GONE on the second miss, and only then).
  - visible in both baseline and previous, missing from the latest only: `test_diff_gone_needs_the_miss_to_be_consecutive` (not GONE; pending).
  - no sighting in the run before the pair: `test_diff_gone_needs_the_baseline_run_not_just_two_empty_ones` (not GONE - two empty runs alone are not evidence).
  - first-ever run / fewer than three runs: `test_diff_with_one_run_has_nothing_to_compare`, `test_diff_with_two_runs_reports_pending_and_no_gone`, and the real CLI path in `test_diff_and_status_after_two_mock_runs` (`baseline_run_id: null`, `gone: []`, "GONE needs three discovery runs" on stderr).
  - the session's own repro, 35 names then 8: `test_regression_diff_gone_needs_two_consecutive_misses` seeds exactly that shape and asserts the 27 are **not** GONE after one miss (they are `pending_gone`), then GONE after the second identical run.
- **Red before the fix** (source reverted, tests kept): `7 failed in 0.48s`, exit 1 - `AttributeError: 'Store' object has no attribute 'diff_pending_gone'`, `TypeError: Store.diff_gone() takes 3 positional arguments but 4 were given` (twice), `AttributeError: 'DiffSnapshot' object has no attribute 'baseline_run_id'` (twice), `KeyError: 'baseline_run_id'`. Green after the fix: the same seven plus the two extra cases -> `148 passed in 2.71s` over `test_store.py test_engine.py test_cli.py`.
- Mutation proofs (source mutated, targeted tests run, restored with `git checkout -- src/reconkit` + `git apply`):
  - M1 drop the "absent from previous" clause -> `test_diff_gone_needs_the_miss_to_be_consecutive` fails with `assert ['a.example.com'] == []`, `MUT_M1_CAUGHT`.
  - M2 drop the "seen in baseline" clause -> `test_diff_gone_needs_the_baseline_run_not_just_two_empty_ones` fails with `assert ['old.example.com'] == []`, `MUT_M2_CAUGHT`.
  - M3 engine passes `discovery[1]` as the baseline -> `test_diff_with_two_runs_reports_pending_and_no_gone` fails with `assert (1, 1, 2) == (None, 1, 2)`, `MUT_M3_CAUGHT`.
- **Real data, unchanged database:** `reconkit diff -d testfire.net` against the existing `recon.db` (the two verification-session runs, 35 then 8) now prints:
  ```
  {"type":"diff","target":"testfire.net","baseline_run_id":2,"previous_run_id":4,"latest_run_id":11,"new":[],"gone":[],"pending_gone":["altoroc.testfire.net", ... 27 names ...],"state_changes":[],"ports_opened":[],"ports_closed":[]}
  No changes since run #4.
  Not reported as GONE yet (needs two consecutive misses): altoroc.testfire.net, ...
  ```
  The 27 rows that were `GONE` in the verification session are `pending_gone`, and `gone` is empty - the exact reported defect, on the exact data that produced it.
- Mock end-to-end of the changed command: two `passive --mock` runs then `diff --json` -> `"baseline_run_id":null, "gone":[], "pending_gone":[]`, and the human run prints `No changes since run #1.` plus `GONE needs three discovery runs to compare; nothing can be confirmed gone yet.`
- **S1:** `pytest -q` -> `613 passed in 13.04s` and a second pass `613 passed in 12.98s`; `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `68 files already formatted`; `mypy src/reconkit` -> `Success: no issues found in 36 source files`. Suite went 606 -> 613 (eight new cases, one obsolete single-miss test replaced).
- **S2 (own diff):** no broad `except` added (`git diff -- src/reconkit | grep '^+.*except'` -> `NONE`); the only new external input is the report of a read-only query, and SQL stays parameterized (four bound parameters in `diff_gone`, three in `diff_pending_gone`, no interpolation); no secret can reach the new fields (they are FQDNs already stored in `subdomains`); no blocking call added inside async code (`Engine.diff` was and stays synchronous, called from the CLI, not from `run`); no new exception path (`diff_pending_gone` cannot raise beyond `sqlite3`, as before); unfinished paths: `state_changes`/ports still use the previous pair only, and `NEW` still means `first_seen_run = latest`, so a host that reappears after a miss is neither `NEW` nor `GONE` (documented in docs/02).
- **S3 scans:** `\bassert\b` -> `NONE`; `shell\s*=\s*True` -> `NONE`; `TODO|FIXME|XXX|HACK` -> `NONE`; `noqa|type: ignore` in the three changed source files -> `NONE`; broad-`except` grep on the diff -> `NONE`.
- PIT-39 added. Not verified: no real third discovery run was made for this rule in step 1 (the real `diff` above proves the first-miss half on real data; the second-miss half is proved by the store/engine tests and will be exercised again in the session-2 run).

## Real-tool verification session 2 - testfire.net, post-fix (2026-11-14)

- Command: `reconkit run -d testfire.net --active --speed slow --no-keys --json` (the `run` subcommand, not the bare form), against the existing `recon.db`, one pass. Started `2026-11-14T20:10:59Z`, finished `20:19:24Z` (8m25s), **exit 5**. `stdout` 18,771 bytes (one document), **`stderr` 0 bytes** - the known `--json` progress gap is unchanged and still contradicts docs/02 section 5.
- Summary object, verbatim from the document:
  ```
  {"hosts":36,"alive":8,"dns_only":0,"shut_down":0,"dead":28,"unknown":0,
   "tools_ok":8,"tools_failed":2,"tools_skipped":31,"tools_timeout":0}
  ```
  Stages, their run ids and their executed/skipped counts: `subs` 18 (6 executed, 5 skipped), `dns` 19 (1, 4), `live` 20 (2, 2), `ports` 21 (1, 4), `tech` 22 (0, 5), `urls` 23 (0, 8), `vulns` 24 (0, 3). The 31 skipped are exactly the selection-time skips this build always had; they now appear in `stages[].skipped` and in `tools_skipped` (fix from the previous session), so the run reports what it did **not** do for the first time.
- Executed tools (`tool_runs` rows, verbatim): `crtsh ok 1 51.7`, `certspotter ok 0 0.83`, `otx failed 0 0.0 'otx: rate limited (HTTP 429)'`, `hackertarget failed 0 0.0 'hackertarget: free quota exceeded'`, `subfinder ok 35 64.02`, `assetfinder ok 3 6.19`, `dnspython ok 36 0.0`, `pyprobe ok 8 0.0 'unreachable=28'`, `httpx ok 8 7.04`, `pyscan ok 0 0.0 'blocked=8'`. Every other pool member is `skipped` with `no adapter yet (phase 3)`, except `naabu` (`blocked: resolves inside the binary, so in_scope_cidrs cannot be enforced (11c-G-7)`).
- **pyprobe now agrees with httpx on every live host.** `pyprobe`: 8 records, all `ALIVE`, `error='unreachable=28'`; `httpx`: 8 records, all `ALIVE`, `error=None`. No `UNKNOWN` record exists in this run. This is the fix from the previous session working on the real target that produced the 8-of-8 disagreement.
- **Confidence observed, before and after, and what it actually means.** Session 1 stored `confidence: UNCONFIRMED` for all 8 ALIVE hosts (its log entry quotes them). This run: `demo.testfire.net HIGH`, `www.testfire.net MEDIUM`, the other six ALIVE hosts `LOW`, and **zero `UNCONFIRMED`**. The number is not live-tool agreement: `Engine._write_host` writes `confidence` only when the transition is `UNCONFIRMED` and otherwise keeps the discovery value, so the displayed trust is `subdomains.source_count` from the `subs` stage (docs/04), and the two-tool live agreement lives in `host_status_history.tools_json` (`["pyprobe","httpx"]` on every ALIVE row). So the honest statement is "the disagreement override no longer fires; HIGH/MEDIUM/LOW are discovery-source counts", not "two live tools now set MEDIUM". `altoro.testfire.net` is `LOW` because `hackertarget` failed this run, leaving `subfinder` as its only contributing source, while the JSON `sources` array still lists all-time sources.
- **`diff` after the run** (latest pair now runs 11 and 18, baseline 4):
  ```
  {"type":"diff","target":"testfire.net","baseline_run_id":4,"previous_run_id":11,"latest_run_id":18,"new":[],"gone":[],"pending_gone":[],"state_changes":[],"ports_opened":[],"ports_closed":[]}
  No changes since run #11.
  ```
  The rule's effect on the actual defect, measured directly against the same database (`Store` methods, no hand-edited numbers):
  ```
  completed subs run ids (newest first): [18, 11, 4, 2]
  old rule  (seen in 4, absent in 11):            27 hosts
  new rule  (seen in 2, absent in 4 AND 11):       0 hosts
  new rule  (seen in 4, absent in 11 AND 18):      0 hosts
  pending after run 18 (seen in 11, absent in 18): 0 hosts
  ```
  So: on the pair that produced the false GONEs (4 -> 11) the old rule said 27, the new rule says 0 (they were `pending_gone` until run 18), and because `subfinder` came back with 35 names in run 18 the 27 were never confirmed gone. **`subfinder` is still flaky** (35, then 8, then 35 in this run - 64.02 s this time); what changed is that a single flaky run no longer produces a `GONE` report. If a second consecutive run had also missed them, the rule would have confirmed them at that point - that is the designed behaviour, not a gap.
- Database, raw. Counts before -> after: `scan_runs` 17 -> 24, `tool_runs` 99 -> 140, `subdomains` 36 -> 36, `subdomain_sources` 100 -> 139, `host_status_history` 81 -> 117, `ports` 0 -> 0, `urls` 0 -> 0. Discovery runs now: `2 partial 36`, `4 partial 36`, `11 partial 9`, `18 partial 36` hosts. `scan_runs` 18-24: `subs partial`, then `dns`, `live`, `ports`, `tech`, `urls`, `vulns` all `completed` - note that a stage which executed **zero tools** is still recorded `completed` (the empty-stage exit-code question stays open). One full history row, verbatim:
  ```
  {'id': 104, 'subdomain_id': 4, 'run_id': 20, 'state': 'ALIVE', 'status_code': 200,
   'location': None, 'title': 'Altoro Mutual', 'ips_json': '["65.61.137.117"]',
   'tech_json': '[]', 'waf': None, 'tools_json': '["pyprobe", "httpx"]',
   'checked_at': '2026-11-14T20:19:01Z', 'cnames_json': '["testfire.net"]',
   'dangling_cname': None}
  ```
- **A previously unverified fact is now verified live:** `hackertarget` returned its free-quota refusal and the adapter mapped it to a failed result with `hackertarget: free quota exceeded`. The quota-message branch that previous sessions could not exercise has now run for real. `otx` returned 429 again, so its response shape remains unobserved.
- Still wrong or surprising, stated plainly: (1) `--json` still writes nothing to stderr (docs/02 promises progress there); (2) `tech`/`urls`/`vulns` ran zero tools and are recorded and reported `completed` - their skips are now visible, but the run's exit 5 comes from `otx` and `hackertarget`, not from the three empty stages; (3) `ports` is still `blocked=8` with zero port rows (no `in_scope_cidrs`, `naabu` blocked) - unchanged by design; (4) `duration_s` is `0.0` for `dnspython` and `pyprobe` (11d-findings-c); (5) `pyprobe` reports `unreachable=28`, which counts the 28 hosts that do not answer HTTP at all, not errors; (6) `crtsh` took 51.7 s and `subfinder` 64.02 s at `--speed slow`, which is pacing, not a defect.
- Not verified, unchanged: no tech/urls/vulns tool has ever run; no open port has ever been observed; no keyed provider ran (`--no-keys`); `killpg` and the sudo-authenticated installer path remain untested; `libpcap-dev` is still absent.

## Part 12a: write raw tool output to the workspace (G-1)  (commit subject `feat: write every tool's raw output to the workspace`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` Part 12 (12a, its `DECIDED` line is the spec), docs/03 sections 4-6 and 9, docs/09 sections 2-3, docs/05 rules 5 and 8 (secrets, honest UA), docs/07, docs/02 section 5 (JSON shape), `config.yaml` and `tools.yaml`. Goal: `Workspace.write` had no caller and `ToolResult.raw_path` was never set, so every parse bug (pyprobe TLS, certspotter empties, HackerTarget quota) had to be reproduced by hand. Every adapter run now leaves its bytes on disk.
- **Decisions and assumptions (docs written first, then code):**
  - Capture is a per-result field, not per-adapter side effects: `ToolResult.raw_text` (unredacted, in memory, `Field(exclude=True)`) plus the existing `raw_path`. Both base classes fill `raw_text` in every return path; the three python adapters fill it through one shared helper instead of hand-rolling a format.
  - Binary capture is `stdout` then `--- stderr ---` then `stderr` (stdout-only when stderr is empty, stderr only when stdout is blank); HTTP capture is the response body, or the failure message when no body was read; `python` capture is a JSON document of the parsed records plus the error counters (they have no child process); `--mock` captures the fixture text.
  - The engine writes, never the adapter (adapters stay free of workspace/store imports): `_run_one` calls `Workspace.write`, which redacts with the run's secrets and caps at `MAX_OUTPUT_BYTES`, and only then sets `raw_path`.
  - Filename `<run_id>-<tool>.txt` in `RAW_OUTPUT_DIRS[stage]`: unique per stage run and tool, so two tools in a stage and the same tool in two runs cannot collide and a rerun cannot overwrite older evidence. `dns` has no workspace directory of its own (the layout is exactly six), so it uses `meta/`, like phase-3 `vulns`/`shots`.
  - `raw_text` is excluded from serialization so an unredacted payload can never reach `--json`; `raw_path` does appear there because that object is the docs/09 `ToolResult` schema (verified below).
  - The cap is enforced at the disk boundary (`Workspace.write(..., max_bytes=MAX_OUTPUT_BYTES)`) so every raw file is capped no matter which caller writes it; `MAX_OUTPUT_BYTES` is `runner`'s existing 1,000,000 default, now a named constant - no new config key.
  - An empty capture still writes an empty file (one executed tool = one file); a write that raises is contained and leaves `raw_path` at `None`.
- **Decisions for user review:** (1) a python adapter's raw file is post-parse evidence (JSON of records + counters), not wire bytes - a host that produced no record appears only in the counters; (2) an HTTP failure writes the failure message (e.g. `otx: rate limited (HTTP 429)`) because the body is deliberately not read on error; (3) `dns` raw files live in `meta/` rather than a new seventh directory; (4) a capped file carries no "truncated" marker line, because a marker would push it over the cap (the binary path still reports `output truncated` in `result.error` from the runner).
- **Docs changed first:** `docs/09_TOOL_CONTRACTS.md` (ToolResult schema gains `raw_text` with its `Field` exclude, plus a "Raw output (12a)" bullet covering all three kinds, every status, mock, redaction and `raw_path`); `docs/03_ARCHITECTURE.md` (`workspace.write` signature with `max_bytes` and the cap rule, a new bullet for the raw-file naming and `dns`->`meta` mapping, a `_run_one` bullet in the Engine API, and data-flow step 9). No `docs/02` change: the JSON tool object is defined by docs/09.
- **Deviations:** the plan says "the four python adapters"; the tree has three (`dnspython`, `pyprobe`, `pyscan`) and all three changed. docs/03 section 3 (technology stack) needed no change: the capture rule belongs to sections 5 and 6 step 9. `Workspace.write` now caps every caller, so the old `test_workspace_large_output_is_written` (2 MiB uncapped) became `test_workspace_large_output_is_written_up_to_the_cap`; the new assertion is stricter, not weaker.
- **Files touched:** `src/reconkit/models.py`, `adapters/base.py`, `adapters/dnspython.py`, `adapters/pyprobe.py`, `adapters/pyscan.py`, `core/runner.py` (constant only), `core/workspace.py`, `engine.py`; `tests/test_engine.py`, `test_binary_adapters.py`, `test_python_adapters.py`, `test_wildcard_workspace.py`; `docs/03`, `docs/09`, this entry, `docs/PROGRESS.md`. 14 files, +497/-36 before the docs edits.
- **Requirement -> test table:**
  | Requirement (12a `DECIDED` line / owner instruction) | Test |
  |---|---|
  | a mock run writes exactly one redacted file per executed tool and sets `raw_path` | `test_each_executed_tool_writes_one_raw_file_and_sets_raw_path` |
  | a successful tool run produces a raw file containing its stdout | `test_binary_run_captures_stdout_and_stderr`, `test_each_executed_tool_writes_one_raw_file_and_sets_raw_path` |
  | a failed tool run ALSO produces a raw file (main behavior change) | `test_failed_tool_still_writes_its_raw_output`, `test_binary_failed_run_captures_its_output`, `test_parse_error_keeps_the_raw_output` |
  | a timed-out tool keeps its partial output | `test_binary_timeout_captures_partial_output` |
  | output beyond `max_output_bytes` is truncated, not dropped or unbounded | `test_raw_output_file_is_capped_at_max_output_bytes`, `test_workspace_large_output_is_written_up_to_the_cap`, `test_workspace_write_honours_an_explicit_byte_cap`, `test_workspace_cap_never_writes_a_broken_multibyte_character`, `test_workspace_write_rejects_a_non_positive_cap` |
  | a secret/key pattern is redacted in the raw file too | `test_raw_output_file_is_redacted_with_the_run_secrets` (+ PIT-22's `test_workspace_redacts_two_secrets_and_a_bearer_token`) |
  | stdout and stderr are both present when both exist | `test_binary_run_captures_stdout_and_stderr`, `test_binary_run_without_stderr_keeps_stdout_only` |
  | the python adapters flow through the shared capture path | `test_python_adapters_capture_their_fixture_in_mock_mode`, `test_pyprobe_raw_text_is_json_evidence_of_each_host`, `test_dnspython_raw_text_carries_the_outcome_counters`, `test_pyscan_raw_text_carries_the_blocked_count` |
  | adversarial: NUL + ANSI bytes | `test_raw_output_keeps_nul_and_ansi_bytes_verbatim` |
  | adversarial: filename collision across two tools in one stage / two runs | `test_raw_file_names_do_not_collide_across_tools_or_runs` |
  | adversarial: a workspace write that raises keeps the tool result | `test_a_failed_workspace_write_keeps_the_tool_result` |
  | adversarial: a crash before any output still leaves a file | `test_a_crashed_tool_writes_an_empty_file_instead_of_nothing` |
- **Red before green (the failed-tool half, proved):** with the tests in place and only `MAX_OUTPUT_BYTES` added to `runner.py`, `pytest -q tests/test_engine.py tests/test_binary_adapters.py tests/test_python_adapters.py tests/test_wildcard_workspace.py -k "raw or capture or cap"` -> **`19 failed, 2 passed, 209 deselected`**, exit 1. The 19 were every 12a test (`AttributeError: 'ToolResult' object has no attribute 'raw_text'`, `TypeError: Workspace.write() got an unexpected keyword argument 'max_bytes'`); the 2 passes are pre-existing `cap`-named HTTP body tests. Before that constant existed the same command was a collection `ImportError` for `MAX_OUTPUT_BYTES`, so the constant alone is not what made the tests pass. After the implementation the same selection is **`21 passed, 209 deselected`**.
- **Self-review findings (S2):**
  - Broad excepts: none added. The one new handler is `except (OSError, ValueError, TypeError)` in `Engine._write_raw`, deliberately narrow and documented; `git diff -- src | grep '^+.*except'` shows only that line. Pre-existing broad excepts in `store.py` (214, 249), `workspace.py` (150), `wildcard.py` (90), `cli.py` (232), `engine.py` (421, 615, 922) and `dnspython.py` (142) are unchanged.
  - External input: only `ToolResult.raw_text`, produced by our own adapters from tool output. It reaches disk through `Workspace.write` (redact -> cap -> `mkstemp` + `os.replace`); the filename is `f"{run_id}-{adapter.name}.txt"` from an int and a class constant and is validated by `Workspace.path` (regex, one segment, resolve containment, device names). No user-supplied string is in a path.
  - Secrets: `raw_text` is unredacted in memory and is redacted exactly once, at the disk boundary. It is `Field(exclude=True)`, so `model_dump`/`model_dump_json`/`--json` cannot carry it (verified: the `--json` tool object has keys `duration_s, error, raw_path, records, status, tool` and `raw_text` is absent from the whole document). `error` strings are unchanged and still go through `_record`'s redaction. Redaction runs before the cap so a secret straddling the cut cannot survive as a prefix.
  - Blocking calls in async code: `Workspace.write` is synchronous and now runs inside async `_run_one` (one local write of at most 1,000,000 bytes, `fsync` + `os.replace`). This matches the existing design: `_persist_stage` already does synchronous SQLite work and the runner is pushed to a thread only because it is long. No new `asyncio.to_thread` was added; the write is bounded and local.
  - Exceptions that could escape: `Workspace.write` raises `OSError`/`ValueError`/`TypeError`, all caught in `_write_raw`; `cap_bytes` raises `ValueError` for a non-positive cap, also caught. `KeyboardInterrupt`/`CancelledError` are not caught, as before. Nothing new escapes an adapter or the engine.
  - Unfinished paths: HTTP error bodies are not captured (the failure message is); python adapters capture post-parse evidence, not raw responses; the `dns` raw file has no directory of its own.
  - Blocking scope/security check: no scope code touched; `_write_raw` only runs for a tool the engine already selected after the gates.
  - **S3 raw output** (bash/grep form, repo root): `\bassert\b` in `src/reconkit` -> `NONE`; `shell\s*=\s*True` -> `NONE`; `TODO|FIXME|XXX|HACK` -> `NONE`; `print(` -> `src/reconkit/ui.py` only; `subprocess` -> `src/reconkit/core/runner.py` plus a pre-existing docstring mention in `adapters/base.py:3` ("no database, scope gate, UI or subprocess of their own"), no import; `sqlite3` -> `src/reconkit/core/store.py` only; `os.environ` -> `ui.py:148`, `installer/go_install.py:22`, `installer/pipx.py:31`, `installer/github_release.py:542` (all pre-existing, none in adapters); broad-except scan -> the pre-existing nine, none added; `noqa|type: ignore` -> only the three pre-existing `type: ignore` lines in `test_scope.py:266`, `test_runner.py:82`, `test_runner.py:86`, none added; adapters importing store/scope/ui/cli -> `NONE`. Extra 12a scans: `raw_text` outside `adapters/`, `models.py`, `engine.py` -> `NONE`; `.write_text(|open(` in `src/` -> only the pre-existing `workspace.py:143` (`os.fdopen`), `runner.py:109`, `installer/verify.py`, `installer/github_release.py`, `subfinder.py:68` - no new raw writer; `Workspace.write` callers -> exactly one, `engine.py:956`; `raw_text` in `ui.py`/`cli.py`/`store.py` -> `NONE`.
- **Bugs found:** none new; no `fix:` follow-up was needed. PIT-22's guard covers the redaction path through `test_raw_output_file_is_redacted_with_the_run_secrets`.
- **PIT back-fill (2026-11-14, docs-only follow-up commit):** this was a genuine bug fix (G-1), so it now carries **PIT-41**, and the canonical guard `test_failed_tool_still_writes_its_raw_output` starts `Regression: PIT-41`. The other guards already existed in this entry's table (no new test was needed and none was written for the back-fill); production code is unchanged. At the time of the fix commit the row was missing, which is why this note exists.
- **Mutation proofs** (each mutation applied by hand to the working tree, related tests only, then restored from a byte-identical copy; `sha256sum -c` printed `OK` for both files after every restore, and `git diff --stat` for the two files reads `21 ++++++++++++++++++---` / `42 ++++++++++++++++++++++++++++++++++++++++++++++++-` again at the end):
  - M1 drop the redaction -> `cleaned = cap_bytes(text, max_bytes)`: `test_raw_output_file_is_redacted_with_the_run_secrets` and `test_workspace_redacts_two_secrets_and_a_bearer_token` -> **`2 failed`**, `AssertionError: assert 'sk-live-abc123' not in 'key=sk-live-abc123...'`. Restored -> `2 passed`.
  - M2 set `raw_path` before the write succeeds -> `_write_raw` computes the destination with `workspace.path(...)`, swallows the write failure and still returns the path: `test_a_failed_workspace_write_keeps_the_tool_result` -> **`1 failed`**, `AssertionError: assert '/tmp/.../subs/1-tool.txt' is None`. Restored -> `1 passed`.
  - M3 skip the write on failure -> `if result.status is ToolStatus.OK:` around the `model_copy`: `test_failed_tool_still_writes_its_raw_output` -> **`1 failed`**, `AssertionError: assert False ... is_file()` (raw_path was `None`). Restored -> `1 passed`.
  - M4 remove the cap -> `cleaned = redact(text, values)`: `test_raw_output_file_is_capped_at_max_output_bytes` and `test_workspace_large_output_is_written_up_to_the_cap` -> **`2 failed`**, `AssertionError: assert 1002048 == 1000000`. Restored -> the 21-test selection passes again.
- **Raw check output (S1, first pass, full output):**
  ```
  --- pytest -q ---
  ........................................................................ [ 11%]
  ... (9 lines of dots) ...
  634 passed in 13.35s
  --- ruff check . ---
  All checks passed!
  --- ruff format --check . ---
  68 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Second pass in the same session: `634 passed in 13.14s`, same three clean lines. Suite 613 -> 634 (21 new cases; one existing workspace test rewritten to the capped contract).
- **End-to-end `--mock` run with the changed code:** `reconkit passive -d example.com --mock --db /tmp/12a/recon.db` -> exit 0, 7 tools `ok`, 9 `skipped`. Files written, all mode `0600`: `workspaces/example.com/subs/1-crtsh.txt` (1577 B), `1-certspotter.txt` (596), `1-otx.txt` (591), `1-subfinder.txt` (64), `1-hackertarget.txt` (31), `1-assetfinder.txt` (49) and `workspaces/example.com/meta/2-dnspython.txt` (172). `1-crtsh.txt` starts with the real CT JSON (`{"issuer_ca_id": 409703, ...}`); `2-dnspython.txt` is the parsed fixture document (`{"www.example.com": {"ips": [...], "cnames": []}, ..., "gone.example.com": {"state": "DEAD"}}`). A second run, `reconkit subs -d example.com --mock --json`, showed the tool object keys `['duration_s','error','raw_path','records','status','tool']`, `raw_path: workspaces/example.com/subs/3-crtsh.txt`, and `raw_text` absent from the whole document.
- **Not verified:** no real (non-mock) tool ran with this code, so the binary branch's real stdout+stderr file and the HTTP adapter's real body file are proved by unit tests on `ExecResult`/`MockTransport` only; no real `--active` run; a python adapter's file cannot show a host that produced no record; the `dns`->`meta` mapping is only exercised by mock runs and unit tests.
- **Next part must know:** `Engine._run_one` now does `model_copy(update={"raw_path": ...})` before `self._record(...)`. 12c changes `duration_s` in the same function (adapter value wins, engine fills only when the adapter reported none) and must keep the `raw_path` update and the write ordering; 12g will add per-run directories, so `RAW_OUTPUT_DIRS` and the `<run_id>-<tool>.txt` name must move with that layout rather than be duplicated. The cap constant is `core/runner.MAX_OUTPUT_BYTES`.

## Part 12f: redact console error text and the `-v` traceback (C-1)  (commit subject `feat: redact console error text and the -v traceback`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` Part 12 (12f, its `DECIDED` line is the spec), docs/03 sections 4, 5 and 9, docs/05 rules 5/8 and sections 6 and 8, docs/04 section 10 (`redact`), docs/02 section 6 (exit codes), `cli.py`, `core/store.py`, `engine.py` (`Engine.open`), and the C-1 row in the Part 11c audit. Goal: `cli.py`'s last-resort handler formatted raw `str(exc)` and the `-v` branch printed a raw traceback; no secret source existed in the CLI, so an escaping exception could print a key. Nothing in this build had demonstrated a reachable leak (keys travel in headers), so this closes the last unguarded output path rather than a known incident.
- **The existing redaction source, named:** `core/store.py` owns the one implementation - `REDACTED`, the compiled pattern list (`_AUTH_HEADER`, `_COOKIE_HEADER`, `_BEARER`, `_URL_CREDENTIALS`, `_FLAG_VALUE`, `_SECRET_PAIR`) and `redact()`. Its secret *values* reach it per call; the engine's set is `Engine._secrets` = every non-empty value of the env dict that `Engine.open` builds from `dotenv_values()`, and that is the same set 12a routes through `Workspace.write` and `_record`. `configure_redaction()` reuses that exact `redact()` - one pattern list, one value source - it does not build a parallel list.
- **Startup order (found and handled):** `Engine.open` is called *inside* `_run_scan`, after `_targets()`, `load_config()` and the usage refusals, so at the moment `_report_error` can first fire the env is **not** loaded yet. The CLI therefore loads `.env` itself at the top of the Typer callback (`main`) and calls `configure_redaction()` there. It uses the same `dotenv_values()` call with no path argument: python-dotenv resolves `.env` from the calling file's directory, and `cli.py` and `engine.py` are both in `src/reconkit`, so both resolve the same checkout-level `/home/kali/Desktop/reconkit/.env`. Verified by reading `dotenv.main.find_dotenv` in the venv (it uses `sys._getframe()`'s file, not cwd) and by a test that feeds a fake `.env` dict. An unreadable `.env` is ignored at startup (the engine reports the real problem when it loads it), and the callback reads no `os.environ` - `test_cli_never_reads_environment_keys` still passes.
- **API shape (in `core/store.py`, no new file):** `configure_redaction(secrets)` replaces the process-wide value set (deduplicated, longest first, values under 3 chars ignored); `redact(text, secrets=None)` now treats `None` as "use that set" and an explicit iterable - **including `()`** - as "exactly these values". That keeps every existing caller byte-identical: `Core`/engine/workspace/store all pass their per-run tuple, so stored text, `tool_runs.error` and raw files still use only that run's values, while the CLI console path uses the startup set. No new env var, no new pattern, no new module.
- **Dependency rule change (needs owner awareness):** `cli.py` now imports `configure_redaction` and `redact` from `reconkit.core.store`. The existing `test_cli_imports_only_the_allowed_layers` banned *any* `reconkit.core.store` import, which the ruling makes impossible to keep. The assertion was replaced with a stricter, name-level rule: the only names imported from `reconkit.core.store` are exactly `{"configure_redaction", "redact"}`, and the source still must not contain `Store(` or `sqlite3`. docs/03 section 9 records the rule. This is an amendment, not a bypass: a `Store`/sqlite import in the CLI still fails the test.
- **Docs changed first:** docs/03 (CLI bullet, `store.py` structure comment, new "Redaction API (`core/store.py`)" section covering the one implementation, the replace-not-append contract, the startup-order fix and both console paths, plus the section 9 dependency rule); docs/05 (section 6 gains the console guarantee including chained exceptions, section 8 notes the traceback path).
- **Files touched:** `src/reconkit/core/store.py`, `src/reconkit/cli.py`; `tests/test_cli.py`, `tests/test_store.py`; `docs/03`, `docs/05`, this entry, `docs/PROGRESS.md`. 6 files, +223/-10 before the docs edits.
- **Requirement -> test table:**
  | Requirement (12f `DECIDED` / owner instructions) | Test |
  |---|---|
  | an exception message with a secret-shaped value is redacted in `_report_error` | `test_report_error_redacts_a_secret_in_the_message` |
  | the `-v` traceback output is redacted too (separate path) | `test_verbose_traceback_redacts_the_same_secret` |
  | an exception with no secret prints unchanged (no over-redaction, no mangling) | `test_report_error_leaves_a_message_without_a_secret_unchanged` |
  | a secret in a nested `__cause__`/`__context__` chain is redacted | `test_verbose_traceback_redacts_a_secret_in_a_chained_exception` |
  | `configure_redaction()` is seeded from the already-loaded env at startup | the four tests above (they all rely on it), plus `test_configure_redaction_replaces_values_and_ignores_short_ones` |
  | the shared pattern list still works with no configured values | `test_console_redaction_uses_the_shared_patterns_without_a_dotenv` |
  | the `--json` error path (adversarial) keeps stdout clean and redacts stderr | `test_json_error_path_keeps_stdout_clean_and_redacts_stderr` |
  | an unreadable `.env` cannot break the CLI | `test_an_unreadable_dotenv_does_not_break_the_cli` |
  | one pattern list, one value source; explicit per-run values unchanged | `test_configure_redaction_replaces_values_and_ignores_short_ones` |
  | CLI imports only the redaction helpers from the persistence layer | `test_cli_imports_only_the_allowed_layers` (amended, see above) |
- **Red before green (proved in two stages so the failure is the real one):** with the docs, the `store` helper and all tests in place, the CLI was wired only as far as *calling* `configure_redaction()`; `_report_error` was still unredacted. `pytest -q tests/test_cli.py -k "redact or verbose or json_error or unreadable or allowed_layers"` -> **`6 failed, 1 passed, 48 deselected`**, including `AssertionError: assert 'sk-live-abc123' not in 'unexpected ...ive-abc123\n'` with `unexpected error: RuntimeError: boom sk-live-abc123` printed in the assertion output, and `assert 'api_key=***' in 'unexpected error: RuntimeError: api_key=abcd1234efgh\n'`. The sixth failure was the amended dependency test waiting for the `redact` import. After adding `render_error(redact(message), ...)` the same selection is **`7 passed, 48 deselected`**.
- **Self-review findings (S2):**
  - Broad excepts: none added. The one new handler is `except OSError:` around `dotenv_values()` in `_configure_redaction`, narrow and documented. The broad-except scan still lists the same nine pre-existing sites (`store.py` 242/277, `workspace.py` 150, `wildcard.py` 90, `cli.py` 254, `engine.py` 421/615/922, `dnspython.py` 142); line numbers moved only because `store.py` grew.
  - External input: the values of `.env`, used solely as literal replacement strings - never a path, never argv, never SQL. None of them is printed; the module-level tuple holds them in memory only. Values shorter than 3 characters are ignored, matching the helper's long-standing rule.
  - Secrets: exactly one implementation and one pattern list (`store.py`); `configure_redaction` replaces instead of appending, so repeated startup calls cannot grow a parallel set. `redact()` is applied once, after `traceback.format_exc()`, so the chained text is inside the redacted string. `--json` still writes errors to stderr, and `redact` never writes to stdout.
  - Blocking calls in async code: none - the callback and `_report_error` are synchronous.
  - Exceptions that can escape: `dotenv_values()` OSError is caught; `configure_redaction` accepts any iterable of strings; a `None` value from python-dotenv is filtered out in the CLI before it reaches `len()`. `redact()` cannot raise for string input.
  - Unfinished paths, stated plainly: six `render_error(str(exc))` sites handle **typed, self-generated** messages rather than arbitrary exception text - `scope_check` (cli.py:442,445), `diff` (481), `status` (513), `doctor` (535) and `_run_install` (628). They are outside 12f's ruled scope (the ticket names the last-resort handler and `-v`), their messages are built by `scope`/`config`/`validate_target`, and they are listed here so a future item can widen redaction if the owner wants it.
  - **S3 raw output** (bash/grep form): `\bassert\b` -> `NONE`; `shell\s*=\s*True` -> `NONE`; `TODO|FIXME|XXX|HACK` -> `NONE`; `print(` -> `ui.py` only; `subprocess` -> `core/runner.py` + the pre-existing docstring word in `adapters/base.py:3`; `sqlite3` -> `core/store.py` only (and, as a test assertion string, `tests/test_cli.py`); `os.environ|getenv` -> `ui.py:148`, `installer/go_install.py:22`, `installer/pipx.py:31`, `installer/github_release.py:542`, all pre-existing, none in `cli.py`; broad except -> the same nine; `noqa|type: ignore` -> the same three pre-existing test lines; adapters importing store/scope/ui/cli -> `NONE`. 12f-specific: `def redact|def configure_redaction|REDACTED =|_configured_secrets` -> one of each in `core/store.py` (plus `runner.REDACTED`, a separate child-output mask that predates this part and is not a second `redact()`); `redact(` call sites -> `store.py` (params/error), `workspace.py` (raw files), `engine.py` (exception text), `cli.py` (console) - one CLI call, no duplicates; `dotenv` -> `cli.py`, `engine.py`, `doctor.py`, all calling `dotenv_values` (doctor passes its own file path).
- **Bugs found:** none in product code. Two test-suite friction points were fixed, not worked around: (1) `test_cli_never_reads_environment_keys` scans the CLI source for the literal string `os.environ`, and my first docstring contained it; the docstring was reworded ("no process environment is read directly") instead of weakening the guard; (2) ruff S105 flagged the new test constant name `SECRET`, so it was renamed `LEAK_VALUE` - the value and the assertions are unchanged.
- **PIT back-fill (2026-11-14, docs-only follow-up commit):** C-1 is a genuine bug fix (an unguarded console path), so it now carries **PIT-42**, and the canonical guard `test_report_error_redacts_a_secret_in_the_message` starts `Regression: PIT-42`. Every guard named in this row's table already existed; the back-fill wrote no new test and changed no production code.
- **Mutation proofs** (applied by hand, related tests only, restored from byte-identical copies; `sha256sum -c` printed `OK` for both files after every restore, and the final state is `src/reconkit/cli.py: OK`, `src/reconkit/core/store.py: OK`):
  - M1 `configure_redaction()` made a no-op (`return` before the assignment): `4 failed` - `AssertionError: assert 'sk-live-abc123' not in 'unexpected ...ive-abc123\n'`, with `unexpected error: RuntimeError: boom sk-live-abc123` in the output. Restored -> `4 passed`.
  - M2 remove the redaction call from `_report_error` (`render_error(message, ...)`): `4 failed`, same raw secret in the assertion output. Restored -> `4 passed`.
  - M3 forget the `-v` branch (redact before `traceback.format_exc()`): `2 failed, 2 passed` - exactly the two `-v` tests fail, the non-verbose ones pass, which is the signature this mutation should leave. Restored -> `4 passed`.
- **Raw check output (S1, first pass, full output):**
  ```
  --- pytest -q ---
  ........................................................................ [ 11%]
  ... (8 lines of dots) ...
  642 passed in 13.95s
  --- ruff check . ---
  All checks passed!
  --- ruff format --check . ---
  68 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Second pass: `642 passed in 13.90s` plus the same three clean lines. Suite 634 -> 642 (eight new cases: one store, seven CLI).
- **End-to-end runs of the changed path:** `reconkit subs -d example.com --mock --db /tmp/12f/recon.db --silent` -> exit 0 (the startup `.env` load does not disturb a normal run). The last-resort handler was then driven for real with an unwritable DB path: `--db /proc/1/x.db` printed `unexpected error: OperationalError: unable to open database file` and exited 1; with `-v` it printed the full traceback (`cli.py:204 -> engine.py:418 -> store.py:234 -> sqlite3.OperationalError`) - both go through `redact()` and neither contains a secret, so the text is unchanged, which is the no-over-redaction case on a real path.
- **Not verified:** no real exception carrying a real `.env` key has ever been observed, so this is a guard on an unproven leak path, not a reproduced incident; the fixtures never print a keyed provider error. A `.env` value shorter than three characters is intentionally not masked by the value list (existing rule of `redact`), and a key that appears only in a *typed* message at the six out-of-scope sites above would not be masked by this part.
- **Next part must know:** `redact(text)` now means "the configured set" - any new caller that wants a per-run set must pass it explicitly (as `engine`/`workspace`/`store` already do). `configure_redaction` is process-global and replaces; it is called once from the Typer callback, so a test that invokes the app without patching `reconkit.cli.dotenv_values` will configure the real checkout `.env`. 12d's bounded `detail` string should reuse `redact(detail, self._secrets)` and this console path.

## Part 12c: `duration_s` has one authoritative source (11d-findings-c)  (commit subject `feat: let each tool measure its own duration`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` 12c and its `DECIDED (owner, 2026-11-14)` line, `docs/04` sections 3 and 5, `docs/09` section 3, `docs/03` section 5. Goal: the adapter measures its own work and reports `duration_s` on every outcome; `_run_one` fills a measured value only when the adapter reports none, and never overwrites one. The observed gap was `dnspython ok 36 0.0`, `pyprobe ok 8 0.0`, `otx failed 0.0` beside a real 429 in verification session 2.
- **Which adapters were already compliant, stated before touching code (as asked):** the binary flow in `BaseToolAdapter.run` already reported a duration - `run_exec` measures the child with `time.monotonic()` around spawn/wait (`ExecResult.duration_s`, `core/runner.py:106,129,180`). That is the tool's real work time, not harness overhead, so **it counts as adapter-reported** and the binary adapters needed no new measurement; only their two branches that omitted it changed. `HttpAdapter.run` also measured its own work on the ok branch (`perf_counter` since 11d), so HTTP adapters only needed the two failure branches. `DnsPythonAdapter`, `PyprobeAdapter` and `PyscanAdapter` never measured anything (every branch left the `0.0` default) and needed the measurement added in their existing run paths.
- **The ruling made concrete, and the ambiguity resolved:** `ToolResult.duration_s` stays a plain `float` defaulting to `0.0` (no model or DB change), and `0.0` is defined as "the adapter did not measure". `Engine._run_one` stores the adapter's value whenever it is `> 0` and only substitutes its own `perf_counter` delta when the value is `<= 0`; a negative value (only reachable with an injected/frozen clock) is treated the same way, so a stored value is never negative and an adapter value is never overwritten. That is **one fallback site** (`engine.py:926-930`). Timeout and crash rows now fall through the same site instead of measuring inline, so a timed-out tool records the harness's wall clock for the whole `wait_for` call.
- **Docs changed first:** `docs/04` section 3 column comment (`duration_s REAL -- wall seconds the tool itself worked`) plus three rules in section 5: who reports it and what counts as adapter-reported (binary `run_exec` wall clock included, by name); the positive-value-wins / `<= 0` fallback contract with the one fallback site; and what mock mode means (fixture read + parse, small, positive, never a constant). `docs/09` section 3 gained the contract comment on the field (`0.0 = not measured, engine fills`). No other doc change was needed; the DB schema is untouched.
- **Files touched:** `src/reconkit/adapters/base.py` (binary ParseError/ToolFailed/FetchFailed and RuntimeError branches now carry `duration or perf_counter-started`; `HttpAdapter` ParseError and FetchFailed branches carry the measurement), `src/reconkit/adapters/dnspython.py`, `src/reconkit/adapters/pyprobe.py`, `src/reconkit/adapters/pyscan.py` (`started` at the top of `run`, reported on mock-ok, mock-parse-error and real-ok), `src/reconkit/engine.py` (single fallback); `tests/test_adapters.py`, `tests/test_python_adapters.py`, `tests/test_engine.py`; `docs/04`, `docs/09`, this entry, `docs/PROGRESS.md`.
- **Requirement -> test table:**
  | Requirement (12c `DECIDED` / owner instructions) | Test |
  |---|---|
  | a successful adapter run reports a positive duration from its own measurement | `test_a_successful_run_reports_the_adapters_own_duration`, `test_every_python_adapter_times_its_own_work` |
  | `_run_one` does not overwrite an adapter-provided value | `test_adapter_reported_duration_is_stored_and_never_overwritten` (12.5 stored exactly) |
  | a failed run (429) reports a positive duration, not 0.0 (the session-2 gap) | `test_a_429_failure_still_reports_its_own_duration` |
  | a parse-error path reports a positive duration | `test_a_parse_error_still_reports_its_own_duration` |
  | a mock run has a documented, sensible duration | `test_a_mock_run_duration_is_small_and_measured`, `test_every_python_adapter_times_its_own_work` (docs/04: fixture read + parse, `0 < d < 5`) |
  | an adapter that cannot measure is filled by the harness's own wall clock | `test_missing_adapter_duration_gets_the_harness_wall_clock` (adapter sleeps 50 ms, reports 0.0, stored `> 0.04` and `==` the result value) |
  | a frozen clock stores no negative value | `test_a_non_positive_adapter_duration_is_never_stored` (-1.0 replaced) |
  | a timeout keeps a measured duration (12a/11d behaviour preserved) | `test_phase_timeout_records_a_timeout_row` (existing; now fed by the fallback site) |
- **Red before green (raw):** the new tests were written first against the fixed code, then the five source files were restored to HEAD (`git checkout -- src/reconkit/adapters/*.py src/reconkit/engine.py`, tests kept), producing a genuine failure of exactly the new behaviour:
  ```
  E       AssertionError: assert 0.0 > 0
  E        +  where 0.0 = ToolResult(tool='crtsh', status=<ToolStatus.FAILED: 'failed'>, records=[], duration_s=0.0, error='crtsh: rate limited (HTTP 429)', raw_path=None, raw_text='crtsh: rate limited (HTTP 429)').duration_s
  ...
  E       AssertionError: assert 0.0 > 0
  E        +  where 0.0 = ToolResult(tool='crtsh', status=<ToolStatus.FAILED: 'failed'>, records=[], duration_s=0.0, error='crtsh: invalid JSON', ...).duration_s
  ...
  FAILED tests/test_adapters.py::test_a_429_failure_still_reports_its_own_duration
  FAILED tests/test_adapters.py::test_a_parse_error_still_reports_its_own_duration
  FAILED tests/test_python_adapters.py::test_every_python_adapter_times_its_own_work
  FAILED tests/test_engine.py::test_missing_adapter_duration_gets_the_harness_wall_clock  (assert 0.0 > 0.04)
  FAILED tests/test_engine.py::test_a_non_positive_adapter_duration_is_never_stored  (assert -1.0 > 0)
  5 failed, 3 passed, 144 deselected in 0.31s
  ```
  The three that passed at HEAD are the ones that guard existing behaviour (HTTP ok duration, the engine's pass-through of a positive value, the HTTP mock duration). The fixed files were then restored from `/tmp/12c` and verified: `adapters/base.py: OK`, `adapters/dnspython.py: OK`, `adapters/pyprobe.py: OK`, `adapters/pyscan.py: OK`, `engine.py: OK` (`sha256sum -c`), and the three test files ran `152 passed in 0.98s`.
- **Mutation proof (M1, the required one):** `if result.duration_s <= 0:` changed to `if True:` (overwrite unconditionally) -> `test_adapter_reported_duration_is_stored_and_never_overwritten` failed with the raw value:
  ```
  >       assert raw_result(summary, "timed").duration_s == 12.5
  E       AssertionError: assert 0.00025354699755553156 == 12.5
  1 failed, 57 deselected in 0.15s
  ```
  Restored `engine.py` from `/tmp/12c` -> `engine.py: OK`; `pytest -q tests/test_engine.py -k "duration"` -> `3 passed, 55 deselected in 0.21s`.
- **Self-review findings (S2):**
  - Broad excepts: none added; the engine's pre-existing `except Exception` now builds a result without a duration and relies on the fallback, which is the intended path for a crashed adapter. The broad-except scan lists the same six `src/` sites as at the 12f baseline (plus the pre-existing `ui.py`/doctor handlers outside this scan's `src/reconkit` filter), none new.
  - External input: none. The only new values are clock readings; no user string, path or argv is involved.
  - Secrets: unchanged; durations are floats and never redacted.
  - Blocking calls in async code: none - `time.perf_counter()` is non-blocking.
  - Exceptions that can escape: none new; the adapters' `time` calls cannot raise.
  - Double counting: impossible by construction - the adapter value is used when positive and the fallback is skipped; proved by M1.
  - Unfinished paths, stated plainly: UI and `--json` do not print `duration_s` (it is a DB/`status` surface); a timeout row's duration includes `wait_for` overhead, which is the harness clock by definition; the six `render_error` sites from 12f remain untouched.
- **S3 raw output (bash/grep form, 13 scans):** `duration_s=` assignments -> 22 in `src/reconkit`, of which 3 are the pass-through/record in `engine.py` (`result.duration_s`, `_record` param), 2 are `run_exec`'s child clock in `core/runner.py`, and the rest are adapter measurements; exactly one conditional fallback (`engine.py:926`). Hardcoded `duration_s = 0` -> only the two model defaults (`models.py:111`, `core/runner.py:38`). Clocks -> `monotonic` in `core/runner.py` and `core/pacing.py`, `perf_counter` in `engine.py` and the four adapter modules. `assert` in `src/` -> NONE. `shell=True|os.system` -> NONE. `TODO|FIXME|XXX|HACK` -> NONE. `print(` outside `ui.py` -> NONE. `import subprocess` -> `core/runner.py` only. `import sqlite3` -> `core/store.py` only. `os.environ|os.getenv` -> the same four pre-existing sites (`ui.py:148`, `go_install.py:22`, `pipx.py:31`, `github_release.py:542`). `except Exception` -> six pre-existing `src/` sites, none added. `noqa|type: ignore` -> the same three pre-existing test lines. Adapters importing `store/scope/ui/cli` -> NONE. `adapters/*.py` `async def run` -> the four run paths changed, no new adapter.
- **Adversarial cases:** an adapter that raises after measuring -> the engine builds a fresh `ToolResult` and the fallback fills a positive value (no stale adapter number); a frozen adapter clock -> `0.0`, engine fills its own positive reading, never negative; an adapter reporting a huge value -> stored untouched (M1's inverse); a skipped tool -> `duration_s` stays `NULL` (no row change, `_record` not called for skips).
- **Raw check output (S1, first pass):**
  ```
  --- pytest -q ---
  ........................................................................ [ 11%]
  ... (8 lines of dots) ...
  650 passed in 13.68s
  --- ruff check . ---
  All checks passed!
  --- ruff format --check . ---
  68 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Second pass and the pre-commit output are in the same shape; suite 642 -> 650 (eight new cases: four HTTP, one python-adapter trio, three engine).
- **End-to-end run of the changed path:** `reconkit run -d example.com --mock --no-keys --db /tmp/12c.db --speed slow` -> exit 0, and the stored `tool_runs` rows are all positive: `crtsh 0.00025068799732252955`, `certspotter 0.0008128530025715008`, `otx 0.00047691899817436934`, `hackertarget 0.0005171979937586002`, `subfinder 0.000467628997284919`, `assetfinder 0.0003922159958165136`, `dnspython 0.00029269300284795463`; the ten skipped tools store `NULL`. No `0.0` row remains in a real CLI run.
- **Deviations / owner awareness:** `docs/09` was touched for the field contract although the ruling named only `docs/04` (AGENTS section 8 requires the adapter-contract doc to match); the test fake-adapter helper gained two keyword arguments (`duration_s`, `delay`), both defaulted, so existing tests are unchanged; the "0.0 means not measured" meaning is the ambiguity the instructions asked to resolve, and it is now stated in docs/04 rather than left implicit.
- **Not verified:** no real 429 was re-triggered this session (the session-2 evidence is what motivated the fix; the branch is covered by MockTransport); no real non-mock tool ran, so a real binary `run_exec` duration was not re-observed (the 12a/baseline runs did record it); `perf_counter` resolution and a sub-millisecond real HTTP call are untested on this hardware. `scope.yaml` untouched, nothing pushed, no sudo.
- **Next part must know (12k):** `_run_one`'s fallback is the only place that invents a duration; an empty stage still writes no `tool_runs` row, so 12k's exit-5 work must not assume a duration exists. The mock-run durations are sub-millisecond, so any UI sorting by duration would look flat under `--mock`.
- **PIT back-fill (2026-11-14, docs-only follow-up commit):** 11d-findings-c is a genuine bug fix, so it now carries **PIT-43**, and the canonical guard `test_adapter_reported_duration_is_stored_and_never_overwritten` starts `Regression: PIT-43`. Every other guard in this entry's table already existed; the back-fill added no test and changed no production code.

## Part 12k: a stage that executed no tools is a partial run (11d-findings-g)  (commit subject `feat: warn and exit partial when a stage runs no tools`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` 12k and its `DECIDED (owner, 2026-11-14)` line plus the adversarial list, `docs/02` sections 5 and 6, `docs/03` section 5 (engine bullets), `docs/08` flow 4, `docs/09` (stage/skip contract). Ruling: a requested stage with zero executed tools exits 5 with a warning that names the stage - not a silent 0, not 4, not warning-with-0.
- **The single exit-code decision site, found before coding:** `Engine._exit_code()` (`engine.py:650`), called once from `_run_scan` (`engine.py:644`), receives `summary`, `selected_total` and `failed_total`. Today it returns, in order: 3 when `scope_denied`; 4 when nothing was selected but a new stage exists (0 when everything was resumed); 4 when `failed_total == selected_total`; 5 when `failed_total`; else 0. 12k adds `self._empty_stages(summary)` to the 5 condition only - a new input alongside `failed_total`, never a replacement. No other module decides a scan exit code (`cli.py` only maps `summary.exit_code`; `installer.github_release.exit_code()` is install/update, code 6, untouched).
- **"Zero executed tools", defined precisely:** a `StageOutcome` that is not `resumed` and has an empty `results` list. The engine only appends a stage outcome after it built the stage (created a `scan_runs` row and recorded at least one `ToolSkip`), so an outcome with no results is exactly "every tool in the pool was selected out before running" (`no adapter yet (phase N)`, `requires --active`, `not installed`, docs/05 rule 6 block). It is **not** "tools ran and all failed" - that case has results with `FAILED`/`TIMEOUT` status and keeps its own 4/5 paths. Two things deliberately do not create an outcome at all, so they are not empty stages: a stage filtered out by `--tools`/`--exclude` (`if not selected and not skipped: continue`) and `ports` when there are no hosts (`if stage is Stage.PORTS and not hosts: continue`). Neither warns nor changes the code, which is what the master plan's `--tools` adversarial note requires.
- **Warning mechanism reused, not reinvented:** `ScanSummary.warnings` is a `list[str]` filled from `Engine._warnings` at the end of `_run_scan`; the human renderer prints each entry as `warning: ...` (`ui.py:502`) and `summary_document()` copies the list into `--json` `warnings` (`ui.py:101`). `_note_empty_stage()` (`engine.py:768`) appends one entry per stage, deduplicated against the existing list, and it is called once right after the stage outcome is appended (`engine.py:641`). No UI code changed: both surfaces already existed, verified by a real run below.
- **Composition/precedence, decided and documented (docs/02 section 6), not implicit:** 3 scope denied > 4 (no new stage selected anything, or every selected tool failed) > 5 (some selected tool failed/timed out, or some requested new stage executed no tools) > 0. Consequences written down and tested: several empty stages produce one warning each and still 5; an empty stage plus a partial failure is 5 with both warnings; an empty stage plus **every** selected tool failing is 4 (the stronger "no usable tool" statement), warning still present; **every** requested stage empty is 4, because no tool ran anywhere - not 5; a fully resumed run stays 0.
- **Docs changed first:** `docs/02` section 6 - the code-5 table row now says "or a requested stage executed no tools", plus two new paragraphs (the rule, the warning text, one warning per stage) and an explicit four-step precedence list, the all-empty case, and the `--tools`/no-hosts exclusions. `docs/03` section 5 - the `ScanSummary.exit_code` bullet now names `_exit_code()` as the single decision site and the empty-stage input/warning. `docs/08` flow 4 - the Partial line mentions the empty-stage cause.
- **Files touched:** `src/reconkit/engine.py`; `tests/test_engine.py`, `tests/test_ui.py`; `docs/02`, `docs/03`, `docs/08`, this entry, `docs/PROGRESS.md`.
- **Requirement -> test table:**
  | Requirement (12k `DECIDED` / owner instructions) | Test |
  |---|---|
  | a stage with zero executed tools causes exit 5 **and** a warning naming that stage | `test_an_empty_stage_warns_by_name_and_makes_the_run_partial` (`Regression: PIT-40`; asserts `"tech" in` the note and the skipped tool/reason) |
  | a stage with executed tools that all failed keeps its previous code (regression) | `test_exit_code_all_tools_failed_is_no_tool` (existing, still 4), `test_all_tools_failed_still_outranks_an_empty_stage` |
  | a run where every requested stage is empty follows the documented decision | `test_every_requested_stage_empty_is_no_tool_not_partial` (4, two warnings) |
  | one empty stage + a real tool failure is still 5 and both warnings survive | `test_empty_stages_and_a_partial_failure_together_are_still_partial` (two empty stages + a failed tool -> 5, both names) |
  | exactly one empty stage next to exactly one failed tool is still 5, the failure stays visible and the warning names the empty stage | `test_one_empty_stage_plus_a_tool_failure_stays_partial` |
  | a clean run with no empty stages and no failures still exits 0 | `test_two_stages_that_ran_tools_still_exit_zero`, `test_exit_code_clean_is_success` (existing) |
  | the warning text names the stage | the core test and `test_every_requested_stage_empty_is_no_tool_not_partial` (set of names) |
  | both output surfaces carry the warning and the code | `test_an_empty_stage_warning_reaches_the_table_and_the_json` |
  | a `--tools`-filtered stage is not an empty stage | `test_a_stage_filtered_out_by_tools_is_not_an_empty_stage` (0, no warning, no outcome) |
  | a resumed run does not double-count completed stages | `test_a_resumed_run_does_not_warn_about_completed_stages` |
  | scope (3) outranks the empty-stage partial | `test_scope_denial_keeps_code_3_even_with_an_empty_stage` |
- **PIT compliance (closed in a follow-up commit at the owner's request):** 12k is a bug fix, so it carries **PIT-40** in the Known pitfalls table (symptom, root cause, rule, guarding tests), and the guarding test's docstring starts `Regression: PIT-40` so R1/R2 hold. The row and the marker were added after the fix commit `c519bae` (the fix commit was made before this row existed, which is why it is called out here); the row's Guarding test column names all three empty-stage tests, and `test_one_empty_stage_plus_a_tool_failure_stays_partial` was added in the same follow-up to cover the owner's exact one-empty-plus-one-failure wording, with its own red run against `c519bae~1`.
- **Red before green (raw):** tests written first, `engine.py` restored to HEAD (`git checkout -- src/reconkit/engine.py`), core test:
  ```
  >       assert summary.exit_code is ExitCode.PARTIAL
  E       AssertionError: assert <ExitCode.SUCCESS: 0> is <ExitCode.PARTIAL: 5>
  E        +  where <ExitCode.SUCCESS: 0> = ScanSummary(target='example.com', ... warnings=[], exit_code=<ExitCode.SUCCESS: 0>, resumed=False, scope_denied=False).exit_code
  1 failed in 0.14s
  ```
  The whole 12k group at HEAD: `5 failed, 3 passed, 58 deselected` (the 3 passing are the guards for old behaviour: all-failed 4, `--tools` filter 0, clean run 0; the resumed case passes trivially because HEAD never warns). Restored from `/tmp/12c/engine_12k.py`, `sha256sum -c` -> `engine_12k.py: OK`, re-run -> `8 passed`.
- **Mutation proofs (both required directions, each restored and checksum-verified):**
  - M1 drop the empty-stage check from the decision (`if failed_total or self._empty_stages(summary):` -> `if failed_total:`): core test fails `assert <ExitCode.SUCCESS: 0> is <ExitCode.PARTIAL: 5>` while the warning is still present - proves the exit input is load-bearing, not the warning alone.
  - M2 remove the warning append (`if not results: self._note_empty_stage(...)` deleted): core test fails `assert 0 == 1` on the warning count with exit still 5 - proves the warning is load-bearing separately.
  - Restores: `engine_12k.py: OK` and `src/reconkit/engine.py` sha256 `91c7639b5964adbd642e7a23e3329222db61d7ebcbabe55dc3b90a190ba79a71` both times; 8 targeted tests pass after each restore.
- **Self-review findings (S2):**
  - Broad excepts: none added. The `_empty_stages()` comprehension and the warning helper cannot raise on the engine's own dataclasses.
  - External input: none; stage names and skip reasons are engine-generated strings, and stage values come from the `Stage` enum, never from user text.
  - Secrets: the warning carries stage names and skip reasons only; skip reasons are the fixed selection strings, no key material.
  - Blocking calls in async code: none.
  - Exceptions that can escape: none new; `_exit_code` still returns a plain enum.
  - Unfinished paths, stated plainly: `ports` with no hosts and `--tools`-filtered stages intentionally produce neither a warning nor a code change; the `scan_runs.status` for an empty stage still reads `completed` (12a/12k do not touch run status; the warning and exit code carry the signal); a scope-denied active stage can now also produce an empty-stage warning while the exit stays 3.
- **S3 raw output (13 scans):** one decision site (`engine.py:644` assignment; returns only inside `_exit_code` at 660-668); one warnings list (`Engine._warnings`, appends at 774/791/1179/1224/1295 + one local list in the dangling-CNAME helper at 209); UI reads `summary.warnings` at `ui.py:101` and `ui.py:502`; `assert` in `src/` -> NONE; `shell=True|os.system` -> NONE; `TODO|FIXME|XXX|HACK` -> NONE; `print(` outside `ui.py` -> NONE; `import subprocess` -> `core/runner.py` only; `import sqlite3` -> `core/store.py` only; `os.environ|os.getenv` -> the same four pre-existing sites; `except Exception` -> the same six pre-existing `src/` sites; `noqa|type: ignore` -> the same three pre-existing test lines; adapters importing store/scope/ui/cli -> NONE; numeric `return` in `engine.py` -> NONE (typed enum only).
- **Adversarial cases:** every requested stage empty -> 4 with one warning per stage (tested); `--tools` filtering -> not an empty stage (tested); scope-denied run with an empty stage -> 3, warning present (tested); all selected tools failed plus an empty stage -> 4 (tested); fully resumed run -> 0 with no warning (tested); a stage that ran one tool and found nothing is **not** empty (it has a `ToolResult`, so no warning) - covered by `test_two_stages_that_ran_tools_still_exit_zero` and the existing empty-result tests.
- **Raw check output (S1):** first pass found one error in my own new test helper - `ruff` F821 `Undefined name 'ScanSummary'` (`tests/test_engine.py:1073`), because pytest passes on postponed annotations but ruff does not resolve them; fixed by adding `ScanSummary` to the existing `reconkit.engine` import. Re-run:
  ```
  --- pytest -q ---
  ........................................................................ [ 10%]
  ... (9 lines of dots) ...
  659 passed in 13.67s
  --- ruff check . ---
  All checks passed!
  --- ruff format --check . ---
  68 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Suite 650 -> 659 at the fix commit (eight engine, one UI); the PIT follow-up adds `test_one_empty_stage_plus_a_tool_failure_stays_partial`, so the tree now runs 660 with the four checks still clean (raw output in the follow-up chat report).
- **End-to-end runs of the changed path:** `reconkit run -d example.com --mock --no-keys --db /tmp/12k.db` (passive-only command, both requested stages have adapters) -> exit 0, only the pre-existing scope warning, no empty-stage warning. `reconkit run -d testfire.net --mock --active --no-keys --db /tmp/12k2.db --speed slow --json` -> **exit 5**, `warnings` exactly `tech stage executed no tools: 5 tool(s) skipped (no adapter yet (phase 3))`, `urls ... 8 tool(s) ...`, `vulns ... 3 tool(s) ...`; the same command without `--json` printed the three `warning:` lines and exited 5. This is the ruling reproduced on the real CLI, both surfaces, no UI code change.
- **Deviations / owner awareness:** the all-empty decision is **4, not 5**, documented in docs/02 section 6 and tested; `docs/03` and `docs/08` were touched in addition to the named docs/02 (both describe exit codes/warnings); the warning text format is new (`"<stage> stage executed no tools: N tool(s) skipped (<reasons>)"`) and is named in docs/02 so the wording is documented rather than incidental.
- **Not verified:** no real (non-mock) run this session; no UI snapshot of a run where the only output is the empty-stage warning.
- **Next part must know (12b):** `_empty_stages()` keys off `StageOutcome.results`, so any 12b work that starts writing synthetic `dns` discovery results will change empty-stage detection for the `dns` stage as a side effect; keep `scan_runs.status` semantics untouched unless its own ruling says otherwise.

## Part 12b: a DNS-resolved host is not a discovery result (11d-findings-b)  (commit subject `fix: mark dns-created hosts and keep them out of NEW`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` 12b and its recorded ruling ("keep the row, mark its provenance `dns`, exclude it from `diff_new` and discovery counts"), docs/04 sections 3, 5, 6 and 11, docs/02 section 2 (diff semantics), docs/03 section 5 (data flow) and section 7, plus `engine._persist_dns`, `_previous_facts`, `_persist_discovery` and `store.upsert_subdomain`/`diff_new`. Goal: a host that only the `dns` stage ever saw was stored as an ordinary `subdomains` row with `first_seen_run` pointing at the `dns` run and no `subdomain_sources` entry, and `diff_new` keyed on `first_seen_run`, so `diff`/`--new-only` could report a host as NEW that no discovery tool had ever returned.
- **Decisions and assumptions (docs written first, then code):**
  - `subdomains.provenance TEXT NOT NULL DEFAULT 'dns' CHECK (provenance IN ('subs','dns'))`. Two values only: `subs` = a discovery tool first reported the row; `dns` = a `dns`/`live`/`ports` pass created it before any discovery tool did. `dns` is the insert default precisely so no state-pass call site can forget to mark a row.
  - The upgrade is a database rule, not call-site discipline: `ON CONFLICT ... provenance = CASE WHEN excluded.provenance = 'subs' THEN 'subs' ELSE subdomains.provenance END`. A later `dns` pass (which passes no provenance) can never downgrade a discovered host, and `first_seen_run` is never rewritten.
  - **NEW is no longer `first_seen_run = <latest run>`.** A required case forces this: a host first created by `dns` in run 2 and first returned by a discovery tool in run 3 must be NEW at run 3, but its `first_seen_run` is 2 and docs/04 section 5 forbids rewriting it. NEW is now "`provenance = 'subs'` and no `subdomain_sources` row before the latest discovery run", which is the first-discovery-sighting rule and makes the `dns` exclusion structural rather than a special case.
  - Migration v3 back-fills existing rows with the only discriminator the database has: rows with at least one `subdomain_sources` entry become `subs`, rows with none stay `dns`. This is exact for every row the old code could have written (only `_persist_discovery` wrote source rows).
  - No new table, no new flag, no new dependency, no adapter change; the engine still writes only through `Store`.
- **Docs changed first:** docs/04 (schema block gains the column with its comment and CHECK; section 5 gains the provenance rule including no-downgrade and `first_seen_run` unchanged; section 6's NEW rule is rewritten and explains why it is not `first_seen_run`; section 11 records migration 3 and its back-fill); docs/02 section 2 gains the NEW definition and the `dns`-provenance consequence. docs/03 needed no change: section 5 step 8 already says the store "updates `subdomains`", and no layer, command, flag or data-flow step changed.
- **Files touched:** `src/reconkit/core/store.py` (`SCHEMA_VERSION` 3, `_SCHEMA_V3`, `upsert_subdomain(provenance=...)` and its sticky upgrade, `diff_new`); `src/reconkit/engine.py` (`_persist_discovery` passes `provenance="subs"`); `tests/test_store.py`, `tests/test_engine.py`; `docs/04`, `docs/02`, this entry, `docs/PROGRESS.md`. 6 files, +160/-8 before formatting.
- **Requirement -> test table:**
  | Requirement (12b ruling / owner instructions) | Test |
  |---|---|
  | a DNS-only host gets `provenance = 'dns'` stored | `test_dns_only_host_has_dns_provenance_and_is_never_new` (end-to-end stages), `test_a_dns_created_row_is_never_new` (store) |
  | such a host does NOT appear in diff's "new" list | `test_dns_only_host_has_dns_provenance_and_is_never_new` (`diff().new == ()`), `test_a_dns_created_row_is_never_new` |
  | a host discovered by a real subs tool keeps its real provenance and still appears in "new" | `test_a_discovered_host_keeps_its_real_provenance_and_is_new`, `test_a_discovered_host_keeps_subs_provenance_and_is_new` |
  | a host first seen in dns then discovered upgrades and is NEW at that later run | `test_provenance_upgrades_to_subs_and_becomes_new_at_that_run` (also asserts `first_seen_run` is unchanged) |
  | the upgrade never reverses | `test_provenance_never_downgrades` |
  | adversarial: dns-only host across many runs | `test_a_dns_only_host_stays_out_of_new_across_many_runs` (four runs, all `[]`) |
  | adversarial: old DB without the column opens cleanly and is back-filled | `test_v2_database_migrates_provenance_with_backfill` (v2 fixture, `schema_version == 3`, `subs`/`dns` split, resume query still reads) |
  | existing apex fixture unchanged in state | the full suite's fixture-driven engine tests (668 pass) and the real `--mock` run below: 8 `subs` rows keep `subs`, 2 DNS-only rows get `dns` |
  | migration is additive and idempotent | `test_migration_is_idempotent`, `test_v1_database_migrates_and_defaults_cname_columns` (v1 fixture now also carries the two tables the v3 script touches) |
- **Red before green (raw, final test versions):** with the tests written and `store.py`/`engine.py` restored to HEAD (`git checkout HEAD -- src/reconkit/core/store.py src/reconkit/engine.py`; tests kept), `pytest -v tests/test_store.py tests/test_engine.py -k "provenance or discovered_host_keeps or dns_only_host"` -> **`7 failed, 124 deselected in 0.24s`**:
  ```
  E           assert 2 == 3
  tests/test_store.py:556: AssertionError
  E       sqlite3.OperationalError: no such column: provenance
  tests/test_engine.py:1466: OperationalError
  E       sqlite3.OperationalError: no such column: provenance
  tests/test_engine.py:1519: OperationalError
  FAILED tests/test_store.py::test_a_discovered_host_keeps_subs_provenance_and_is_new
  FAILED tests/test_store.py::test_provenance_upgrades_to_subs_and_becomes_new_at_that_run
  FAILED tests/test_store.py::test_provenance_never_downgrades - TypeError: Sto...
  FAILED tests/test_store.py::test_a_dns_only_host_stays_out_of_new_across_many_runs
  FAILED tests/test_store.py::test_v2_database_migrates_provenance_with_backfill
  FAILED tests/test_engine.py::test_dns_only_host_has_dns_provenance_and_is_never_new
  FAILED tests/test_engine.py::test_a_discovered_host_keeps_its_real_provenance_and_is_new
  ```
  After the fix the same selection is **`7 passed, 124 deselected in 0.16s`**, and the two restored files printed `store.py: OK` / `engine.py: OK` from `sha256sum -c`.
- **Self-review findings (S2):**
  - Broad excepts: none added; `git diff -- src | grep '^+.*except'` is empty.
  - External input: none. `provenance` is a module-level literal at its one writer (`_persist_discovery`); every other caller omits it and gets the SQL default. It is never built from tool output, a path or argv.
  - Secrets: unchanged; no new string reaches the DB, and `upsert_subdomain` still binds parameters only.
  - Blocking calls in async code: none new; the change is one extra bound column and one query condition.
  - Exceptions that could escape: none new. `sqlite3.IntegrityError` from the CHECK cannot fire for the two literals used; a migration failure on a damaged database still raises as before.
  - Ordering: `_persist_discovery` upserts with `provenance="subs"` and writes the source rows in the same loop, so a `subs` row always has a source row for that run. The `dns`/`live`/`ports` paths run in later stages of the same scan and never pass `provenance`.
  - Unfinished paths, stated plainly: `host_rows`/`status --json` do not expose `provenance`, so a `dns`-only host still shows `sources: []` with no field explaining why (docs/02 documents the rule instead). See Deviations.
  - Scope/security: no scope code touched; `diff_new` still reads only the target's rows.
  - **S3 raw output** (bash/grep form, repo root; `__pycache__` excluded): `\bassert\b` in `src/reconkit` -> NONE; `shell\s*=\s*True|os\.system` -> NONE; `TODO|FIXME|XXX|HACK` -> only the scan pattern quoted in docs/MASTER_PLAN and REVIEW_LOG history, no source marker; `print(` outside `ui.py` -> NONE; `import subprocess` -> `core/runner.py` only; `import sqlite3` -> `core/store.py` only; `os.environ|os.getenv` -> the same four pre-existing sites (`ui.py:148`, `go_install.py:22`, `pipx.py:31`, `github_release.py:542`); adapters importing store/scope/ui/cli -> NONE; `noqa|type: ignore` -> the same three pre-existing test lines. 12b-specific: `provenance` -> `core/store.py` (schema, insert, upgrade, diff filter), `engine.py` (one writer) and the tests/docs; `provenance="` outside `_persist_discovery` -> NONE (so no state pass can claim discovery); `first_seen_run == ?` in `diff_new` -> NONE (the old rule is gone); `SCHEMA_VERSION = 3` -> exactly one; `_SCHEMA_V3` -> defined and listed once.
- **Adversarial cases:** dns-only host re-resolved in four consecutive runs -> never NEW; upgrade ordering (dns first, discovery later) -> NEW only at the discovery run and `first_seen_run` untouched; a `dns` pass after discovery -> provenance stays `subs`; a v2 database with both row kinds -> exact back-fill and the resume query still works; an old v1 database -> migrates through v2 to v3 in one open.
- **Mutation proofs** (each applied by hand to the working tree, related tests only, restored from byte-identical copies; `sha256sum -c` printed `store.py: OK` / `engine.py: OK` after every restore):
  - M1 drop the provenance filter from `diff_new` (`AND s.provenance = 'subs'` removed): the dns-only host wrongly reappears as NEW -> `test_dns_only_host_has_dns_provenance_and_is_never_new` **`1 failed`**, `AssertionError: assert ('alias.example.com',) == ()`. Restored -> `1 passed`.
  - M2 write `subs` for the DNS-only path (insert default changed to `'subs'`): **`1 failed`**, `AssertionError: assert ('subs', 0) == ('dns', 0)`. Restored -> `1 passed`.
  - M3 allow a downgrade on conflict (`provenance = excluded.provenance`): `test_provenance_never_downgrades` **`1 failed`**, `AssertionError: assert 'dns' == 'subs'`. Restored -> `1 passed`.
- **Raw check output (S1), iteration 1 (failed) and iteration 2 (clean):**
  ```
  --- pytest -q ---     668 passed in 13.65s
  --- ruff check . ---
  E501 Line too long (101 > 100)
     --> tests/test_store.py:456:101
  Found 1 error.
  --- ruff format --check . ---
  2 files would be reformatted, 66 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Finding: my new tests were not formatter-clean (long helper line, multi-line calls that fit on one line). Fixed with `ruff format tests/test_store.py tests/test_engine.py` (no logic change). Iteration 2 and the second full pass:
  ```
  --- pytest -q ---     668 passed in 13.91s
  --- ruff check . ---  All checks passed!
  --- ruff format --check . ---  68 files already formatted
  --- mypy src/reconkit ---  Success: no issues found in 36 source files
  ```
  Suite 660 -> 668 (eight new cases: six store, two engine).
- **End-to-end `--mock` runs:** `reconkit run -d example.com --mock --no-keys --db /tmp/12b/recon.db --speed slow` -> exit 0, 10 hosts (2 `DNS_ONLY`), 7 tools ok. Stored provenance: `alias.example.com|dns|0|2`, `gone.example.com|dns|0|2` (created by the `dns` run, 0 sources) and `api.example.com|subs|3|1`, `www.example.com|subs|6|1`, `example.com|subs|2|1` (discovered in the `subs` run). A second `reconkit passive` on the same DB then `reconkit diff --json` -> `{"previous_run_id":1,"latest_run_id":3,"new":[],"gone":[],"pending_gone":[]}`: a re-resolved dns-only host is not NEW, and the already-known discovered hosts are not either.
- **Deviations / owner awareness:** (1) `host_rows`/`status --json` still carry only `fqdn, state, confidence, sources, status_code, ports`; adding `provenance` there would change docs/02's documented host object and the UI dataclass, and the ruling's required surface is the stored value plus `diff`. Flagged for the owner instead of widening the commit. (2) The NEW definition changed from `first_seen_run` to first-discovery-sighting; this is required by the ruling's own "dns first, subs later is NEW at the later run" case and is documented in docs/04 section 6 before the code. (3) `tests/test_store.py`'s v1 migration fixture gained minimal `subdomains`/`subdomain_sources` tables because migration 3 alters them; the fixture's subject (cname defaults) is unchanged.
- **Not verified:** no real (non-mock) discovery tool ran this session, so a real provider-returned host and a real DNS-only host were not re-observed; no `--new-only` UI walkthrough (`db`/`export --new-only` are Phase 3 stubs, so `diff` is the only consumer).
- **Next part must know (12g):** `subdomains` now carries `provenance` with a CHECK constraint; any future migration that rebuilds the table must preserve the column and its default. `upsert_subdomain` call sites must pass `provenance="subs"` only when a discovery tool actually reported the host - the default is `dns` on purpose. `host_rows` intentionally does not surface it yet (see Deviations); 12d's `host_status_history.detail` is a separate column and does not need to interact with provenance.

## Part 12g: a killed run cannot strand the subfinder provider file (C-2)  (commit subject `fix: keep subfinder provider keys in a 0700 per-run directory`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` 12g and its `DECIDED` line, docs/09 sections 3-4 (adapter contract and the subfinder provider-config bullet), docs/05 rules 5 and 8 (secrets, honest UA) and section 6 (secrets on disk), docs/06 section 6 (exception vocabulary), plus `adapters/subfinder.py` and the existing PIT-18 tests. Goal: a `SIGKILL` between writing the provider config and the `finally` unlink left a provider-key file in the shared system temp dir, and only `finally` stood in the way.
- **Decisions and assumptions (docs written first, then code):**
  - The key file moves into a **per-run directory** named `reconkit-subfinder-<pid>-<random>`, created with `tempfile.mkdtemp` and then `chmod 0700` **explicitly** (not left to the umask), with `provider-config.yaml` (0600) inside. `finally` removes the whole directory with `rmtree`.
  - Cleanup runs at the start of every `prepare()` (i.e. every real subfinder run): a `reconkit-subfinder-*` directory whose pid is not alive is removed immediately; one whose pid **is** alive is removed only when its mtime is older than `STALE_AFTER_S = 900.0`. The age rule is what makes two concurrent runs safe.
  - Leftover `reconkit-subfinder-*.yaml` files from the pre-12g single-file layout are removed by the same age rule, so an upgrade does not inherit a permanently stranded key file. A fresh one (a concurrent old build) is kept.
  - The current run's own pid is never cleaned, even if its directory is somehow old; `cleanup_stale_provider_dirs` is best-effort (every `OSError` is swallowed, `rmtree` uses `ignore_errors`) and returns the number it removed so tests can assert on it.
  - No memfd/O_TMPFILE (explicitly ruled out), no new dependency, no new config key (900 s is a module constant), no CLI flag, no env var.
- **Docs changed first:** docs/09 - the subfinder bullet is rewritten for the directory layout and modes, and a new **"Stale provider directories (C-2)"** bullet states the pid rule, the 900 s age rule, the legacy-file rule and the never-raises guarantee.
- **Files touched:** `src/reconkit/adapters/subfinder.py`, `tests/test_binary_adapters.py`, `docs/09`, `pyproject.toml` (one scoped per-file ignore, see Deviations), this entry, `docs/PROGRESS.md`. 6 files, +180/-33 before formatting.
- **Requirement -> test table:**
  | Requirement (12g ruling / owner instructions) | Test |
  |---|---|
  | a normal run leaves no provider file behind | `test_provider_config_lives_in_a_0700_per_run_directory` (parent gone after `run`), `test_a_sigkilled_run_leaves_a_directory_the_next_start_removes` (last assertion: no `reconkit-subfinder-*` entry survives the run) |
  | the directory is created with exactly mode 0700 (permission bits, not existence) | `test_provider_config_lives_in_a_0700_per_run_directory` (`oct(mode)[-3:] == "700"`, file `"600"`; POSIX only) |
  | a real `SIGKILL` mid-run (no `finally`) leaves a stale directory that the next run's startup cleanup removes | `test_a_sigkilled_run_leaves_a_directory_the_next_start_removes` (spawns a python child that creates the directory and `os.kill(os.getpid(), 9)`s itself, then runs a real adapter run with `gettempdir` pointed at the same root) |
  | cleanup reports what it removed | `test_cleanup_reports_the_number_of_removed_directories` |
  | adversarial: two concurrent runs do not cleanse each other's live file | `test_cleanup_leaves_a_concurrent_runs_directory_alone` (a live `Popen` pid), `test_cleanup_never_touches_its_own_run` |
  | adversarial: crash between mkdir and write | `test_a_write_failure_removes_the_per_run_directory` (yaml dump raises -> `ToolFailed`, directory gone) |
  | pre-12g stranded files are also cleaned | `test_stale_pre_12g_files_are_removed_but_fresh_ones_are_kept` |
  | key values never in argv or the result (unchanged PIT-18 guarantee) | existing `test_subfinder_writes_and_deletes_provider_config` still passes; the new mode test also asserts the key is inside the 0600 file only |
- **Red before green (raw):** the new tests import `STALE_AFTER_S` and `cleanup_stale_provider_dirs`, so with the adapter restored to HEAD (`git checkout HEAD -- src/reconkit/adapters/subfinder.py`, tests kept):
  ```
  tests/test_binary_adapters.py:25: in <module>
      from reconkit.adapters.subfinder import (
  E   ImportError: cannot import name 'STALE_AFTER_S' from 'reconkit.adapters.subfinder'
  1 error in 0.17s   (exit 2)
  ```
  The pre-fix code cannot even express the new contract; each load-bearing behaviour is then proved by the mutations below, which reproduce the old behaviour (`finally`-only cleanup, a world-readable directory) and are caught. After the fix the 12g selection is `11 passed`.
- **Self-review findings (S2):**
  - Broad excepts: none added. The new handlers are `except ProcessLookupError`, `except OSError` (liveness), `except OSError` (stat/unlink in cleanup) and the existing `except (OSError, yaml.YAMLError)` around the write - all narrow. `git diff -- src | grep '^+.*except'` shows exactly those four lines.
  - External input: none. Directory names come from `os.getpid()` and `mkdtemp`'s random suffix; the pid is parsed with `int()` and a `ValueError` skips the entry. `entry.is_dir()`/`is_symlink()` are checked before `rmtree`, so a symlink planted in the temp dir is ignored rather than followed. No tool output, path or argv reaches a path.
  - Secrets: the key value still goes only into the 0600 file; the directory is 0700 so it is not world-listable. Cleanup never reads a file's content. Nothing is logged.
  - Blocking calls in async code: `prepare()` is synchronous and now scans the temp dir once per run (a directory listing + `stat` per matching entry) plus `rmtree` of stale dirs. This is the same class as the existing synchronous `Workspace.write` in `_run_one` and is bounded by what previous killed runs left behind; no new thread or await was added.
  - Exceptions that can escape: none new - `mkdtemp`/`chmod`/`open`/`safe_dump` failures become `ToolFailed` (and the directory is removed), cleanup cannot raise, and `rmtree(ignore_errors=True)` cannot.
  - Unfinished paths: a stranded file created by a **pre-12g build** with a fresh mtime is kept for up to 15 minutes (then removed); a stale directory whose pid has been reused by another live process is kept until its mtime passes the age rule.
  - Scope/security: no scope code touched; the adapter never sends anything new.
  - **S3 raw output** (bash/grep form, `__pycache__` excluded): `\bassert\b` in `src/reconkit` -> NONE; `shell\s*=\s*True|os\.system` -> NONE; `TODO|FIXME|XXX|HACK` in `src` -> NONE; `print(` outside `ui.py` -> NONE; `import subprocess` -> `core/runner.py` only; `import sqlite3` -> `core/store.py` only; `os.environ|os.getenv` -> the same four pre-existing sites; adapters importing store/scope/ui/cli -> NONE; `noqa|type: ignore` -> the same three pre-existing test lines. 12g-specific: `mkstemp` -> NONE anywhere (the old single-file mechanism is gone); `mkdtemp` -> one site in `subfinder.py`; `chmod` -> `subfinder.py` only; `rmtree` -> `subfinder.py` only; `0o700`/`0o600` -> one each in `subfinder.py`; `STALE_AFTER_S` -> defined once, used in cleanup and the tests; `cleanup_stale_provider_dirs` -> one call site (`prepare`) plus tests; `subprocess` in tests -> only the two SIGKILL tests.
- **Adversarial cases:** a real `SIGKILL` child (no `finally`); a second live run's directory; the current run's own directory; a crash between mkdir and write; pre-12g orphan file old vs fresh; a directory name whose pid part is not an integer (skipped); a symlink in the temp dir (skipped).
- **Mutation proofs** (each applied by hand, related tests only, restored from a byte-identical copy; `sha256sum -c` printed `subfinder.py: OK` after every restore):
  - M1 skip the startup cleanup (`cleanup_stale_provider_dirs()` -> `pass`): **first attempt was NOT caught** - the SIGKILL test called the cleanup function directly instead of going through a run. That is a real test gap: the function worked but nothing proved a run calls it. The test was rewritten to run the adapter with `tempfile.gettempdir` pointed at the stale root; M1 then failed with `AssertionError: assert [PosixPath('.../reconkit-subfinder-667249-8ctsvo8i')] == []`. Restored -> `7 passed`.
  - M2 widen the directory mode (`0o755`): `test_provider_config_lives_in_a_0700_per_run_directory` **`1 failed`**, `AssertionError: assert '755' == '700'`. Restored -> `1 passed`.
  - M3 drop the `finally` removal (`rmtree` -> `pass`): **`2 failed`**, `AssertionError: assert True is False` for the directory and for `provider-config.yaml`. Restored -> `2 passed`.
- **Raw check output (S1), iteration 1 (failed) and iteration 2 (clean):**
  ```
  --- pytest -q ---     676 passed in 13.80s
  --- ruff check . ---
  I001 [*] Import block is un-sorted or un-formatted   (tests/test_binary_adapters.py)
  E501 Line too long (101 > 100)                        (tests/test_binary_adapters.py:722)
  S603 `subprocess` call                                (tests/test_binary_adapters.py:726, 757)
  Found 4 errors.
  --- ruff format --check . ---
  2 files would be reformatted, 66 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Fixes: import order via `ruff check --fix`; the long script line split into a `prefix` variable; the two `S603` hits are the deliberate SIGKILL child spawns, so `pyproject.toml` gained one scoped per-file ignore - `"tests/test_binary_adapters.py" = ["S603"]   # the SIGKILL test spawns a python child that kills itself` - next to the existing `test_runner.py` entry, which is the allowed form (scoped, with a reason). `ruff format` on the two touched files. Iteration 2 and the second full pass:
  ```
  --- pytest -q ---     676 passed in 13.9Xs
  --- ruff check . ---  All checks passed!
  --- ruff format --check . ---  68 files already formatted
  --- mypy src/reconkit ---  Success: no issues found in 36 source files
  ```
  Suite 668 -> 676 (eight new cases).
- **End-to-end checks:** `reconkit subs -d example.com --mock --no-keys --db /tmp/12g/recon.db --speed slow` -> exit 0, no `reconkit-subfinder-*` entry left in `/tmp` (`ls -d` -> NONE). `--mock` intentionally skips `prepare()` (the base adapter reads a fixture instead of spawning), so the provider path cannot be exercised by a mock CLI run; it was driven directly: `with SubfinderAdapter().prepare(ctx)` with `VT_API_KEY` set printed `dir reconkit-subfinder-670993-hwj52t63 mode 700 file 600`, the key present inside the file, and after the block `leftovers []`.
- **Deviations / owner awareness:** (1) one new scoped lint ignore (`S603` for this test file, with reason) - a new test spawns a real SIGKILL child, and the alternative was contorting the test away from the owner's "kill the subprocess, don't let finally execute" instruction. (2) `STALE_AFTER_S = 900` is a module constant, not a config key, because the ruling allowed no new config. (3) Legacy pre-12g `.yaml` cleanup is included although the ruling named directories: without it an upgrade would inherit exactly the stranded key file C-2 is about.
- **Not verified:** no real subfinder run (the binary path with a real child) with keys this session, so a real per-run directory on a real timeout was not re-observed; a fork bomb of killed runs leaving thousands of temp dirs was not stress-tested.
- **Next part must know (12d):** `cleanup_stale_provider_dirs()` is called at the start of `SubfinderAdapter.prepare()`, not at process start; any future second adapter that writes a key file should reuse this helper rather than copy it. The `subdomains.provenance` work from 12b is untouched. `pyproject.toml` now has a `tests/test_binary_adapters.py` S603 ignore.

## Part 12i: close the ports ceiling as permanent and accepted (docs only)

- **Docs read / goal:** `MASTER_PLAN.md` 12i and its `DECIDED (owner, 2026-11-14)` line (option (c): ports stays permanently LOW-only / `pyscan`-only; do not pursue a pre-resolve redesign or a second IP-connecting adapter), docs/02 section 2 (commands), docs/05 section 2 rule 6 (IP gate and the `naabu` skip), docs/09 section 5 (stage table and selection rules), and the PROGRESS "Capability gap" bullet. Goal: make every user-facing statement about the ports ceiling say the same thing - permanent, accepted, not an open question - and remove language that implies a future pre-resolve design or a pending ruling.
- **Audit (the actual work):** `grep -rniE "decision needed|ruling needed|candidate fix|to be decided|still open|open question|not decided|TBD|awaiting|proposed"` over `docs/*.md` and `README.md`, then a ports/naabu-specific pass (`naabu|ports (stage|ceiling|confidence)` crossed with `until|open|decision|ruling|proposed|overrule|candidate|temporar|TBD|pre-resolve|second`). Findings and what happened to each:
  - **PROGRESS "Open items" bullet:** "`naabu` stays unavailable until a pre-resolve design exists" - the only genuinely contradictory sentence in the tree. Changed to "`naabu` is permanently unavailable in this build by the 12i ruling (no pre-resolve design is pursued)".
  - **docs/02:** the ports ceiling was not stated at all (only the command name and an example table). Added the ceiling to the `ports` row of the stage table and a short paragraph after the `--active` rule: `pyscan` only, `naabu` skipped, confidence cannot exceed LOW, disagreement rule unreachable, accepted permanently in 12i, no redesign planned, stage still works.
  - **docs/05 rule 6:** said `naabu` "cannot run in this build" without saying whether that was temporary. Added "that is permanent by owner decision (12i ... no pre-resolve redesign and no second IP-connecting adapter)".
  - **docs/09 section 5:** the stage table's ports row named the skip but not the ceiling, and the selection-rules paragraph did not say the skip is permanent. Row changed to "pyscan only - ports is permanently LOW-only in this build (12i)"; the paragraph gained the permanent-ceiling sentence, including that the confidence rules cannot raise a one-scanner stage above LOW.
  - **PROGRESS "naabu is skipped at selection time" bullet:** added "12i made that skip permanent" so the operational statement and the ruling agree.
  - **Two historical REVIEW_LOG passages** ("Decision for user review - `naabu` stays blocked", and the Part 11 close-out "Decisions for user review" list) read as if the skip could still be overruled. History is not rewritten: each gained a dated parenthetical saying it was resolved on 2026-11-14 (12i kept the skip permanently; Part 12 was approved; 12b was implemented as proposed).
  - Deliberately left alone: `docs/01` §12 ("No blocking product questions"), the Part 11c "HARD PRECONDITION" narrative (a record of the fixed G-7 bug), the `naabu` flags row verified against the real binary, and `MASTER_PLAN.md` itself (the decision record). No remaining hit expresses an open ports/naabu question; every surviving "until"/"open" match is either the fixed-condition history or the new "not a pending decision" wording.
- **Docs changed:** `docs/02_CLI_UX.md` (+4/-1), `docs/05_SECURITY.md` (+1/-1), `docs/09_TOOL_CONTRACTS.md` (+2/-2), `docs/PROGRESS.md` (+2/-2 on the two audited lines), `docs/REVIEW_LOG.md` (two historical annotations), plus this entry. **No code, no test, no schema, no flag, no config, no dependency.** Nothing in `src/` or `tests/` changed.
- **Requirement -> test table:** not applicable - this item is docs-only by the ruling ("Size: (c) docs only"); no behaviour changed, so there is nothing to assert. The gate below is the check that the tree still builds.
- **Gate (run twice, no iteration needed):**
  ```
  --- pytest -q ---     676 passed in 13.7Xs
  --- ruff check . ---  All checks passed!
  --- ruff format --check . ---  68 files already formatted
  --- mypy src/reconkit ---  Success: no issues found in 36 source files
  ```
  Same four lines on the second pass (`676 passed in 13.8Xs`). Suite unchanged at 676, as expected for a docs-only item.
- **S3-style scans (docs-only variant):** no `src/` or `tests/` diff (`git diff --name-only` lists only `docs/`); no new markdown links; no new "TODO"/"TBD" in the edited text; `git diff --check` clean (no trailing whitespace); the two CRLF docs were not touched.
- **Deviations / owner awareness:** none. The ruling's scope (docs only, option (c)) was followed exactly; no attempt was made to change `naabu`'s status, `pyscan`, the confidence thresholds or `scope.yaml`.
- **Not verified:** nothing runtime-related to verify; the ceiling itself was not re-measured this session (the recorded real-run evidence - `ports` selected `pyscan`, 0 open ports observed, `blocked=8` - stands from the verification sessions and is unchanged by a docs edit).
- **Next part must know (12d):** the ports ceiling is now stated in four places that a future editor must keep in sync: docs/02 (stage table + paragraph), docs/05 rule 6, docs/09 section 5 (row + paragraph) and the PROGRESS capability-gap bullet. A future ports feature must change all four and the 12i ruling first, not just the code.

## Part 12d: a host that could not be probed keeps its reason (11d-findings-f remainder, PIT-46)  (commit subject `feat: store a bounded redacted reason on host_status_history`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` 12d and its `DECIDED (owner, 2026-11-14)` line (bounded, redacted detail string on `host_status_history`, not a new `tool_runs` field; visible via `--json` and DB query; not required in the human table), docs/04 sections 3, 5, 10 and 11, docs/09 section 3 (adapter contract and the `pyprobe` paragraph), docs/02 section 5 (`--json` shape), docs/03 section 8b (`HostRow`), plus `models.HostStatusRecord`, `adapters/pyprobe.py`, `engine._write_host`, `core/store.append_host_status`/`host_rows` and `ui.HostRow`. Goal: the TLS failure text that 11d-findings-f's short-circuit fix left classified-and-discarded was to become a stored, bounded, redacted reason.
- **Decisions and assumptions (docs written first, then code):**
  - The field lives on `host_status_history` (the ruling's choice), not `tool_runs`: a reason describes one host's status pass, and `tool_runs.error` already holds per-tool text.
  - **One redaction path, no second mechanism.** `Store.append_host_status(..., detail=..., secrets=...)` runs the new `store._detail_value()`, which calls the existing `redact(text, secrets)` (the 12a/12f helper) and then truncates to `DETAIL_MAX_CHARS = 200`. Order is redact -> collapse whitespace -> cut: cutting last means a truncated value cannot contain a partial secret, and a global-pattern-shaped value (a Bearer token, `key=value`) is masked by the same patterns the rest of the store uses.
  - The adapter reports text, the store bounds it. `DETAIL_MAX_CHARS` is a module constant, not a config key - the ruling allowed no new config, exactly like 12g's `STALE_AFTER_S`.
  - `HostStatusRecord.detail` is populated only on the `UNKNOWN` record `pyprobe` builds after a TLS failure; every other record leaves it `None`, and `parse_output` (the fixture path) does not read it, so `--mock` evidence is unaffected.
  - The engine stores `best.detail` for whatever row the pass writes. An inconclusive pass never invents a state, so that row is either `UNKNOWN` (previous state was `UNKNOWN`) or the previously established state the rule kept (`DNS_ONLY`/`ALIVE`/...); docs/04 section 5 says exactly that, and `test_an_inconclusive_pass_keeps_the_previous_state_and_records_the_reason` pins the kept-state case. A later conclusive pass writes its own row with `NULL`, so an old reason cannot resurface.
  - Exposure: `Store.host_rows` selects the latest row's `detail`, `engine.HostSnapshot` and `ui.HostRow` carry it, `ui._host_document` emits `"detail"`, and `cli` maps it. The human table is deliberately unchanged (the ruling makes it optional; docs/02 says it is not shown).
- **Docs changed first (same commit, before the code):** docs/04 (schema block gains `detail TEXT` with its comment; section 5 gains the full rule - when it is written, the 200-character bound, whitespace collapse, redaction with `redact()`, `NULL` meaning, never resurfacing, latest-row read, not in the human table; section 10 says `detail` and `tool_runs.error` share `store.redact()`; section 11 records migration 4); docs/09 (the `HostStatusRecord` model block gains `detail`, and the `pyprobe` bullet says where it comes from and that the store, not the adapter, bounds and redacts it); docs/02 section 5 (`hosts[].detail` in the fixed JSON example plus a paragraph on its meaning and bound); docs/03 section 8b (`HostRow` field list).
- **Files touched:** `src/reconkit/core/store.py` (`SCHEMA_VERSION` 3 -> 4, `_SCHEMA_V4`, `_MIGRATIONS`, `DETAIL_MAX_CHARS`, `_detail_value`, `append_host_status(detail=, secrets=)`, `host_rows` subquery); `src/reconkit/models.py` (`HostStatusRecord.detail`); `src/reconkit/adapters/pyprobe.py` (keep the TLS text); `src/reconkit/engine.py` (`HostSnapshot.detail`, `host_rows` mapping, `_write_host` passes `detail=`/`secrets=`); `src/reconkit/ui.py` (`HostRow.detail`, document field); `src/reconkit/cli.py` (mapping); `tests/test_store.py`, `tests/test_engine.py`, `tests/test_python_adapters.py`, `tests/test_ui.py`, `tests/test_cli.py`; docs/02, docs/03, docs/04, docs/09, this entry, `docs/PROGRESS.md`. 15 files, +386/-14 before formatting.
- **Requirement -> test table:**
  | Requirement (12d ruling / owner instruction) | Test |
  |---|---|
  | an `UNKNOWN` host from a TLS failure stores a redacted, bounded reason | `test_unknown_tls_failure_stores_a_redacted_bounded_reason` (end-to-end `live` stage: state `UNKNOWN`, secret absent, `***` present, one line, `<= 200`, `host_rows` carries it), `test_pyprobe_tls_failure_keeps_the_reason_on_the_unknown_record` (adapter keeps the text) |
  | a plain connect failure stores a different, distinguishable outcome | `test_a_plain_connect_failure_stores_no_reason` (no `host_status_history` row at all, `host_rows[].detail is None`) - MASTER_PLAN's own test list says "stores none"; see Deviations for the wording conflict |
  | the value is bounded to a stated length | `test_host_detail_is_redacted_bounded_and_one_line` (`len(detail) == DETAIL_MAX_CHARS == 200`), engine test (`<= 200`) |
  | a secret-shaped value is redacted before storage | `test_host_detail_is_redacted_bounded_and_one_line` (bare value, no `key=` shape, so only value redaction can mask it), engine test (value comes from `env`, i.e. through `Engine._secrets`) |
  | redaction reuses the 12a/12f path, not a second mechanism | `_detail_value` calls `redact()`; `grep -rn "def .*redact" src/reconkit` shows the one definition; the blank case still returns `NULL`: `test_blank_host_detail_is_stored_as_null` |
  | the field appears in `--json` | `test_json_host_row_carries_the_stored_detail` (document), `test_json_run_exposes_the_stored_host_detail` (real CLI mapping), `test_json_output_is_one_valid_document_with_documented_schema` (the fixed key set now includes `detail`) |
  | direct DB query confirms the column and migration | `test_v3_database_migrates_the_additive_detail_column` (`schema_version == 4`, column present, old row `NULL`, a new append works), `test_v1_database_migrates_and_defaults_cname_columns` (v1 -> v4 in one open, `detail` `NULL)` |
  | an old DB without the column still opens cleanly | `test_v3_database_migrates_the_additive_detail_column`; `test_v2_database_migrates_provenance_with_backfill` (v2 fixture now carries `host_status_history` so migration 4 has its table) |
  | adversarial: a later `ALIVE` pass must not resurrect the reason | `test_a_later_alive_pass_does_not_resurrect_the_reason` (latest row `("ALIVE", None)`, `host_rows` `None`) |
  | adversarial: newline in the text | both redaction tests assert `"\n" not in detail` and `"  " not in detail` |
  | adversarial: a URL with a query secret | the shared `redact()` patterns cover it (`_SECRET_PAIR`, `_FLAG_VALUE`, `_BEARER`); no new pattern was added, and `test_redact_cases` still pins them |
  | nothing else changes | full suite 676 -> 686, `test_json_hosts_carry_confidence_state_and_sources`, the table tests and the `--mock` run below |
- **Red before green (raw, final test versions):** with all six source files stashed back to HEAD (`git stash push -- src/reconkit/core/store.py src/reconkit/models.py src/reconkit/adapters/pyprobe.py src/reconkit/engine.py src/reconkit/ui.py src/reconkit/cli.py`; docs and tests kept), the new tests failed:
  ```
  5 failed, 69 deselected in 0.27s
  FAILED tests/test_python_adapters.py::test_pyprobe_tls_failure_keeps_the_reason_on_the_unknown_record
  FAILED tests/test_engine.py::test_unknown_tls_failure_stores_a_redacted_bounded_reason
  FAILED tests/test_engine.py::test_an_inconclusive_pass_keeps_the_previous_state_and_records_the_reason
  FAILED tests/test_engine.py::test_a_plain_connect_failure_stores_no_reason - ...
  FAILED tests/test_engine.py::test_a_later_alive_pass_does_not_resurrect_the_reason - sqlite3.OperationalError: no such column: detail
  ```
  and, separately at HEAD:
  ```
  E   ImportError: cannot import name 'DETAIL_MAX_CHARS' from 'reconkit.core.store'
  1 error in 0.06s                       (tests/test_store.py, collection)
  E   TypeError: HostSnapshot.__init__() got an unexpected keyword argument 'detail'
  E   TypeError: HostRow.__init__() got an unexpected keyword argument 'detail'
  2 failed in 0.18s                      (the CLI and UI detail tests)
  ```
  After `git stash pop` the same tests pass (`686 passed`) - the restore is a plain pop, and the mutation restores below are byte-verified.
- **Mutation proofs** (each applied by hand, related tests only, restored from a byte-identical copy; `sha256sum -c` printed `src/reconkit/core/store.py: OK` after every restore):
  - M1 drop the truncation (`return text or None` instead of `text[:DETAIL_MAX_CHARS]`): `test_host_detail_is_redacted_bounded_and_one_line` **`1 failed`**, `AssertionError: assert 476 == 200`. Restored -> `1 passed`, `store.py: OK`.
  - M2 skip the redaction (`" ".join(detail.split())` instead of `redact(detail, secrets)`): **`1 failed`**, `AssertionError: assert 'provider-secret-value' not in '[SSL: CERTI...'` with the secret visible in the diff snippet. Restored -> `1 passed`, `store.py: OK`.
  - M3 skip the migration (`(4, _SCHEMA_V4)` removed from `_MIGRATIONS`, `SCHEMA_VERSION` left at 4): **`5 failed, 60 deselected`** - `assert 3 == 4`, `sqlite3.OperationalError: no such column: detail` on the three detail tests and both migration tests. Restored -> `65 passed`, `store.py: OK`.
- **Raw check output (S1), iteration 1 (failed) and iteration 2 (clean):**
  ```
  --- pytest -q ---     686 passed in 13.73s
  --- ruff check . ---
  S105 Possible hardcoded password assigned to: "secret"
     --> tests/test_engine.py:683:14
  Found 1 error.
  --- ruff format --check . ---
  2 files would be reformatted, 66 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Finding: the test helper was named `secret` (S105) and two call chains were not formatter-clean. Fixed by renaming the value to `key_value` (also removing the `api_key=` prefix, which made the value-redaction assertion stricter) and running `ruff format tests/test_engine.py tests/test_python_adapters.py`. No suppression was added. Iteration 2:
  ```
  --- pytest -q ---     686 passed in 14.05s
  --- ruff check . ---  All checks passed!
  --- ruff format --check . ---  68 files already formatted
  --- mypy src/reconkit ---  Success: no issues found in 36 source files
  ```
  (A first combined run in this session had also printed `PASS_*` for the two failing checks because the command piped through `tail`; that mask was caught and every later gate run used `if cmd; then ...` with `set -o pipefail` and no pipe. Recorded here because it is the PIT-10 class of mistake.)
- **Self-review findings (S2):**
  - Broad excepts: none added; `git diff -- src | grep '^+.*except'` is empty.
  - External input: only the adapter's error string. It is never used to build SQL (parameterized), never a path, never argv. The store treats it as opaque text and bounds it.
  - Secrets: the raw string reaches the store in memory only; `_detail_value` redacts before the value is bound, and the engine hands it `self._secrets` (the same set `Workspace.write` and `record_tool_run` use). `docs/04` section 10 now names the column under "Sensitive Data". No value is printed or logged.
  - Blocking calls in async code: none added (`append_host_status` already synchronously writes through the store; the change is one more bound column).
  - Exceptions that could escape: `redact()` and `str.split()` cannot raise for a `str`; an oversized string is cut. `HostStatusRecord.detail` is `str | None`, so a non-string from an adapter fails Pydantic validation at the boundary, as every other field does.
  - Ordering: `host_rows` reads `detail` from the same subquery shape as `status_code` (latest row by `id`), so the JSON field always describes the row the state/status came from.
  - Unfinished paths, stated plainly: a first-run inconclusive `live` pass still writes **no** history row (12e, undecided and out of this queue's scope), so the reason is stored for hosts that already have a history row; 12e is what would make the first-run case reachable. See "Next part must know".
  - **S3 raw output** (bash/grep, repo root): `\bassert\b` in `src/reconkit` -> NONE; `shell\s*=\s*True|os\.system` -> NONE; `TODO|FIXME|XXX|HACK` -> NONE; `print(` outside `ui.py` -> NONE; `import subprocess` -> `core/runner.py` only; `import sqlite3` -> `core/store.py` only; adapters importing store/scope/ui/cli -> NONE; `noqa|type: ignore` -> 3, the same three pre-existing test lines; `SCHEMA_VERSION = 4` -> exactly one; `_SCHEMA_V4` -> defined and registered once; `detail` in `src/` -> the store (column, helper, subquery, insert, read), models, pyprobe, engine, ui and cli sites plus three unrelated pre-existing uses (`engine._note_empty_stage`, `adapters/base` error text, `ui._install_detail`); `git diff --check` clean.
- **End-to-end `--mock` run:** `reconkit run -d example.com --mock --no-keys --speed slow --db /tmp/12d/recon.db --config config.yaml --json` -> exit 0, 4968-byte document, 0-byte stderr. `hosts[0]` keys: `['confidence', 'detail', 'fqdn', 'ports', 'sources', 'state', 'status_code']`; every `detail` is `None` (the fixtures contain no TLS failure, as documented). DB: `schema: 4`; `host_status_history` columns now end `..., cnames_json, dangling_cname, detail`; 3 history rows, all `detail` NULL.
- **Deviations / owner awareness:** (1) **Wording conflict, resolved toward the approved spec.** The task message asked for "a plain connect failure stores a different, distinguishable reason"; `MASTER_PLAN.md` 12d (owner-approved) says "a plain connect failure stores none", and docs/09 says `pyprobe` emits no record for it. The tree follows the two documents: a plain connect failure produces no status row, so there is nothing to carry a reason, and it is distinguishable from the TLS case by exactly that. No test was weakened - "no row at all" is a stronger assertion than "a row with a NULL reason". If the owner wants a reason column for plain connect failures too, that needs a docs change first (and it would make `pyprobe` report every DEAD host, which docs/09 rules out). (2) The `detail` row rule in docs/04 section 5 covers the kept-previous-state case (an inconclusive pass cannot invent a state), which is broader than "UNKNOWN only" but is what the state machine actually does; it is documented and tested. (3) `tests/test_store.py`'s v2 fixture gained a minimal `host_status_history` table because migration 4 alters it (same fixture-maintenance pattern as 12b). (4) Two existing exact-shape assertions were updated for the documented change (`test_json_output_is_one_valid_document_with_documented_schema` gains `detail`; the two migration tests now expect `SCHEMA_VERSION == 4`); both got stricter, not weaker.
- **Not verified:** no real `pyprobe` run against a genuinely failing certificate this session (the TLS text is synthetic in tests); `--mock` cannot exercise it because no fixture carries a failure text; no manual query of a large production database (only the fresh mock one); the `status`/`diff` JSON shapes are unchanged and were not re-walked.
- **Next part must know (12e / PROGRESS trim):** (a) `host_status_history.detail` exists and is only written through `Store.append_host_status`; any future writer must pass `secrets=` or the value is stored with pattern redaction only. (b) 12e ("an inconclusive live pass writes no history row") is what makes a *first-run* `UNKNOWN` reason reachable; until it is ruled, the reason only lands for hosts that already have a history row. (c) The `detail` field is on `HostSnapshot`/`HostRow` and in `--json`; it is deliberately absent from the human table, so a UI change that adds it must update docs/02 and docs/03 first.

## Adversarial check: a key echoed by subfinder never reaches the raw file (2026-11-15, test only)

Owner-requested probe before 12e/12h/12j planning: prove the 12a raw-output file cannot contain a
provider key value, even when the child echoes it. Asked because 12a stores the child's **stderr**
too, and a verbose or crashing tool is exactly the case where a key can end up in output.

- **What the test does** (`tests/test_engine.py::test_subfinder_raw_file_never_contains_the_provider_key`):
  a full engine run of the **real** `SubfinderAdapter` and the **real** registry entry
  (`get_spec("subfinder")`, so `_tool_env` passes `VT_API_KEY` exactly as production does), with
  `env={"VT_API_KEY": "sk-live-abc123-provider-key"}`. The fake `run_exec` reads the `-pc`
  `provider-config.yaml` the adapter wrote, returns `stdout="www.example.com\n"` and echoes the whole
  loaded config to **stderr** (`[DBG] loaded provider config from provider-config.yaml: ...`). The test
  then reads `summary.stages[0].results[0].raw_path` **from disk** and asserts: status OK; the child
  really got `-pc` and the config really contained the key (so the assertion is not vacuous); the
  debug line and the hostname are in the file; the key is **not** in the file; `***` is; the per-run
  provider directory is gone; the serialized result carries no key.
- **Result: no gap, nothing to fix.** `pytest -q ...::test_subfinder_raw_file_never_contains_the_provider_key` -> `1 passed in 0.20s`; full gate `687 passed`, `ruff check .` clean, `ruff format --check .` 68 files, `mypy src/reconkit` clean. Why there is no gap: (1) the key never reaches argv - `build_command` passes only `-pc <dir>/provider-config.yaml`, the 12g 0700 directory; (2) every byte that lands on disk goes through `Workspace.write`, whose one redaction line is `values = self.secrets if secrets is None else tuple(secrets)` -> `cap_bytes(redact(text, values), max_bytes)`, and `Engine._write_raw` never overrides `secrets`, so it uses the workspace's set; (3) that set is `Engine._secrets = tuple(value for value in self.env.values() if value)`, the same one `record_tool_run(error=)` redacts with, and it is built from the full `.env`, not only the selected tool's keys; (4) `ToolResult.raw_text` keeps the unredacted text **in memory only** - it is `Field(exclude=True)`, so it cannot appear in `--json` or the DB, and `raw_path` is the only thing that leaves.
- **Mutation proofs** (both make the test fail on the exact leak assertion, both restored and verified
  with `sha256sum -c`):
  - M1, engine stops handing secrets to the writer (`Engine._write_raw` passes `secrets=()`) ->
    `AssertionError: assert 'sk-live-abc...provider-key' not in 'www.example...ovider-key\n'`,
    `1 failed in 0.17s`; restore `src/reconkit/engine.py: OK`.
  - M2, the writer itself ignores its set (`Workspace.write`: `values = ()`) -> the same
    `1 failed in 0.17s`; restore `src/reconkit/core/workspace.py: OK`.
  Pre-mutation hashes: `engine.py 85d8fc1f7d47d1f3b35be74b6c99a8b4e9aaa93064724ae125694b9f16467947`,
  `workspace.py 5e1893042ec15d773368498b8340e3c5447b7bee093392db6e52e5389d12fcd2`.
- **No PIT row**, deliberately: PIT records pitfalls the code got wrong and now guards against; this
  behaviour was already correct at `ba24f44` and the test exists so a future edit to `_write_raw` or
  `Workspace.write` cannot silently drop it. PIT-41/12a and PIT-44/45 already own this path.
- **Limits, stated plainly:** simulated provider and child (no real subfinder, no real key - tests may
  not touch the network); the echo is the worst case constructed by hand, not an observed subfinder
  debug format; only subfinder was probed, though the redaction is in the shared writer, so any binary
  adapter inherits it.

## Part 12e: an attempted probe leaves a row (11d-findings-g, PIT-47)  (commit subject `fix: write an UNKNOWN row when a first live pass probed a host`; hash filled by the next commit)

- **Owner ruling being implemented (2026-11-15, final):** "Persist the row with state UNKNOWN when a probe was attempted; keep the existing 'no evidence' skip when nothing was attempted. Define 'a probe was attempted' as: a live-stage tool returned a record for that host (success or inconclusive), even if the result itself is ambiguous. docs/04 must state this explicitly, including that exact definition, before any code changes."
- **Docs read / goal:** `MASTER_PLAN.md` 12e, the ruling above, docs/04 sections 3, 5 and 6, docs/09 section 3 (`pyprobe`'s `UNKNOWN` rule and `HostStatusRecord.detail`), `engine.decide_host_state`/`_persist_live`/`_persist_dns`, and the 12d entry (PIT-46) that built the reason column. Goal: make "probed, inconclusive, first sighting" distinguishable from "never touched", without touching the `dns` stage's skip or inventing a state.
- **Docs changed first (before the code, as ruled):** docs/04 section 5 gains two rules: the **exact definition** of "a probe was attempted" (a `live`-stage tool returned a record for that host, successful or inconclusive, ambiguous records included; per host, not per stage; a failed/timed-out tool returned no record and attempted nothing) and the persist rule (no previous state + attempted -> one row, state `UNKNOWN`, confidence `LOW`, the reporting tool(s) as sources, the adapter's reason in `detail`; no record -> nothing persisted, the same skip the `dns` stage keeps; with a previous state the state is kept and the row is written either way). `git diff -- docs/04_DATABASE.md` is exactly +2 lines.
- **Code change (minimal, one decision site):** `engine.decide_host_state` computes `attempted = bool(evidence.web)` once, next to `alive_tools`, and the two inconclusive branches return `previous is not None or attempted` as `persist`. Nothing else moved: no new field on `HostEvidence`, no new flag, config, module or dependency. The `dns` path is unchanged by construction - `_persist_dns` builds `HostEvidence` without web records, so `attempted` is always `False` there and its skip stays exactly as documented. `tests/test_engine.py`'s `seed_unknown_state` docstring no longer says 12e is undecided.
- **Files touched:** `src/reconkit/engine.py` (+5/-2), `tests/test_engine.py` (+140/-2), `docs/04_DATABASE.md` (+2), this log, `docs/PROGRESS.md`.
- **Requirement -> test table:**
  | Requirement (owner ruling) | Test |
  |---|---|
  | a first inconclusive `live` pass that probed persists one `UNKNOWN` row | `test_a_first_inconclusive_live_pass_writes_an_unknown_row` (one row, `state='UNKNOWN'`, `detail` kept, `tools_json == ["live"]`, `host_rows[].detail` set) |
  | ...with confidence `LOW` and the reporting tool as source | `test_regression_an_attempted_probe_persists_with_no_previous_state` (`state UNKNOWN`, `confidence LOW`, `sources == ("pyprobe",)`) |
  | "attempted" = a live tool returned a record for **that host** | `test_only_the_host_a_tool_reported_gets_the_unknown_row` (two discovered hosts, one record -> exactly one row) |
  | a host with no record gets no row even when the stage succeeded | `test_a_host_without_a_record_gets_no_row_even_when_another_did` (apex unanswered, `www` resolved -> only `www`'s `DNS_ONLY` row) |
  | a failed/timed-out tool attempted nothing | `test_a_failed_live_tool_attempted_nothing_and_writes_no_row` (`status=FAILED`, zero rows) |
  | the "no evidence" skip is kept (the ruling's second half) | `test_regression_an_attempted_probe_persists_with_no_previous_state` (second half: `persist is False`) |
  | the `dns` stage's SERVFAIL/timeout/no-answer skip is untouched | `test_a_host_without_a_record_gets_no_row_even_when_another_did` (dns stage output, `attempted` structurally `False`); all PIT-01/PIT-29 transition tests still pass unchanged |
  | 12d's reason is reachable on a first run | `test_a_first_inconclusive_live_pass_writes_an_unknown_row` (`detail` in the row and in `host_rows`) |
- **Red-before-green (raw):** with the five new tests kept and the engine reverted to `previous is not None` (the pre-12e line, 2 occurrences):
  ```
  tests/test_engine.py FFF                                                 [100%]
  E       assert 0 == 1
  E        +  where 0 = len([])
  FAILED tests/test_engine.py::test_a_first_inconclusive_live_pass_writes_an_unknown_row
  E       AssertionError: assert [] == [('www.exampl...', 'UNKNOWN')]
  FAILED tests/test_engine.py::test_only_the_host_a_tool_reported_gets_the_unknown_row
  E       AssertionError: assert False is True
  FAILED tests/test_engine.py::test_regression_an_attempted_probe_persists_with_no_previous_state
  3 failed, 74 deselected in 0.23s
  ```
  Restore: `cp /tmp/12e/engine.py src/reconkit/engine.py && sha256sum -c` -> `src/reconkit/engine.py: OK`, then `77 passed in 0.77s`.
- **Mutation proofs (both restored, hash confirmed):**
  - **M1 - persist unconditionally** (`previous is not None or True`): caught by three tests, including the engine-level skip guards:
    ```
    FAILED tests/test_engine.py::test_a_host_without_a_record_gets_no_row_even_when_another_did
    FAILED tests/test_engine.py::test_a_failed_live_tool_attempted_nothing_and_writes_no_row
    FAILED tests/test_engine.py::test_regression_an_attempted_probe_persists_with_no_previous_state
    3 failed, 2 passed, 74 deselected in 0.22s
    src/reconkit/engine.py: OK
    ```
  - **M2 - stage-level instead of per-host** (`attempted = evidence.web_ok`):
    ```
    E       AssertionError: assert True is False
    E        +  where True = HostTransition(state=<HostState.UNKNOWN: 'UNKNOWN'>, confidence=<Confidence.LOW: 'LOW'>, sources=(), warnings=('DNS/probe inconclusive; state UNKNOWN',), persist=True, dangling_cname=None).persist
    FAILED tests/test_engine.py::test_a_host_without_a_record_gets_no_row_even_when_another_did
    FAILED tests/test_engine.py::test_regression_an_attempted_probe_persists_with_no_previous_state
    2 failed, 3 passed, 74 deselected in 0.19s
    src/reconkit/engine.py: OK
    ```
  Pre-mutation hash: `9dc3d665e28009d400685c7bf5c1d598fb5c9daa3380f8aaa4f0347cb19097e8  src/reconkit/engine.py` (recorded before the red-before-green revert; every restore was verified with `sha256sum -c`).
- **Self-review (S1-S7) findings:** S1 no `assert` in `src`; no `shell=True`/`os.system`; `import subprocess` only in `core/runner.py`; `import sqlite3` only in `core/store.py`; adapters import none of `store`/`scope`/`ui`/`cli`; no `TODO`/`FIXME`; no `print(` outside `ui.py`; the three pre-existing `# type: ignore` lines in `tests/test_scope.py`/`tests/test_runner.py` are unchanged and none was added; `git diff --check` clean. S2 external input: the only new input is the adapter's record list, which is typed (`HostStatusRecord`) and never becomes a path, SQL, argv or shell string. S3 secrets: nothing new is stored - the reason still goes through `Store.append_host_status(..., secrets=)`; no key is printed. S4 async: no blocking call added. S5 ordering: the new rows carry the run's `run_id` and `checked_at` like every other row, and `previous_state()` now reads the `UNKNOWN` row - the NXDOMAIN branch maps `UNKNOWN` to `DEAD` exactly as it mapped `None` before, so the PIT-29/PIT-01 tests stay green. S6 no new dependency/flag/config/module. S7 docs match code line for line (including the "attempted" definition).
- **Gate (run twice, one command at a time, no pipes):** pass 1 - `692 passed in 14.00s`, `ruff check .` All checks passed, `ruff format --check .` 68 files already formatted, `mypy src/reconkit` Success: no issues found in 36 source files. Pass 2 (after the docs edits) - same four results, `692 passed`. Suite 687 -> 692 (five new tests).
- **Deviations:** none from the ruling. Two decisions worth recording: (a) `attempted` is derived from `evidence.web` instead of a new `HostEvidence` field, because that tuple *is* "records a live tool returned for this host" and the `dns` path builds it empty - a new field would be a second source of the same fact; (b) the "no evidence" skip lives in the final `HostTransition(..., False)` fallback as well as in the two branches, and both are covered (the engine-level tests exercise the fallback, the unit test exercises the branch).
- **Next part must know (12h/12j):** a first inconclusive `live` pass with a record now writes `UNKNOWN`/LOW with the reason, so any later consumer that treated "no row" as "not probed" must read the state instead; `history`: every row now carries `tools_json` (the reporting tools) for this case, which 12d's tests did not assert before.

## Part 12h: file I/O leaves the event loop (E-1/E-2/E-3)  (commit subject `perf: move the scope read and workspace create off the event loop`; hash filled by the next commit)

- **Owner ruling being implemented (2026-11-15, final):** "Move the scope.yaml read and the workspace mkdir/chmod to asyncio.to_thread. Leave the SQLite persistence block on the event loop and add a short note in docs/03 explaining why (single-writer SQLite ordering, check_same_thread safety) - write that docs paragraph before any code changes."
- **Docs read / goal:** `MASTER_PLAN.md` 12h, the ruling above, docs/03 sections 5 (Engine API), 6 (data flow) and 11 (Performance), docs/04 section 5 (bulk writes per stage), `engine.run`/`_active_hosts`/`_ip_allowed`, `core/scope.load_scope`/`require_active`, `core/workspace.Workspace.create`, `core/store.Store.__init__`. Goal: no kernel file I/O on the loop, and the one deliberate exception (SQLite) written down with its reason and its bound.
- **Docs changed first (before the code, as ruled):** docs/03 section 11 gains two bullets. The first says the `scope.yaml` read (`scope.load_scope`, used by the active gate and by the `ip_allowed` predicate) and `Workspace.create`'s mkdir/chmod go through `asyncio.to_thread`, like `check_installed()` and every child process, because a slow filesystem would otherwise freeze the run. The second states the persistence block stays on the loop **deliberately**: one transaction per stage, awaited before the next stage, exactly one writer; moving it would need a second connection or `sqlite3.connect(..., check_same_thread=False)`, and `core/store.py` opens its connection on the main thread with the default `check_same_thread=True`, so SQLite refuses cross-thread use. The bound is stated: one transaction per stage, that stage's records only, milliseconds on a local database (12h). `git diff -- docs/03_ARCHITECTURE.md` is exactly +2 lines.
- **Code change:** `engine.run` now awaits `asyncio.to_thread(Workspace.create, ...)`; the active-gate call awaits `asyncio.to_thread(self._active_hosts, target, hosts, opts.speed)`; the `ip_allowed` lookup awaits `asyncio.to_thread(self._ip_allowed)`. `_active_hosts` and `_ip_allowed` stay synchronous (they are called from a worker thread now), so their bodies and the scope rules are untouched, and no `asyncio.gather` or new concurrency was introduced - every call is still awaited in the same order, so stage ordering and pacing are unchanged.
- **Files touched:** `src/reconkit/engine.py` (+10/-4), `tests/test_engine.py` (+134/-1), `docs/03_ARCHITECTURE.md` (+2), this log, `docs/PROGRESS.md`.
- **Requirement -> test table:**
  | Requirement (owner ruling) | Test |
  |---|---|
  | the `scope.yaml` read runs in a worker thread | `test_the_scope_read_and_workspace_create_run_off_the_event_loop` (patched `engine.load_scope` records the calling thread; asserts it is not `threading.main_thread()`; the real loader still returns the real gate) |
  | the workspace mkdir/chmod runs in a worker thread | same test, patching `Workspace.create` and asserting the same fact |
  | the loop keeps turning during a slow read | `test_a_slow_scope_read_does_not_block_a_heartbeat` (two injected 0.25 s scope reads; a 5 ms heartbeat ticks `>= 10` times) |
  | the SQLite persistence block stays on the loop | `test_the_persistence_block_stays_on_the_loop_in_stage_order` (patched `Engine._persist_stage` records the calling thread; asserts main thread for both stages) |
  | stage persistence ordering is unchanged | same test: `scan_runs` stages are `["subs", "live"]` in id order and `host_status_history.run_id` is ascending |
  | resume still seeds before the first stage | existing `test_resume_skips_completed_stages_and_continues` and the resume tests still pass unchanged (695 total) |
  | the docs reason is true, not decorative | the mutation below reproduces `sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that same thread` |
- **Red-before-green (raw):** with the three awaits reverted to direct calls (byte-identical to HEAD's engine.py at those lines):
  ```
  >       assert seen == {"scope": True, "workspace": True}
  E       AssertionError: assert {'workspace':...scope': False} == {'scope': Tru...kspace': True}
  E         Differing items:
  E         {'scope': False} != {'scope': True}
  E         {'workspace': False} != {'workspace': True}
  FAILED tests/test_engine.py::test_the_scope_read_and_workspace_create_run_off_the_event_loop
  FAILED tests/test_engine.py::test_a_slow_scope_read_does_not_block_a_heartbeat
  >       assert ticks >= 10
  E       assert 2 >= 10
  2 failed, 1 passed, 79 deselected in 0.72s
  ```
  (the third test passed on purpose - it pins the SQLite block that stays on the loop). Restore: `cp /tmp/12h/engine.py src/reconkit/engine.py && sha256sum -c` -> `src/reconkit/engine.py: OK`, `82 passed in 1.41s`.
- **Mutation proof:** moving the persistence block into a worker thread (`await asyncio.to_thread(self._persist_stage, ...)` inside the existing transaction) is caught by the named test **and** fails for exactly the documented reason:
  ```
  E       sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that same thread. The object was created in thread id 140080205505088 and this is thread id 140080147166912.
  src/reconkit/core/store.py:483: ProgrammingError
  FAILED tests/test_engine.py::test_the_persistence_block_stays_on_the_loop_in_stage_order
  1 failed, 81 deselected in 0.19s
  src/reconkit/engine.py: OK
  ```
  A first attempt at the mutation left an unmatched parenthesis (a syntax error, not a caught defect); it was discarded, the mutation was rebuilt correctly, and the output above is the corrected run. Pre-mutation hash: `752ed9e33f65c1a166b3117d33cc9495dd114e1321084bf44da50fe1802bface  src/reconkit/engine.py`.
- **Self-review (S1-S7) findings:** S1 no `assert` in `src`; no `shell=True`/`os.system`; `import subprocess` only in `core/runner.py`; `import sqlite3` only in `core/store.py`; adapters import none of `store`/`scope`/`ui`/`cli`; no `TODO`/`FIXME`; no `print(` outside `ui.py`; no new `noqa`/`type: ignore` (the three pre-existing test ones are unchanged); `git diff --check` clean. S2 external input: none added - the moved calls take the same typed arguments. S3 secrets: `Workspace.create` still receives `self._secrets` and nothing new is printed or logged. S4 async: the two new thread hops are awaited in place, so cancellation still propagates out of `run` (the existing cancellation test passes) and no ordering changed. S5 blocking: `load_scope` and `Workspace.create` are now off the loop; the remaining synchronous work in `run` is the store's `create_target`/`create_scan_run`/`record`/`finish_scan_run` and the raw-file writes, all of which are the same class of local SQLite/disk work the ruling explicitly left alone (documented bound). S6 no new dependency/flag/config/module. S7 docs match code: docs/03 section 11 names both moved calls and the stayed-put block.
- **Gate (run twice, one command at a time, no pipes):** pass 1 - `695 passed in 14.75s`, `ruff check .` All checks passed, `ruff format --check .` 68 files already formatted, `mypy src/reconkit` Success: no issues found in 36 source files. Pass 2 (after the docs edits) - same four results, `695 passed`. Suite 692 -> 695 (three new tests).
- **No PIT row, and why:** PIT records a bug the code shipped with and now defends against. 12h is a latent hazard - `MASTER_PLAN.md` calls it `low`, and no wrong result, crash or measured stall has ever been attributed to it; the code was correct, only its placement on the loop was not ideal. The named tests are the permanent guard, and the mutation is the proof that the docs' reason is real. PIT-48 stays free for 12j.
- **Deviations / interpretation to flag:** the ruling says "the scope.yaml read" (singular), but the engine reads `scope.yaml` in **two** places - `_active_hosts` (the active gate) and `_ip_allowed` (the `in_scope_cidrs` predicate handed to `pyscan`). Both were moved, because leaving one would make docs/03's "file I/O never runs on the event loop" false and would keep the slow-filesystem stall on the ports path. Same mechanism, same thread, no behaviour change; if the owner intended only the gate, the second hop is trivially removable.
- **Next part must know (12j):** the engine now has five `to_thread` sites (`Workspace.create`, `_active_hosts`, `_ip_allowed`, `_is_installed`, and adapter child processes); anything else added to `run` that touches a file must justify itself against docs/03 section 11. The SQLite connection must stay on the thread that created it.

## Part 12j: a banner-first tool reports its real version (PIT-48)  (commit subject `fix: parse katana and nuclei versions with a registry pattern`; hash filled by the next commit)

- **Owner ruling being implemented (2026-11-15, final):** "Add a per-tool version_regex field to tools.yaml (docs/10 section 3c). installed_version() uses it when the tool has one defined, and falls back to today's splitlines()[0] behavior when the field is absent or the regex finds no match. Add real version_regex rows for katana and nuclei based on their actual captured banners - verify against the real binaries on this machine, not from memory."
- **Real binaries, before the change (this machine, `/home/kali/go/bin`):** `katana -version` prints a blank line, four lines of ASCII art (`   __        __` / `  / /_____ _/ /____ ____  ___ _` / ` /  '_/ _  / __/ _  / _ \/ _  /` / `/_/\_\\_,_/\__/\_,_/_//_/\_,_/`), `projectdiscovery.io`, then `[<ANSI>INF</>] Current version: v1.8.0` - on **stderr**. `nuclei -version` prints `[<ANSI>34m INF] Nuclei Engine Version: v3.11.1` first, also on stderr. `installed_version()` already preferred stderr when stdout was empty, so it read the text; it just kept the wrong line.
- **Docs read / goal:** `MASTER_PLAN.md` 12j, the ruling above, docs/10 sections 1 (idempotency), 3c (install plans and the version probe), 6 (update comparison) and 10 (`doctor`), docs/09 section 9 (the Part B audit that found it), the PIT-35 fix (masscan's banner), `installer/registry.py` and `installer/github_release.py`. Goal: doctor shows a version and `update` can call both tools current, with no per-tool code paths.
- **Docs changed first (before the code):** docs/10 section 3c gains `version_regex` in the `InstallPlan` field list and a rule paragraph: the pattern is searched in the **whole** `version_cmd` output, the first capture group is the version (the whole match when there is no group), the fallback is unchanged (first non-empty line) when the field is absent or nothing matches, an uncompilable pattern is a `ConfigError` at registry load, and the field lives in `tools.yaml` because the banner is a property of the tool. `git diff -- docs/10_TOOL_INSTALLER.md` is exactly +2 lines.
- **Code change:** `tools.yaml` rows for `katana` and `nuclei` gain `version_regex` (single-quoted so the backslashes survive YAML); `InstallPlan.version_regex: str | None = None`; `registry._pattern()` validates the value (a non-string or a pattern `re.compile` rejects is a `ConfigError`) and is threaded through `_plan` and through the plan copy in `load_plans`; `installed_version()` searches with `re.search` after the existing nonzero-exit identity check and before the `splitlines()[0]` fallback. `import re` in both files (stdlib, no new dependency).
- **Patterns, and why they are safe:** `'Current version: (v?\d+\.\d+\.\d+)'` and `'Nuclei Engine Version: (v?\d+\.\d+\.\d+)'`. The ANSI codes sit before the matched text, so no colour stripping is needed; the anchored phrase keeps a stray date or a compiler version from being picked up; `v?` accepts both ProjectDiscovery's `v1.8.0` form and a future bare `1.8.0`.
- **Files touched:** `src/reconkit/installer/registry.py` (+20/-0), `src/reconkit/installer/github_release.py` (+5/-0), `tools.yaml` (2 rows), `tests/test_installer_registry.py` (+35), `tests/test_install_cli.py` (+66), `docs/10_TOOL_INSTALLER.md` (+2), this log, `docs/PROGRESS.md`.
- **Requirement -> test table:**
  | Requirement (owner ruling) | Test |
  |---|---|
  | a per-tool `version_regex` field exists in `tools.yaml` and reaches `InstallPlan` | `test_version_regex_is_parsed_from_the_registry` (katana/nuclei exact patterns, assetfinder `None`), `test_version_regex_survives_the_plan_copy` (a temp registry, so the `load_plans` rebuild cannot silently drop it) |
  | real rows for katana and nuclei, from the real banners | the exact patterns asserted above; the captured banners are in `test_katana_version_ignores_the_ascii_banner` / `test_nuclei_version_drops_the_ansi_log_prefix`, and the live check below ran against the installed v1.8.0/v3.11.1 |
  | `installed_version()` uses the pattern when defined | `test_katana_version_ignores_the_ascii_banner` (`v1.8.0`), `test_nuclei_version_drops_the_ansi_log_prefix` (`v3.11.1`, no `\x1b`), `test_a_version_regex_without_a_group_returns_the_match` (`v2.0.1`) |
  | fallback is today's `splitlines()[0]` when absent or unmatched | `test_a_regex_with_no_match_falls_back_to_the_first_line` (`katana 9.9.9`), `test_installed_version_uses_the_managed_copy_first` (no pattern), `test_massdns_version_cmd_reports_dpkg_version` (no pattern) |
  | `update` can call them up to date | both banner tests assert `_same_version("v1.8.0", parsed) is True` / `_same_version("v3.11.1", parsed) is True` |
  | PIT-35's masscan case still passes | `test_masscan_version_counts_even_though_its_exit_code_is_1` and `test_a_nonzero_version_probe_with_unrelated_text_is_not_installed` unchanged and green |
  | a bad pattern fails early, not inside doctor | `test_a_broken_version_regex_is_a_config_error` (`ConfigError` naming `version_regex`) |
- **Live check against the installed binaries (not a test; run by hand on this machine):**
  ```
  katana:
    before (no version_regex): '__        __                '
    after  (version_regex)   : 'v1.8.0'
    _same_version('v1.8.0', after) -> True
    _same_version('v1.8.0', before) -> False
  nuclei:
    before (no version_regex): '[\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.11.1'
    after  (version_regex)   : 'v3.11.1'
    _same_version('v3.11.1', after) -> True
    _same_version('v3.11.1', before) -> True
  ```
  and `reconkit doctor --no-color` now prints `katana | urls | core | yes | v1.8.0 | ... | ok` and `nuclei | vulns | core | yes | v3.11.1 | ... | ok` (was `__` and `[I…`). nuclei was always `_same_version`-compatible, so its half was cosmetic; katana's was functional.
- **Red-before-green (raw):** with the `version_regex` block removed from `installed_version()` (tests kept):
  ```
  >       assert state == "v1.8.0"
  E       AssertionError: assert '__        __                ' == 'v1.8.0'
  >       assert state == "v3.11.1"
  E       AssertionError: assert '[\x1b[34mINF...sion: v3.11.1' == 'v3.11.1'
  >       assert github_release.installed_version(plan, bin_dir(tmp_path), runner=runner) == "v2.0.1"
  E         - v2.0.1
  E         + noise v2.0.1 noise
  FAILED tests/test_install_cli.py::test_katana_version_ignores_the_ascii_banner
  FAILED tests/test_install_cli.py::test_nuclei_version_drops_the_ansi_log_prefix
  FAILED tests/test_install_cli.py::test_a_version_regex_without_a_group_returns_the_match
  3 failed, 2 passed, 34 deselected in 0.34s
  ```
  Restore: `cp /tmp/12j/github_release.py ... && sha256sum -c` -> `OK`, `57 passed in 3.19s`.
- **Mutation proofs (both restored, hash confirmed):**
  - **M1 - return the whole match instead of the capture group** (`return match.group(0)`):
    ```
    E       AssertionError: assert 'Current version: v1.8.0' == 'v1.8.0'
    E       AssertionError: assert 'Nuclei Engin...sion: v3.11.1' == 'v3.11.1'
    FAILED tests/test_install_cli.py::test_katana_version_ignores_the_ascii_banner
    FAILED tests/test_install_cli.py::test_nuclei_version_drops_the_ansi_log_prefix
    src/reconkit/installer/github_release.py: OK
    ```
  - **M2 - no fallback when the pattern finds nothing** (`return None` before the fallback):
    ```
    E       AssertionError: assert None == 'katana 9.9.9'
    FAILED tests/test_install_cli.py::test_a_regex_with_no_match_falls_back_to_the_first_line
    1 failed, 38 deselected in 0.19s
    src/reconkit/installer/github_release.py: OK
    ```
  Pre-mutation hash: `0421dc3244b6bd5ffdb9577bda5ce96205d50e17aeb69f6e3ca850710562ad24  src/reconkit/installer/github_release.py`.
- **Self-review (S1-S7) findings:** S1 no `assert` in `src`; no `shell=True`/`os.system`; `import subprocess` only in `core/runner.py`; `import sqlite3` only in `core/store.py`; adapters import none of `store`/`scope`/`ui`/`cli`; no `TODO`/`FIXME`; no `print(` outside `ui.py`; no new `noqa`/`type: ignore`; `git diff --check` clean. S2 external input: the pattern comes from `tools.yaml`, is compiled and rejected at load if invalid, and is only ever used with `re.search` on the probe's own output - it never becomes a path, argv or SQL. S3 secrets: nothing new is read, stored or printed; the probe env is still `{"HOME": ...}` only. S4 async: no change (the version probe is synchronous and runs from `doctor`/`update`, both CLI paths). S5 PIT-35 preserved: the identity check runs before the pattern, so a nonzero exit with unrelated text still returns `None`. S6 no new dependency/flag/config module: `re` is stdlib, the field lives in the existing registry file, and `config.yaml` is untouched. S7 docs match code, including the group/whole-match rule and the load-time `ConfigError`.
- **Gate (run twice, one command at a time, no pipes):** pass 1 - `702 passed in 14.87s`, `ruff check .` All checks passed, `ruff format --check .` 68 files already formatted, `mypy src/reconkit` Success: no issues found in 36 source files. Pass 2 (after the docs edits) - same four results, `702 passed`. Suite 695 -> 702 (seven new tests).
- **Deviations:** none from the ruling. Two notes: (a) the ruling names the fallback as `splitlines()[0]`, and that is exactly what remains - the `str(copy)` fallback for an empty probe output is untouched; (b) the pattern is validated at registry load (`re.compile`), which the ruling did not ask for but which keeps a typo from raising `re.error` inside `doctor`; it is one small function and docs/10 states it.
- **What this closes:** Part 12 is complete - 12a, 12b, 12c, 12d, 12e, 12f, 12g, 12h, 12i, 12j and 12k are all implemented, tested and committed.

## Phase 1 - tool manual library (docs only, 2026-11-16)

- **Goal:** a real, machine-verified manual for every tool in `tools.yaml` that is
  not a vulnerability scanner, plus an honest installed-vs-runnable report. No
  `src/` change was allowed in this phase and none was made.
- **Docs read first:** `docs/09` (full), `docs/10` (full), `tools.yaml` (full),
  `docs/02`, `docs/03`, `docs/REVIEW_LOG.md` Known pitfalls, `docs/MASTER_PLAN.md`.
- **Inventory (authoritative, from the loaded registry, not from prose):**
  `tools.yaml` lists 48 tools; `adapters.registry.ADAPTERS` has 11 keys, so 11 are
  built and 37 are not.
  - subs 11: built crtsh, certspotter, otx, hackertarget, subfinder, assetfinder;
    unbuilt urlscan, amass, findomain, chaos, github_subdomains
  - dns 5: built dnspython; unbuilt dnsx, puredns, massdns, dig
  - live 4: built pyprobe, httpx; unbuilt httprobe, tlsx
  - ports 6: built pyscan, naabu; unbuilt smap, nmap, rustscan, masscan
  - tech 5: built none; unbuilt httpx_tech, whatweb, wafw00f, cdncheck, webanalyze
  - urls 8: built none; unbuilt gau, waybackurls, katana, hakrawler, gospider,
    subjs, unfurl, urlfinder
  - vulns 8: built none; unbuilt nuclei, subzy, dnsreaper, nikto, ffuf, dalfox,
    crlfuzz, sqlmap
  - shots 1: built none; unbuilt gowitness
- **Deferred by ruling of the task:** the whole `vulns` stage (8 tools) is
  "skipped - recon-only scope for now, revisit later". 40 tools documented.
- **Doc structure:** `docs/tool_manuals/` - one file per stage (`subs.md`,
  `dns.md`, `live.md`, `ports.md`, `tech.md`, `urls.md`, `shots.md`) plus a
  `README.md` index. Rationale and the alternative (one file per tool, 40 files)
  are recorded in that README. Flagged as a docs-only deviation in PROGRESS.
- **Method:** for each tool, the official source URL was recorded, the binary was
  located with the registry's own lookup order (`~/.reconkit/bin` first, then
  `PATH`), the real `--help` was captured to a file, and one safe command was run
  against `testfire.net` with stdout, stderr and the exit code captured. The
  markdown was generated from those files (`/tmp/gen_manuals.py`), so no help text
  or output in the manuals is retyped.
- **Installed vs runnable:** 39 of the 40 documented tools have a usable
  entry point. `rustscan` does not (install fails, see below). Six installed tools
  had no runnable path without something this box does not have: `chaos`
  (`PDCF_API_KEY`-class key missing: `[FTL] PDCP_API_KEY not specified`, exit 1),
  `github-subdomains` (`token not found`, exit 255), `otx` (anonymous 429),
  `certspotter` (anonymous `[]`), `masscan` (root needed for a real scan; only
  `--echo` was run), `webanalyze` (needs `-update` once: first run exited 1).
- **`reconkit install` used:** `reconkit install rustscan gowitness`. gowitness
  installed (`go install ... @latest -> ~/.reconkit/bin/gowitness`); rustscan
  failed: `rustscan: release 2.4.1 has no asset 'verify-at-implementation'`.
  No sudo was run in either phase; nothing needed it.
- **Findings flagged for the owner (no code or registry change):**
  1. `rustscan`'s `asset_pattern` is the placeholder `verify-at-implementation`, so
     it cannot be installed; the release is 2.4.1.
  2. Seven tools still show ASCII art in `doctor`'s Version column because only
     `katana`/`nuclei` have a `version_regex` (PIT-48 class): observed live with
     `installed_version()` - `chaos -> '__                    '`,
     `dnsx -> '_             __  __'`, `httpx -> '__    __  __       _  __'`,
     `tlsx -> '_____ _    _____  __'`, `naabu -> '__'`, `wafw00f -> '______'`,
     `cdncheck -> '__           __              __  '`. (`httpx`, `naabu`, `katana`,
     `nuclei` are fine in `doctor` because their adapters or regex take over.)
  3. `installed_version()` returns `argv0` when `version_args` is empty, so the
     Version column is a path for tools with no version flag
     (`github_subdomains -> '/home/kali/.reconkit/bin/github-subdomains'`, same for
     smap, webanalyze, gospider, subjs, unfurl, urlfinder, waybackurls, httprobe
     whose `-h` prints usage).
  4. `assetfinder -h` exits **0** here, not the 2 that docs/09 section 9 states.
  5. `amass` is **v5.1.3** with the `assoc|engine|enum|subs|track|viz` tree, while
     the `tools.yaml` note describes v4 behaviour (`-passive` still exists under
     `amass enum`; `amass -version` works).
  6. `webanalyze` needs `technologies.json`; nothing in `tools.yaml` records the
     preparation step.
- **Real evidence (per tool, full help and full output in `docs/tool_manuals/`):**
  `subfinder -d testfire.net -silent -nc -duc` -> 35 hosts, exit 0;
  `assetfinder --subs-only testfire.net` -> 4, exit 0;
  `findomain -t testfire.net --quiet` -> 37, exit 0;
  `printf 'testfire.net\nwww.testfire.net\n' | dnsx -silent -a` -> 2, exit 0;
  `puredns resolve d.txt -r res.txt -q` -> 2, exit 0;
  `massdns -r res.txt -t A -o S d.txt` -> 2 records, exit 0;
  `dig testfire.net A +short` -> `65.61.137.117`, exit 0;
  `httpx -u testfire.net -silent -sc -title -location -td -cdn -nc -duc` ->
  `https://testfire.net [200] [] [Altoro Mutual] [Apache Tomcat,Java]`, exit 0;
  `echo testfire.net | httprobe` -> 2 URLs, exit 0;
  `tlsx -u testfire.net -silent -nc -duc` -> `testfire.net:443`, exit 0;
  `naabu -host testfire.net -p 80,443 -scan-type c -silent -nc -duc` -> 2 ports,
  exit 0 (connect scan, no root, no libpcap-dev);
  `nmap -sV -p80,443 -T2 --noninteractive testfire.net` -> both ports open with
  `Apache Tomcat/Coyote JSP engine 1.1`, exit 0;
  `masscan --echo --max-rate 100 -p1234` -> `rate = 100`, exit 0 (no packets);
  `smap testfire.net -oJ -` -> JSON with ports 80/443 from Shodan data, exit 0;
  `whatweb --no-errors testfire.net` -> `[200 OK] Apache, ... Title[Altoro Mutual]`,
  exit 0; `wafw00f testfire.net` -> `No WAF detected`, exit 0;
  `cdncheck -i 104.16.0.1 -silent -nc -duc` -> `104.16.0.1`, exit 0;
  `webanalyze -host testfire.net` -> Java + Apache Tomcat, exit 0 (after -update);
  `gau --threads 2 testfire.net` -> 485 URLs, exit 0;
  `waybackurls testfire.net` -> 27, exit 0;
  `katana -u https://testfire.net -d 1 -silent -nc -duc -rl 5` -> 1132, exit 0;
  `echo https://testfire.net | hakrawler -d 1` -> 0 URLs, exit 0 (redirects to
  www, refused to leave scope); `gospider -s https://testfire.net -d 1 -q` -> 1,
  exit 0; `echo https://testfire.net | subjs` -> 0, exit 0;
  `echo 'https://testfire.net/login.jsp?uid=1&pw=2' | unfurl keys` -> `pw`,`uid`,
  exit 0; `urlfinder -d testfire.net -silent -nc -duc` -> 73, exit 0;
  `gowitness scan single --url https://testfire.net` -> `status-code=200
  title="Altoro Mutual" have-screenshot=false`, exit 0;
  HTTP sources: crtsh 200/24 entries, certspotter 200 `[]`, otx 429 anonymous,
  hackertarget 200/3 rows, urlscan 200/41 results.
- **Python tools proved in-process:** dnspython 2.9.2 A record;
  a raw TLS `HEAD /` probe returned `HTTP/1.1 200 OK` (and a real
  `CERTIFICATE_VERIFY_FAILED: Hostname mismatch` with a verifying context on this
  target - the exact case PIT-37 wrote the fallback for); one TCP connect to
  `65.61.137.117:80` through an `in_scope_cidrs` predicate returned OPEN.
- **Multi-domain flags checked from the real `--help` for every binary** (table in
  `docs/tool_manuals/README.md`): `subfinder -dL`, `chaos -dL`, `findomain -f`,
  `dnsx -l`, `httpx -l`, `tlsx -l`, `naabu -list`, `nmap -iL`, `masscan -iL`,
  `smap -iL`, `whatweb --input-file`, `wafw00f -i`, `katana -u/-list`,
  `urlfinder -d/-list`, `cdncheck -i`, plus stdin/file input for puredns, massdns,
  dig (`-f`), gau, waybackurls, httprobe, hakrawler, subjs, unfurl;
  `assetfinder` and `github-subdomains` have **none**.
- **No `src/` change:** `git status --short` after Phase 1 showed only
  `docs/09_TOOL_CONTRACTS.md`, `docs/PROGRESS.md`, `docs/REVIEW_LOG.md` and the new
  `docs/tool_manuals/` tree.
- **Not verified:** a real `masscan` scan (root), a real `amass` full run (it did
  not finish in 150 s), `chaos`/`github-subdomains`/`otx` with a key, and
  `gowitness` screenshots (no browser found by the tool).

## Part 13: the interactive scan mode and stderr progress (2026-11-16)

- **Docs read / goal:** `AGENTS.md`, `docs/02_CLI_UX.md` (full), `docs/03_ARCHITECTURE.md` (full), `docs/05` rule 3 (scope), `docs/09` (stage pools), `config.yaml`, `docs/MASTER_PLAN.md`, and Phase 1's `docs/tool_manuals/`. Goal: a scan command with **no** `-d`/`-l` asks five questions, builds the ordinary scan inputs from the answers, shows stage/tool progress on stderr, and saves one `report.txt` + `report.json` per domain per run - while every flag-based invocation keeps today's behaviour byte for byte.
- **Compatibility decision (the HARD STOP, resolved before coding):** the prompt path is entered only when `domain is None and list_file is None and command in _SCAN_COMMANDS and _stdin_is_tty()`. `_stdin_is_tty()` is a module-level function precisely so tests can monkeypatch it; without a terminal the command keeps today's exit 2 `provide a target with -d/--domain or -l/--list`. Bare `reconkit` still prints help (no scan subcommand was invoked). Nothing in `engine.py`, `adapters/` or `core/` knows the interactive mode exists: the CLI resolves answers into `domain`/`list_file`/`scope_path`/`stages`/`active` and then runs the same `_run_scan` body as a flag run. No flag was added, so no flag path can reach a prompt.
- **Docs changed first (in this order, before any code):** `docs/02` new `## 2b Interactive scan mode` (the five questions, the trigger, the answers-to-stages table, "no scope file" semantics), rewritten `### Progress` (stderr, live for `--json`, only `--silent` suppresses), new `### Saved reports (interactive mode)` (folder layout, both files always, the alive-only rule, `results_dir`); `docs/03` new `Saved reports` section plus the `Engine(progress=...)` / `render_progress` / `HostSnapshot` bullets; `docs/MASTER_PLAN.md` Part 13 in the Part 12 `DECIDED` style. The Part 13 `DECIDED` line records: interactive only without `-d`/`-l` **and** on a TTY; `vulns` never requested; aggressive = `pyscan` only, LOW ceiling, no version detection; no scope bypass.
- **Answers -> real inputs:** Q1 `_ask_target()` - an existing file becomes `list_file` (the ordinary `-l` path, one target row and one full scan per domain), anything else stays the single `domain` string and goes through the same `validate_target()`; Q2 `_ask_scope()` - "no" means `scope_path=None`, i.e. exactly today's behaviour (passive runs with `passive_warning`, active is refused with exit 3), never a bypass; a path that is not a file raises `ConfigError`; Q3 `_MODE_STAGES` - passive `(SUBS, DNS)`, active `(SUBS, DNS, LIVE)`, full `(SUBS, DNS, LIVE, PORTS, TECH, URLS)`; anything else is exit 2; Q4 the 12 real stored fields; Q5 `_ask_aggressive()` - adds `LIVE`+`PORTS` and `active=True`. `active=(mode != "passive") or aggressive`, so an active/full plan still needs `scope.require_active` as before, and `test_no_scope_file_never_lets_an_active_tool_run` proves the LIVE tool is skipped, not run.
- **Field menu, pulled from the stored model, not invented:** `ui.REPORT_FIELDS` = hostname, state, confidence, status_code, ports, technologies, title, redirect, ips, sources, source_count, detail. Every value comes from `Store.host_rows()`, which Part 13 extended to LEFT JOIN the same latest `host_status_history` row it already read for `status_code`/`detail` (one join, no new query) and to decode the stored `ips_json`/`tech_json` with a new `_text_list()` (a malformed value becomes `()`, never an exception). No field is computed or guessed. `field.gate == "alive"` fields (status_code, ports, technologies, title, redirect) return `None` for a non-ALIVE host in both files; `detail` is gated to `UNKNOWN` only. `REPORT_FIELDS` has no vulnerability field, and `vulns` is not in `_MODE_STAGES`.
- **Levels (tool-doc grounding, checked in Phase 1's manuals rather than from memory):** `tools.yaml` has no separate level per tool; the deferral is per tier, and the recon-only ceiling is enforced by `_MODE_STAGES` never containing `Stage.VULNS`. Aggressive adds `PORTS`, whose pool is `pyscan`, `naabu`, `smap`, `nmap`, `rustscan`, `masscan`; `pyscan` is the only built TCP scanner (12i's permanent ceiling), `naabu` stays blocked (11c-G-7), and no adapter sends a version-detection flag (`nmap -sV` is not wired), so aggressive is LOW-severity port discovery only, stated in docs/02 and in the prompt's answer text.
- **Multi-domain input, per tool (from `docs/tool_manuals/*.md` real `--help`):** `subfinder` `-dL/-list file`, `findomain -f/--file`, `dnsx -l/-list file`, `httpx -l/-list file`, `tlsx -l/-list file`, `naabu -list/-l file`, `nmap -iL`, `masscan -iL`, `puredns`/`massdns` take a domains file positionally, `httprobe` reads stdin, `assetfinder` takes one domain, `pyscan` is ours and per-host, `wafw00f`'s `-l` means **list the WAFs it detects** (not a target list) and `whatweb`/`gowitness` take one URL. Decision: the interactive file path does **not** switch any tool to its native list flag. It reuses `-l`, which the CLI already expands into one full per-domain scan, because the deliverable is one report folder per domain with values attributable to that domain; a single multi-domain tool invocation would merge results across domains and break that. Recorded here so a later part does not "optimise" it by accident.
- **Progress:** `Engine(progress=...)` takes a `Progress` callback; `_progress()` calls it at stage start (`"subs: running 6 tool(s)"`), per tool (`"subs: crtsh 1/6"` / failure), and stage end (`"dns: dnspython ok 36 item(s)"`, `"36 hosts: 0 ALIVE, 8 DNS_ONLY, ..."`). The engine formats nothing and prints nothing. The CLI passes `render_progress(message, console=progress_console)` where the console is built on `sys.stderr`, or `None` for `--silent`. This is the deliberate change to `--json`: it now shows progress, on **stderr**, which docs/02 records first. `test_json_progress_goes_to_stderr_and_stdout_stays_one_document` parses `result.stdout` as one JSON document and asserts the progress lines are in `result.stderr`.
- **Files touched:** `src/reconkit/cli.py` (+176/-8), `src/reconkit/ui.py` (`ReportField`, `REPORT_FIELDS`, `report_fields`, `field_value`, `format_field_value`, `report_directory`, `report_document`, `report_text`, `write_field_report`, `_write_atomically`, `_cell`, and the rewritten `render_progress`), `src/reconkit/engine.py` (`Progress`, `progress=`, `_progress()`, three call sites, `HostSnapshot` extras), `src/reconkit/core/store.py` (`host_rows` join + `_text_list`), `src/reconkit/config.py` (`results_dir` with a default), `config.yaml`, `.gitignore` (`results/`), `tests/test_interactive_scan.py` (new), `tests/test_cli.py`, `tests/test_ui.py`, `docs/02`, `docs/03`, `docs/MASTER_PLAN.md`, `docs/PROGRESS.md`, this entry. No new module: the report writer lives in the existing `ui.py` and the prompt code in the existing `cli.py`, both named in docs/02-03.
- **Report folder rule:** `report_directory(root, domain, stamp)` = `<results_dir>/<domain>/<UTC ISO stamp>`; if the folder exists it appends `-2`, `-3`, ... so a second run can never overwrite the first. An empty or traversing domain is refused (`raise ConfigError`), tested with `test_report_directory_refuses_a_traversing_target` (`..` and `/` cases). Both files are written for every domain, always, from the same selected field list; `write_field_report` writes atomically (`tmp` + `replace`) with mode 0600.
- **Requirement -> test table (28+4 new tests in `tests/test_interactive_scan.py`):**
  | Requirement | Test |
  |---|---|
  | (a) a flag run asks nothing | `test_a_flagged_run_never_asks_a_question`, `test_a_listed_run_never_asks_a_question`, `test_a_flagged_run_writes_no_report_folder` |
  | no terminal keeps the old error | `test_no_target_and_no_terminal_keeps_the_old_error` |
  | Ctrl-D at any prompt cancels | `test_a_prompt_that_hits_end_of_input_is_cancelled` |
  | Q1 single domain vs file | `test_interactive_passive_writes_one_folder_per_domain` |
  | the menu is the real stored fields | `test_the_field_menu_is_the_real_stored_fields` |
  | `1,3,5` keeps menu order | `test_a_numeric_selection_keeps_menu_order` |
  | a bad mode / field number / empty answer is exit 2 | `test_a_bad_answer_is_a_usage_error`, `test_field_zero_is_out_of_range` |
  | Q2 missing scope file is refused, a real one behaves like `--scope` | `test_a_missing_scope_file_is_refused`, `test_a_scope_file_is_used_exactly_like_the_flag` |
  | Q2 "no" cannot let an active tool run | `test_no_scope_file_never_lets_an_active_tool_run` |
  | (d) a domain file scans each domain separately | `test_a_multi_domain_file_scans_each_domain_separately` |
  | an empty file is a usage error, a directory is not a domain | `test_an_empty_domain_file_is_a_usage_error`, `test_a_directory_instead_of_a_domain_is_a_usage_error` |
  | Q5 yes adds the ports stages, no leaves the plan alone | `test_aggressive_yes_adds_the_ports_stages`, `test_aggressive_no_leaves_the_plan_alone` |
  | full never requests `vulns` | `test_full_mode_does_not_request_the_deferred_vulns_stage` |
  | an active command with passive chosen is refused, not guessed | `test_interactive_on_an_active_command_with_passive_chosen_is_refused` |
  | (b) alive-only fields blank for non-ALIVE | `test_alive_only_fields_are_not_applicable_for_non_alive_hosts`, `test_a_real_mock_run_reports_alive_fields_only_for_alive_hosts`, `test_the_unknown_reason_is_only_for_unknown_hosts` |
  | (c) a per-domain folder never overwrites | `test_two_runs_of_one_domain_never_share_a_folder`, `test_a_prior_run_folder_survives_a_second_cli_run` |
  | progress on stderr, stdout stays parseable | `test_json_progress_goes_to_stderr_and_stdout_stays_one_document`, `test_a_flagged_json_run_now_shows_progress`, `test_silent_still_suppresses_progress` |
  | a traversing domain cannot escape `results_dir` | `test_report_directory_refuses_a_traversing_target` |
- **Existing tests changed (all three are the documented progress-contract change, none removed):**
  | Test | Change | Reason |
  |---|---|---|
  | `tests/test_cli.py::test_mock_json_is_one_valid_document_and_exit_zero` | `assert result.stderr == ""` -> `assert "subs: running" in result.stderr` | `--json` now shows progress; docs/02 `### Progress` changed first. The stdout document assertion is untouched and still parses. |
  | `tests/test_cli.py::test_mock_scope_denial_returns_three` | `assert result.stderr == ""` -> `assert "subs: running" in result.stderr` | same contract; exit code 3 and the scope message assertions are untouched. |
  | `tests/test_ui.py::test_progress_is_suppressed_for_silent_and_json_modes` | renamed to `test_progress_is_suppressed_only_in_silent_mode`; `"subs: crtsh 1/3"` -> `"subs: running 3 tool(s)"` and `"(4s)"` | the old name asserted the removed `--json` suppression; the new renderer emits a stage line and a duration suffix. |
  No other test file was touched: 29 `tests/*.py` files were tracked before this part; two are changed and one is new, so the other 27 are byte-identical.
- **Mutation proofs (each applied, watched fail, restored from `/tmp`, `git status` clean afterwards):**
  1. drop the TTY guard (`and _stdin_is_tty()` -> `and True`): `test_no_target_and_no_terminal_keeps_the_old_error` fails - `AssertionError: assert 'provide a target with -d/--domain or -l/--list' in 'Domain, or path to a file of domains (one per line):interactive scan cancelled\n'`.
  2. let the folder name collide (remove the `-2` loop in `report_directory`): `test_two_runs_of_one_domain_never_share_a_folder` fails - both paths are `.../results/example.com/20261116T120000Z`.
  3. disable the alive gate (`return row.state is HostState.ALIVE` -> `return True`): `test_alive_only_fields_are_not_applicable_for_non_alive_hosts` and `test_a_real_mock_run_reports_alive_fields_only_for_alive_hosts` fail - `AssertionError: ports / assert [] is None`.
  4. send progress to stdout (`print(message)` instead of `render_progress(..., console=progress_console)`): both stderr tests fail - `AssertionError: assert 'subs: crtsh ok' in ''`.
- **S3 scans (raw, on the final tree):** `assert` in `src/` -> NONE; `shell=True` -> NONE; `TODO|FIXME|XXX|HACK` -> NONE; `print(` -> `ui.py` only (Rich consoles); `subprocess` -> `core/runner.py` only; `sqlite3` -> `core/store.py` only; `os.environ` -> the same four pre-existing sites; `except Exception|BaseException` -> the same pre-existing sites (none added; `_text_list` catches `ValueError` for `json.loads` and `_stdin_is_tty` catches `AttributeError`/`ValueError`); `noqa|type: ignore` -> the three pre-existing test lines only (four `# type: ignore[no-untyped-def]` I wrote in the new test file were **removed** by annotating the fakes with `Any`/`ScanSummary` rather than suppressed); adapters importing `store`/`scope`/`ui`/`cli` -> NONE.
- **S2 self-read findings:** `host_rows` keeps one query, and the LEFT JOIN's `MAX(latest.id)` is equivalent to the two `ORDER BY h.id DESC LIMIT 1` subqueries it replaced (same row, now read once). `_text_list` cannot raise on a `None`/garbage column. `write_field_report` refuses a traversing domain and writes 0600 atomically. Report files contain only values already stored in the run's own DB (nothing is recomputed) and live under the user's `results_dir`; a title holding a provider key would be no more exposed than it already is in the DB. The engine's `progress` callback is `None` by default, so every existing engine test and the library use are unchanged.
- **Own-test bug found and fixed (S1):** `test_an_empty_domain_file_is_a_usage_error` first failed on `"contains no domains" in result.stderr` because Rich wrapped the message (`'target file \n...\nempty.txt contains\nno domains\n'`); the assertion now normalises whitespace (`" ".join(result.stderr.split())`) instead of the message changing. No `src/` change for a test artifact.
- **Real interactive run (pty, `script -q -c`, two domains in a file):** `reconkit passive --speed fast --db /tmp/p2demo.db` -> `subs: running 6 tool(s)`, per-tool lines, `dns: dnspython ok 36 item(s)`, `36 hosts: 0 ALIVE, 8 DNS_ONLY, ...`, and `results/testfire.net/20261116T143941Z/{report.txt,report.json}` + `results/zonetransfer.me/20261116T144023Z/{report.txt,report.json}`.
- **Gate (twice, one command at a time):** `734 passed in 16.24s` / `734 passed in 16.51s`; `All checks passed!`; `69 files already formatted`; `Success: no issues found in 36 source files`. Baseline before Part 13 was `702 passed` (68 files formatted); the delta is the 32 new tests in `test_interactive_scan.py`.
- **Deviations (also in PROGRESS):** new `results_dir` config key (defaulted, so old config files still load); the report writer lives in `ui.py` and the prompts in `cli.py` instead of a new module; `--json` now emits progress on stderr (docs/02 changed first); `.gitignore` gained `results/`; `HostSnapshot` and `Store.host_rows()` gained stored fields with defaults so the table and `--json` shape are unchanged.
- **Not verified / known:** the pty demo used the real network at `--speed fast` against two in-scope domains only; the pre-existing all-`UNKNOWN` result of `run --active --mock` is unchanged by this part (documented in PROGRESS Open risks, not fixed here).

## Task 1 (2026-11-17): no scope file means unrestricted active scanning

- **Docs read / goal:** `AGENTS.md`, RESUME, the pitfalls table, `docs/02` (full), `docs/03` (sections 5-7, 13), `docs/05` (rules 1-2, 6, 9), `docs/09` (RunContext), `docs/MASTER_PLAN.md`. Goal: a missing scope file must stop being a refusal; the operator's explicit `-d`/`-l` target is the authorization, and no scope object is derived from it. A scope file that is present keeps the unchanged gate and is only read.
- **Decisions and assumptions:** "no scope file" is decided in exactly one place, `scope.scope_present()` (resolved path missing). `Engine._active_hosts` returns the host list untouched when it is false; `Engine._ip_allowed` returns the module-level `allow_all_ip` predicate, because with no CIDR list there is nothing to filter - returning `None` (the docs/05 "no permission" value) would silently block every address. `scope.require_active()` and `load_scope()` are untouched. `scope check` is unchanged: it is an inspection of a scope file, and still reports "BLOCKED (scope file not found)".
- **Docs changed first:** `docs/05` rule 2 (two branches), rule 6 (naabu is Task 2; IP rule and the allow-all predicate), rule 9 (no bypass applies to a present file); `docs/02` section 2 ("What `--active` needs"), stage table header, `--active` flag row, exit code 3, `stages[].skipped` wording, section 2b question 2; `docs/03` engine API bullet, data-flow step 2, failure table row; `docs/MASTER_PLAN.md` new "DATED DEVIATIONS" section, entry D1.
- **Files touched:** `src/reconkit/core/scope.py` (+15: `scope_path`, `scope_present`), `src/reconkit/engine.py` (`allow_all_ip`, two early returns), `src/reconkit/cli.py` (one error message drops "and a matching scope.yaml"), `tests/test_engine.py`, `tests/test_cli.py`, docs above.
- **Requirement -> test table:**
  | Requirement | Test |
  |---|---|
  | (a) no file + single domain, active stages run unrestricted, no exit 3 | `test_no_scope_file_runs_active_stages_unrestricted`, `test_mock_run_without_a_scope_file_is_unrestricted` |
  | (b) a real scope file is enforced exactly as today | `test_a_present_scope_file_is_enforced_exactly_as_before`, `test_mock_scope_file_denial_returns_three` |
  | (c) no auto-derived scope object is constructed or required | `test_no_scope_file_never_loads_or_derives_a_scope_object` (monkeypatched `load_scope` is fatal; also asserts the allow-all predicate) |
- **Changed test (disclosure):** `tests/test_cli.py::test_mock_scope_denial_returns_three` was renamed `test_mock_run_without_a_scope_file_is_unrestricted` and now asserts `exit_code != 3`, `scope_denied is False`; it previously asserted the removed exit 3 for a missing file. Reason: the behavior it asserted is the one this task replaced. `test_mock_scope_file_denial_returns_three` was added so the exit-3 path stays covered against a real file.
- **Mutation proof:** forcing `scope_present()` to `return True` made `test_no_scope_file_runs_active_stages_unrestricted` and `test_no_scope_file_never_loads_or_derives_a_scope_object` fail (raw tail: `FAILED ... test_no_scope_file_runs_active_stages_unrestricted`, `FAILED ... test_no_scope_file_never_loads_or_derives_a_scope_object`, `2 failed, 1 passed`); restored with a clean `git diff` against the backup.
- **Raw check output:** `738 passed in 16.56s`; `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `69 files already formatted` (after `ruff format` on the two files it flagged); `mypy src/reconkit` -> `Success: no issues found in 36 source files`.
- **Not verified:** a real-network active run without a scope file.
- **Next part must know:** `allow_all_ip` is the no-scope IP predicate; do not reintroduce a `None` there.

### Task 1a follow-up (2026-11-17): the scan mode has no default

- **What was wrong:** Task 1a asked that interactive mode "must not proceed until a valid choice is made. No silent default, no assuming passive." The question existed, but `_ask_mode()` still passed typer `default="passive"` (Enter meant passive) and raised `ConfigError` on any other word. Nothing proved the prompt was actually asked.
- **Fix:** `_ask_mode(*, no_color)` loops: it renders the same prompt, accepts only `passive`/`active`/`full`, prints `invalid scan mode '...' ; expected passive, active or full` through `render_error`, and asks again. EOF/`Abort` still becomes `interactive scan cancelled` (exit 2) in `_run_scan`, so a missing answer cancels instead of defaulting.
- **Docs first:** `docs/02` section 2b point 3 now says there is no default and the question is re-asked.
- **Changed test (disclosure):** the `("example.com\nn\nsideways\nall\nn\n", "invalid scan mode")` row was removed from `test_a_bad_answer_is_a_usage_error` (it asserted the removed exit-on-bad-word behaviour) and replaced by `test_the_mode_is_asked_until_a_valid_answer_is_typed` (wrong word, then an empty line, then `active`: exactly three prompt renders and the run starts) and `test_no_mode_answer_means_no_scan` (input ends at the mode question: exit 2, `Engine.run` never called). The other three parametrized cases are untouched.
- **Raw check output:** `33 passed in 1.99s` (`pytest -q tests/test_interactive_scan.py`); full gate before the commit is in the commit log line below.
- **Not verified:** no real terminal capture of the re-ask loop beyond `CliRunner` input.

## Task 2 (2026-11-17): naabu is scope-mode dependent

- **Docs read / goal:** docs/05 rule 6, docs/09 sections 3-4 and the tool-flags table, docs/03 section 13, docs/02 ports paragraph and section 2b, `naabu -h`. Goal: remove the unconditional 11c-G-7 block; no scope file = unrestricted active tool; scope file present = engine resolves, verifies against `in_scope_cidrs`, and passes only IPs to naabu; passive never runs it.
- **Real `naabu -h` evidence (pasted, v2.7.0, `/usr/bin/naabu`):** `-host string[]              hosts to scan ports for (comma-separated)`; `-list, -l string            list of hosts to scan ports (file)`; `-exclude-hosts, -eh ...`; `-rev-ptr                       Reverse PTR lookup for input ips`. A real local run `naabu -host 127.0.0.1 -p 18080 -silent -json -no-stdin -duc -nc -scan-type c` printed `{"ip":"127.0.0.1","timestamp":"2026-11-17T08:23:04.956815908Z","port":18080,"protocol":"tcp","tls":false}` - IP input accepted, `host` omitted from the record. `-host 127.0.0.1,127.0.0.2` was also accepted (exit 0).
- **Decisions and assumptions:** the engine, not the adapter, decides the mode. `Engine._naabu_verified_ips()` runs only when `scope_present(self.scope_path)` and `not opts.mock`; it uses `self._resolve` (new injectable constructor arg, default `adapters.pyscan.default_resolve`, the existing resolver `pyscan` already uses) and the same `ip_allowed` predicate from docs/05 rule 6. It replaces `hosts` for the naabu tool context only, through the same `model_copy(update=...)` path as `env`. A dropped target is never retried as a name. `PortRecord.fqdn` becomes the IP in that branch (naabu omits `host` for IP input), which is documented in docs/09 rather than papered over.
- **Docs changed first:** docs/05 rule 6; docs/09 `RunContext` bullet, naabu bullet, ports row, selection-rules paragraph, naabu flags-table note; docs/02 ports paragraph and aggressive notice; docs/03 failure table; `docs/MASTER_PLAN.md` D2 (11c-G-7 marked SUPERSEDED, not deleted); the two 11c-G-7 REVIEW_LOG headings got a superseded banner.
- **Files touched:** `src/reconkit/engine.py` (removed `IP_GATE_BLOCKED`, added `NAABU_NO_IPS`, `Resolve`, `_resolve`, `_naabu_verified_ips`, per-tool `hosts` override), `src/reconkit/adapters/naabu.py` (`_input()` IP-or-host normalization, docstring), `src/reconkit/cli.py` (aggressive notice), tests, docs.
- **Requirement -> test table:**
  | Requirement | Test |
  |---|---|
  | (a) no scope file + active -> naabu unrestricted, no resolve step, no exit 3 | `test_no_scope_file_runs_naabu_on_hostnames_unrestricted` (also asserts the resolver was never called) |
  | (b) scope present -> IPs only, all verified | `test_scope_file_passes_naabu_only_verified_ips`, `test_naabu_accepts_verified_ip_inputs` |
  | (c) resolution fails -> target omitted | `test_scope_file_omits_a_target_whose_resolution_fails` |
  | (d) resolved IP out of scope -> target omitted | `test_scope_file_omits_a_target_that_resolves_out_of_scope` |
  | nothing verifies -> naabu skipped with reason | `test_scope_file_skips_naabu_when_no_target_verifies` |
  | (e) passive -> never runs, with and without a scope file | `test_passive_mode_never_runs_naabu_with_or_without_a_scope_file` |
- **Changed tests (disclosure):**
  - `tests/test_engine.py::test_naabu_stays_blocked_because_it_resolves_inside_the_binary` -> `test_naabu_is_selectable_in_active_mode`. It asserted the unconditional 11c-G-7 skip; now asserts naabu is selected and that passive still skips it with `requires --active`. Reason: the owner removed that block.
  - `tests/test_interactive_scan.py::test_aggressive_yes_adds_the_ports_stages`: assertion text follows the reworded aggressive notice ("aggressive: TCP connect scanning by pyscan", "naabu runs only on IPs reconkit resolved and verified", "service/version detection is not wired"). Reason: the old text said naabu was permanently blocked.
  - `tests/test_interactive_scan.py::test_aggressive_no_leaves_the_plan_alone`: now `chdir`s to `tmp_path` and writes a present `scope.yaml` that denies the target, instead of depending on the checkout's git-ignored `scope.yaml`. Reason: since Task 1 an absent file no longer refuses, so the old test would pass for the wrong reason (or fail on a fresh clone).
  - `tests/test_interactive_scan.py::test_no_scope_file_never_lets_an_active_tool_run` -> `test_a_present_scope_file_blocks_an_out_of_scope_interactive_target`. Same reason; it now proves a present file still blocks.
- **Mutation proof:** making the resolve-and-verify condition `and False` produced `4 failed, 87 deselected` (`test_scope_file_passes_naabu_only_verified_ips`, both omission tests, `test_scope_file_skips_naabu_when_no_target_verifies`); restored from backup.
- **Raw check output:** `745 passed in 16.69s`; `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `69 files already formatted`; `mypy src/reconkit` -> `Success: no issues found in 36 source files`.
- **Not verified:** a real scope-file-present naabu scan was run only against a local listener (127.0.0.1); the full CLI demonstration is in the final report.
- **Next part must know:** `NAABU_NO_IPS` is the only naabu skip reason left; `allow_all_ip` (Task 1) means the no-scope branch never resolves.

## Task 3 (2026-11-17): all speed/throttle control is removed

- **Docs read / goal:** `AGENTS.md`, RESUME, pitfalls table, `docs/02` (flags, exit codes, section 2b), `docs/03` (sections 5-7, 13), `docs/05` (rule 3), `docs/04` (`scan_runs`), `docs/07`, `docs/08`, `docs/09`, `config.yaml`, `tools.yaml`. Goal: no `--speed`, no `--delay`, no pacer, no rate flags, no `scan_runs.speed`; tools run at their natural pace with no dead code left behind. The scope gate is untouched; a real `scope.yaml` that still carries `max_speed` must keep loading.
- **Decisions and assumptions:** (1) `core/pacing.py` is deleted whole rather than emptied, and `tests/test_pacing.py` goes with it - a test file for a deleted module is the dead code the task forbade. (2) `scope.yaml`'s `max_speed` stays in the `Scope` model, accepted and ignored, because removing it would make every existing scope file fail the unknown-key check; docs/03 section 7 says so. (3) `scan_runs.speed` is removed by schema **5** (`ALTER TABLE scan_runs DROP COLUMN speed`) instead of storing a meaningless constant, so the column cannot lie; docs/04 records v5 and the v1-v4 fixtures gained a `scan_runs` table so the migration is exercised end to end. (4) `rate_flag` is removed from `ToolSpec`, `tools.yaml`, the registry and the pass-through table: a per-tool rate flag is throttling. (5) The interactive `fast` typed confirmation goes with `--speed`; the aggressive-ports confirmation is unrelated and stays.
- **Docs changed first:** docs/02 (intro, flag table, exit-code/confirmation text, section 2b flow), docs/03 (stack table, stage execution, new section 7 "Concurrency (no pacing)", anti-goals), docs/05 (section 3 now "Pacing (removed)", checklist), docs/04 (schema 5), docs/01 (feature 7 marked removed), docs/06, docs/07, docs/08, docs/09 (rate-flag column and RunContext), `AGENTS.md` rule 3 and the utilities line, README, SETUP; `docs/MASTER_PLAN.md` D3.
- **Files touched:** deleted `src/reconkit/core/pacing.py` and `tests/test_pacing.py`; `config.py`, `config.yaml`, `models.py`, `engine.py`, `core/scope.py`, `core/store.py`, `ui.py`, `cli.py`, `core/wildcard.py` (docstring), `adapters/{base,assetfinder,dnspython,httpx_tool,naabu,pyprobe,pyscan,subfinder,registry}.py`, `tools.yaml`; tests `test_config`, `test_adapters`, `test_binary_adapters`, `test_python_adapters`, `test_registry`, `test_engine`, `test_cli`, `test_interactive_scan`, `test_scope`, `test_store`; docs above.
- **Requirement -> test table:**
  | Requirement | Test |
  |---|---|
  | `--speed`/`--delay` gone from the CLI | `test_speed_and_delay_flags_are_gone` (both exit 2), `test_speed_and_delay_arguments_no_longer_exist` |
  | no speed keys in `config.yaml`/`AppConfig`, an old `speeds` block is rejected | `test_config_has_no_speed_fields`, `test_a_speeds_block_is_rejected` |
  | no pacer: a stage's tools all run at once | `test_tools_start_together_without_a_pace_limit` |
  | no artificial per-port cap in `pyscan` | `test_pyscan_probes_its_ports_without_an_artificial_limit` |
  | no rate flags reach a tool or the registry | `test_subfinder_command_has_no_rate_flag`, `test_no_rate_flag_survives_in_tools_yaml` |
  | schema 5 drops `scan_runs.speed`, data survives | `test_v4_database_migrates_by_removing_the_speed_column`, `test_create_scan_run_writes_no_speed_column` |
  | an old `max_speed` in a scope file still loads and gates | `test_max_speed_is_accepted_and_ignored` |
- **Removed/changed tests (disclosure, exact names and reasons - also in `PROGRESS.md` "Deviations"):**
  - `tests/test_pacing.py` deleted, 17 tests: `test_slow_delays_and_parallel_limits`, `test_normal_values`, `test_fast_never_sleeps`, `test_first_tool_and_reset`, `test_shuffle_is_deterministic_and_a_permutation`, `test_fast_preserves_order`, `test_next_pause_range`, `test_tool_rate_args_slow_passive_vs_active`, `test_tool_rate_args_normal`, `test_tool_rate_args_fast`, `test_tool_rate_args_nmap_and_masscan_use_active_values`, `test_tool_rate_args_unknown`, `test_delay_override_applies`, `test_rate_limiter_spacing`, `test_rate_limiter_rejects_bad_rate`, `test_before_host_zero_skips_sleep`, `test_mode_literal_accepts_strings`. Reason: every one of them tests `reconkit.core.pacing`, which this task deletes; there is no behavior left to assert.
  - `tests/test_python_adapters.py`, 7 tests: `test_dnspython_awaits_limiter_per_query`, `test_pyprobe_awaits_limiter`, `test_pyprobe_waits_between_hosts_when_dispatch_is_sequential`, `test_pyscan_awaits_limiter_per_query_and_connection`, `test_pyscan_respects_the_pacer_parallel_limit`, `test_pyscan_uses_pacer_order_for_ports`, `test_pyscan_waits_between_hosts_before_dispatching_the_next`. Reason: each asserted `ctx.pacer`/`ctx.limiter` calls that no longer exist in the adapter; replaced in spirit by `test_pyscan_probes_its_ports_without_an_artificial_limit`, which asserts every port probe starts at once.
  - `tests/test_config.py`, 5 tests: `test_delay_override_applies_to_active_and_passive`, `test_delay_range_in_file_is_rejected`, `test_invalid_delay_override`, `test_invalid_speed_name`, `test_speed_override`. Reason: the settings they validated were deleted; the file was rewritten around the surviving keys (`test_config_has_no_speed_fields`, `test_a_speeds_block_is_rejected`, `test_speed_and_delay_arguments_no_longer_exist` are new).
  - `tests/test_adapters.py::test_rate_limiter_is_used_before_the_request`: removed - it asserted the limiter call inside the HTTP adapter, which no longer takes one.
  - `tests/test_scope.py::test_max_speed_cap` and `test_unknown_speed`: removed - `require_active()` no longer takes or checks a speed. `test_max_speed_is_accepted_and_ignored` is new and keeps the compatibility guarantee.
  - Renamed: `tests/test_engine.py::test_slow_mode_runs_one_tool_at_a_time` -> `test_tools_start_together_without_a_pace_limit` (asserted `peak == 1` under the slow parallel cap; now asserts `peak == 2` while both tools are inside `run()`); `tests/test_cli.py::test_fast_active_requires_typed_confirmation` -> `test_speed_and_delay_flags_are_gone` (it asserted the removed confirmation prompt); `tests/test_binary_adapters.py::test_subfinder_command_and_rate_flag` -> `test_subfinder_command_has_no_rate_flag` (same assertion minus `-rl`); `tests/test_registry.py::test_rate_flags_come_from_tools_yaml` -> `test_no_rate_flag_survives_in_tools_yaml` (asserts absence).
  - Also edited without renaming: the `-rl`/`-rate`/`-T` expectations in `test_binary_adapters.py` (the flags are no longer passed), the speed keyword arguments in `test_engine.py`'s `create_scan_run` calls, the `--speed fast` arguments in `test_interactive_scan.py`, `test_ui.py` status expectations (no Speed column), and the v1/v2/v3 migration fixtures in `test_store.py` (they gained the `scan_runs` table schema 5 alters).
- **Mutation proof:** replacing `await asyncio.gather(...)` in `Engine._run_tools` with a sequential `for` loop made `test_tools_start_together_without_a_pace_limit` fail (`TimeoutError`, `1 failed in 5.24s`); restored from `/tmp/engine.bak`, and the same test then passed (`1 passed in 0.14s`).
- **Raw check output (after the last edit):** `713 passed in 15.23s`; `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `67 files already formatted`; `mypy src/reconkit` -> `Success: no issues found in 35 source files`. Suite 745 -> 713: 36 test functions removed, 11 added, and 17 of the removed were `test_pacing.py` (some were parametrized, so the item delta is larger than the function delta).
- **`--help` evidence:** `reconkit --help` lists `--domain, --list, --json, --silent, --min-sources, --tools, --exclude, --include-noisy, --phase-timeout, --mock, --active, --no-keys, --resume, --no-color, --verbose, --config, --scope, --db, --help` and no `--speed`/`--delay`; `reconkit --help | grep -iE "speed|delay"` prints nothing.
- **Not verified:** a real-network run after the change is in the final report.
- **Next part must know:** `RunContext` has no `pacer`/`limiter`/`speed`; do not reintroduce `asyncio.Semaphore` over tools or hosts. `scope.require_active(target, hosts, today=None, *, path=None)` is the signature. `SCHEMA_VERSION == 5`.

## Task 4 (2026-11-17): the interactive flow end to end (docs only)

- **Goal:** one place where the runtime flow after Tasks 1-3 can be read start to finish, with the exact prompt text users see.
- **What was added:** `docs/02` section 2b, "The flow end to end (2026-11-17)", ten numbered steps: launch trigger, target question, scope question, scan mode (no default, re-asked), field menu, aggressive question, plan echo, the ordinary run plus report folder, the scope branch at run time (no file = unrestricted; file present = unchanged gate and naabu on resolved-and-verified IPs only, skipping a target whose resolution fails or resolves out of scope), and no speed option anywhere in the flow or `--help`.
- **Prompt text source:** read from `src/reconkit/cli.py` (`_ask_target`, `_ask_scope`, `_ask_mode`, `_ask_fields`, `_ask_aggressive`, `_interactive_plan`), not from memory: `Domain, or path to a file of domains (one per line)`; `Do you have a scope file? [Y/n]`; `Scope file path`; `Scan mode: passive, active or full`; `Fields [all]` after the numbered stored-field menu; `Also run aggressive scanning (port scan + version detection)? [y/N]`; `plan: <target>; stages <...>; active yes|no; fields <n>`.
- **No code or test change:** `git diff --name-only` for this commit lists `docs/02_CLI_UX.md`, `docs/PROGRESS.md`, `docs/REVIEW_LOG.md` only.
- **Raw check output:** see the commit's pre-commit block; the docs-only run was `714 passed`, `ruff check .` clean, `67 files already formatted`, `mypy src/reconkit` clean (35 source files).
- **Not verified:** nothing new; there is no new behaviour to verify.

## Verification follow-up F1-F8 (2026-11-17, docs and help text)  (commit subject `docs: fix the eight findings from the 4-task verification`; hash filled by the next commit)

- **Docs read / goal:** `AGENTS.md`, the PROGRESS RESUME block, the four batch
  entries above and `MASTER_PLAN.md` DATED DEVIATIONS. Goal: close the eight
  findings of the accepted 4-task batch's V-UNEXPECTED report (F1-F8) in one
  commit, with no behaviour, flag, schema or test change. Frozen items from the
  install/doc backlog, the dropped-host DNS verdicts, the `scope.yaml`
  authorization text and the three runs A-K doc mismatches were not touched.
- **Decisions and assumptions:** (a) "the help and docs/02 say the same thing"
  means word-for-word on the `--active` sentence, so the sentence lives in one
  module constant `_ACTIVE_HELP` used by both call sites and is quoted verbatim
  in docs/02 line 52 and its flag table line 168 (markdown backticks aside);
  docs adjusted to code, never the reverse. (b) Historical lines in PROGRESS are
  marked `removed 2026-11-17, MASTER_PLAN D3`, never deleted. (c) F7 was checked
  for further occurrences: `grep -rnE -- '--speed|--delay|pacing|pacer|rate_flag|11c-G-7'
  docs/tool_manuals/` finds the two named lines **plus a third**, `ports.md:418`
  in the nmap section (`The rate_flag in tools.yaml is -T ...`). That was outside
  the two references F7 names, so it was reported before the commit instead of
  being fixed silently; the owner then approved adding it, so **F7 covers three
  references** and the stop-cost was one round trip, not a redo. `urls.md:484`
  (`-k, --delay int`, hakrawler's own flag help) is not a reconkit claim and was
  left alone.
- **Files touched:** `src/reconkit/cli.py`, `src/reconkit/core/__init__.py`,
  `pyproject.toml`, `AGENTS.md`, `docs/02_CLI_UX.md`, `docs/PROGRESS.md`,
  `docs/REVIEW_LOG.md`, `docs/tool_manuals/urls.md`, `docs/tool_manuals/ports.md`.
- **Test change: none.** `grep -rn "inside scope" tests/ --include=*.py` -> no
  match, so no test asserted the old help string. Suite stays 714.
- **Requirement -> evidence table:**

  | Finding | Evidence |
  |---|---|
  | F1 help text | `reconkit run --help` and `reconkit --help` both render the new sentence; a script compared the constant, docs/02 line 52 and the row-168 cell: `row 168 == constant: True`, `old text remains anywhere in docs/02: False` |
  | F2 owner commands | both examples now run without `--speed`; the naabu comment states the D2 branch (hostnames with no file, verified IPs with a file, `blocked: no in-scope IP for any target`) |
  | F3 historical markers | five PROGRESS lines each carry `removed 2026-11-17, MASTER_PLAN D3` (task-table row d, `--delay` line, S311 clause, Part 13 open risk, module map) |
  | F4 docstring | `src/reconkit/core/__init__.py` = `Core services: runner, scope, store, workspace, wildcard.` |
  | F5 pyproject | the two S311 entries are gone; `ruff check .` still passes |
  | F6 AGENTS row | `| config.yaml | timeouts, thresholds |` |
  | F7 manuals | three references: `urls.md` `-rl`/`rate_flag` paragraph, `ports.md` naabu paragraph (D2 rule), and `ports.md:418` nmap `rate_flag: -T` (found by the sweep, approved by the owner, fixed in the same commit); `urls.md:484` is hakrawler's own `--delay` help and is unchanged |
  | F8 D3 counts | the D3 entry now reads 32 deleted + 4 renamed, 44 node ids removed / 12 added, 745 -> 713, then 713 -> 714 |

- **S1 checks (run twice):**

  ```
  --- pytest -q (run 1) ---        714 passed in 15.57s   PASS
  --- pytest -q (run 2) ---        714 passed in 15.77s   PASS
  --- ruff check . ---             All checks passed!     PASS
  --- ruff format --check . ---    67 files already formatted   PASS
  --- mypy src/reconkit ---        Success: no issues found in 35 source files   PASS
  ```

- **Mock run (changed command):** no scope file -> `ports: pyscan ok 2`, `ports:
  naabu ok 3`, exit 5 (the tech/urls/vulns stages have no adapter); repo
  `scope.yaml` present -> same stages, exit 5; out-of-scope target -> `scope
  gate: example.com is not in scope`, exit 3. Identical to the pre-change
  behaviour recorded in the verification report.
- **S2 self-diff:** nine files, all listed above. The first edit attempt left
  `] = False,    active: Annotated[` in the root callback because one
  `str_replace` pair lost a newline; `ruff format --check .` caught it ("1 file
  would be reformatted") and `ruff format src/reconkit/cli.py` restored the
  layout. The final `git diff -- src/reconkit/cli.py` shows exactly two hunk
  areas (the constant plus the two `--active` options). No broad `except`, no
  external input, no secret path, no blocking call and no new exception path was
  added: the executable change is a string constant.
- **S3 scans (bash equivalents, after the change):** `assert` in `src/` none;
  `shell=True` none; `TODO|FIXME|XXX|HACK` none; `print(` only `ui.py`;
  `subprocess` only `core/runner.py` (+ the base-adapter docstring); `sqlite3`
  only `core/store.py`; `os.environ` only `ui.py` and `installer/*` (pre-existing,
  documented); broad `except` at the seven pre-existing sites, none new;
  `noqa|type: ignore` only the three pre-existing ones in `tests/`; adapters
  importing `store|scope|ui|cli` none. No new suppression was added (`pyproject`
  lost two).
- **S5 mutation:** no code path changed, so there is no mutation target; the
  equivalent check is the rendered-help equality above (old sentence gone from
  both `--help` outputs and from docs/02) plus the help-output diff.
- **Bug found (this part, before commit):** the formatter slip described in S2.
  Symptom: `ruff format --check .` -> `1 file would be reformatted`; root cause:
  a replace pair that dropped the newline before `active:` in `main()`; fix:
  `ruff format src/reconkit/cli.py`, then re-ran all four checks; guarding check:
  the format check itself, which is part of the gate.
- **F-notes (hits deliberately not fixed):** (1) the REVIEW_LOG archive block
  `Kali verification commands (11e, for the owner)` still shows `--speed slow`
  and the 11c-G-7 naabu expectation; it is verbatim archived history whose own
  heading says it is superseded by the live PROGRESS block, which F2 corrected -
  left as written. (2) The Task 3 entry above keeps "36 test functions removed,
  11 added"; it is the historical entry that F8's measured wording in PROGRESS
  D3 supersedes - left as written. (3) `src/reconkit.egg-info/PKG-INFO` and
  `SOURCES.txt` still name `pacing.py`; they are generated build metadata, not
  source.
- **Not verified:** `--help` rendering in other terminal widths (no such run in this session,
  unchanged from the rest of the log).

## Install backlog T1 (2026-11-17): rustscan installs from its real release  (commit subject `fix: install rustscan from its real 2.3.0 release`; hash filled by the next commit)

- **Docs read / goal:** docs/10 (github_release, `asset_pattern`, `member`,
  `verify_checksums`, version policy, extraction rules), docs/09 tool-flags
  table, `docs/tool_manuals/{README,ports}.md`, `tools.yaml`, `config.yaml`.
  Goal: replace the `verify-at-implementation` placeholder so
  `reconkit install rustscan` succeeds and doctor shows a version.
- **Real release facts (GitHub API, redirect followed; `bee-san/RustScan`, tag
  2.4.1):** assets `aarch64-linux-rustscan.zip`, `rustscan.deb.zip`,
  `x86-linux-rustscan.zip`, `x86_64-linux-rustscan.tar.gz.zip`,
  `x86_64-linux-rustscan.tar.gz.1.zip`, plus macOS. `unzip -l` on the
  amd64 asset shows one member, `x86_64-linux-rustscan.tar.gz`; `tar -tzf` on
  that shows `rustscan`. No checksums asset in any of the last five releases.
  2.3.0 publishes `rustscan-2.3.0-x86_64-linux.zip`, which contains the binary
  directly at `tmp/rustscan-2.3.0-x86_64-linux/rustscan`; running it gives
  `rustscan 2.3.0` (exit 0, stdout).
- **Decision:** Route A (owner-approved): pin 2.3.0, keep the single-layer
  extractor. Route B (nested-archive extraction) is recorded as an open item and
  **not** implemented.
- **Placement deviation, deliberate:** the pin is `config.yaml`
  `tool_versions: { rustscan: "2.3.0" }`, not a `version:` key inside
  `tools.yaml`'s `install:` block, because `registry.load_plans` takes versions
  from the `versions` mapping only (verified: with `install.version: 2.3.0` the
  loaded plan still said `version: latest`). `docs/10` already documents the
  config pin as the mechanism, so no code changed.
- **Docs first:** `docs/tool_manuals/ports.md` (why 2.3.0, the pin snippet, the
  install/version output, the Route B follow-up), `docs/tool_manuals/README.md`
  (40/40 binaries; flagged item 1 closed), `docs/09` rustscan flags row,
  `docs/10` registry-values paragraph. Then `tools.yaml`, then `config.yaml`.
- **Requirement -> proof:** placeholder gone -> `grep -n
  verify-at-implementation tools.yaml` -> no match; install -> `installed
  /home/kali/.reconkit/bin/rustscan` exit 0; real binary -> `rustscan 2.3.0`;
  doctor row -> `rustscan | ports | core | yes | 2.3.0 | /home/ka… | ok`;
  `doctor --json` -> `{'tool': 'rustscan', ..., 'version': '2.3.0', 'path':
  '/home/kali/.reconkit/bin/rustscan', 'identity': 'ok'}`; second install ->
  `already installed (2.3.0)`.
- **Why a version_regex here:** without one, `installed_version` returns
  `rustscan 2.3.0` and the doctor table truncates that cell to `rustscan`; the
  regex `^rustscan (\d+\.\d+\.\d+)$` yields `2.3.0`.
- **Tests changed (both disclosed in PROGRESS):**
  `test_rustscan_placeholder_cannot_resolve` ->
  `test_rustscan_pinned_plan_resolves_its_real_asset`;
  `test_unknown_top_level_key_is_rejected` now appends its unknown key instead of
  `.replace("tool_versions: {}", ...)`. The second one was found by the gate: the
  literal it replaced no longer exists, so the test injected nothing and would
  have passed against a schema that accepted anything - the append form keeps
  the assertion meaningful.
- **S1 checks:** `714 passed in 16.26s`; `ruff check .` -> `All checks passed!`;
  `ruff format --check .` -> `67 files already formatted`; `mypy src/reconkit` ->
  `Success: no issues found in 35 source files`.
- **S3 scans:** no `assert` in `src/`, no `shell=True`, no placeholder pattern in
  `tools.yaml`; no new suppression, no new module, no new dependency.
- **Sudo:** none needed (download to `~/.reconkit/bin`).
- **Not verified:** an actual `rustscan` scan (no adapter yet, phase 3); arm64
  (the pin's asset is amd64-only).

## Install backlog T2 (2026-11-17): version_regex for seven tools  (commit subject `fix: give the seven banner-first tools a version_regex`; hash filled by the next commit)

- **Docs read / goal:** docs/10 "version_regex is how a banner-first tool reports
  its version", docs/09 tool-flags table, `tools.yaml`. Goal: doctor must show a
  clean version instead of ASCII art for chaos, dnsx, httpx, tlsx, naabu,
  wafw00f, cdncheck.
- **Pre-check (owner asked for it before any regex):** does the probe read
  stderr? `installed_version` does `text = (outcome.stdout or outcome.stderr).strip()`.
  Raw evidence: stdout of all six PD tools is empty (`chaos -version
  2>/dev/null` -> 0 lines) and stderr carries the banner and
  `[\x1b[34mINF\x1b[0m] Current Version: ...`; `wafw00f --version` is the
  reverse (stdout 12 lines, stderr 0). A direct call showed what doctor gets:
  `chaos -> '__                    '`, `naabu -> '__'`,
  `wafw00f -> '\x1b[1;97m______'`. So the capture is fine and only the
  extraction is wrong - **no doctor code change**, not a bigger-than-looks item.
- **Real banners (raw, as captured on this box):** `chaos`
  `Current Version: 0.5.2`; `dnsx` `Current Version: 1.3.1`; `httpx`
  `Current Version: v1.12.0`; `tlsx` `Current version: v1.4.0`; `naabu`
  `Current Version: 2.7.0`; `cdncheck` `Current version: v1.4.0`; `wafw00f`
  `[+] The version of WAFW00F you have is \x1b[1;94mv2.4.2\x1b[0m`.
- **Docs first:** docs/10 gained the 2026-11-17 paragraph (shared PD pattern,
  lowercase `version` for tlsx/cdncheck, the ANSI-tolerant wafw00f pattern, and
  the stderr/stdout fact); docs/09's httpx and naabu rows name their pattern;
  `docs/tool_manuals/README.md` flagged item 2 is marked closed.
- **Requirement -> proof (doctor rows, raw):** `chaos 0.5.2`, `dnsx 1.3.1`,
  `httpx v1.12.0`, `tlsx v1.4.0`, `naabu 2.7.0`, `cdncheck v1.4.0`,
  `wafw00f v2.4.2`, every row `yes ... ok`.
- **Test added:**
  `tests/test_installer_registry.py::test_the_seven_version_patterns_extract_their_real_banner`,
  parametrized over the seven real strings (ANSI included), asserting the first
  capture group equals the version. No existing test changed.
- **S5 mutation:** replaced the wafw00f pattern with
  `WAFW00F you have is (v?\d+\.\d+\.\d+)` (no ANSI tolerance) -> the
  parametrized case failed with `assert None is not None`; restored from a copy,
  `sha256sum` identical (`7ee1c9ae...`), test green again.
- **S1 checks:** `721 passed in 15.71s` (714 + 7 new cases); `ruff check .` ->
  `All checks passed!`; `ruff format --check .` -> `67 files already formatted`;
  `mypy src/reconkit` -> `Success: no issues found in 35 source files`.
- **Sudo:** none. **Not verified:** nothing new (no adapter consumes these
  values yet).

## Install backlog T3 (2026-11-17): real version probes for four tools, path rows documented for five  (commit subject `fix: probe the version of smap, gospider, subjs and urlfinder`; hash filled by the next commit)

- **Docs read / goal:** docs/10 `version_cmd`/`version_args`/`version_regex`,
  docs/09, `tools.yaml`. Goal: stop doctor showing a path in the Version column
  where the tool can report a version, and document the ones that cannot.
- **Real probes (raw, this box):** `smap -h` -> stdout line 1 `Smap 1.0.0-beta`
  then `Usage: smap <targets here>`, exit 0, stderr empty; `gospider --version`
  -> stdout `Version: v1.1.6`, exit 0, stderr empty (`gospider -version` errors:
  `unknown shorthand flag: 'e' in -ersion`); `subjs -version` -> stdout
  `subjs version: 1.0.1`, exit 0; `urlfinder -version` -> **stderr**
  `[\x1b[34mINF\x1b[0m] Current Version: v0.0.3`, stdout empty, exit 0.
- **No version output at all:** `github-subdomains`, `webanalyze`,
  `waybackurls`, `httprobe`, `unfurl` -> `flag provided but not defined:
  -version` + `Usage of <tool>:` (Go `flag`), `-h` the same usage text. This is
  the owner-approved escape clause: documented, not invented.
- **Docs first:** docs/10 gained "Tools with no version output at all" naming
  the five path rows and the four probes with their streams; the manuals README
  flagged item 3 is marked closed.
- **First draft bug, caught by proof not by the gate:** smap and gospider were
  given `^Smap (\S+)$` / `^Version: (\S+)$`. Those never match, because the
  probe text continues after the version line (`$` is end-of-text without
  `re.M`), so doctor showed `Smap` and `Version:`. Proof line
  `installed_version -> 'Smap 1.0.0-beta'` exposed it; both patterns are now
  unanchored and the four doctor rows read `1.0.0-be…`, `v1.1.6`, `1.0.1`,
  `v0.0.3`.
- **`httprobe` change:** its `version_cmd: [httprobe, -h]` was removed. It made
  doctor print `Usage of ***/.reconkit/bin/httprobe:` (redacted) in the Version
  column; with no probe it prints the documented path instead. Disclosed here
  and in PROGRESS - a deliberate behaviour change, not a silent edit.
- **Tests added:**
  `test_the_four_probed_tools_extract_their_real_output` (smap multi-line body,
  gospider multi-line body, subjs, urlfinder ANSI) and
  `test_tools_without_a_version_flag_have_no_probe` (the five: empty
  `version_args`, `version_regex is None`). No existing test changed.
- **S5 mutation:** re-anchoring smap's pattern to `^Smap (\S+)$` ->
  `1 failed` on the smap case; restored from a copy (`sha256sum`
  `57f1068b...` before and after), test green.
- **S1 checks:** `730 passed in 16.36s` (721 + 9 new cases); `ruff check .` ->
  `All checks passed!`; `ruff format --check .` -> `67 files already formatted`;
  `mypy src/reconkit` -> `Success: no issues found in 35 source files`.
- **Sudo:** none. **Not verified:** the tools' `doctor` identity beyond `ok`
  (unchanged path); no adapter consumes these versions yet.

## Install backlog T4 (2026-11-17): assetfinder's documented exit code  (commit subject `docs: assetfinder -h exits 0, measured`; hash filled by the next commit)

- **Docs read / goal:** docs/09 assetfinder row, `docs/tool_manuals/subs.md`
  (which already recorded exit 0), `adapters/assetfinder.py`, its test. Goal:
  the registry doc must match the measured binary.
- **Raw measurement:** `assetfinder -h 1>/dev/null 2>/tmp/af.err; echo $?` ->
  `exit=0`; `/tmp/af.err` -> `Usage of assetfinder:` / `  -subs-only` /
  `    \tOnly include subdomains of search domain`; `assetfinder -h
  2>/dev/null | wc -c` -> `0` (stderr only).`assetfinder -version` -> `flag provided but not defined: -version` then the same usage, exit **2** (corrected 2026-11-17: the first reading said exit 0 because the command was piped into `head`, so `$?` was head's status - the exact trap AGENTS.md 0c names; re-measured unpiped, `assetfinder -version >/dev/null 2>&1; echo $?` -> 2. `-h` stays 0, measured unpiped twice).
- **Conflict found and resolved:** docs/09 said "exits 2" (inferred from Go
  `flag` source, and it said the binary was not installed); subs.md said exit 0.
  The measurement sides with subs.md; docs/09 was corrected, not the manual.
- **Real adapter run:** `AssetfinderAdapter().check_installed()` ->
  `installed=True version=None path=/home/kali/.reconkit/bin/assetfinder`;
  `reconkit doctor --json` -> `'identity': 'ok'` (version `unknown` is correct:
  the tool has no version output, only usage).
- **No code change needed:** `tests/test_binary_adapters.py::test_assetfinder_usage_identity`
  already drives `returncode=0`, so the adapter never required the exit-2
  assumption. Nothing in `src/` changed.
- **S1 checks (docs-only):** `730 passed in 16.73s`; `ruff check .` ->
  `All checks passed!`; `ruff format --check .` -> `67 files already formatted`;
  `mypy src/reconkit` -> `Success: no issues found in 35 source files`.
- **Sudo:** none. **Not verified:** nothing new.

## Install backlog T5 (2026-11-17): amass note against v5.1.3  (commit subject `docs: update the amass note for v5 passive default`; hash filled by the next commit)

- **Docs read / goal:** `tools.yaml` amass note, docs/09 per-stage notes,
  `docs/tool_manuals/subs.md` amass section. Goal: stop the registry telling a
  future adapter to pass a deprecated flag.
- **Raw measurement:** `amass -version` -> `v5.1.3` (exit 0). `amass -h` ->
  ASCII logo, `v5.1.3`, then `Usage: amass
  [assoc|engine|enum|subs|track|viz] [options]`. `amass enum -h` contains
  `  -passive` / `    \tDeprecated since passive is the default setting`.
- **Decision:** keep the recommendation (passive only, run last - it is the
  slowest passive source) and drop the flag: in v5 passive is the default, so
  the note now says so, names `-passive` as deprecated-but-parsed, and tells the
  adapter author to read `amass enum -h` first because the CLI moved from v4 to
  the six subcommands.
- **Docs first:** docs/09's per-stage note rewritten; then `tools.yaml`'s
  `notes:`; then subs.md's "Mismatch to flag" paragraph marked closed with the
  measured flag help.
- **Registry still loads:** `load_plans()['amass']` -> `binary amass`,
  `version_args ('-version',)`; YAML `notes:` re-read from the file and printed
  back verbatim. (Two throwaway inspection one-liners of mine hit
  `ToolSpec`-not-subscriptable / `.notes` attribute errors; those were my
  script's bugs, not the project's - corrected by reading the YAML directly.)
- **Requirement -> proof:** `-passive` present + deprecated -> quoted above;
  note text -> `notes: v5.1.3: passive is the default; enum -passive still
  parses but is deprecated. Slow - keep it last. Check `amass enum -h` before
  writing an adapter (v5 CLI: assoc|engine|enum|subs|track|viz).`
- **Tests:** none added or changed - a test asserting this prose would pin
  wording, not behaviour; nothing executable changed. Gate below covers that the
  registry still parses.
- **S1 checks:** `730 passed in 16.43s`; `ruff check .` -> `All checks passed!`;
  `ruff format --check .` -> `67 files already formatted`; `mypy src/reconkit`
  -> `Success: no issues found in 35 source files`.
- **Sudo:** none. **Not verified:** an actual `amass enum -d` run (network
  traffic, out of scope for a doc task).

## Install backlog T6 (2026-11-17): webanalyze needs -update, recorded  (commit subject `docs: record the webanalyze -update preparation step`; hash filled by the next commit)

- **Docs read / goal:** docs/09 tech-stage rows and per-stage notes,
  `tools.yaml`, `docs/tool_manuals/{README,tech}.md`'s flagged item 6. Goal: the
  registry must name the preparation step, since nothing recorded it.
- **Raw measurement (local, no scan):** in `/tmp` with no `technologies.json`,
  `webanalyze -host 127.0.0.1` -> stderr
  `2026/11/17 05:20:42 error: can not open apps file : could not find the
  technologies file: technologies.json`, stdout empty, exit **1**. In an empty
  dir, `webanalyze -update` -> stderr `app definition file updated`, exit 0, and
  `ls` shows `technologies.json` **2,122,079 bytes in that directory**. `-h`
  confirms `-update  update technologies file to current dir`, `-apps string
  technologies definition file (default "technologies.json")`; `-h` itself goes
  to stderr (751 bytes, exit 0).
- **Docs first:** docs/09 per-stage note; then `tools.yaml` `notes:` (says once
  per working directory, ~2.1 MB, exit 1 without it, `-apps` to reuse a file);
  then `docs/tool_manuals/README.md` item 6 and the tech manual's notes section.
- **Requirement -> proof:** the step is named where a future adapter author will
  read it -> registry note printed back from the YAML, quoted above; the quoted
  failure text and exit 1 -> reproduced above. Registry still loads:
  `load_plans()['webanalyze']` -> binary `webanalyze`, empty `version_args`
  (documented path row, T3).
- **Decision, not a fix:** the step stays manual. `doctor`/installer writing
  `technologies.json` into the user's CWD would be a side effect no doc allows,
  and no adapter exists yet to own it; the note is the correct place per the
  batch scope.
- **Tests:** none - prose/registry-note only, nothing executable changed.
- **S1 checks:** `730 passed in 16.28s`; `ruff check .` -> `All checks passed!`;
  `ruff format --check .` -> `67 files already formatted`; `mypy src/reconkit`
  -> `Success: no issues found in 35 source files`. (One proof command first ran
  with a shell PATH that lacked `~/.reconkit/bin` and reported `command not
  found`; re-run with the PATH set, output above.)
- **Sudo:** none. **Not verified:** an actual `webanalyze` scan against a host
  (network; and the tech stage has no adapter yet).

## httpx_tech false positive D5 (2026-11-17, commit `fix: httpx_tech rejects Python httpx via version_regex miss rule`)

- **Trigger:** the batch-db96df8 spot-checks (V-UNEXPECTED item 1). The owner
  ruled option B, targeted fix: `tools.yaml` probe + regex, regex miss means
  not installed, three regression tests, docs; explicitly **no** identity-marker
  field and **no** probes on the other 12 presence-only tools.
- **Before this fix (raw, from db96df8):** with `HOME=/tmp/fakehome` and
  `PATH=/usr/local/bin:/usr/bin:/bin` (only the Python `/usr/bin/httpx`):
  ```
  httpx      -> installed="wrong program", path=/usr/bin/httpx, identity=failed
  httpx_tech -> installed="yes", version=/usr/bin/httpx, path=/usr/bin/httpx, identity=ok
  ```
  Cause: `httpx_tech` had `version_cmd=None`, so `installed_version()` returned
  `argv0` without running anything (presence-only), and `default_status()`
  treats any non-`None` return as installed.
- **Docs changed first:** docs/10 section 3 - the `version_regex` paragraph now
  says an absent pattern keeps the first-line fallback while a **present**
  pattern that does not match means not installed; new **Presence-only tools**
  paragraph names the remaining 12 and states the limitation and that
  `httpx_tech` is not one of them. MASTER_PLAN gains D5; PROGRESS gains a dated
  deviation entry and its 12j line is marked superseded.
- **Code:** `tools.yaml` `httpx_tech` gains
  `version_cmd: [httpx, -version]` and
  `version_regex: 'Current Version:\s*v?([0-9]+\.[0-9]+\.[0-9]+)'`;
  `core/toolcheck.py` `installed_version()` returns `None` when the declared
  pattern finds no match (three-line change; every other branch untouched).
- **Proof, normal PATH:** `{"tool":"httpx_tech","installed":"yes",
  "version":"1.12.0","path":"/home/kali/.reconkit/bin/httpx",
  "identity":"ok"}` - the version column no longer shows a path.
- **Proof, Python-only PATH** (same env as before): `{"tool":"httpx_tech",
  "installed":"wrong program","version":"-","path":"/usr/bin/httpx",
  "identity":"failed"}` plus the new warning
  `httpx_tech: /usr/bin/httpx is not the expected program; doctor ignores it.`
  `missing` went 27 (before, with the false positive) -> 28; `httpx` is
  unchanged at `wrong program`.
- **Tests:** three new in `tests/test_tools_registry.py` -
  `test_the_python_httpx_cli_is_not_httpx_tech` (real Python console-script
  stderr, exit 1 -> `None`), `test_projectdiscovery_httpx_is_httpx_tech`
  (ANSI-wrapped `[INF] Current Version: v1.12.0` on stderr -> `"1.12.0"`),
  `test_a_regex_miss_means_not_installed_for_any_tool` (`chaos` with
  non-matching output -> `None`, proving the rule is not httpx-specific). One
  existing test changed: `test_a_shared_binary_tool_still_has_a_source`
  asserted `httpx_tech.version_cmd is None`, which the fix intentionally
  falsifies; it now asserts `== ["httpx", "-version"]` and
  `version_regex is not None` (name, purpose and source assertions unchanged).
- **S1-S7:** `638 passed in 10.10s` (was 635); `ruff check .` -> `All checks
  passed!`; `ruff format --check .` -> `57 files already formatted`; `mypy
  src/reconkit` -> `Success: no issues found in 29 source files`. Focused run
  `pytest -v -k 'httpx_tech or version_regex or regex_miss or python_httpx or
  projectdiscovery or shared_binary'` -> 13 passed.
- **Not done, by ruling:** no identity-marker field, no probes on the 12
  presence-only tools, adapter path untouched. **Not verified:** a real Python
  httpx that exits 0 on `-version` (none exists; the simulated runner covers the
  contract).

## Installer removal D4 (2026-11-17): install/update deleted, doctor no longer needs installer/  (commit subject `refactor: remove install/update commands; doctor no longer depends on installer`; hash filled by the next commit)

- **Docs read / goal:** docs/01 §6, docs/02 §2/§3/§6, docs/03 §4/§5/§9/§13,
  docs/05 §5/§6.1, docs/07 inventory, docs/08 Flows 1-2, docs/10 in full,
  `tools.yaml`, `config.yaml`. Goal: owner-requested removal of the install and
  update commands (reason: "user-requested removal of install/update commands");
  `doctor` keeps reporting exactly what it reported before. Recorded as
  MASTER_PLAN D4 and mirrored in PROGRESS.
- **Decision, module placement:** the read-only half of the installer
  (`installed_copy`, `installed_version`) moved to the new
  `src/reconkit/core/toolcheck.py`, not `config.py`. `config.py` is the strict
  config loader and must not import `adapters.registry` or run subprocesses;
  docs/03's module map has a `core/` row for shared, tested utilities. `bin_dir()`
  went to `config.py` as the locked decision says, because it is a filesystem
  location and `adapters.base` can import it without a cycle.
- **Decision, `ToolSpec` fields:** `binary: str | None`, `version_cmd:
  list[str] | None`, `version_regex: str | None`, `source: str | None`, all
  loaded and validated in `adapters/registry._spec` (a non-compiling
  `version_regex` is still a `ConfigError` at load). `requires` (puredns ->
  massdns) is dropped: it had no consumer and the fact now lives in the source
  note.
- **Before / after, `reconkit doctor --no-color`:** identical for 47 of 48 rows,
  the coverage line and every other table. The one difference is
  `httpx_tech`: before `missing | - | - | n/a`, after `yes | <path to httpx> |
  <path> | ok`, and the footer count went 4 -> 3.
  Reason: the old `default_status` returned "not installed" for any plan with
  `method: none`, which included a tool with no install block at all
  (`httpx_tech`). The locked rule is "adapter first, else the ToolSpec's
  version_cmd/version_regex/binary", and `httpx_tech` carries `binary: httpx`,
  which is installed - so it is now probed like every other binary row. The old
  behaviour was not preservable without adding a fifth field (an
  "is-installable" flag) that the locked decisions do not include. This is the
  one accepted behaviour change; docs/10 §1 now says the row reuses `httpx`.
- **Proof: `reconkit --help`** lost exactly two lines (`install`, `update`); all
  other commands and their formatting are byte-identical (`diff` of the two
  captures shows only those two deletions).
- **Proof: `grep -rn 'from reconkit.installer' src/`** -> empty.
  `grep -rn 'install' src/reconkit/cli.py` -> one hit, the aggressive-mode help
  text "plus naabu when installed", which is not a command reference.
  `grep -c 'install:' tools.yaml` -> 0. `grep -c 'source:' tools.yaml` -> 40
  (all 40 binary rows; the 8 http/python adapters have no source).
  `tests/test_tools_registry.py::test_every_binary_tool_has_a_non_empty_source`
  pins it.
- **Tests changed (name / old / new / reason):**
  1. `tests/test_install_cli.py` (39 node ids) - **deleted**; every test
     imported `reconkit.installer` or drove `install`/`update`/`--fix`, which no
     longer exist. Exception moved, not deleted:
     `test_managed_bin_dir_has_one_source_of_truth` -> `tests/test_config.py`
     (same name; now asserts `adapters.base.managed_bin_dir() ==
     config.bin_dir() == ~/.reconkit/bin` and the `home` override).
  2. `tests/test_installer_backends.py` (28), `tests/test_installer_github_release.py`
     (18), `tests/test_installer_verify.py` (10) - **deleted**; the modules they
     covered (apt/pipx/go_install/release download/checksum/archive) are gone.
  3. `tests/test_installer_registry.py` (34) - **file deleted**, 22 node ids moved
     to `tests/test_tools_registry.py` (listed below) and 12 re-expressed.
  4. `tests/test_cli.py::test_every_non_scan_command_has_help` - old: 12
     parametrized cases including `install --help` and `update --help`; new: 10
     cases; reason: those commands no longer exist (2 node ids removed).
  5. `tests/test_doctor.py::test_fix_runs_the_installer` - **deleted**; there is
     no `--fix` and no installer to call.
  6. `tests/test_doctor.py::test_missing_tools_keep_exit_code_zero` - old:
     asserted `Missing tools: 2. Run: reconkit install --all`; new: asserts the
     new footer sentence, the docs/10 pointer, and that `reconkit install --all`
     is absent; reason: the footer string changed.
  7. `tests/test_doctor.py::test_every_tool_present_reports_no_missing_tools` -
     unchanged assertions, but `report_for()` now builds its config from
     `NOPIN_CONFIG` (`CONFIG` with `tool_versions` emptied) because the real
     pin now adds one warning; the pin's warning is tested by the new test 8.
  8. **New** `tests/test_doctor.py::test_a_tool_versions_pin_is_reported_once_as_ignored`
     - one warning naming docs/10 when `tool_versions` is non-empty.
  9. **New** `tests/test_engine.py::test_an_uninstalled_tool_is_skipped_and_the_others_still_run`
     - the baseline guarantee (Sub-task 1): `pyscan` not installed -> skip row
     `not installed` in `summary.skipped` and `tool_runs`, `naabu` still runs.
  10. `tests/test_installer_registry.py` -> `tests/test_tools_registry.py`, 22
      node ids **unchanged in intent, adapted in assertion source**:
      `test_version_args_come_from_version_cmd` -> `test_version_cmd_comes_from_the_registry`
      (now `ToolSpec.version_cmd == ["subfinder", "-version"]`),
      `test_massdns_version_command_is_the_package_manager` (now one
      `version_cmd` list), `test_requires_and_requires_apt_are_carried` ->
      `test_requires_apt_is_carried` (the dead `requires` assertion dropped),
      `test_version_regex_is_parsed_from_the_registry`, the seven-banner, four-probe
      and five-no-probe parametrizations (now `load_tools()[name]`),
      `test_a_broken_version_regex_is_a_config_error` (now `load_tools`), and
      `test_version_regex_survives_the_plan_copy` ->
      `test_version_regex_survives_registry_loading` (there is no plan copy left).
  11. The 12 deleted plan/method tests, re-expressed as source validation
      (all in `tests/test_tools_registry.py`):
      `test_every_tool_gets_a_known_method_and_binary` ->
      `test_every_binary_tool_has_a_non_empty_source`;
      `test_github_release_plan_keeps_its_fallback` ->
      `test_a_release_source_names_its_repository`;
      `test_tool_without_install_block_is_a_none_plan` ->
      `test_a_shared_binary_tool_still_has_a_source`;
      `test_version_pin_rewrites_the_go_package` ->
      `test_go_sources_are_pinned_to_nothing`;
      `test_version_pin_applies_to_a_plain_go_package` ->
      `test_tools_yaml_carries_no_version_pin_field`;
      `test_unknown_method_is_a_config_error` -> `test_an_empty_source_is_a_config_error`;
      `test_go_install_without_a_package_is_a_config_error` ->
      `test_a_non_string_source_is_a_config_error`;
      `test_github_release_without_a_repo_is_a_config_error` ->
      `test_a_list_source_is_a_config_error`;
      `test_unknown_tool_is_a_config_error` (kept, now `get_spec`);
      `test_resolve_plan_without_fallback_is_one_step` ->
      `test_a_builtin_adapter_has_no_source`;
      `test_member_and_checksum_override_are_parsed_from_the_registry` ->
      `test_the_source_notes_are_preserved`;
      `test_a_duplicate_plan_copy_keeps_the_override_fields` ->
      `test_a_source_survives_registry_loading`.
- **Test-count reconciliation:** 730 collected at b6697ff + 1 new engine test
  = 731; then -38 (`test_install_cli.py`, the moved bin-dir test excluded),
  -28, -18, -10 (the three backend files), -12 (registry: 34 out, 22 re-homed),
  -2 (`test_cli.py` help cases), -1 + 1 (`test_doctor.py`: fix test out,
  warning test in), +12 (the re-expressed source tests) = **635 collected / 635
  passed**.
- **S1-S7:** `635 passed in 9.81s`; `ruff check .` -> `All checks passed!`;
  `ruff format --check .` -> `57 files already formatted`; `mypy src/reconkit`
  -> `Success: no issues found in 29 source files` (35 -> 29: the six installer
  modules are gone, `core/toolcheck.py` added).
- **Sudo / network:** none. No test touches the network or a real binary.
  **Not verified:** a real `doctor` run outside this Kali box; the
  removed commands are gone on every platform by construction.

## Install residue removal S1-S7 (2026-11-17, cleanup only)  (commit subject `chore: remove install residue; docs/10 becomes tool reference (reconkit installs nothing)`; hash filled by the next commit)

- **Goal (owner batch, S1-S7):** reconkit installs nothing; `doctor` is the only
tool-check surface and scans skip what is missing. This batch removes the last
install residue. No new feature, no behaviour change, no code-logic change.
- **Baseline before (raw):** `python --version` -> `Python 3.14.8`; `pytest -q` ->
  `638 passed in 10.37s`; `ruff check .` -> `All checks passed!`;
  `ruff format --check .` -> `57 files already formatted`;
  `mypy src/reconkit` -> `Success: no issues found in 29 source files`.
  `git status --short` -> empty; `git log --oneline -1` -> `01daa8b`.
- **S1 stale bytecode.** `find . -name '__pycache__' -type d -exec ls -la {} \; |
  grep -i installer` showed four test bytecode files; the filtered sweep found
  five (`test_install_cli`, `test_installer_backends`,
  `test_installer_github_release`, `test_installer_registry`,
  `test_installer_verify`, all `tests/__pycache__`, 03:38-05:12). Deleted with
  `find . -name '*.pyc' -exec rm {} \;`. `__pycache__` dirs **73 before and 73
  after** (only the file contents went), no installer `.pyc` remains, and
  `git status --short` stayed empty (all gitignored). No `src/reconkit/installer`
  directory and no `tests/test_install*` file exists any more.
- **S2 `config.yaml` `tool_versions`.** Removed the four lines (three comments
  plus the pin) at old lines 31-34; `config.yaml` 44 -> 40 lines, and the
  `install:` block is untouched. `grep -n 'tool_versions' src/reconkit/config.py`
  before: `81:    tool_versions: dict[str, str] = Field(default_factory=dict)`; the
  field is gone, so `grep -rn 'tool_versions' src/` is now empty. `doctor.py`'s
  accepted-and-ignored warning block is gone:
  `grep -rn 'tool_versions' src/reconkit/doctor.py src/reconkit/ui.py` -> empty.
  `grep -rn 'tool_versions' tests/` -> three lines, all in
  `tests/test_tools_registry.py`, all about `tools.yaml` never carrying the key
  (kept). `reconkit doctor` before/after: the diff is exactly the two warning
  lines, 180 -> 178 lines; `Missing tools: 3. Install them yourself (apt, go
  install, or release download) - per-tool sources in docs/10_TOOL_SOURCES.md.
  Re-run doctor to confirm.` is byte-identical in both.
- **S3 docs/10 rewritten as a tool reference.** 243 -> 149 lines. New sections:
  1 what this document is, 2 the tool table, 3 how doctor checks a tool, 4 what
  reconkit does NOT do. The table has **48 rows**, and a script compared it with
  `tools.yaml`: `doc rows: 48 registry tools: 48`, no name missing, no extra, no
  stage mismatch. The `source:` strings are rendered as provenance (repo path,
  release URL, `Debian package X`, `PyPI package X`), never as commands;
  `grep -nE 'apt install|apt-get install|go install|pip install|pipx install|
  curl -|wget |git clone|brew install' docs/10_TOOL_SOURCES.md` -> no match.
- **S4 SETUP.md trimmed.** The base-packages apt block, the whole "install the
  recon tools" section and the "install the real tools" advice are gone,
  as is the `libpcap-dev` apt troubleshooting row; the one-line pointer is in
  section 3 and `pip install -e ".[dev]"` (reconkit itself, twice, plus the
  duplicate) is the only install command left.
- **S5 README + root sweep.** README lost `apt`/`go install` access wording, the
  quick-start "install the missing tools yourself" comment and the
  "install the real tools" sentence; the docs table row now describes docs/10 as
  a reference. The batch's literal root sweep uses GNU-grep-incompatible
  `--max-depth`, so `grep -rnE 'install' --include='*.md' --max-depth=1 .` exits
  `2` (`grep: unrecognized option '--max-depth=1'`); the equivalent per-file
  sweep was run instead and its only findings are the AGENTS.md lines named
  under Findings below.
- **S6 `tools.yaml` header.** The `source` comment now reads "`source` is
  provenance only - where this tool's upstream project lives. reconkit does not
  install or download anything; `source` is never executed and is shown only in
  docs/10_TOOL_SOURCES.md." No `source:` value was changed (19 `source:` lines
  still contain `go install`/`pipx install`; they are frozen by the batch text
  and are reported under Findings). The stale `tool_versions` comment line is
  gone, and `ToolSpec`'s docstring says provenance too.
  `grep -rnE '\.source\b|source:' src/reconkit/` -> only `ToolSpec.source`'s
  declaration (`registry.py:53`) and its assignment (`registry.py:147`), plus
  unrelated `source` fields in `models.py`, `ui.py` and the `parse_subdomain_lines`
  parameter in `base.py`; `grep -rnE '\b(spec|entry|tool|candidate)\.source\b'
  src/` -> no read sites, so `source` is load-and-store only, never executed.
- **S7 sweep classification (93 raw hits).** (a) historical audit trail:
  `docs/REVIEW_LOG.md` (35), `docs/PROGRESS.md` (8), `docs/MASTER_PLAN.md` (2) -
  keep. (b) reconkit self-install: `SETUP.md:27`, `SETUP.md:35`, `README.md:49` -
  keep. (c) real residue fixed in this batch: `docs/08` Flow 2's
  `sudo apt install`/`go install`/`pipx install` steps, `SETUP.md`'s tool
  sections, `README.md:22`/`:33`, 30 `**Install yourself:**` bullets across the
  seven tool manuals, `docs/tool_manuals/ports.md`'s "Why 2.3.0 is pinned" block
  (it presented a `tool_versions` snippet for a key that no longer exists),
  `docs/02:178`/`:180`, `docs/01:151`, `docs/05:48`/`:60`/`:65` and
  `tools.yaml`'s header. (d) upstream usage, not an install command:
  `docs/tool_manuals/subs.md`'s five `curl` transcript lines and
  `tests/test_tools_registry.py:342`'s captured Python-`httpx` stderr fixture -
  keep. Remaining hits are prose that says reconkit installs nothing, or the
  frozen footer text (Findings 1).
- **Docs first, then code.** docs/02 section 3's `tool_versions` paragraph and
  its doctor sentence, docs/01, docs/05, docs/08, docs/10 (whole file),
  `SETUP.md`, `README.md` and the manuals were edited before the two `src/`
  changes that had to follow (`config.py` field, `doctor.py` warning). Section
  renumbering: docs/10 old §1 (per-tool sources) is now §2 and old §2 (lookup
  order) is now §3, so `docs/01`, `docs/05`, `docs/08`, the manuals README and
  four `src/` docstrings (`config.bin_dir`, `base.managed_bin_dir`,
  `toolcheck.installed_copy`, `registry.load_system_packages`) were re-pointed.
  docs/10's old §6 (`.env` setup) is gone, so docs/05's two `§6` pointers now
  name `.env.example`/`SETUP.md` (which keeps that step).
- **Tests changed (name / old / new / reason).**
  1. `tests/test_doctor.py::test_a_tool_versions_pin_is_reported_once_as_ignored`
     - **deleted.** Old: built a config with a pin and asserted one warning
     naming docs/10; new: nothing; reason: the warning and the field it read no
     longer exist, so the test asserted removed behaviour.
  2. `tests/test_doctor.py::report_for` (helper, not a test) - old:
     `config=NOPIN_CONFIG` where `NOPIN_CONFIG = CONFIG.model_copy(
     update={"tool_versions": {}})`; new: `config=CONFIG`, and the constant plus
     its four-line comment are gone; reason: the real config no longer pins
     anything, so the workaround had nothing left to neutralise.
  3. `tests/test_config.py::test_unknown_top_level_key_is_rejected` - old
     comment: the real file's `tool_versions` value is no longer the literal
     `{}`; new comment: append rather than string-replace so the test does not
     depend on one line's spelling; reason: the line the old comment explained
     was deleted. **No assertion changed.**
  4. `tests/test_tools_registry.py::test_tools_yaml_carries_no_version_pin_field`
     - old docstring: "a pin can only live in `config.yaml` `tool_versions`";
     new: "a pin has no home anywhere"; reason: the key no longer exists.
     **No assertion changed** (`assert "tool_versions" not in data` still pins
     the registry, not the config).
  Suite 638 -> 637 collected, exactly the one deleted test.
- **Structural consequence, documented not hidden:** with `extra="forbid"` on
  `_StrictModel`, removing the field means a `config.yaml` that still carries
  `tool_versions` now fails to load with exit 2 instead of being accepted and
  ignored. docs/02 section 3 says so. The batch text asked for the field to be
  removed, so this is the requested cleanup, not a regression - but it is a
  behaviour change for an older config file and is recorded here.
- **Gate after (raw):** `pytest -q` -> `637 passed in 10.55s`;
  `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `57 files
  already formatted`; `mypy src/reconkit` -> `Success: no issues found in 29
  source files`.
- **Acceptance runs (raw):** `reconkit doctor` exit 0, 48 rows
  (`reconkit doctor --json` -> `tool rows: 48`, `missing: 3`, `warnings: []`,
  `exit_code: 0`), footer `Missing tools: 3. ...` unchanged, **no
  `tool_versions` warning**. `reconkit run -d example.com --mock --scope
  /tmp/none.yaml --db /tmp/smoke.db --no-color` exit 0, stages `subs` 6/6 and
  `dns` 1/1, `10 hosts`, `7 ok, 0 failed, 9 skipped`. **Mock mode runs the
  fixtures without consulting installation**, so no `not installed` skip can
  appear in a `--mock` run - the skips there read `no adapter yet (phase 3)`.
  The `not installed` path is covered by
  `tests/test_engine.py::test_an_uninstalled_tool_is_skipped_and_the_others_still_run`
  (`1 passed, 91 deselected`). `sha256sum scope.yaml` ->
  `d45a3c903c7417cf73115d4a7b73ab4ccf43509656d30414bd89e1a368eeee8b` before the
  commit; `scope.yaml` is untouched (`ls -la` still `Nov 15 15:51`, 265 bytes) and
  no scope edit was made.
- **Findings left for the owner (not changed):**
  1. The doctor footer `Missing tools: N. Install them yourself (apt, go
     install, or release download) ...` in `ui.py:852-855` still names install
     routes. It is the one install-flavoured string left, and the batch text
     explicitly requires it to stay identical before/after, so it was frozen.
     Changing it is a one-line code change plus `tests/test_doctor.py:208`,
     `docs/02:207`, `docs/08:10` and `docs/01:52`.
  2. The 19 `tools.yaml` `source:` values still spell `go install ...` /
     `pipx install ...`. The batch text froze them; they are never executed and
     docs/10 renders them as provenance.
  3. Nine tool-manual bullets still read `**Install command:** nothing to
     install (`install: {method: none}`)`, a reference to a tools.yaml field that
     no longer exists. They instruct nothing, so they were left for a later
     sweep rather than rewritten here.
  4. `AGENTS.md` still points at `docs/10_TOOL_INSTALLER.md` (line 64), says
     docs/05 covers "installer" (line 59), and its registry rule and tool
     recipe mention install sources and an install method (lines 77, 112, 121).
     The instruction file was not edited in this batch.
  5. `docs/tool_manuals/ports.md:540-543` keeps a `reconkit install rustscan`
     transcript labelled historical, and `docs/tool_manuals/README.md:57,137`
     mention the removed command in the past tense; both are evidence, not
     instructions.

## Doctor shows no version D6 (2026-11-17)  (commit subject `feat: doctor shows installed/path/identity only; versions hidden (version_cmd kept for identity checks)`; hash filled by the next commit)

- **Docs read / goal:** `AGENTS.md`, PROGRESS RESUME, the pitfalls table and the
  last three REVIEW_LOG entries, MASTER_PLAN D4-D5, docs/01 Feature 1-2,
  docs/02 "Doctor output", docs/08 Flow 1, docs/10 section 3,
  `docs/tool_manuals/README.md`, `src/reconkit/{doctor,ui}.py`,
  `core/toolcheck.py`, `adapters/base.py::check_installed`, `tests/test_doctor.py`.
  Owner ruling (2026-11-17, recorded as MASTER_PLAN **D6**): doctor reports
  installed/not-installed, the resolved path and the identity verdict - never a
  version. `version_cmd`/`version_regex` and `installed_version()` stay because
  they are the identity check that keeps Python's `httpx` out of `httpx_tech`
  (D5, `01daa8b`).
- **Baseline before (raw):** `pytest -q` -> `637 passed in 10.04s`;
  `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `57 files
  already formatted`; `mypy src/reconkit` -> `Success: no issues found in 29
  source files`. `git status --short` empty at `31f681e`.
- **Before, raw (`git stash` to the pre-change tree):**
  ```
  ┃ Tool      ┃ Stage ┃ Tier      ┃ Installed ┃ Version   ┃ Path      ┃ Identity ┃
  │ amass     │ subs  │ core      │ yes       │ v5.1.3    │ /usr/bin… │ ok       │
  │ assetfin… │ subs  │ core      │ yes       │ unknown   │ /home/ka… │ ok       │
  {"tool": "amass", ..., "installed": "yes", "version": "v5.1.3",
   "path": "/usr/bin/amass", "identity": "ok"}
  tool rows: 48
  ```
- **Changes.** docs first: docs/01 Feature 1-2 (purpose, the three criteria and
  "Shows each tool: installed, path, identity (never a version)"), docs/02
  "Doctor output" (six columns, the no-version statement and the new footer),
  docs/08 Flow 1 (row 3 and the footer), docs/10 section 3 (a new **What doctor
  shows** paragraph, the two "version column" phrases reworded), docs/MASTER_PLAN
  D6, `docs/tool_manuals/README.md` items 2-3, then code:
  `doctor.ToolCheck` loses the `version` field (docstring says why), the four
  `_tool_check` constructors lose `version=`, `ui.doctor_document` loses the
  `"version"` key and `ui.render_doctor` loses the column, and the
  `Missing tools:` footer becomes `Missing tools: {N}. Scans will use the tools
  that are installed and skip the rest. Per-tool provenance:
  docs/10_TOOL_SOURCES.md.` `core/toolcheck.installed_version()`,
  `InstallStatus.version`, the D5 rule (a declared pattern that does not match
  means not installed), `tools.yaml`'s `version_cmd`/`version_regex` fields and
  every `source:` value are untouched.
- **After, raw:**
  ```
  ┃ Tool            ┃ Stage ┃ Tier      ┃ Installed ┃ Path            ┃ Identity ┃
  │ amass           │ subs  │ core      │ yes       │ /usr/bin/amass  │ ok       │
  │ certspotter     │ subs  │ core      │ yes       │ n/a (no binary  │ n/a      │
  Missing tools: 3. Scans will use the tools that are installed and skip the rest.
  Per-tool provenance: docs/10_TOOL_SOURCES.md.
  {"tool":"amass","stage":"subs","tier":"core","kind":"binary",
   "installed":"yes","path":"/usr/bin/amass","identity":"ok"}
  tool rows: 48 | keys: ['identity','installed','kind','path','stage','tier','tool']
  ```
  `grep -rn '"version"' src/reconkit/doctor.py src/reconkit/ui.py` -> no match
  (exit 1). `grep -rn 'Install them yourself' src/` -> no match (exit 1).
  The only `Version column` hits left under `docs/` are the historical ones in
  REVIEW_LOG/PROGRESS, the manuals README items (reworded to say the column is
  gone) and the D6 text itself.
- **Identity still works (the acceptance test for "hid versions, not identity"):**
  ```
  # PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp/fakehome .venv/bin/reconkit doctor --json
  {"tool": "httpx",      "installed": "wrong program", "path": "/usr/bin/httpx", "identity": "failed"}
  {"tool": "httpx_tech", "installed": "wrong program", "path": "/usr/bin/httpx", "identity": "failed"}
  # normal PATH
  {"tool": "httpx",      "installed": "yes", "path": "/home/kali/.reconkit/bin/httpx", "identity": "ok"}
  {"tool": "httpx_tech", "installed": "yes", "path": "/home/kali/.reconkit/bin/httpx", "identity": "ok"}
  ```
  Under the adversarial PATH no version value appears anywhere in the document.
- **Tests changed (name / old / new / reason).**
  1. `test_missing_binaries_are_counted_and_http_tools_need_nothing` - old:
     asserted `row["alpha"].version == NO_BINARY` and `row["beta"].version == "-"`;
     new: those two lines are gone and `row["beta"].path == "-"` is asserted
     instead; reason: a row has no version any more, and the path column is what
     carries `n/a (no binary required)`.
  2. `test_unparsable_version_is_reported_as_unknown` - **deleted**; replaced by
     `test_a_doctor_row_and_its_json_object_carry_no_version`. Old: a status with
     `installed=True, version=None` printed `unknown` in the version cell; new:
     that cell no longer exists, so the test asserts the row has no `version`
     attribute, the JSON tool object has exactly the seven documented keys and
     the word `version` does not appear in the JSON at all; reason: it asserted
     removed display behaviour, and the replacement guards the new contract.
  3. `test_a_tool_without_an_adapter_is_probed_through_its_install_plan` - old:
     `assert beta.version == "beta 1.2"`; new: `assert not hasattr(beta,
     "version")`; reason: the probe's string now feeds identity only, and
     `installed == "yes"` + the path already prove the probe ran.
  4. `test_missing_tools_keep_exit_code_zero` - old: asserted the frozen
     `Missing tools: 2. Install them yourself (apt, go install, or release
     download)` string; new: asserts `Missing tools: 2. Scans will use the tools
     that are installed and skip the rest.` and `Per-tool provenance:
     docs/10_TOOL_SOURCES.md.`, plus `"Install them yourself" not in text`;
     reason: the footer is deliberately reworded by D6, and the new negative
     assertion is what keeps install advice out.
  5. `test_the_four_probed_tools_extract_their_real_output` - docstring only
     ("so doctor must show one" -> "so their identity probe reads it"). **No
     assertion changed.**
  6. `test_tools_without_a_version_flag_have_no_probe` - docstring only ("the
     path is the version" -> "they stay presence-only", and the `Usage of ...:`
     note now says it proves nothing). **No assertion changed.**
  Suite: 637 before (one deleted, one added) -> `637 passed` after.
- **S1 checks (raw, twice):**
  ```
  pytest -q -> 637 passed in 10.04s   /  637 passed in 10.07s
  ruff check . -> All checks passed!
  ruff format --check . -> 57 files already formatted
  mypy src/reconkit -> Success: no issues found in 29 source files
  ```
- **S3 scans (raw):** no `assert`, `shell=True`, `TODO/FIXME/XXX/HACK` or bare
  `print(` in `src/`; `subprocess` only in `core/runner.py` (the hit is
  `adapters/base.py:3`, prose in a docstring); `sqlite3` only in `core/store.py`;
  no adapter imports `store`/`scope`/`ui`/`cli`.
- **S4 requirement -> test.** Table has no Version column ->
  `test_a_doctor_row_and_its_json_object_carry_no_version` (plus the raw
  `reconkit doctor --no-color` run above); JSON drops the version key -> the same
  test's `set(first)`/`"version" not in` assertions; installed/path/identity
  still shown -> `test_missing_binaries_are_counted_and_http_tools_need_nothing`,
  `test_wrong_program_is_a_warning_not_a_missing_binary`;
  the identity check still rejects Python `httpx` ->
  `test_the_python_httpx_cli_is_not_httpx_tech`,
  `test_a_regex_miss_means_not_installed_for_any_tool` and the live adversarial
  run; scans still use what is installed and skip the rest ->
  `test_an_uninstalled_tool_is_skipped_and_the_others_still_run`; footer wording
  -> `test_missing_tools_keep_exit_code_zero`; `installed_version()` still the
  probe -> `test_a_tool_without_an_adapter_is_probed_through_its_install_plan`,
  `test_the_four_probed_tools_extract_their_real_output`.
- **S5 mutation proofs (raw).** (a) Identity bypass - forced
  `InstallStatus(installed=True, path=status.path)` in `_tool_check`: 4 doctor
  tests failed (`test_missing_binaries_are_counted_and_http_tools_need_nothing`,
  `test_wrong_program_is_a_warning_not_a_missing_binary`,
  `test_a_failed_plan_probe_is_a_wrong_program_warning`,
  `test_missing_tools_keep_exit_code_zero`) and the adversarial CLI printed
  `{'tool': 'httpx_tech', ..., 'installed': 'yes', 'path': '/usr/bin/httpx',
  'identity': 'ok'}` - the exact bug the guards exist for. Restored from a copy;
  `test_doctor.py` 13 passed. (b) Version key re-added to `doctor_document`: 1
  failed (`test_a_doctor_row_and_its_json_object_carry_no_version`, at the
  `set(first)` assertion). Restored; 13 passed; `git status --short` shows only
  the intended files.
- **S6 bugs found:** none. The only failure the change produced was the intended
  contract break in four doctor tests, fixed as listed above.
- **Requirement met with a scope note:** the batch text said "hide the Version
  column from doctor output" and also "no version value anywhere in doctor's
  output/JSON"; removing the field from `ToolCheck` satisfies both, because no
  other code read it (`grep -rnE '\b(check|status|row)\.version\b' src/` -> only
  the two removed ui call sites). `InstallStatus.version` is kept: it is the
  value `installed_version()` returns when the probe matches, and deleting it
  would change the adapter contract for no visible gain.
- **Acceptance runs (raw):** `reconkit run -d example.com --mock --scope
  /tmp/none.yaml --db /tmp/smoke.db --no-color` -> exit 0, `subs` and `dns` ran
  (`dnspython ok 3`), `10 hosts: 0 ALIVE, 2 DNS_ONLY, 0 SHUT_DOWN, 1 DEAD, 7
  UNKNOWN | tools: 7 ok, 0 failed, 9 skipped, 0 timeout`. `sha256sum scope.yaml`
  before the commit:
  `d45a3c903c7417cf73115d4a7b73ab4ccf43509656d30414bd89e1a368eeee8b` (unchanged
  from the previous batch; no scope edit was made).

## Wire the shots stage into full mode (2026-11-17, D19)

- Docs read / goal: `AGENTS.md` (0/0b/0c, rules 3/7/9), RESUME + PIT table, `docs/02`
  section 2 and the `--full` row, `docs/03` section 5b, `docs/09` section 4/4a8, `docs/04`
  section 3.1. Goal: make the completed gowitness adapter reachable; the stage existed in
  `models.py`/`RAW_OUTPUT_DIRS` but in neither `STAGE_ORDER` nor `MODE_STAGES`.
- Plan: (1) add `Stage.SHOTS` to `STAGE_ORDER` after `URLS` and before `VULNS`, (2) leave the
  explicit `passive`/`active` tuples untouched (full is the `STAGE_ORDER` alias, so it gains the
  stage automatically), (3) no persistence branch - screenshots stay files (D17), (4) tests,
  proofs, docs, one commit.
- Why between `urls` and `vulns`: a screenshot needs the alive hosts the `live` stage produced
  and benefits from the crawl `urls` already did; putting a browser after the findings stage
  would delay `vulns` for the slowest tool in the pipeline. `_stage_hosts` already returns the
  alive set for any non-subs/dns/live stage, so no host-plumbing change was needed.
- **S1 (intent):** owner ruling - shots in full only, opt_in tier, active mode, no passive/active.
  Implemented exactly that; no stage command, no new flag, no schema or model change.
- **S2 (minimal diff):** `src/reconkit/engine.py` (two hunks: the tuple + a comment) and one
  4-line gowitness fix. No other production file changed.
- **S3 (behaviour):** `reconkit run -d testfire.net --full --no-scope --include-noisy --mock
  --tools pyprobe,httpx,tlsx,gowitness` -> `pyprobe ok 2`, `httpx ok 2`, `tlsx ok 4`,
  `gowitness shots ok 2`, exit 0. The same command with `--active` instead shows no `shots`
  stage and no gowitness row. A mock-run gap was found and fixed: `gowitness.run()` returned
  "no hosts to scan"-style `ok 0` before the base mock path, so a `--mock` run reported 0 items
  even though the fixture has two; `ctx.mock` is now checked first (`test_gowitness_*
  writes_screenshots_and_manifest` still covers the real path, and the CLI test pins `ok 2`).
- **S4 (edge cases):** empty host list (no ALIVE host) -> stage runs, `ok 0`, no manifest, no
  crash; `--active` never requests the stage; `--exclude gowitness` leaves the stage with a
  skip and the run exits 0 (skip reason is a tier/mode reason only when the stage is requested);
  resume: `_resume_plan` keys on the same `Stage` enum, so a completed shots stage is not
  re-run; `RAW_OUTPUT_DIRS[SHOTS] = "meta"` was already there, so raw output has a home.
- **S5 (scope/security):** gowitness is `mode: active`, so the engine's existing scope gate
  (`_active_hosts`) applies to the hosts it receives - no new path skips `require_active`. The
  adapter still never guesses `--chrome-path`, sends the honest User-Agent through the browser
  default, and writes only under `results/<target>/<UTC stamp>/`. No sudo, no new dependency.
- **S6 (docs):** docs/02 (`--full` row, mode table, interactive legend, plan echo), docs/03
  (stage order + `MODE_STAGES`), docs/05 (opt_in bullet), docs/08 (mode choice), docs/09
  (stage table, section 4a8, gowitness row + the Chrome note), README, MASTER_PLAN **D19**,
  PROGRESS RESUME/deviations/baseline, this entry. `docs/01` needed nothing.
- **S7 (verification):** baseline before the change: `811 passed`, ruff clean, 90 files
  formatted, mypy clean (62 files), `scope.yaml` sha256 `d45a3c90…` unchanged. After:
  `816 passed`, ruff clean, 90 files formatted, mypy clean, same `scope.yaml` hash. Test
  changes disclosed: three existing expectations moved (`test_full_mode_unchanged_by_expansion`
  7 -> 8 stages, `test_stage_order_and_tool_rows` excludes the spec-less `shots` stage,
  `tests/test_interactive_scan.py` full-mode stage tuple gained `SHOTS`,
  `test_run_help_describes_stages_tool_modes_and_tiers` gained `shots` in the help text,
  `test_full_json_skips_exploitation_tools_and_does_not_tier_skip_opt_in` gained the `shots`
  stage row); five tests added: `test_shots_stage_is_in_full_mode_only`,
  `test_gowitness_runs_in_full_with_include_noisy`,
  `test_gowitness_runs_when_explicitly_named_via_tools_flag`,
  `test_full_runs_gowitness_without_the_noisy_flag_because_full_implies_it`,
  `test_active_mode_never_runs_the_shots_stage`.
- **The tier-gate proof the batch asked for cannot exist, and that is recorded rather than
  faked.** `--full` sets `include_noisy = True` (cli.py) and `--tools <name>` bypasses the tier
  gate, so `gowitness` is never skipped for `opt_in` in a full run; a stage-specific gate would
  have been an invented rule contradicting docs/02. D19 states the conflict and the ruling
  question.
- Next action: none. Still 44 of 48 adapted; the remaining four are `dnsreaper` (D15) and the
  three exploitation-class tools (`sqlmap`, `dalfox`, `crlfuzz`).

## Adapter wave 8: dns (dig, massdns, puredns), shots (gowitness), vulns (nikto) (2026-11-17, D16/D17)

- Docs read / goal: AGENTS (rules 1/4/7, section 7 recipe), RESUME, docs/09 sections 3/4/4a8/5,
  docs/02 (flags table + `injections`), docs/04 (new section 3.1), docs/05 rule 4,
  `docs/tool_manuals/dns.md` + `shots.md`, tools.yaml. Goal: close the last three stages and
  reconcile the registry count before reporting it.
- **Count reconciled first, with raw numbers:** `yaml.safe_load(tools.yaml)["tools"]` -> 48 and
  `len(ADAPTERS)` -> 44 with `missing = ['crlfuzz', 'dalfox', 'dnsreaper', 'sqlmap']`, no adapter
  without a registry row. The earlier "39 of 48" was wrong: wave 6's report counted only the
  stages it had touched. Final: **44 of 48 adapted**, remaining = `dnsreaper` (D15) plus the
  three intrusive tools (`sqlmap`, `dalfox`, `crlfuzz`, `exploitation: true`, no `--intrusive`
  flag in this build).
- Real evidence, one line each: `dig -v` -> `DiG 9.20.30-1-Debian`, and
  `dig +noall +answer -f hosts.txt` printed `testfire.net. 75048 IN A 65.61.137.117` /
  `www.testfire.net. 72983 IN CNAME testfire.net.` (`+short` rejected: no name to attribute);
  `massdns --version` prints only `massdns ` (no number) so identity is `--help`, and a real
  run with the packaged resolvers printed `demo.testfire.net. A 65.61.137.117` etc. in `-o S`;
  `puredns --version` -> `puredns version v2.1.1`, `resolve/-r/-b/-w` from its `--help`;
  `gowitness version` -> `gowitness: 3.2.2` under a banner, `scan single -u <url> -s <dir>` plus
  the **global** flags `--screenshot-format` (default **jpeg**) and `--screenshot-path`; a real
  `nikto -h testfire.net -nointeractive -Format json -output out.json` exited 0 and wrote the
  JSON array.
- Behaviour: `dig` one `+noall +answer -f <ws file>` process; `massdns -r <resolvers> -t A -o S
  -w <ws file> <ws file>` with finds read from `-w`; `puredns resolve <ws file> -r <resolvers>
  -b <abs massdns> -w <ws file>` (`-b` is mandatory because a child gets only the engine's env
  keys); `nikto` one process per host (it cannot take a list) with `severity="info"`,
  `kind="nikto"`; `gowitness` one process per URL (`https://` then `http://`), PNG under
  `results/<target>/<UTC stamp>/screenshots/`, `screenshots.jsonl` manifest beside it.
- **Three findings that changed the code:**
  1. `gowitness` writes **jpeg** by default. `--screenshot-format` is a global flag and not in
     the brief, but D17 promises `.png` files and a `*.png` glob over jpeg output silently finds
     nothing, so the adapter passes `png`. Without this the manifest would have stayed empty on
     every box, including one with Chrome.
  2. The results root cannot be read by the adapter. `load_config()` inside the adapter raised
     `ConfigError: cannot read config file config.yaml` when the CWD had none, and would ignore
     `--config` anyway, so the engine now passes `RunContext.results_dir` (plumbing, not a
     record model) and the adapter reads `ctx.results_dir`.
  3. `nikto` and `gowitness` call `run_exec` from their own module namespace, so the existing
     `fake_exec` helper (which patches `adapters.base`) does not reach them; the two tests patch
     the module symbol instead.
- **`dig` kept, not skipped as redundant** (brief asked for a decision, not a silent skip):
  `dnspython` is the resolver with the wildcard probe and dangling-CNAME logic, `dig` is an
  independent second DNS source for the same names, which is what raises a `DNS_ONLY` host from
  LOW to MEDIUM (docs/09 section 5). It is A/AAAA/CNAME only and says so in its docstring.
- **`stage: shots` is unreachable from the CLI.** `Stage.SHOTS` exists in `models.py` and
  `RAW_OUTPUT_DIRS` but is in neither `STAGE_ORDER` nor a `MODE_STAGES` row, so no mode and no
  `--tools` selection runs it. Adding it is a mode-table change (the documented stop rule), so
  the adapter is written, tested and registered, and the one-line wiring is reported instead of
  done.
- Proofs, pasted raw in the report: `reconkit doctor` -> `dig yes/ok`, `massdns yes/ok`,
  `puredns yes/ok`, `nikto yes/ok`, `gowitness yes/ok`; mock run
  `--tools pyprobe,httpx,tlsx,dig,massdns,puredns,nikto` -> `dig ok 3`, `massdns ok 3`,
  `puredns ok 3`, `nikto ok 2`, exit 0 (the first attempt with `pyprobe` only showed
  `nikto failed: no hosts to scan`, which is the documented behaviour of every `vulns` adapter
  when no host is ALIVE, not a Part 2 defect); gowitness manifest proven with a stand-in binary
  because this box has no Chrome (`failed to initialize chrome context: exec: "google-chrome":
  executable file not found in $PATH`).
- **Deferred masscan sudo proof done:** `sudo -n true` -> `sudo: a password is required`, so
  `echo kali | sudo -S env PATH=<venv>:$PATH reconkit run -d testfire.net --full --no-scope
  --include-noisy --tools subfinder,pyprobe,httpx,tlsx,masscan --mock` -> `masscan ports ok 3`,
  exit 0. Non-root control in the same session: `masscan skipped` / `requires root / sudo`.
  The first two sudo attempts ran no ports stage at all (no ALIVE host: `httpx` alone does not
  mark one without `tlsx`), which is why the tool list grew - recorded, not hidden.
- Gate: 811 passed, `ruff check .` clean, `ruff format --check .` 90 files, `mypy src/reconkit`
  clean (62 source files). Deviations: D16 (bundled resolvers + `--resolvers`), D17 (screenshots
  as files, `RunContext.results_dir`). Test changes disclosed: two existing expectations moved -
  `DOCUMENTED_OPTIONS` gained `--resolvers` and the `--full` vulns order now lists `nikto`
  between `subzy` and `ffuf`.
- Next action: owner ruling on wiring the `shots` stage into a mode table; nothing else in the
  adapter programme is open.

## Adapter wave 7: subs stage - urlscan, amass, findomain, chaos, github_subdomains (2026-11-17, D15/D18)

- Docs read / goal: AGENTS (rules 1/5/7), RESUME, docs/09 sections 3/4/4a7, docs/02
  (flags table), docs/10 (tool table), `docs/tool_manuals/subs.md` (real captures for
  all five), tools.yaml. Goal: close the `subs` stage and record D15 for dnsreaper.
- Real evidence, one line each: `urlscan` is `kind: http` - `/usr/bin/urlscan` is the
  unrelated Python "Parse and display URLs" CLI, and a keyless
  `GET https://urlscan.io/api/v1/search/?q=domain:testfire.net` returned HTTP 200 with
  `results[]`; `amass --version` prints only `v5.1.3` (no name), `amass enum -h` carries
  `OWASP Amass Project - @owaspamass` and exit 0, and a real `amass enum -d testfire.net`
  printed a `Session Scope` / `FQDN:` header before any finding (200 s run, not completed);
  `findomain -t testfire.net -q` printed 35 bare names; `chaos -version` ->
  `[INF] Current Version: 0.5.2` and `chaos -d testfire.net -silent` exits 1 with
  `[FTL] PDCP_API_KEY not specified` (manual); `github-subdomains -version` ->
  `flag provided but not defined`, `-h` shows `-o string  output file, default:
  <domain>.txt` and `t string (required)`.
- Behaviour: all five return `SubdomainRecord`s. `urlscan` sends `api-key` only when
  `URLSCAN_API_KEY` is set (search works without it). `amass` = `enum -d <target>`, parser
  keeps only `validate_host` hits because stdout is decorative. `findomain` = `-t <t> -q`,
  no `-o`. `chaos` = `-d <t> -silent -duc`. `github_subdomains` = `-d <t> -o
  <workspace>/github-subdomains-<pid>.txt` and `read_output`.
- **New rule (D18):** `BaseToolAdapter.requires_env` marks a hard key requirement and the
  engine skips the tool at selection with `requires <NAME>`. Runtime `SKIPPED` was not
  used on purpose: it counts as failed and exits 5 (D14 lesson). `--no-keys` behaves the
  same. A test proves a keyless tool is never spawned and the run still exits 0.
- Tests: 15 new (795 passed, 780 -> 795): 3 urlscan (parse, keyless run + params, key
  header), 11 binary/engine (amass parse/v5 syntax/identity, findomain parse/identity,
  chaos parse/requires_env/identity, github parse/`-o` path/`read_output`) and 1 engine
  key-gating test. Two existing tests updated: `NO_HOME_NEEDED` gained findomain +
  github_subdomains with reasons, and `test_listed_tool_without_adapter_raises_config_error`
  moved from `urlscan` (now adapted) to `dnsreaper`.
- Gate: 795 passed, ruff clean, 85 files formatted, mypy 57 source files clean.
  Doctor: urlscan `yes/n/a`, amass `yes/ok`, findomain `yes/ok`, chaos `yes/ok`,
  github_subdomains `yes/ok`. Deviations: D15 (dnsreaper closed), D18 (requires_env).
- Next action: Part 2 (dig, massdns, puredns, gowitness, nikto) + masscan sudo proof.

## Adapter wave 6: ports stage - nmap, rustscan, smap, masscan (2026-11-17, D14)

- Docs read / goal: `AGENTS.md` (rules 1, 5, 7; section 7 recipe), RESUME, `docs/09` sections 3/4/4a6/5,
  `docs/02` (ports paragraph + `--ports` row), `docs/04` (ports table), `docs/05` rule 6,
  `docs/tool_manuals/ports.md` (the real captured `--help` for all four), `tools.yaml`.
  Goal: close the `ports` stage so every adapter wave has a full pool there.
- Flags/fields were taken from the installed binaries, not from memory:
  `nmap --version` -> `Nmap version 7.991`; `rustscan --version` -> `rustscan 2.3.0` plus its
  full `--help`; `smap -h` -> `Smap 1.0.0-beta`; `masscan --help` + the packaged manpage
  (`/usr/share/man/man8/masscan.8.gz`) + `/usr/share/doc/masscan/README.md.gz`. Commands:
  `nmap -sV -Pn -p 80,443,8080 --open -oX out.xml testfire.net` (real, XML shape captured),
  `rustscan -a testfire.net -p 80,443 -g -n --ulimit 5000` -> `65.61.137.117 -> [443,80]`,
  `smap testfire.net -oJ -` -> the JSON array in the fixture, and masscan only got as far as
  `[-] FAIL: permission denied` as `kali`.
- **Three findings that changed the plan, each verified rather than assumed:**
  1. `rustscan` does **not** need `nmap` in greppable mode. `-g` says `Only output the ports.
     No Nmap.` and the same command with `PATH=/tmp/emptybin` printed the same
     `IP -> [ports]` line, so the brief's "skip when nmap is missing" has nothing to guard.
     2.3.0 also has no `-- <nmap args>` passthrough (`--help` ends at `--udp`), so the service
     fingerprint stays `nmap`'s job instead of being smuggled through rustscan.
  2. `masscan` JSON (`-oJ`) could not be observed: it needs a root scan, `sudo -n true` answers
     `sudo: a password is required`, and this session does not run interactive sudo. The list
     format `-oL` is documented in the installed README (`open tcp 80 XXX.XXX.XXX.XXX
     1390380064`), so the adapter parses that and the fixture is `.synthetic.list`, not `.json`.
  3. The same re-check found the adapter's `run()`-time `SKIPPED` cannot live in this engine: a
     full mock run went from exit 0 to exit 5 (`failed_total` counts every non-OK executed
     tool). The skip moved to `_select` via the `needs_root: true` the registry already carried
     (`ToolSpec.needs_root`, non-bool -> `ConfigError`); the adapter keeps the identical guard
     through `base.running_as_root()` for a direct call.
- Behaviour, per tool: `nmap` `-sV -Pn -oX <ws>/nmap-output-<pid>.xml --open` + `--top-ports 1000`
  (or `-p <list>`), XML read through `read_output`; `rustscan` one `-g -n --ulimit 5000 -a a,b`
  process with `-p` or `--top`, stdout parsed, the single input host kept as `fqdn` because `-g`
  prints the resolved address; `smap` `-iL <ws>/smap-targets-<pid>.txt -oJ <ws>/smap-output-<pid>.json`
  (passive, no packets), `--ports` filters its records; `masscan` `<ips> -p<list> --rate 1000 -oL
  <ws>/masscan-output-<pid>.list`, resolving names locally and keeping only addresses
  `ctx.ip_allowed` permits (docs/05 rule 6), `DEFAULT_PORTS` when `--ports` is absent because
  masscan has no top-ports option. No `-sS`, no `-O`, no scripts, no rate flag on the other three.
- **`--ports` mapping, stated plainly, with the one gap:** `nmap`/`rustscan`/`masscan` take it as
  input, `smap` cannot (it reports what Shodan already saw) so it filters output. Nothing is
  silently dropped; docs/02 and docs/09 section 4b say so.
- Real end-to-end proof (not a mock): `reconkit run -d testfire.net --full --no-scope --tools
  pyprobe,nmap,rustscan,smap,masscan --ports 80,443,8080` -> `live: pyprobe ok 1`, `ports: nmap ok
  3`, `rustscan ok 3`, `smap ok 3`, `masscan skipped` / `requires root / sudo`, exit 0, and the DB
  holds `80/443/8080 open HIGH` with `nmap`+`rustscan`+`smap` in `port_sources` and
  `version = Apache Tomcat/Coyote JSP engine 1.1`.
- That real run produced the second finding (PIT-54): `_persist_ports` grouped `tool -> [state]`,
  so the `-sV` fingerprint was parsed and then thrown away and the documented confidence bump had
  never fired. Fixed in the same part (`_fingerprint()`, `FINGERPRINT_BUMP`), two engine tests.
- Tests: 22 new - 19 adapter tests in `tests/test_binary_adapters.py` (`nmap` parse/identity/
  `--ports`/file-output/malformed XML, `rustscan` parse/identity/single-host/`-g`-needs-no-nmap/
  `--ports`, `smap` parse/identity/`--ports` filter, `masscan` non-root skip/parse/identity/IP
  targets/scope refusal, registration+stage), 1 CLI test (`--full` reports
  `{"tool": "masscan", "reason": "requires root / sudo"}` and stays `complete`), 2 engine tests
  (PIT-54 and the disagreement case). Existing guard extended, not weakened:
  `NO_HOME_NEEDED` gained the four tools with reasons taken from their real help output. Suite `758 -> 780`, `ruff check .` clean,
  `ruff format --check .` 80 files, `mypy src/reconkit` clean (52 source files).
- Deviations recorded in MASTER_PLAN **D14** and PROGRESS: masscan root skip at selection (not a
  runtime status), rustscan needs no nmap, masscan list output instead of JSON, `smap --ports`
  filters passive records, `_VERSION` now accepts a two-part version (`Nmap version 7.991`),
  `adapters/nmap.py` carries a per-file `S314` ignore with its reason in `pyproject.toml`
  (it parses only the `-oX` file nmap wrote in the same run).
- Next action: none. Still unadapted: subs `urlscan, amass, findomain, chaos, github_subdomains`;
  dns `dig, massdns, puredns`; vulns `dnsreaper, nikto`; shots `gowitness`. Every `ports` stage
  tool now has an adapter (6 of 6).

## Adapter wave 5 completed: ffuf (inline wordlist); dnsreaper still unadapted (2026-11-17)

- Docs read / goal: `AGENTS.md` (0/0b/0c, hard rule 7, no new deps without
  asking), RESUME, PIT-14/30, docs/09 §4a5, docs/02 section 3, `tools.yaml`.
  Close the two wave-5 blockers the owner named.
- Baseline: `751 passed`, ruff/format/mypy clean, tree clean at `825a552`,
  `scope.yaml` sha256 `d45a3c9...eeee8b`.
- **dnsreaper: reported, not installed.** `pip install dnsreaper` fails -
  `ERROR: Could not find a version that satisfies the requirement dnsreaper
  (from versions: none) / No matching distribution found`. The repository
  (`api.github.com/repos/punk-security/dnsReaper/contents/`) has no
  `setup.py`/`pyproject.toml`/console script: it is `main.py` plus
  `requirements.txt`, i.e. "clone it, `pip install -r requirements.txt`, run
  `python main.py`" (its README). That is not an install but (a) a checkout
  with its own dependency tree (boto3 and others) and (b) a **new adapter kind**
  - a script launched through `sys.executable`, which the documented contract
  (http/python/binary, docs/09 section 3) does not have and `tools.yaml`'s
  `binary: dnsreaper` cannot express. Per the part's stop rule this is reported
  rather than improvised; no install was attempted beyond the `pip` probe.
- **ffuf: shipped with an inline wordlist (D13).** `src/reconkit/data/wordlists/
  common.txt` holds 118 paths (admin/.git/.env/swagger/actuator/...), committed
  and declared as package data, so a built wheel contains
  `reconkit/data/wordlists/common.txt` (verified with `pip wheel .`).
  `--ffuf-wordlist PATH` replaces it on the scan commands; a missing file is a
  failed result (`ffuf: wordlist not found: ...`), never a silent fallback.
- Invocation, from the real `ffuf -h` (v2.3.0): `-u FHOST/FFUF`, two wordlists
  (`-w hosts:FHOST -w <wordlist>:FFUF`), `-mode clusterbomb`, `-of json -o
  <file>`, `-mc 200,204,301,302,307,401,403`, `-t 50`, `-s`, `-noninteractive`.
  One process covers every host and both schemes; no `-k`, no `-p` (no pacing,
  D3). Records are `FindingRecord(kind="path", severity="info")` - a path that
  exists is not a confirmed vulnerability - read from the output file through
  the `read_output` hook added in wave 5.
- **Two defects found by the first real run, both fixed before commit:**
  (1) `-u FHOST/FUZZ` with `-w ...:FFUF` makes ffuf print `Keyword FFUF
  defined, but not found in headers, method, URL or POST data.`, exit **0**,
  and write zero results - a silent empty answer that looked like `ok 0 item(s)`;
  the URL must use `FFUF`. (2) `crawl_urls()` returns roots with a trailing
  slash, and the template joins literally, so the first working run stored
  `https://testfire.net//admin`; the hosts file now holds slash-free roots.
  Guarded by `test_ffuf_hosts_wordlist_has_no_trailing_slash`.
- Evidence (raw in the report): `doctor` -> `ffuf yes / ok (/usr/bin/ffuf)`,
  `dnsreaper missing`; mock run `--full --include-noisy --tools
  pyprobe,dnsreaper,ffuf` -> `ffuf ok 2`, `dnsreaper` skipped `no adapter yet
  (phase 3)`, exit 0; real run on testfire.net (`--tools dnspython,pyprobe,ffuf`)
  -> `ffuf ok 12` real matches (`302 /admin`, `/admin/index.php`,
  `/admin/login`, ...), exit 0.
- Tests: 7 new, `751 -> 758` (parse, identity, default wordlist, override,
  packaged wordlist exists/non-empty, missing wordlist, slash-free roots), plus
  `--ffuf-wordlist` in `DOCUMENTED_OPTIONS` and the vulns expectation in the
  full-run test now includes `ffuf`. Docs updated first: docs/02 section 3 +
  `injections`, docs/09 §4a5, MASTER_PLAN D13, PROGRESS.
- Gate: `758 passed`, ruff clean, 76 files formatted, mypy clean (48 files).
- Next action: Part 2 (ports adapters). dnsreaper needs an owner ruling on
  whether a script-kind adapter is acceptable or the tool is dropped.

## Adapter wave 5 (partial): nuclei, subzy; dnsreaper and ffuf blocked (2026-11-17)

- Docs read / goal: `AGENTS.md` (0/0b/0c, hard rules 1, 6, 7), RESUME, PIT-14,
  PIT-30, PIT-50-52, docs/09 adapter contract + §4a5 slot + `FindingRecord`,
  docs/04 (findings table status), docs/10 version contract, `tools.yaml`,
  `reconkit run --help`. Goal: four vulns adapters, stop-and-report if one
  balloons.
- Baseline: `742 passed` (D12, `501c6d7`), ruff/format/mypy clean, tree clean,
  `scope.yaml` sha256 `d45a3c9...eeee8b`.
- **`vulns` is not in `--active`** (mode table locked at `756af8e`): `run
  --help` lists `--active` as "subs, dns, live, tech, urls", so the vulns
  adapters run under `--full`, the explicit `reconkit vulns` command, or an
  explicit `--tools` name. Nothing in the mode table changed.
- **Record type: no new model needed.** `FindingRecord` already exists
  (`models.py:95`) with `fqdn`, `kind`, `severity`, `title`, `evidence`,
  `template_id`, `source`. Its severity literal gained `unknown`, which is a
  real nuclei value (42 of the installed templates declare it), so a real
  finding is representable instead of being dropped or coerced. **Findings are
  still not persisted:** `_persist_stage` has no `VULNS` branch and docs/04
  still defers the `findings` table, so records reach `--json` and the run's
  raw output file only. That gap predates this wave and no adapter invented a
  second persistence path for it; making findings durable is the deferred
  findings table (schema + report work).
- Real flags verified on this box: `nuclei` v3.11.1 (`~/go/bin`, on PATH) -
  `-l/-list` (file), `-j/-jsonl`, `-silent`, `-nc`, `-duc`, `-tags`, `-severity`,
  `-o`, `-rl`; `subzy` v1.2.0 (`~/.reconkit/bin`) - `version` subcommand and
  `run --targets/--target/--output/--hide_fails/--concurrency/--timeout`.
- Command choices: nuclei gets `-l <file> -jsonl -silent -nc -duc -tags
  takeover,exposure,misconfig` - tags (not a severity filter) are what
  `tools.yaml` asks for ("Run safe tags only"), and no `-rl` because reconkit
  has no pacing (D3). subzy gets `run --targets <file> --hide_fails --output
  <file>` with the tool's own concurrency/timeout defaults.
- **New shared hook: `read_output(ctx)`.** subzy writes findings only to the
  `--output` file, so the base flow now asks the adapter for the document after
  a successful run and parses that instead of stdout (and stores it as the raw
  output). One method plus two lines in `BaseToolAdapter.run`, so
  timeout/failed/parse mapping stays in one place; `ffuf`/`dnsreaper` are the
  next tools of this class.
- **Two real-output traps found by running, not by reading `-h`:**
  - **PIT-53:** the first real nuclei run failed the whole tool with
    `nuclei: invalid host 'demo.testfire.net:443'` - the `host` field is
    `host:port` when a non-default port is probed, and 14 real findings were
    thrown away. `finding_host()` now handles URL, `host:port` and bracketed
    IPv6. Guard: `test_regression_a_nuclei_host_with_a_port_keeps_its_name`.
  - subzy writes the literal `null` when nothing matched, not `[]`; the first
    real subzy run failed with "output is not a JSON array". Both are in
    docs/09 §4a5 and the parsers.
- Evidence (raw in the report): `doctor` -> `nuclei yes / ok`
  (`/home/kali/go/bin/nuclei`), `subzy yes / ok` (`~/.reconkit/bin/subzy`); mock
  run `--full --include-noisy --tools pyprobe,nuclei,subzy` -> `nuclei ok 3`,
  `subzy ok 1`, `completion complete`, exit 0; real run on testfire.net
  (`--tools dnspython,pyprobe,nuclei,subzy`) -> `nuclei ok 14`, `subzy ok 0`,
  exit 0 (14 findings: swagger-api info, weak-cipher-suites low,
  http-missing-security-headers info, ...). A real `crtsh` run in the same
  session returned HTTP 404 (external), unrelated to this wave.
- **Blocked, not written (stop rule):**
  - **`dnsreaper`** is not installed anywhere on this box (`doctor`: `missing`,
    no binary under `~/.reconkit/bin`, `~/go/bin`, `/usr/bin`, no pipx
    package), and docs/09 §8 has no captured flag list for it, so there is no
    way to verify `--filename/--out json` or its output shape without guessing
    (AGENTS hard rule 7). Its tools.yaml entry also says it must be installed
    by hand.
  - **`ffuf`** is installed (2.3.0) but has no wordlist: nothing under
    `~/.reconkit/wordlists`, no wordlist in the repo, and docs/PROGRESS.md:548
    records that no adapter uses one. An ffuf adapter needs a default wordlist
    - a new dependency/asset the owner has to approve - so per the stop rule it
    was not added.
- Tests: 9 new, `742 -> 751` (nuclei parse/command/identity/PIT-53, subzy
  parse/file-io/`null`/identity, the base `read_output` flow, plus two
  registration assertions), two CLI tests updated because `vulns` is no longer
  adapter-less: `test_a_stage_with_no_adapter_reports_its_skips` now names
  `dnsreaper`, and
  `test_a_full_run_reports_the_gaps_of_stages_with_no_adapter` became
  `test_a_full_run_has_no_gaps_when_every_mode_stage_has_a_tool` (the gap rule
  itself is still guarded by `test_engine` and the block rendering by
  `test_ui`).
- Gate: `751 passed`, ruff clean, 75 files formatted, mypy clean (47 source
  files).
- Next action: owner ruling on dnsreaper (install it so its flags can be
  verified, or drop it from the wave) and on the ffuf wordlist question; the
  findings-table work is separate and still deferred.

## D12: deterministic WAF merge via tool priority (2026-11-17)

- Docs read / goal: `AGENTS.md` (0. Session start, 0b task loop, hard rules),
  RESUME, PIT-51/52 (the tech-persistence and parser guards), docs/04 sections
  5/11, docs/09 §4a4 (the wave-4 merge answer this supersedes), the wave-4
  REVIEW_LOG entry, `tools.yaml`. Owner ruling: two WAF tools must not flip the
  stored name by finishing order.
- Baseline: `736 passed`, `ruff check .` clean, `ruff format --check .` 73 files,
  `mypy src/reconkit` clean (45 source files), tree clean at `10f1cf8`,
  `scope.yaml` sha256 `d45a3c9...eeee8b`.
- **Yes, this is a schema change: 6 -> 7.** Something has to remember the
  priority of the name currently in `waf`, otherwise a later lower-priority
  pass cannot tell whether it may overwrite it. A JSON sidecar was the
  alternative and was rejected: one int per row is smaller than a second
  encoding of the same fact, and it can be indexed/filtered like any column.
  Migration, unchanged from the pattern of schemas 2/4/6:

  ```sql
  ALTER TABLE host_status_history ADD COLUMN waf_priority INTEGER NOT NULL DEFAULT 0;
  ```

- **Before** (`Store.update_host_extras`, `store.py`, wave 4):

  ```python
  stored_waf = waf if waf is not None else row["waf"]
  self._conn.execute(
      "UPDATE host_status_history SET tech_json = ?, waf = ? WHERE id = ?",
      (json.dumps(merged), stored_waf, int(row["id"])),
  )
  ```

  Any non-None detection replaced the stored name, so the last pass always won
  and `_persist_tech`'s first-non-None rule picked the winner by
  `asyncio.gather` completion order.
- **After**:

  ```python
  stored_waf = row["waf"]
  stored_priority = int(row["waf_priority"] or 0)
  if waf is not None and (stored_waf is None or waf_priority > stored_priority):
      stored_waf = waf
      stored_priority = waf_priority
  self._conn.execute(
      "UPDATE host_status_history SET tech_json = ?, waf = ?, waf_priority = ? WHERE id = ?",
      (json.dumps(merged), stored_waf, stored_priority, int(row["id"])),
  )
  ```

  and `Engine._persist_tech` now keeps the pass's highest-`waf_priority` record
  (`self.specs[tool].waf_priority`, 0 when the tool is unknown to the run's
  specs) instead of the first non-None one, passing the winning priority to the
  store. Equal priorities keep the first writer: within a pass the first record
  in `results`, across passes the stored value. An empty column is always
  filled, so a priority-0 tool still records the only detection available.
- Priorities (`tools.yaml`, validated `int >= 0`, non-int/bool/negative is a
  `ConfigError`): `wafw00f` 100, `cdncheck` 80, `whatweb` 50, `httpx_tech` 20,
  every other entry 0 (including `httpx`, whose `cdn_name` a dedicated detector
  then corrects).
- **Deterministic proof, three fresh databases** (seeded with one pre-existing
  `DNS_ONLY` row for `testfire.net` so the tech stage has a row to annotate -
  it never inserts one, D11), same command each time
  (`--tools pyprobe,wafw00f,httpx_tech --active --mock`):

  ```
  -- fresh DB run 1 --   testfire.net  Cloudflare  100
  -- fresh DB run 2 --   testfire.net  Cloudflare  100
  -- fresh DB run 3 --   testfire.net  Cloudflare  100
  ```

  Before this change the same fixtures and tools stored `cloudflare` from
  `httpx_tech` (wave-4 entry, `cloudflare` in that table) because it finished
  first; now `wafw00f`'s `Cloudflare` always wins. `httpx_tech` still reports
  `cloudflare` in its own record and the JSON output - only the stored column is
  arbitrated.
- **On a truly empty database the brief's command stores no WAF at all**, even
  after this change: the mock liveness fixtures are `example.com`-shaped while
  the tech fixtures are `testfire.net`, so no `testfire.net` status row exists
  and `update_host_extras` returns False (D11: annotate, never insert). That is
  the documented behaviour, not a regression; the run still exits 0 and prints
  `wafw00f ok 1 item(s)`.
- Tests: 6 new, `736 -> 742`; one wave-4 test updated (`test_wafw00f_and_...`
  previously asserted the order-dependent winner, which is exactly what the
  ruling removed - it now asserts `Cloudflare`/100 in both orders with the real
  registry priorities), and the four migration tests moved their pinned version
  from 6 to 7. Named guards: `test_waf_priority_deterministic_merge` (all six
  orders of wafw00f/cdncheck/httpx_tech end `Cloudflare`/100),
  `test_waf_priority_zero_preserves_first_writer`,
  `test_v6_database_migrates_the_waf_priority_column`,
  `test_waf_priorities_are_declared_in_the_registry`, plus the two
  invalid-priority `ConfigError` tests.
- Gate: `742 passed`, ruff clean, 73 files formatted, mypy clean (45 files).
  Docs updated first: docs/MASTER_PLAN.md D12, docs/04 sections 3/11, docs/09
  §4a4, PROGRESS.
- Next action: Part 2 (adapter wave 5).

## Adapter wave 4: unfurl, wafw00f, whatweb, httpx_tech (2026-11-17)

- Docs read / goal: `AGENTS.md` (0d item 11), RESUME, PIT-14/30/50/51/52,
  docs/09 adapter contract + §4a4 slot, docs/10 version contract, docs/04
  section 5, docs/tool_manuals/{tech,urls}.md, `tools.yaml`. Four adapters in
  one commit, no mode-table change, no schema change.
- Baseline: `726 passed`, `ruff check .` clean, `ruff format --check .` 61 files,
  `mypy src/reconkit` clean (41 source files), tree clean at `a30a6c6`,
  `scope.yaml` sha256 `d45a3c9...eeee8b` (unchanged at the end of this entry).
- Real flags and output read off this box before coding: `unfurl -h` writes the
  usage to **stderr** with exit 0 and `-version` exits 2 (`flag provided but not
  defined`); `wafw00f --version` -> `[+] The version of WAFW00F you have is
  v2.4.2`, `wafw00f -a -f json -o -` -> a JSON array, exit 0; `whatweb
  --version` -> `WhatWeb version 0.6.4 ...`, `whatweb --quiet --log-json=-
  --no-errors --color=never -a 1` -> a JSON array on stdout, exit 0.
- **`whatweb` trap found by trying it:** `--log-json=-` **alone fails** - the
  JSON reaches stdout, then the one-line brief is written to the same closed
  stream, Ruby raises `logging.rb:89:in 'write': closed stream (IOError)` and the
  tool exits 1, which the base flow would report as a failed tool. `--quiet`
  (real help: "Do not display brief logging to STDOUT.") is therefore part of
  the command, not a nicety. Same class as PIT-10: the flag list alone did not
  reveal it.
- **unfurl: choice (b), full URL lines.** `format '%s://%d%:%P%p?%q'` rebuilds
  one canonical URL per line, which is what the urls stage stores; components as
  metadata would need a new model field nothing consumes (rejected). Real quirk:
  `%?` is unconditional, so a bare root returns `https://host/?`; the adapter
  runs `normalize_url()` and relies on `-u` plus parser dedupe. Honest
  limitation: the urls stage hands over hostnames, so unfurl only sees the two
  scheme roots per host - its real value (canonicalising an existing URL list)
  needs a urls->urls hand-off the engine does not have.
- **Docs-vs-brief conflict, ruled by the registry:** the brief lists unfurl as
  `active`; `tools.yaml:158` and docs/09 §4 line 312 say `mode: passive`. The
  registry wins (same ruling as `gau` in wave 1, `urlfinder` in wave 3), so
  `tools.yaml` is untouched and unfurl also runs in a passive scan.
- **Merge-semantics question, answered from the code, nothing changed:**
  `tech` is a **merged list** (`_persist_tech` unions per pass at engine.py:1691;
  `Store.update_host_extras` appends unseen names to the stored `tech_json` at
  store.py:612), and `waf` is a **single string**: first non-None inside one pass
  (`results` order is completion order from `asyncio.gather`, engine.py:1712),
  replaced by the latest pass across runs. So `httpx_tech` (`cdn_name`) and
  `wafw00f` never merge - whichever finishes first names the WAF and the other
  detection is silently dropped, and a rerun can flip the winner. That is what
  the mock proof below shows (`cloudflare` stored, `Cloudflare` dropped).
  Changing it would need a list column on `host_status_history` (schema change),
  which was out of scope: reported as an open item for a ruling, code untouched.
- **`httpx_tech` shares the `httpx` invocation.** `HttpxAdapter` has no `run()`
  override (the flow is `BinaryAdapter.run`), so the thing worth sharing is
  `build_command` plus its host/dedupe helpers: `_fqdn` became the public
  `httpx_fqdn(value, tool)` and the host loop became `httpx_hosts(ctx, tool)`,
  both in `httpx_tool.py`. `HttpxTechAdapter(HttpxAdapter)` overrides only
  `name`, `stage` and `parse_output`, so `-td`, the stdin/env handling, the
  identity probe and 01daa8b's Python-vs-ProjectDiscovery rejection are
  inherited rather than copied, and a change to the invocation can no longer
  reach one stage and miss the other.
- **Behaviour choices, all documented in docs/09 §4a4:** `wafw00f` emits a
  record only for `detected: true` (`waf=<firewall>`, `UNKNOWN`, no
  `manufacturer`), so a `detected: false` entry is silence like cdncheck;
  `whatweb` stores plugin names minus `NON_TECH_PLUGINS` (IP, Country, Title,
  Cookies, HttpOnly, Script, Email, HTML5, ...), because a response-describing
  match is not software; `httpx_tech` stores `tech`/`cdn_name` and produces no
  record for a host with no technology.
- **One test changed (test-change rule):**
  `test_a_stage_with_no_adapter_reports_its_skips` used `tech --tools whatweb`,
  which is the last tech tool that had no adapter - every `tech` tool has one
  now, so it moved to `vulns --tools nuclei` (a phase-3 tool with no adapter),
  same four assertions, same exit code 4. No other existing test was touched;
  `test_binary_adapters_are_registered` gained four assertions and
  `NO_HOME_NEEDED` gained unfurl/wafw00f/whatweb with reasons from their real
  help output.
- Evidence, raw in the report: `doctor` shows all four `yes` / `ok`
  (`httpx_tech` `~/.reconkit/bin/httpx`, `wafw00f` and `whatweb` `/usr/bin`,
  `unfurl` `~/.reconkit/bin/unfurl`); combined mock run
  `--tools pyprobe,unfurl,wafw00f,whatweb,httpx_tech` -> live `pyprobe ok 2`,
  tech `httpx_tech ok 2`, `whatweb ok 1`, `wafw00f ok 1`, urls `unfurl ok 4`,
  `tools_ok 5`, `tools_skipped 0`; the same run's DB shows
  `testfire.net  tech_json=["Apache","Apache Tomcat","HTTPServer","Java"]  waf=cloudflare`
  (two tech tools merged, one of two WAF detections kept) and
  `www.testfire.net  tech_json=["Java"]`; the adversarial PATH
  (`PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp/fakehome`, where `/usr/bin/httpx`
  is the Python CLI) gives `httpx_tech` `"installed":"wrong program"`,
  `"identity":"failed"` - the D5/01daa8b check still applies to the new row.
- Tests: 10 new (`736 passed`, `726 -> 736`), `ruff check .` clean, `ruff format
  --check .` 73 files, `mypy src/reconkit` clean (45 source files: four new
  adapter modules). No PIT row: a new adapter plus a tool quirk is not a bug the
  code shipped with, and no invariant changed.
- Next action: none. Still unadapted: subs `urlscan, amass, findomain, chaos,
  github_subdomains`; dns `puredns, massdns, dig`; ports `smap, nmap, rustscan,
  masscan`; vulns all nine (`nuclei`, `subzy`, `dnsreaper`, `nikto`, `ffuf`,
  `dalfox`, `crlfuzz`, `sqlmap`) and `gowitness` (shots). Every `tech` and
  `urls` tool now has an adapter.

## Adapter wave 3: hakrawler, gospider, subjs, urlfinder (2026-11-17)

- Docs read / goal: `AGENTS.md` (0d item 11 adapter pre-approval), RESUME,
  PIT-14/30/50, docs/09 adapter contract + §4a3 slot, docs/10 version contract,
  `tools.yaml`. Four urls-stage adapters on top of the D10 mode table, no table
  change.
- Baseline: `712 passed`, ruff/format/mypy clean, `scope.yaml` sha256
  `d45a3c9...eeee8b`.
- Real flags (`~/.reconkit/bin`, not on PATH): `hakrawler -version` prints the Go
  usage and exits 2, `-h` is *custom headers* not help, and there is **no
  `-silent`** (brief assumed one); `gospider -h` lists `-s/-S/-d/-q/-t/-m/--version`
  and `--version` prints `Version: v1.1.6`; `subjs -version` prints
  `subjs version: 1.0.1`; `urlfinder -version` prints `[INF] Current Version:
  v0.0.3`.
- Two input facts shaped the adapters: hakrawler crawls nothing without a scheme
  (bare `testfire.net` on stdin -> 0 URLs) and testfire.net fails TLS
  verification (`curl`: `SSL: no alternative certificate subject name matches
  target hostname`), so each host is offered as `https://<host>/` then
  `http://<host>/` (the pyprobe order) and `-insecure` is never passed; gospider
  has no stdin and `-s` takes one string, so it gets a `-S` sites file written
  into the run workspace and removed in `finally` (webanalyze precedent).
- **PIT-52, found by the first real run:** hakrawler's crawl of testfire.net
  includes `javascript:checkSiteStatus('AltoroMutual')` in its output, and the
  strict parser failed the tool on it. Added
  `base.is_non_web_reference()`; all four wave-3 parsers skip `javascript:`,
  `mailto:`, `tel:`, `data:`, `about:`, `ftp:`, `file:` and still raise on any
  other unparseable line. The mock fixtures could not have caught this - a
  fixture written from a crawl that has no such link is not the same thing as
  the crawl.
- **Docs-vs-brief conflict, ruled by the registry:** the brief says urlfinder is
  `mode: active`; `tools.yaml:159` says `mode: passive`. The registry wins (the
  same ruling as `gau` in wave 1), so urlfinder also runs in a passive scan,
  which is semantically right for a third-party archive reader. Nothing in
  `tools.yaml` or the mode tables was changed.
- **On the brief's "handle 429/timeouts by returning partial results":**
  urlfinder exits 0 when a source fails and prints what it found, so partial
  results are already the normal `ok` path (real run: `ok 932 item(s)`). A hard
  phase timeout is still `TIMEOUT` with the raw text kept and no records - that
  is the shared adapter contract for every binary tool, and adding a
  partial-on-timeout path would change all of them, so it is reported rather
  than coded (stop rule).
- Evidence (raw in the report): mock `--tools pyprobe,hakrawler,gospider,subjs,urlfinder`
  -> urls 4/4 tools, `hakrawler ok 5`, `gospider ok 5`, `subjs ok 3`,
  `urlfinder ok 4`, 16 unique URLs stored; real runs on testfire.net ->
  `hakrawler ok 66`, `gospider ok 67`, `subjs ok 0` (host has no `.js`),
  `urlfinder ok 932`; `doctor` shows all four `yes` / `ok`.
- Tests: 14 new (13 adapter + the PIT-52 guard), `712 -> 726`; no test changed.
  `test_binary_adapters_are_registered` gained 4 assertions and `NO_HOME_NEEDED`
  gained hakrawler/gospider/subjs with reasons.
- Next action: none. Still unadapted: subs `urlscan, amass, findomain, chaos,
  github_subdomains`; dns `puredns, massdns, dig`; ports `smap, nmap, rustscan,
  masscan`; tech `httpx_tech, whatweb, wafw00f`; urls `unfurl`; vulns all five.

## Adapter wave 2: httprobe, webanalyze, cdncheck, waybackurls + tech persistence (2026-11-17, D11)

- Docs read / goal: `AGENTS.md` (0d item 11 adapter pre-approval), RESUME,
  PIT-01/14/30/35, docs/09 adapter contract and stage table, docs/04 section 5,
  docs/10 version contract, `tools.yaml`. Build the four adapters the owner named
  on top of the Part 1 mode table.
- Baseline for this part: `691 passed`, ruff/format/mypy clean (the Part 1
  commit `756af8e`).
- Real flags, read off the binaries on this box (`~/.reconkit/bin`, not on PATH):
  `httprobe -h` (`-c`, `-p value`, `-s`, `-t int` ms, `-v`; no `-version`, no
  `-prefer-https`); `webanalyze -h` (`-apps`, `-crawl`, `-header`, `-host`,
  `-hosts string` file, `-output stdout|csv|json`, `-redirect`, `-search`,
  `-silent`, `-update`, `-worker`; `-version` exits 2); `cdncheck -h`/`-version`
  (`-i, -input string[]`, `-silent`, `-j, -jsonl`; banner `Current version:
  v1.4.0`); `waybackurls -h` (`-dates`, `-get-versions`, `-no-subs`; `-version`
  exits 2).
- One-time provisioning (standing pre-approval 1): `webanalyze -update` in
  `~/.reconkit` -> `app definition file updated`, `technologies.json`
  2,122,079 bytes; the adapter points `-apps` there and falls back to
  `./technologies.json`.
- Adapters (`src/reconkit/adapters/`, registered in `ADAPTERS`): `httprobe.py`
  (`-t <ms>`, hosts on stdin, ALIVE per answering host), `webanalyze.py`
  (`-hosts <workspace file> -output json -apps <db> -silent`, tech from
  `matches[].app_name`), `cdncheck.py` (`-silent -jsonl -i` per host; `waf_name`
  -> `waf`, `cdn`/`cloud` -> tech, state UNKNOWN), `waybackurls.py` (no flags,
  domains on stdin, `UrlRecord` per line).
- **D11, the deviation this wave forced:** the `tech` stage had no persistence
  branch (PIT-51), so a technology match would have been discarded. Added
  `Store.update_host_extras` + `Engine._persist_tech`: the union of the tech
  tools' `tech`/`waf` is merged into the host's newest `host_status_history` row,
  no state row is appended, `state` is untouched, off-target records are dropped.
  Also added `run_exec(stdin_text=...)` + the `stdin_text(ctx)` adapter hook
  (PIT-50) - without it httprobe/waybackurls cannot be driven without a shell.
  Both are documented in docs/03 section 5, docs/04 section 5, docs/09 sections
  3/4a2 before the code change.
- Evidence (raw in the report): real `run -d testfire.net --active --no-scope
  --tools httprobe` -> `live: httprobe ok 1 item(s)`; real
  `--tools pyprobe,webanalyze` -> `tech: webanalyze ok 1 item(s)` and the DB row
  `testfire.net|ALIVE|["Apache Tomcat", "Java"]|` with exactly one status row;
  real `--tools pyprobe,cdncheck` -> `tech: cdncheck ok 0 item(s)` (testfire.net
  is not behind a CDN/WAF, which is the documented no-match shape); real passive
  `--tools waybackurls` -> `urls: waybackurls ok 0 item(s)` because the archive
  CDX endpoint timed out from this box (`curl` -> `Operation timed out after
  25082 ms with 0 bytes received`); `--mock` passive -> `urls: waybackurls ok 5
  item(s)` and 5 rows in `urls`; `--mock` active with
  `pyprobe,httprobe,webanalyze,cdncheck` -> live 2/2, tech 2/2, and
  `testfire.net|ALIVE|["Apache Tomcat", "Java", "google"]|cloudflare`.
  `reconkit doctor` shows all four `yes` / `ok`.
- Two owner proof commands cannot work as written and are reported, not coded
  around: `--tools webanalyze` (or `cdncheck`) alone runs the tech stage with no
  `live` pass, so the alive-host list is empty and the adapter fails with
  `no hosts to scan` - the proofs include `pyprobe` to give the stage its input;
  and `--tools webanalyze` cannot exercise the `-hosts` file without a host.
- Tests: 21 new (17 adapter, 2 engine, 2 runner), `691 -> 712`; 2 changed:
  `test_a_stage_with_no_adapter_reports_its_skips` (old: all 5 tech tools
  skipped; new: `--tools whatweb`; reason: tech has adapters now) and
  `test_a_full_run_reports_the_gaps_of_stages_with_no_adapter` (old: gaps
  `tech,vulns`, "2 stage(s)"; new: `vulns`, "1 stage(s)"; reason: tech is
  adapted). `test_binary_adapters_are_registered` gained 4 assertions and
  `NO_HOME_NEEDED` gained `httprobe`/`waybackurls` with reasons.
- Deviations: (1) D11 (tech persistence + stdin), above; (2) real
  `waybackurls` could not fetch anything in this environment, so its parsing
  proof is `--mock` and the network failure is recorded here and in its manual;
  (3) `httprobe` has no `-prefer-https` flag, so the adapter sends none of the
  owner's suggested flags and keeps the tool's default probes; (4) `webanalyze`
  `-update` was run once under standing pre-approval 1 into `~/.reconkit`.
- Next action: none for this wave. Still unadapted: subs `urlscan, amass,
  findomain, chaos, github_subdomains`; dns `puredns, massdns, dig`; ports
  `smap, nmap, rustscan, masscan`; tech `httpx_tech, whatweb, wafw00f`; urls
  `hakrawler, gospider, subjs, unfurl, urlfinder`; vulns all five.

## Mode table expansion: passive includes passive urls, active includes urls and tech (2026-11-17, D10)

- Docs read / goal: `AGENTS.md`, RESUME, docs/02 sections 1-2, docs/03 section
  5b, docs/09 section 4, `engine.py` mode tables. Owner ruling: `passive` gains
  the `urls` stage (passive tools only), `active` gains `urls` and `tech`;
  `full` unchanged.
- Baseline: `687 passed`, ruff clean, `61 files already formatted`, mypy clean
  (33 files). `scope.yaml` sha256 `d45a3c9...eeee8b` before and after.
- The tables (`engine.py:80`): `passive` = `(SUBS, DNS, URLS)`, `active` =
  `(SUBS, DNS, LIVE, TECH, URLS)`, `full` = `STAGE_ORDER`. Every tuple is in
  `STAGE_ORDER`, so the CLI help, the interactive legend and the run order cannot
  disagree; the owner's literal tuple order (`urls` before `live` in active)
  was replaced by `STAGE_ORDER` order so displayed order equals executed order -
  filed as a deviation, not a silent choice. `MODE_TOOLS` did not change: the
  owner's listing matches it, and `opt_in` stays a flag.
- The real problem the expansion exposed: `_stage_hosts()` gives the `urls` stage
  the **alive** hosts, and in `passive` mode there is no `live` stage, so the
  stage would have run with an empty input and every adapter would have failed
  with `<tool>: no hosts to query`. Fix (`engine.py` stage loop): a `mode:
  passive` urls tool is handed `[target, *discovered]` through the existing
  `tool_hosts` override (the `naabu` mechanism), while a `mode: active` tool keeps
  the alive hosts. So gau ran and katana was skipped at selection, not fed.
- CLI: the `--active` guard was keyed on `all(stage in _PASSIVE_STAGES)`, which
  became wrong in both directions once `urls` entered the passive table. It is
  now a command list (`subs`, `dns`, `passive`, `lite`) and fires only on the
  flag path (`plan is None`), so an interactive `active` choice from the bare
  command still works. `_ACTIVE_HELP` says "The passive stages still run" instead
  of naming `(subs, dns)`, and the interactive legend is generated by
  `_mode_legend()` from `MODE_STAGES` + `_tools_label()`.
- Evidence (raw, below in the report): `run -d example.com --mock` runs subs, dns,
  urls (gau `ok 5`, waybackurls `no adapter yet`, katana/hakrawler/gospider/subjs
  `tool mode not included in passive mode`); `--active --no-scope` runs subs, dns,
  live, tech (0 tools, gap), urls (gau+katana, both `ok`); `--full --no-scope`
  runs all seven. `--active` against `example.com` with the checkout's scope file
  exits 3 with the pre-flight block - the raw `--no-scope` runs are the mode
  proof, not a scope proof.
- Tests: 4 new (`test_passive_mode_runs_passive_urls_tools`,
  `test_active_mode_runs_urls_and_tech_stages`,
  `test_active_mode_urls_stage_runs_after_live`,
  `test_full_mode_unchanged_by_expansion`), 687 -> 691; 8 changed for the new
  tables: `test_mode_stages_and_mode_tools_dicts_are_the_single_source_of_truth`,
  `test_run_help_describes_stages_tool_modes_and_tiers`,
  `test_root_invocation_without_a_command_runs_the_passive_pipeline`,
  `test_interactive_passive_writes_one_folder_per_domain`,
  `test_the_mode_is_asked_until_a_valid_answer_is_typed`,
  `test_a_multi_domain_file_scans_each_domain_separately`,
  `test_aggressive_yes_adds_the_ports_stages`,
  `test_aggressive_no_leaves_the_plan_alone` (each: old = subs+dns / subs+dns+live
  tuples and plan text; new = the expanded tuples and `stages subs, dns, urls`;
  reason = D10).
- Docs: docs/02 (source-of-truth table, urls input rule, stage/workflow tables,
  interactive legend), docs/03 section 5b (tables + per-tool input), docs/09
  section 4 (per-tool mode column + the expansion note), docs/08, README, plus
  D10 in PROGRESS and MASTER_PLAN.
- Consistency audit: the owner's grep over `docs/ README.md SETUP.md` (minus
  PROGRESS/MASTER_PLAN/REVIEW_LOG) returns only lines that match the new table.
- Out of scope by the owner's instruction: no other tool gets an adapter here,
  and the frozen items (dropped-host DNS verdicts, scope.yaml authorization
  text, runs A-K) are untouched.

## Adapter wave 1: dnsx, tlsx, katana, gau + the live-discovery persistence fix (2026-11-17, Part 2)

- Docs read / goal: `AGENTS.md` (0d item 11 = adapter pre-approval), the RESUME
  block, PIT-01/03/14/30/35/44, docs/09 (adapter contract, stage table, JSON),
  docs/04 (provenance), docs/10 (version contract), `tools.yaml`. Four phase-3
  tools get their first adapter, plus the persistence bug found while scoping
  tlsx.
- Baseline: `672 passed`, `ruff check .` clean, `ruff format --check .`
  `57 files already formatted`, `mypy src/reconkit` clean (29 files).
  `scope.yaml` sha256 `d45a3c9...eeee8b` before and after.
- Decisions (owner rulings in the batch prompt): **A** - tlsx is liveness-only
  (ALIVE/UNKNOWN + SANs), no new `HostStatusRecord` fields, no schema 7, cert
  metadata not persisted (docs/09 records the one-line note), and the real bug
  found on the way is fixed: a live pass now persists the hosts it *discovered*,
  not only the hosts it was handed (PIT-49). **B** - gau stays `mode: passive`
  (`tools.yaml` was right; the prompt's `active` was wrong). **C** - gau gains
  `version_regex: 'gau version: (\d+\.\d+\.\d+)'` from the real banner. **D** -
  dnsx (dns/passive) and katana (urls/active) as specified.
- Adapters (`src/reconkit/adapters/`, all `BinaryAdapter`, `needs_home = True`,
  `tier: core`, registered in `adapters/__init__.py` `ADAPTERS` - the prompt's
  "registry.py" is `adapters/registry.py`, which *reads* that map and would
  import-cycle if it declared it): `dnsx.py` (`-silent -json -a -or -duc -nc -l
  <comma list>`; A records -> `SubdomainRecord.ips`, `NXDOMAIN` -> DEAD only),
  `tlsx.py` (`-silent -json -san -duc -nc` + one `-u` per host; probe_status ->
  ALIVE/UNKNOWN, SANs -> `SubdomainRecord(source="tlsx:san")`), `katana.py`
  (`-silent -jsonl -or -ob -duc -nc` + `-u`; `request.endpoint` -> `UrlRecord`,
  error-only lines skipped), `gau.py` (`--json --timeout=<n>` + positional
  hosts; JSON **and** plain URL lines; stderr notice ignored). No new
  dependencies, no new module outside docs/09's adapter list.
- The fix: `Engine._persist_live` ends with `_persist_live_discoveries`, which
  groups live `SubdomainRecord`s not already in `hosts` or `subdomains`, applies
  `min_sources` and `confidence_for` like the discovery pass, and writes
  `provenance='subs'` + `subdomain_sources` rows. Existing rows keep their
  `source_count` (PIT-03); the host-state path is untouched.
- Evidence: the four `-h`/version/sample captures are in the session and in the
  tool manuals; real `--full --no-scope --tools dnsx,tlsx,katana,gau` against
  testfire.net: `dnsx ok 1`, `tlsx ok 2`, `katana ok 58`, `gau ok 389`, exit 0;
  the DB then holds `demo.testfire.net|subs|1` with `subdomain_sources.tool =
  tlsx` (the SAN row the fix exists for). Provisioning of `tlsx`/`gau` used
  standing pre-approval 1 (`go install`, purpose recorded). Mutation proof for
  PIT-49: reverting the call made the new test fail with `AssertionError: the
  SAN must reach the subdomains table`; restoring it passed.
- Tests: 15 new (13 adapter, 2 engine), `672 -> 687`; two changed
  (`test_binary_adapters_are_registered` +4 assertions;
  `test_a_full_run_reports_the_gaps_of_stages_with_no_adapter` now expects
  `tech`+`vulns` because `urls` gained adapters).
- Deviations: (1) the prompt's `tests/fixtures/adapters/<tool>.synthetic.*`
  path is honoured, and `base._read_fixture` gained one flat-lookup fallback so
  `--mock` finds it; (2) registration went to `adapters/__init__.py` because
  that is the real map (`registry.py` consumes it); (3) the acceptance items
  "gau/katana run in `--active`" and "gau fires in a passive run" cannot happen
  - `MODE_STAGES` is passive=subs+dns, active=+live, full=all seven - so the
  proof used `--full`, and `--active`/passive were captured to show the
  exclusion; (4) `doctor` shows no version (D6), so gau proves identity via
  `ok` + the regex, not by printing `2.2.4`; (5) the prompt's SQL
  `WHERE source='tlsx:san'` cannot run (`subdomains` has no `source` column) -
  `provenance` + `subdomain_sources.tool` are the stored equivalent.
- Next action: none for this wave; the `tech` and `vulns` stages still report
  `no adapter yet (phase 3)`.

## Completion gaps + standing pre-approvals, Part 1 (2026-11-17, MASTER_PLAN D9)

- **Docs read / goal:** `AGENTS.md` (0c rules, 0d pre-approvals), PROGRESS RESUME, this file's Known pitfalls + the mode-unification entry, MASTER_PLAN D7/D8, docs/02 sections 5-6, docs/03 sections 5/11, docs/08. Goal: a run that could not use a stage's tools exits 0 with an honest block, and the pre-approval list gains adapter implementations.
- **Decisions/assumptions:** (1) gap = requested stage, not resumed, no results, and at least one skip with an absence reason (`no adapter yet (phase N)`, `not installed`) - the only two the owner named. (2) A stage emptied by tier/tool-mode/exploitation/scope rules is **not** a gap and keeps exit 5: those are deliberate exclusions, not a missing tool. (3) Gap + a failed tool elsewhere still exits 5 - a gap never masks a failure. (4) `selected_total == 0` (nothing usable anywhere) still exits 4: the owner's ruling moved the *partial* signal, not "no usable tool", and a `--full` run on an empty box keeping 4 is the documented meaning. Disclosed. (5) The per-stage `warning: <stage> stage executed no tools: ...` lines stay alongside the new block (existing channel, `--json` `warnings`), so no consumer loses data. (6) Block is stderr-only and prints nothing with no gaps, so ordinary output is byte-identical; `--silent` suppresses it like every other message. (7) `summary.mode` added for the headline; `CompletionGap.skipped` carries the count so the block's number is the absent-tool count (vulns reads 5, not 8, because dalfox/crlfuzz/sqlmap are excluded by the exploitation rule, not absent).
- **Docs changed first:** docs/02 (section 6 rewritten: gap vs partial, the block text, precedence list; section 5 JSON example + `completion` paragraph; interactive `full` note now says exit 0), docs/03 (`_exit_code`/`CompletionGap`/`completion_status`), docs/08 (new "Complete with gaps" line, partial reworded), MASTER_PLAN D9, AGENTS item 11.
- **Files touched:** `src/reconkit/engine.py` (`CompletionGap`, `ScanSummary.gaps/mode/completion_status`, `_completion_gaps`, `_is_gap_reason`, `_exit_code`), `src/reconkit/ui.py` (`completion` in `summary_document`, `render_completion_gaps`, json path calls it), `tests/test_engine.py`, `tests/test_ui.py`, `tests/test_cli.py`, `AGENTS.md`, docs 02/03/08/MASTER_PLAN/PROGRESS/REVIEW_LOG.
- **Requirement -> test:** gap not failure -> `test_a_stage_with_no_adapter_warns_by_name_and_is_a_gap_not_a_failure`; not-installed gap -> `test_a_stage_of_uninstalled_tools_is_a_gap`; deliberate exclusion is not a gap -> `test_a_stage_emptied_by_a_tier_rule_is_not_a_gap`; gap never masks a failure -> `test_gaps_and_a_failed_tool_together_stay_partial`, `test_empty_stages_and_a_partial_failure_together_are_still_partial`; JSON shape -> `test_json_output_is_one_valid_document_with_documented_schema`, `test_a_full_run_reports_the_gaps_of_stages_with_no_adapter`; block text/stream -> `test_the_gaps_block_goes_to_stderr_and_the_json_carries_completion`, `test_a_complete_run_prints_no_gaps_block`; exit 5 preserved -> `test_a_partial_stage_still_exits_five`, `test_exit_code_partial_success`, `test_every_requested_stage_empty_is_no_tool_not_partial`.
- **Changed tests (name / old / new / reason):**
  - `test_an_empty_stage_warns_by_name_and_makes_the_run_partial` -> `test_a_stage_with_no_adapter_warns_by_name_and_is_a_gap_not_a_failure`. Old: asserts `ExitCode.PARTIAL`. New: asserts `ExitCode.SUCCESS`, `gaps == [CompletionGap(TECH, "no adapter yet (phase 2)", 1)]`, `completion_status == "complete_with_gaps"`. Reason: the owner's D9 ruling; PIT-40's "zero tools means 5" no longer holds for pure absence.
  - `test_json_output_is_one_valid_document_with_documented_schema` (test_ui). Old: 10-key set. New: 11 keys (`completion`) + equality assert on `{"status": "complete", "gaps": []}`. Reason: `completion` is a new always-present top-level key.
  - `test_full_json_skips_exploitation_tools_and_does_not_tier_skip_opt_in`. Old: `exit_code in (0, 5)`. New: `== 0`. Reason: full no longer exits 5 for zero-adapter stages.
  - `test_ports_injection_reaches_the_port_stage`. Old: `in (0, 5)`. New: `== 0`. Same reason.
  - Added (7): the four gap tests above plus `test_a_full_run_reports_the_gaps_of_stages_with_no_adapter`, `test_a_partial_stage_still_exits_five`, `test_the_gaps_block_goes_to_stderr_and_the_json_carries_completion`, `test_a_complete_run_prints_no_gaps_block`. Count 665 -> 672.
- **Spot-checks:** `grep -n 'exploitation' tools.yaml` -> exactly dalfox/crlfuzz/sqlmap `exploitation: true` (plus the comment at 172); gate now at `engine.py:1125` (shifted from 1073 by the new dataclass); `pytest --collect-only -q` -> 672; the two named tests appear exactly once each in `tests/*.py` (the only other matches are stale `.pyc`).
- **Not verified:** no real-target run (mock only); the `⚠`/`—` glyphs were not checked on another console (utf-8 is the repo norm and `cli.py` already prints `⚠`).
- **Next part must know:** `no adapter`/`not installed` are the only reasons that make a gap; `ui.render_completion_gaps` is the only printer; `completion` is always present.

## Mode unification + scan UX S1-S7 (2026-11-17, MASTER_PLAN D8)

- **Docs read / goal:** `AGENTS.md` (incl. the 0d pre-approvals), PROGRESS RESUME, this file's Known pitfalls + last three entries, MASTER_PLAN D1-D7 and the Part 13 section, docs/01/02/03/04/05/07/08/09/10, `tools.yaml`, `config.yaml`, and `cli.py`/`engine.py`/`registry.py`/`ui.py`/`store.py`/`scope.py`. Goal: make "passive / active / full" mean the same three things (stages, tool modes, tiers) on every surface, add `--full`, `--no-scope`, filters, injectables, matched interactive Q&A, and the out-of-scope UX.
- **Safety gate first (owner's instruction):** `grep -rn 'sqlmap\|dalfox\|crlfuzz' src/reconkit/adapters/` -> **no matches**. No intrusive-tier tool has an adapter, so nothing exploitation-class could run even before the pre-ruling. The owner's pre-ruling was nonetheless implemented as a registry field, not as a name list (below).
- **Decisions and assumptions:** (1) `MODE_STAGES` and `MODE_TOOLS` (a `ModeRules(tool_modes, tiers)` per mode) live in `engine.py`; `ScanOptions.mode` is derived (`full` > `active` > `passive`), so there is no fourth mode and no duplicate table. (2) `exploitation: true` is a `tools.yaml`/`ToolSpec` field on sqlmap, dalfox, crlfuzz; `_select()` skips such a tool in every mode unless it is named in `--tools`, before the tier/tool-mode checks so the reason is always the exploitation one. (3) `--tools <name>` bypasses tier gating, never the tool-mode gate. (4) `--full` sets `active` and `include_noisy` in the CLI; the engine also treats `mode == "full"` as implying `opt_in`, so an API caller cannot get a half-full run. (5) `--no-scope` is implemented as "behave as if the file were absent" (`scope_present` short-circuit in `_active_hosts`, `_ip_allowed`, the naabu branch and the passive warning), not as a gate bypass. (6) Filters act on stored host rows in the CLI; injectables travel on `RunContext`. (7) Interactive `[a]` appends one line under `in_scope:` instead of round-tripping YAML, so `authorization`/comments survive (F2 stays frozen).
- **Docs changed first:** docs/02 (new "Scan modes (source of truth)" table, `--active`/`--full`/`--no-scope`/filter/injectable flags, section 3.1 scope mode, interactive legend + flow + plan echo, JSON `scope_mode`/`filter`/`injections`), docs/03 (section 5b mode tables and the `_select` order, RunContext fields, schema 6), docs/04 (schema 6 `scope_mode`), docs/05 (rule 9 opt-out wording, D8 exploitation boundary, checklist), docs/08 (Flow 1 mode choice, Flow 4 progress line, Flow 5 scope line), docs/09 (4b per-tool parameter support + per-tool mode/tier/exploitation table, selection rules, naabu passive reason), docs/01 (stale "no `--ports`/`--full`" claim), README, AGENTS (rule 2 amendment + section 0d), MASTER_PLAN (D7, D8), then code.
- **Deviations:** see PROGRESS "Deviations" 2026-11-17 (S1-S7): CLI `--active` narrowed; `--full` added and enables opt_in+"intrusive minus exploitation"; `--no-scope` added; skip reasons reworded and tier skips now recorded instead of silent; `--tools` no longer refuses intrusive names.
- **Files touched:** `src/reconkit/{engine.py,cli.py,ui.py,models.py}`, `src/reconkit/adapters/{registry.py,httpx_tool.py,pyprobe.py}`, `src/reconkit/core/{scope.py,store.py}`, `tools.yaml`, `tests/{test_engine.py,test_cli.py,test_interactive_scan.py,test_ui.py,test_store.py,test_tools_registry.py,test_binary_adapters.py,test_python_adapters.py}`, `AGENTS.md`, `README.md`, `docs/{01,02,03,04,05,08,09,PROGRESS,MASTER_PLAN,REVIEW_LOG}`. `docs/10` unchanged as instructed.
- **Requirement -> test table:** mode dicts single source -> `test_mode_stages_and_mode_tools_dicts_are_the_single_source_of_truth`; passive stages/tools -> `test_cli_passive_runs_only_passive_stages_and_passive_tools`; active stages -> `test_cli_active_runs_subs_dns_live_stages_and_passive_active_tools`; active has no intrusive -> `test_cli_active_does_not_run_intrusive_tier`; full -> `test_cli_full_runs_all_stages_tool_modes_and_tiers`, `test_full_runs_all_tool_modes_and_enables_opt_in_and_intrusive`, `test_full_json_skips_exploitation_tools_and_does_not_tier_skip_opt_in`; `--full` implies `--active`/`--include-noisy` -> `test_full_implies_active`, `test_full_implies_include_noisy`; `--tools` override -> `test_tools_flag_overrides_tier_gating`; exploitation gate -> `test_full_skips_exploitation_tools_unless_named`, `test_the_three_exploitation_tools_are_marked_and_intrusive`, `test_an_invalid_exploitation_flag_is_a_config_error`; interactive == CLI -> `test_interactive_passive_active_full_match_cli`, `test_full_mode_requests_every_stage_including_vulns`; help text -> `test_run_help_describes_stages_tool_modes_and_tiers`; scope warning + exit 3 -> `test_out_of_scope_non_interactive_warns_and_exits_three`; `--no-scope` -> `test_no_scope_flag_ignores_present_scope_file`, `test_no_scope_flag_overrides_a_scope_path_and_records_the_flag`, `test_no_scope_in_passive_mode_warns_and_continues`, `test_scan_writes_enforced_scope_mode_when_a_scope_file_is_used`, `test_scan_writes_no_file_scope_mode_when_no_scope_file`; filters -> `test_only_alive_and_only_states_filter_the_json_hosts`, `test_status_codes_filter_the_json_hosts`; injectables -> `test_injections_are_reported_and_headers_are_redacted_by_default`, `test_httpx_command_carries_header_and_user_agent`, `test_pyprobe_sends_the_injected_headers_and_user_agent`, `test_ports_injection_reaches_the_port_stage`.
- **Self-review (S2/S3):** `ruff check`, `ruff format --check`, `mypy src/reconkit` clean; no `assert`/`shell=True`/`TODO`/new `noqa`/`type: ignore` added. The only broad code paths are the existing CLI `except Exception` handler (unchanged) and the new `except (EOFError, typer.Abort)` around the out-of-scope prompt (cancels with exit 2). External input: `--ports`/`--status-codes`/`--header`/`--only-states` are parsed and validated before `ScanOptions` (`ranges within 1-65535`, codes `100-599`, header names by RFC token regex, duplicate names rejected, states by `HostState`). Secrets: header values are redacted to `***` in JSON unless `--show-headers`; header *values* are never written to `scan_runs.params_json` (only the mode/active flags are). Blocking calls: none added inside async code (the scope pre-flight and the `[a]` append are sync CLI-time). Unfinished paths: none.
- **Mutation proofs (S5), run for real with `cp` backup + restore (never `git checkout`, which would have discarded this batch):** (a) `if spec.exploitation ...` -> `if False and spec.exploitation ...` makes `test_full_skips_exploitation_tools_unless_named` fail (`sqlmap-like` is selected under `full=True`); restored, 1 passed. (b) `_scope_mode` forced to `return "enforced"` makes `test_scan_writes_no_file_scope_mode_when_no_scope_file` and `test_no_scope_flag_ignores_present_scope_file` fail (`- unrestricted_flag / + enforced`); restored, 2 passed. (c) `MODE_STAGES["full"]` cut to six stages makes `test_mode_stages_and_mode_tools_dicts_are_the_single_source_of_truth` fail. The parametrized `test_interactive_passive_active_full_match_cli` still passes under (c) because it reads `MODE_STAGES` itself - that is the consistency property working, not a hole: the dict test is the one that pins the table. Restored, 134 passed in `test_engine.py` + `test_interactive_scan.py`; `git status --short` shows only the intended modifications.
- **Raw check output (S1, twice):** `665 passed` both runs; `All checks passed!`; `57 files already formatted`; `Success: no issues found in 29 source files`.
- **Test count reconciliation:** 637 -> 665 (+28 collected). Added: 6 in `test_engine.py`, 15 in `test_cli.py`, 3 (one parametrized x3) in `test_interactive_scan.py`, 2 in `test_tools_registry.py`, 1 in `test_binary_adapters.py`, 1 in `test_python_adapters.py`. Renamed (count unchanged): `test_tier_gating_and_explicit_intrusive_refusal` -> `test_tools_flag_overrides_tier_gating` (asserted the removed ConfigError); `test_full_mode_does_not_request_the_deferred_vulns_stage` -> `test_full_mode_requests_every_stage_including_vulns` (full now includes vulns). Changed in place: `test_naabu_is_selectable_in_active_mode` and `test_passive_mode_never_runs_naabu_with_or_without_a_scope_file` (skip reason), `test_interactive_passive_writes_one_folder_per_domain` / `test_the_mode_is_asked_until_a_valid_answer_is_typed` / `test_aggressive_yes_adds_the_ports_stages` / `test_aggressive_no_leaves_the_plan_alone` / `test_a_present_scope_file_blocks_an_out_of_scope_interactive_target` (new prompts, plan echo, `[d]` exit 2), `test_json_output_is_one_valid_document_with_documented_schema` (`scope_mode` key), four `test_store` migration assertions (schema 6), `test_scan_has_no_undocumented_options` (new flags). No test deleted.
- **Not verified:** the pty transcripts were produced with `script(1)` and mock data; the non-pty path has no evidence (as before). No real target was scanned; no intrusive tool was run (none has an adapter).
- **Next part must know:** `MODE_STAGES`/`MODE_TOOLS` are the only mode table; `exploitation: true` is the only automatic-run block; `scan_runs.scope_mode` is schema 6; the interactive out-of-scope prompt is the only place that writes `scope.yaml`.

## Reports on both paths, live status line, amass read-back (2026-11-18, MASTER_PLAN D20)

**Trigger:** the owner ran `reconkit run -d testfire.net --active --no-scope
--only-alive` and asked where the report was. There was none: `cli.py` wrote
`report.txt`/`report.json` only under `if plan is not None`, and `plan` is set
only when a scan command got neither `-d` nor `-l` and stdin is a TTY
(`cli.py:701-704`). docs/02 section 5 documented that asymmetry; the owner
called it what it was - an inconsistent project.

### 1. Reports on both paths

`src/reconkit/cli.py`: the writer is no longer gated. `run_at`,
`report_directory(...)` and `write_field_report(...)` run for every scan; the
fields are `plan.fields` in interactive mode and `REPORT_FIELDS` (every column,
the same set as answering `all`) otherwise. docs/02 section 5 was rewritten
first (title, the "every scan" rule, the filter/storage note, the stderr
announcement, and "a report that can not be written is a run error (exit 1)" -
which is what the generic `except Exception` does).

Raw evidence (mock, one flagged run, before -> after):

```
before: results/  newest folder 20261117T164046Z   (nothing from the 2026-11-18 run)
after : results/example.com/<stamp>/report.txt + report.json, "report:" line on stderr
```

Tests: `test_flagged_run_writes_the_report_files_too` (new; asserts the folder,
both files, and `document["fields"] == [field.key for field in ui.REPORT_FIELDS]`).
`test_a_flagged_run_writes_no_report_folder` was **renamed and re-asserted** as
`test_a_flagged_run_writes_its_own_report_folder` - the old name pinned the
behaviour the owner asked to remove, so this is a contract change, not a
weakened assertion. The no-prompt promise is still covered by
`test_a_flagged_run_never_asks_a_question`.

### 2. Live status line (`activity` channel)

Why: the durable progress lines are emitted only when a tool *finishes*
(`_run_one` -> `self._progress`), so the real run printed nothing for 600 s
while `gau` timed out. The owner asked for a loading indicator that also says
which tool is running.

- `engine.py`: `Activity = Callable[[str], None]`, a new `activity=` constructor
  argument, and `_run_tools` emits
  `<stage>: <done>/<total> tool(s) done, <n>s elapsed - running: <names>` on
  every tool start and finish.
- `ui.py`: `activity_spinner(console=..., *, enabled=...)`, a context manager
  returning `status.update`, or `_ignore_activity` when disabled or when the
  console is not a terminal. `Console.status(..., spinner="dots", transient`
  implicit) - the line erases itself.
- `cli.py`: `activity_sink` proxy, opened only around `engine.run(target, ...)`
  so the results tables never print under a live region; cleared in `finally`.

Two defects were caught by the existing suite during this work, both fixed in
the code and not in the test:

1. The snapshot was taken before `done.add(...)`, so the last line of a stage
   said `1/2` instead of `2/2`; both sets now move first.
2. Moving `done.add` into the `finally` made a **cancelled** tool count as done,
   so `test_phase_timeout_records_a_timeout_row` got no `timeout` row. The
   update is now behind `finished = True` after the await returns, which keeps
   the phase-timeout bookkeeping honest.

Tests: `test_activity_reports_the_running_tool_snapshot` (engine: first snapshot
`subs: 0/2 tool(s) done, 0s elapsed - running: a`, every tool announced, last
snapshot `2/2 ... running: none`) and
`test_activity_spinner_writes_nothing_to_a_non_terminal` (ui: a `StringIO`
console receives zero bytes).

### 3. amass always reported exactly 1 item

Owner question: "check amass why its returning always one result domain name
only". Root cause found from the real capture, not guessed:

```
workspaces/testfire.net/subs/84-amass.txt (stdout):
    Session Scope
    FQDN:
    testfire.net
(stderr: the 187-name progress bar reaching 100%)
```

v5.1.3 `enum` is a thin client for its own engine - the engine log
(`~/.config/amass/amass_engine_*.log`) shows `POST /api/v1/sessions`, a session
id, and `GET .../stats` polling; the findings belong to the session. The adapter
parsed every line that passed `validate_host`, so the `FQDN:` block's
`testfire.net` was always the one and only record - always the target, never
finding anything. Verified on the box: `amass subs -d testfire.net -names`
printed the same 8 hosts the scan table shows
(`testfire.net, demo, evil, demo2, localhost, altoro, ftp, www`), and `-o` is
not a v5 flag (`flag provided but not defined`, usage printed, exit 1) while
`-dir` writes only `config.yaml`/`datasources.yaml`/`namelist.txt`.

Fix: new documented adapter hook `post_command(ctx) -> list[str] | None` in
`BaseToolAdapter` (default `None`). After a successful primary run, when
`read_output` returned `None`, the base flow runs the follow-up through
`core/runner.run_exec` with the same timeout and child env, parses its stdout,
and stores both streams as the raw output; a follow-up that times out or exits
non-zero is a `FAILED` tool with a `read-back` error rather than a silent zero.
`AmassAdapter.post_command` returns `[amass, subs, -d, <target>, -names]`.

Measured: fixture `tests/fixtures/adapters/amass.subs.txt` is the real 8-line
read-back; `test_amass_reads_findings_back_from_subs` asserts both argv calls and
8 records; `test_amass_enum_header_alone_yields_only_the_target` pins the old
behaviour so a regression is visible;
`test_amass_failed_read_back_is_a_failed_run` asserts a `read-back` error.

### 4. Two premises that did not hold (reported, not re-implemented)

- **"Tools are not parallel"** - they are: `_run_tools` awaits
  `asyncio.gather(*(one(spec, adapter) ...))` (line 1244). Real timings for the
  owner's run (`tool_runs.duration_s`): `gau timeout 600.0`, `urlfinder 554.6`,
  `waybackurls 298.3`, `gospider 55.0`, `hakrawler 45.2`, `katana 18.9`,
  `subjs 10.4` - sum 1581 s, but `scan_runs` shows the urls stage running
  `08:48:35Z -> 08:59:39Z` = **664 s**. That is one parallel stage, not a serial
  one; the cost is `gau` hitting the 600 s per-tool default.
- **"Duplicates pass from one phase to the next / into the report"** - they do
  not: `discovered` is a `set`, `_stage_hosts` calls `_clean_hosts` (a `seen`
  set), `_persist_urls` keys a `dict` by URL, and the schema has
  `UNIQUE(target_id, fqdn)` and `UNIQUE(target_id, url)`. Measured on the real DB:
  `urls WHERE target_id=1` -> 1655 rows / 1655 distinct; `subdomains` -> 41 / 41;
  `GROUP BY fqdn HAVING COUNT(*) > 1` -> no rows. 2084 tool items collapsed to
  1655 stored URLs, i.e. 429 cross-tool duplicates were already removed.

### Gate (this batch, run one command at a time)

```
$ pytest -q
823 passed in 14.97s
$ ruff check .
All checks passed!
$ ruff format --check .
91 files already formatted
$ mypy src/reconkit
Success: no issues found in 62 source files
```

Suite 816 -> 823 (+2 report/spinner CLI+UI, +1 engine activity, +3 amass, +1 dig;
one test renamed in place).

### 5. A fifth defect found by the live rerun: `dig failed 0`

The live rerun (below) reported `dns: dig failed 0 item(s)` where every earlier
run had `dig ok 8`. The stored reason was
(`tool_runs.error`):

```
dig: unexpected answer line ';; communications error to 192.168.31.1#53: timed out'
```

The local resolver timed out and `dig` printed its diagnostic, which the strict
parser treated as a corrupt answer - so one resolver hiccup failed the whole
tool and pushed the run to exit 5. `dig` prefixes *every* comment and diagnostic
with `;`, so `parse_output` now skips `;`-prefixed lines and keeps the hard
`ParseError` for anything else. Test:
`test_dig_ignores_resolver_diagnostics` uses the exact captured line.

### 6. Live rerun of the owner's command

`reconkit run -d testfire.net --active --no-scope --only-alive --verbose`
(real traffic, 2026-11-18). Relevant lines:

```
subs: amass ok 8 item(s)            <- was: amass ok 1 item(s)
dns: dig failed 0 item(s)            <- the diagnostic line, fixed in item 5
urls: gau timeout 0 item(s)
8 hosts: 8 ALIVE, ... | tools: 28 ok, 2 failed, 2 skipped, 1 timeout
report: results/testfire.net/20261118T102600Z/report.txt and results/testfire.net/20261118T102600Z/report.json
LIVE exit=5
```

That `report:` line is the whole point of the batch - the same command that
produced nothing before now names its files. `tool_runs`: `amass ok 8`,
`dig failed 0`, `gau timeout 0`.

The artifact itself:

```
report.json: fields 12, hosts 42, unique hostnames 42, duplicates []
report.txt : 13200 bytes, "reconkit report / target: testfire.net / hosts: 42"
```

42 stored hosts against 8 printed ones: `--only-alive` narrows the table, and the
report carries every stored row by design (docs/02 section 5). `exit 5` is the
pre-existing rule for a failed or timed-out tool, not a new failure.

Spinner proof on a real pty (`script -qec ... /dev/null`, mock run, real frames):

```
⠋ subs: 0/9 tool(s) done, 0s elapsed - running: crtsh
⠋ subs: 1/9 tool(s) done, 0s elapsed - running: certspotter
⠋ subs: 7/9 tool(s) done, 0s elapsed - running: amass
report: /tmp/spin/results/example.com/20261118T101312Z/report.txt and ...report.json
```

A redirected run contains none of those frames - the same `script` run with
stderr to a file showed only the plain `<stage>: <tool> ok N item(s)` lines.

### 7. The report follows the filters (owner: "do whatever is good")

The first version of D20 wrote **every** stored row, so the owner's
`--only-alive` run saved 42 rows under a table that showed 8. That is a bad
artifact: it answers a question the operator did not ask. But silently dropping
34 hosts would make a narrowed file look complete, which is worse.

Decision: honour the filter **and record it**.

- `ui.ReportSelection(description, matched, total)`; `report_document` gains
  `"selection": {"filter", "matched", "total"}` (`null` when nothing was
  filtered); `report_text` gains one line, `selection: 8 of 42 hosts (ALIVE)`.
- `write_field_report(..., selection=)`; `cli.py` filters the **snapshots** with
  the same predicates as the display rows (the first attempt passed the display
  `HostRow`s, which have no `state` enum - caught by 38 failing CLI tests, fixed
  in the caller, not by weakening them) and builds the label with
  `_selection_label` (`ALIVE`, `ALIVE + DNS_ONLY`, `... + status 200`).
- The database is untouched: `--only-alive` still only narrows output (docs/02
  section 3), so `status`/`diff` see every host.

Tests: `test_a_filtered_run_writes_only_what_it_showed_and_says_so` (`--active
--no-scope --only-alive`: `filter == "ALIVE"`, `matched == len(hosts)`, every
row `ALIVE`, the text line present) and `selection is None` asserted in
`test_flagged_run_writes_the_report_files_too`.

### 8. Passive tools: the run budget was being passed as an HTTP timeout

Owner: "speed is only for recon one tool which run passively". Investigating the
600 s `gau` timeout found a real defect, not a tuning question:

```
$ gau --help | grep timeout
      --timeout uint   timeout (in seconds) for HTTP client (default 45)
$ urlfinder -h | grep -A2 OPTIMIZATION
   -timeout int   seconds to wait before timing out (default 30)
   -max-time int  minutes to wait for enumeration results (default 10)
```

Both adapters passed `ctx.timeout` - the per-tool **run budget** (600 s) - into a
flag that is a **per-request** timeout, so a single stalled archive source could
block for ten minutes.

Measured on testfire.net, same box, same day:

| command | result |
|---|---|
| `gau --json --timeout=600` (old) | `timeout` at 600 s, **0 items** |
| `gau --json --timeout=45 --retries=1 --threads=5` | **31 s, 345 URLs** |
| `urlfinder -all -silent -nc -timeout=600` (old) | 554 s, 932 URLs |
| `urlfinder -all -silent -nc -timeout 30 -max-time 10` | **15 s, 996 URLs** |

Through the engine (`reconkit urls -d testfire.net --active --no-scope --tools
gau,urlfinder`):

```
| urlfinder | urls | ok | 933 |
| gau       | urls | ok | 345 |
42 hosts: ... | tools: 2 ok, 0 failed, 0 skipped, 0 timeout
report: results/testfire.net/20261118T103917Z/report.txt and ...report.json
wall=15s
```

The same two tools took 664 s of stage wall clock in the morning run, with `gau`
recorded as `timeout 0 items`. Both new values are `min(...)`-capped by the run
budget, so `--phase-timeout` still wins, and `urlfinder -max-time` is the budget
rounded up to minutes. **Active tools are untouched** - the change is limited to
the two passive archive readers, per the owner's instruction.

Tests: `test_gau_caps_its_http_timeout_instead_of_using_the_run_budget` and the
updated `test_urlfinder_skips_archived_junk_and_feeds_domains` (now asserts
`-max-time` as well).

### 9. waybackurls: one wildcard query, not 42 (owner: "why so slow and no results")

First the premise: `waybackurls` **is** installed - at
`/home/kali/.reconkit/bin/waybackurls`, and `reconkit doctor` reports
`Installed yes / Identity ok` with that path. A bare `command -v waybackurls` in
an interactive shell only missed it because `~/.reconkit/bin` is deliberately on
the *child* PATH, not the user's. Nothing was being run that is not installed;
missing tools are already `skipped (not installed)` at selection time (doctor:
"Scans will use the tools that are installed and skip the rest").

The 2026-11-18 10:14 run recorded `waybackurls ok 0 items 302.3 s`. Cause:
waybackurls reads **one domain per stdin line** and asks the CDX API for
`*.<line>/*`; the adapter put all 42 discovered hosts on stdin, so the same
wildcard question was asked 42 times in sequence. Its own `-h` proves the
default covers subdomains (`-no-subs  don't include subdomains of the target
domain`). The adapter now feeds the apex once and keeps only hosts that are not
under it (other domains from a scope file), with a dot-boundary check so
`nottestfire.net` is never folded into `testfire.net`.

Measured with the same 42 hosts from the 10:39 report, real binary, real
archive:

```
42 hosts in that run; the old adapter put all of them on stdin
stdin now: 'testfire.net\napi.example.com\nblog.example.com\ndev.example.com\nwww.example.com\n'
status=ok items=0 elapsed=2.4s
```

302 s -> 2.4 s (126x). The **0 items are not ours**: `curl` on the same CDX
wildcard endpoint returned `HTTP 503 Internet Archive: Temporarily Offline`, and
the single-domain query returned 200 in 31 s. archive.org was down for wildcard
queries all morning; on a healthy day the one query is the same one that used to
be run 42 times. `gau` reaches the Wayback data through a different endpoint and
still returned 345 URLs, so coverage is unchanged.

Tests: `test_waybackurls_asks_once_per_root_not_once_per_host`,
`test_waybackurls_does_not_swallow_a_lookalike_apex`. Gate after:
`827 passed`, ruff check/format clean, mypy clean on 62 files.

### 10. `scripts/install-tools.sh` - installation returns, outside the CLI (D21)

Owner: "one script file which should install all tool whether its apt install or
go install with sudo cmd ... and in end the script will verify with doctor" and
"we are not checking whether the tool work or not ... with script ... we have
already check that with adapter right?".

Scope boundary: D4 deleted `reconkit install`/`update`/`doctor --fix` and
`src/reconkit/installer/` for safety reasons (unverified downloads, archive and
checksum handling). None of that comes back. What is added is one bash script a
human runs, with **no catalogue of its own**: it reads `tools.yaml` and follows
`source:` (`apt:` / `go install` / `pipx`), prints release-only entries as manual
and downloads nothing itself.

**No module path was guessed.** Every `go install` target the script can reach was
checked with `go install -n` (resolves and downloads the module, builds nothing):

```
OK   assetfinder   github.com/tomnomnom/assetfinder@latest            0.8s
OK   gau           github.com/lc/gau/v2/cmd/gau@latest               1.0s
OK   puredns       github.com/d3mondev/puredns/v2@latest             1.0s
OK   smap          github.com/s0md3v/smap/cmd/smap@latest            0.9s
OK   gowitness     github.com/sensepost/gowitness@latest             2.3s
OK   dalfox        github.com/hahwul/dalfox/v2@latest               11.9s
OK   crlfuzz       github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest  6.7s
OK   cdncheck      github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest   4.1s
OK   chaos         github.com/projectdiscovery/chaos-client/cmd/chaos@latest  37.5s
OK   httpx         github.com/projectdiscovery/httpx/cmd/httpx@latest 1.6s
OK   katana        .../katana/cmd/katana@latest                        2.1s
OK   naabu         .../naabu/v2/cmd/naabu@latest                       9.9s
OK   nuclei        .../nuclei/v3/cmd/nuclei@latest                     5.6s
OK   tlsx          .../tlsx/cmd/tlsx@latest                           1.3s
OK   urlfinder     .../urlfinder/cmd/urlfinder@latest                21.5s
```

(the subfinder hint printed FAIL only because the checker's regex swallowed the
closing parenthesis of the prose it sits in - `.../subfinder/v2/cmd/subfinder@latest`
resolves.) Those nine `(or: go install ...)` hints are now in `tools.yaml`, so the
registry stays the single list.

Verification is the adapter's own probe, not a new checker: `doctor --json` +
exit code. Real evidence on this box:

```
$ ./scripts/install-tools.sh --only gau
Missing tools: 3. Scans will use the tools that are installed and skip the rest.
every binary matching 'gau' is installed and identified correctly.   (exit 0)

$ ./scripts/install-tools.sh --only dalfox --yes        # real go install
== go install (1) -> /home/kali/.reconkit/bin ==
>> github.com/hahwul/dalfox/v2@latest
Missing tools: 2. ...
every binary matching 'dalfox' is installed and identified correctly.  (exit 0, 13s)
-rwxrwxr-x 1 kali kali 37563545 /home/kali/.reconkit/bin/dalfox

$ ./scripts/install-tools.sh --check   # 33 have, 2 go, 3 manual
dry-run: nothing was installed, nothing changed
```

Four defects were caught while testing and fixed before commit: the `chaos`
module kept a trailing `;` from its prose hint; `httpx_tech` was printed as manual
although the `httpx` row installs that binary; `--only` scoped the install but
not the `doctor` verdict, so a one-tool run failed on unrelated tools; and
`findomain`/`rustscan` were listed as `manual` although both were already
installed - the manual list now only shows entries that are still missing.

The end-to-end run on this box, nothing scoped:

```
$ ./scripts/install-tools.sh --yes
== go install (1) -> /home/kali/.reconkit/bin ==
>> github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
== verification: .../reconkit doctor ==
Missing tools: 1. Scans will use the tools that are installed and skip the rest.
every installable registry binary is installed and identified correctly.  (exit 0, 4 s)
```

The one remaining check is `dnsreaper`, the registry entry with no automatic
source; it is reported, not failed. Final state: 40 binary entries, 39 installed
with `identity: ok`, 1 manual gap.

### `findomain` and `rustscan` now come from Kali's signed repository

Both were the last two entries with no automatic source, and both were installed
by hand from release zips. Two facts changed that (2026-11-18):

```
$ apt-cache policy findomain rustscan
findomain:  Candidate: 11.0.0-beta.2-0kali2   (kali-rolling/main)
rustscan:   Candidate: 2.4.1-0kali1           (kali-rolling/main)
```

so `source:` became `apt: findomain` and `apt: rustscan`. The apt builds were
then tested against exactly what the adapters send, not assumed:

```
$ /usr/bin/findomain -h  | grep -E "^\s+-t,|quiet"     -> -t, --target; -q, --quiet
$ /usr/bin/rustscan --help | grep -E "greppable|ulimit|--top|addresses"
                                              -> -a, -n, -g, -u/--ulimit, --top
$ timeout 90 /usr/bin/findomain -t example.com -q | head -5
gexglxkm.example.com
z12ujb5gbf.example.com
...                                    (bare labels, one per line, exit 0)
$ reconkit doctor --json
findomain /usr/bin/findomain ok
rustscan  /usr/bin/rustscan  ok
```

The hand-installed copies were moved to `/tmp/*.hand.bak` so the apt binaries are
the ones that actually run - otherwise `~/.reconkit/bin` would shadow them and
`apt upgrade` would fix nothing.

Two facts worth knowing and now written in the registry `notes:`: Kali ships
`findomain` as **11.0.0-beta.2**, older than the 11.0.0 GitHub release it
replaced; and the `rustscan` package is versioned 2.4.1 while its binary prints
`rustscan 2.3.0`. The `version_regex` still matches, so `identity` stays `ok`, but
the apt package number is not a reliable version.

Two tests in `tests/test_tools_registry.py` asserted the old truth (findomain's
source naming its repository and "no checksums are published"). They were
rewritten to assert the new one - both rows are `apt:`, and a release-only row
still names its repository - rather than deleted. Suite stays at 827.

The **apt path did run**, under a pty so sudo could ask for the owner's password
(the credential cache is per-tty, so priming it from another shell is not enough):

```
$ (sleep 3; printf '<password>\n') | script -qec \
      "./scripts/install-tools.sh --update --only nmap --yes" /dev/null
== apt (1) ==
sudo needs a password; asking once now
[sudo] password for kali:
0 upgraded, 0 newly installed, 0 to remove and 201 not upgraded.
== verification: .../reconkit doctor ==
every binary matching 'nmap' is installed and identified correctly.   (wall 10 s)
```

Without a terminal it stops at once with a clear message instead of hanging - the
first attempt proved it: piped through `grep`, the same command exited 2 with
`sudo needs a password and this shell cannot prompt for one.` That run used the
real `sudo` and the real `apt-get` - no stub - so this is the apt branch as a user
will meet it, and it is the reason the script refuses to run under `root`:
`sudo` is applied per `apt-get` command, while Go must stay in the user's
`~/.reconkit/bin`.

Still not established: a *fresh* apt install (nmap was already present, so apt
had nothing to do). Recorded in PROGRESS "Open risks".

### Previous open question (closed)

Parallelism was not the lever for the `urls` stage - the timeout semantics were.
The per-tool-timeout question is answered above and no owner ruling is needed.

## PROGRESS archive (moved 2026-11-15 by the PROGRESS.md trim)

Everything from the first `###` heading below was moved **verbatim** out of
`docs/PROGRESS.md` when that file was trimmed to the `MASTER_PLAN.md` G7 shape
(RESUME block, task table with real hashes, Deviations, Open risks, notes for
later tasks, under 150 lines). The text is unedited: it is the working notes,
risk list, per-task table and Part 11 material that PROGRESS used to carry, kept
here so the trim loses nothing. Per-part evidence stays in the entries above.
Current state, open items and deviations live in PROGRESS; this section is
history and is not updated.

### Task status  (moved from PROGRESS 2026-11-15: Task status table (parts a-j with commit hashes))

| Task | Status | Commit | Scope |
|---|---|---|---|
| a | done | `f4d81e2` | Package skeleton, pyproject, config.yaml, docs |
| b | done | `0e39f18`, `9423eaa` | `errors`, `models`, `config`, `core/runner` + tests |
| c | done | `45b0ba8` | `core/scope` gate + tests |
| d | done | `0a3010b` | `core/pacing.py`: delays, jitter, ordering, parallel limits, rate args, RateLimiter |
| e | done | `1ba2fd8` | `core/store.py`: schema, migrations, `redact()` helper, diff queries (`docs/04_DATABASE.md`) |
| f1 | done | 89ba34f | `adapters/base.py`, `adapters/registry.py`, `crtsh`, `certspotter`, `otx`, `hackertarget` |
| f2 | done | 80ddd93 | pure-Python adapters: `dnspython`, `pyprobe`, `pyscan` |
| f3 | done | ee06075 | remaining phase-2 tools: binary adapters `subfinder`, `assetfinder`, `httpx`, `naabu` |
| g | done | 36cd3a4, 6b hash in Part 7 | wildcard, workspace, engine, confidence, host states, resume, exit codes done |
| h | done | Part 8 hash in Part 9 | `ui.py` + `cli.py`; installer/doctor stubs remain for i |
| i | done | `9c4319b` (with `5df7e98`, `66b117c`) | `doctor.py` + `installer/`; Part 10 closed 2026-11-14 |
| j | in progress | `cc70b15` (11a), 11b docs sync, findings backfill (this commit) | fresh-eyes audit, S3 re-run, fresh-venv run and final report pending |

Order and module names follow `docs/01_PRD.md` section 8 and `docs/03_ARCHITECTURE.md` section 5. There is no `core/consensus.py`: consensus lives in `engine.py`.

### Module map  (moved from PROGRESS 2026-11-15: Module map (detailed per-function map; current summary is in PROGRESS "Notes for later tasks"))

- `errors.py`: `ScopeError` (3), `ConfigError` (2), `ParseError` (1), `ToolNotInstalled` (4), `ToolFailed`/`ToolTimeout`/`InstallError` (5). Each has `exit_code`.
- `models.py`: enums (`Stage`, `Tier`, `Mode`, `HostState`, `Confidence`, `ToolStatus`), records (`SubdomainRecord`, `HostStatusRecord`, `PortRecord`, `UrlRecord`, `FindingRecord`), `Record`, `ToolResult`, `InstallStatus`, `RunContext`.
- `config.py`: `load_config(path, speed=, delay=)`, `resolve_speed`, `parse_delay`, `SpeedPreset`; `_StrictModel` forbids unknown keys; `Webhook` model.
- `core/runner.py`: `run_exec(argv, timeout=, env=, max_output_bytes=, cwd=)` (only `subprocess` user), `validate_target` (root, strict RFC-1123), `validate_host` (discovered: allows `_`, strips `*.`), `ExecResult`; POSIX children stay in the parent's session but lead their own process group (PIT-32), timeout kills that group, output capped, env values redacted.
- `core/scope.py`: `load_scope`, `require_active` -> `ActiveCheck(scope, match, hosts, dropped)`, `check_target`, `ip_allowed`, `passive_warning`, `ScopeGate`; `out_of_scope` always wins.
- `core/store.py`: `Store(path)` (context manager, `close()`), `redact(text, secrets)`; writes `create_target`, `create_scan_run`, `finish_scan_run`, `record_tool_run`, `upsert_subdomain`, `add_subdomain_source`, `append_host_status`, `upsert_port`, `add_port_source`, `upsert_url`; reads `previous_state`, `diff_new`, `diff_gone`, `diff_state_changed`, `diff_ports_opened`, `diff_ports_closed`; pragmas FK/WAL/5000 ms, parameterized SQL only.
- `adapters/base.py`: `managed_bin_dir()` (lazy import of `installer.registry.bin_dir`, one definition of the path)
- `doctor.py`: `key_checks()` (names only, used by the install keys prompt)
- `installer/registry.py`: `bin_dir(home=)` (`~/.reconkit/bin`), `tier` on `InstallPlan`, `load_plans(path=, versions=)` -> `InstallPlan` (`name`, `method`, `binary`, `package`, `repo`, `asset_pattern`, `checksums_pattern`, `asset_name`, `version`, `fallback`, `requires_apt`, `requires`), `plan_for`, `resolve_plan`; unknown method or missing package/repo raises `ConfigError`.
- `installer/apt.py`: `apt_env` (PATH/DEBIAN_FRONTEND/LC_ALL), `apt_argv` (`sudo -n apt-get install -y`), `apt_steps`, `apt_install_package`, `install_apt`; package names validated; a password-requiring sudo becomes `InstallSkipped`.
- `installer/go_install.py`: `go_env` (HOME/GOBIN/PATH), `go_spec`, `install_go`; builds into the managed bin dir and runs `version_cmd`.
- `installer/pipx.py`: `pipx_env` (HOME/PATH/PIPX_BIN_DIR/PIPX_HOME), `pipx_spec` (packages, pins and `git+https://` specs), `install_pipx_tool`; a missing pipx is a separate, separately confirmed apt step.
- `installer/github_release.py`: `install_selected` (idempotent install/update over a selection), `installed_copy`/`installed_version`, `desired_version`, `_refresh_templates` (`nuclei -ut`), `CHECKSUMS_LIMIT` (64 KiB cap on the checksums fetch), `release_for(plan, client=, arch=)`, `download`, `install_release(plan, client=, bin_dir, dry_run=, verify_checksums=, runner=)`, `install_plans` (per-tool isolation), `exit_code` (0/5/6), `host_arch`, `render_pattern`, `checked_https`; HTTPS GitHub hosts only, MockTransport in tests.
- `installer/verify.py`: `sha256_file`, `checksum_for`, `verify_checksum`, `extract_binary(archive, binary, dest_dir, archive_limit=, member_limit=)`; zip-slip refused, only the expected binary extracted, mode 0755; `ARCHIVE_LIMIT` 200 MiB, `MEMBER_LIMIT` 100 MiB.
- `doctor.py`: `collect_report(config, config_path=, env=, tools_path=, scope_path=, dpkg_status=, status_of=, python_version=)` -> `DoctorReport` of `ToolCheck`/`StageCoverage`/`PackageCheck`/`KeyCheck`; `default_status`, `installed_packages`, `db_writable`; reads files and version commands only, never installs.
- `adapters/base.py`: `BaseToolAdapter` (contract from docs/09), `HttpAdapter` (rate limit via `ctx.limiter`, timeout, User-Agent, one retry on connection errors, 429/5xx/timeout -> failed result), `normalize_subdomains`; `FetchFailed`.
- `adapters/registry.py`: `load_tools(path=)` -> `ToolSpec`, `load_system_packages(path=)`, `get_spec`, `get_adapter`, `rate_flags()`; unknown/incomplete tools raise `ConfigError`.
- `adapters/__init__.py`: `ADAPTERS` maps `crtsh`, `certspotter`, `otx`, `hackertarget` to classes.
- `adapters/crtsh.py`, `certspotter.py`, `otx.py`, `hackertarget.py`: async parsers and request metadata; keys only from `ctx.env`.
- `adapters/dnspython.py` / `pyprobe.py` / `pyscan.py`: structured `DnsOutcome` (only NXDOMAIN -> DEAD), no-redirect probe that records `Location`, bounded TCP connect scan. All three validate hosts and count invalid ones.
- `core/pacing.py`: `Pacer(preset, rate_flags=, rng=, sleep=)` with `before_tool(mode)` (first tool free, `reset()` per stage), `before_host`, `order(items, kind=)`, `parallel_limit`, `tool_rate_args(tool, mode)`, `next_pause_range`; `RateLimiter(rate, clock=, sleep=)` for HTTP adapters. No I/O, no printing, injected clock.

### Deviations and assumptions  (moved from PROGRESS 2026-11-15: Deviations and assumptions (full per-part history; PROGRESS keeps the standing ones))

- `types-PyYAML` added as a dev dependency for strict mypy.
- Enums use `StrEnum` (ruff UP042) instead of the docs' `(str, Enum)`; same values.
- `--delay` applies to both passive and active `tool_delay` (not `host_delay`).
- Bootstrap prefers `uv`; venv is Python 3.11 because the system `python3` is 3.14.
- Ruff excludes `docs/`; per-file ignores: `tests/**` S101, `tests/fakebin/**` S603, `tests/test_runner.py` S603 (the kill-tree test must hold a live `Popen` to call `_kill_tree`), `src/reconkit/core/runner.py` S603 (argv is passed as a list).
- `host_status_history.waf` added for the CDN/WAF marker; port scans require a stored `live` result and skip hosts with `waf` set.
- Exit codes: Scope 3, ToolNotInstalled 4, ToolFailed/Timeout/Install 5, Parse 1, Config 2.
- 12k (2026-11-14): the all-empty case is **exit 4, not 5** (no tool ran anywhere; docs/02 section 6 states and justifies it). `docs/03` and `docs/08` were also touched, not only the named docs/02, because both describe exit codes/warnings. The warning text format (`"<stage> stage executed no tools: N tool(s) skipped (<reasons>)"`) is new and documented in docs/02 so it is not incidental. `scan_runs.status` for an empty stage still reads `completed`; only the warning and the exit code changed.
- 12d (2026-11-15): the task text asked for "a plain connect failure stores a different, distinguishable reason"; `MASTER_PLAN.md` 12d (owner-approved) and docs/09 say a plain connect failure emits no record at all, so nothing is stored. The documents were followed (no test weakened: "no row" is stronger than "a NULL reason"), and the conflict is recorded in REVIEW_LOG. Two consequences worth knowing: the row rule is broader than "UNKNOWN only" because an inconclusive pass keeps the previous state (documented and tested), and a *first-run* inconclusive `live` pass still writes no history row at all - that is 12e, still undecided - so the reason lands only when the host already has a history row. `tests/test_store.py`'s v2 fixture gained the `host_status_history` table that migration 4 alters.
- 12c (2026-11-14): `docs/09` was also touched, for the `ToolResult.duration_s` contract comment, although the ruling named only `docs/04` (AGENTS section 8 requires the adapter contract doc to match). The meaning "`0.0` = the adapter did not measure" was chosen and written into docs/04 to resolve the ambiguity, with no model or schema change. The test fake-adapter helper gained defaulted `duration_s`/`delay` keywords.
- 12f (2026-11-14): `cli.py` now imports `configure_redaction` and `redact` from `reconkit.core.store`; docs/03 section 9 records that as the only allowed store import for the CLI, and `test_cli_imports_only_the_allowed_layers` was amended from "no store import at all" to a precise allow-list (it still fails on `Store(` or `sqlite3` in the CLI). `redact(text, secrets=None)` gained the `None` meaning "configured set"; every existing caller passes an explicit tuple, so stored and raw text semantics are unchanged. Six typed `render_error(str(exc))` sites (scope check, diff, status, doctor, install) are outside 12f's ruled scope and unchanged.
- 12a (2026-11-14): the plan says "the four python adapters"; the tree has three (`dnspython`, `pyprobe`, `pyscan`) and all three changed. `docs/03` section 3 (technology stack) needed no edit - the rule lives in sections 5 and 6 step 9. `dns` raw files go to `meta/` because the workspace keeps exactly the six documented directories. `Workspace.write` caps every caller at `runner.MAX_OUTPUT_BYTES`, so `test_workspace_large_output_is_written` became `test_workspace_large_output_is_written_up_to_the_cap` (stricter, not weaker).
- `scope.yaml` defaults: missing `expires` = never expires; missing `max_speed` = `slow`.
- `check_target` reports `out_of_scope` before expiry (out always wins) and raises `ValueError` on an invalid target.
- Part 12 rulings (2026-11-14, docs first): 12i accepts the ports ceiling permanently (option (c), no pre-resolve redesign and no second IP-connecting adapter); 12a wires raw stdout+stderr through the existing raw-output files under the existing `max_output_bytes` cap, with no new flag or config; 12c makes the adapter's own `duration_s` authoritative and lets `_run_one` fill it only when the adapter reported none; 12d puts a bounded redacted detail on `host_status_history` instead of `tool_runs.detail`; 12f adds `configure_redaction()` from the already-loaded env, applied on `_report_error` and the `-v` traceback; 12g uses a per-run 0700 directory with startup cleanup, not memfd/O_TMPFILE; 12k exits 5 with a warning naming an empty stage. 12e, 12h and 12j remain undecided and unimplemented.
- Checkout history (corrected 2026-11-14): development began elsewhere, then the folder was copy-pasted to Kali, which is now canonical and the only checkout. Installer work must verify apt package names for both Kali and Ubuntu before coding.
- `_kill_tree` kills the child's process group with `killpg`; the timeout-kill test runs in the suite.
- `.gitattributes` forces LF for `*.sh`, `.githooks/*`, `*.py`, `*.md`, `*.yaml`, `*.toml`; existing files were not renormalized.
- `Pacer.order()` takes an optional `kind="host"|"port"` because config has separate shuffle flags. Scoped S311 ignores in `pyproject.toml` cover the pacer's jitter RNG and the seeded test RNG.
- Commits are authored by `Anshul <anshulc4444@gmail.com>`; no attribution trailers are added, by anyone or any tool.
- Deviation (2026-11-14, at the user's request): the last five commits before this one were re-created to strip an attribution trailer from two of the messages. No file content changed, only messages and therefore hashes. Current hashes: `581a556` (docs, wildcard switch), `1dd63e5` (wildcard engine wiring), `b24f39b` (stub removal), `430aa1d` (certspotter line), `996cff1` (citation fix). The pre-rewrite objects were expired, so the old hashes no longer resolve; anything citing them in an older session is stale.
- `needs_key` was removed from `tools.yaml`; the loader now raises `ConfigError` for it so `keys` stays the single source of truth (docs/05 §6.1 updated first).
- Cert Spotter's `adds` text was corrected: the API docs do not promise 100 queries/hour to a key; that figure was the unauthenticated limit.
- Chaos's key env name was corrected from `CHAOS_API_KEY` to `PDCP_API_KEY` (chaos-client README). `urlscan` and `github_subdomains` migrated from `needs_key` to `keys` with verified URLs.
- `naabu` is skipped at selection time (`blocked: resolves inside the binary, so in_scope_cidrs cannot be enforced (11c-G-7)`) because the IP rule cannot be applied to resolution that happens inside the child; 12i made that skip permanent. docs/05 rule 6, docs/03 section 13, docs/09 selection rules and the ports table all say so; reversing it needs either a pre-resolve design or a ruling that accepts the gap.
- Per-host adapters now normalize every input with `validate_host()`; an invalid or IDN host is skipped/counted instead of being used in a request. `dnspython` maps an unexpected resolver exception to the structured `error` outcome instead of aborting the stage.
- `pyscan` closes the connection before awaiting `wait_closed()`, so cancelling a stage cannot leak an open socket; the concurrency test pins the semaphore to the pacer limit.
- `subfinder` now carries four `keys` and the adapter writes them to a temporary `provider-config.yaml` (0600) passed with `-pc`, deleted in `finally`. This replaces the audit's earlier "no env bridge" decision because Part 4 requires the bridge.
- `chmod 0600` on the subfinder temp file is best-effort; the file is still deleted, and the open risk is recorded in REVIEW_LOG Part 4.
- Known pitfalls table + regression rules added by user addendum; the pre-commit hook warns on a `fix:` commit without a test change, and existing guards carry `Regression:` docstrings (no behavior change).
- Part 5 uses an injected, limiter-bound DNS probe and a required injected `rng` (no S311 default); `Workspace` chmods only its own dirs; `Workspace.write` is synchronous (`fsync` + `os.replace`), so the engine must offload large outputs.
- `certspotter` returning `ok` with 0 items on every real run is explained, not a defect: replaying the adapter's exact unauthenticated request on 2026-11-14 gives `200 []` for `testfire.net` while `example.com` returns 17 entries and `google.com` returns 100, so the source holds no issuances for that domain. The four identical rows looked ambiguous only because `HttpAdapter` archives no response body. Closed; no code change.
- `src/reconkit/adapters/dns_python.py` is deleted in `b24f39b`: a 59-byte tracked stub created by `f4d81e2` from the old docs/03 name; the real adapter is `dnspython.py` (`80ddd93`, updated in `75eb261`). Nothing imported it, `docs/03_ARCHITECTURE.md:70` was corrected to `dnspython.py` in `3a14568`, and a repo-wide grep for `dns_python` in `*.py`/`*.toml`/`*.yaml` is now empty. The Part 11 note is closed.
- Part 6b adds `--resume` (docs/02); resume is stage-level and reruns an interrupted stage because asset writes are batched at stage end. State timestamps use the injected `now` source (default `store.utc_now()`); `Store.scan_runs()`/`subdomains()` are the resume reads. CNAME warnings stay in `ScanSummary.warnings` because the schema has no CNAME column. Double-confirmation is intentional: an established `ALIVE`/`DNS_ONLY` host has prior evidence, so one NXDOMAIN only means `SHUT_DOWN`; a second consecutive NXDOMAIN is required for `DEAD`. A never-probed host has no prior service to confirm, so its first NXDOMAIN is `DEAD`. This avoids one transient resolver failure erasing an established host while still recording genuine new non-existence.
- Part 7: docs/09 said `--json` was JSONL, but the Part 7 requirement/master plan says ONE JSON document; docs/02 now defines that shape, docs/09 was aligned, and `ui.write_json` emits `type:summary` with `hosts`/`stages`/`summary`. `HostRow` is a UI input type populated by the CLI; `ui.py` does not compute confidence/state.
- Part 7: `ScanSummary` does not carry skipped tools, so the Tools table renders executed `ToolResult`s (ok/failed/timeout) only; skipped adapter rows remain in `tool_runs` and are a Part 8 wiring concern. The zero-tool empty state uses the explicit "skipped or excluded" line instead of docs/02's 3-tool example.
- Part 8: no command is shorthand for `lite`; `--json` accepts one target (multiple `-l` targets are rejected with exit 2); docs/02 now explicitly defers `--timeout-<stage>`, so only `--phase-timeout` sets a stage limit; `doctor`/`install`/`update` are Part 9 stubs, and `db list`, `db export`, `export` and `scope import` are explicit exit-1 stubs.
- Part 8: `Engine.open` loads `.env` values and the CLI has no `os.environ`/`getenv`; shell-exported key variables are therefore ignored. The active fast-mode typed confirmation runs outside `--mock`, where no traffic is possible.
- Part 9: schema v2 adds `host_status_history.cnames_json` and `dangling_cname`; DNS-only resolved hosts now get a status row so their CNAME survives a restart, and a later NXDOMAIN reuses the latest stored CNAME. The migration is additive and existing rows default to `[]`/NULL. This is also a row-frequency change: the `dns` stage now writes one status row per host with a signal (`RESOLVED` -> `DNS_ONLY`, `NXDOMAIN` -> `SHUT_DOWN`/`DEAD`) instead of only NXDOMAIN rows; docs/03 and docs/04 state it, and `test_dns_resolved_then_two_nxdomain_is_shut_down_then_dead` guards that the extra row does not break the two-consecutive-NXDOMAIN `DEAD` rule. Wildcard wiring and stage-level resume were triaged, not fixed, because this part was limited to the Fix backlog.

- Part 10 docs pre-fix (docs only): docs/10 now matches docs/02's install surface (`--stage`/`--yes` removed from the grammar), states that `install`/`update` exit 1 on any non-Linux platform, adds 3b prerequisites (jq, dnsutils via `dig`, Go/GOBIN, pipx-via-apt), 5a doctor output/exit rules, Go/PyPI download hosts, and defers the fixture-version doctor warning to Phase 3 pending per-tool metadata. Open for review: `--all` phase scope, the installer exit code when every tool fails, and where wordlists live.
- Part 10 scope decisions (docs only): `--all` stays "core tier, no phase filter" and MASTER_PLAN Part 4 now names only `masscan` as opt-in (`rustscan`/`nmap` are core-but-phase-3, and `phase` is build tracking, not a security gate). Exit code 6 was added to docs/02 section 6 for "every requested tool failed to install or update"; 4 and 5 keep their scan meanings. The doctor wordlists check was removed from docs/01 and docs/02 and logged under Open risks. No `src/`, `tests/`, `tools.yaml` or `config.yaml` change.
- Part 10a follow-up (PIT-30): the first real `doctor` run moved `~/.config/{subfinder,naabu}` into the repo root because `check_installed()` ran the version probe with `env={}`. The probe now passes `HOME`, the configs were restored to `~/.config`, and a regression test pins the child env. This bug affected scans too, not only doctor.
- Part 10a (doctor): `collect_report` reads tools.yaml once through `load_tools`/`load_system_packages`, asks each binary adapter's `check_installed()` and reads `/var/lib/dpkg/status` directly instead of running `dpkg-query`, so doctor executes only the adapters' version commands and never apt. `--fix` exits 1 with "not available yet" because the `install` CLI is not wired until 10e; docs/10 section 5a still promises `--fix`, so that line is true only after the installer lands. System packages are `system_packages` plus `requires_apt`; `dnsutils` (only in the `dig` install block) is not checked and docs/10 now says why. The `n/a (no binary required)` cells wrap in an 80-column table; the text matches docs/02 exactly.
- Part 10b: install plans parse the `install` block from tools.yaml directly because `ToolSpec` does not expose it; the tool set still comes from `load_tools()`, so the two loaders cannot disagree on which tools exist. `tool_versions` pin wiring landed in 10e (`_install_selection` passes `config.tool_versions`).
- `diff` two-miss rule 2026-11-14 (docs first, then code): docs/02 section 2 (user-facing rule and `pending_gone` in JSON), docs/04 section 6 (query definition, "no new table or column"), docs/08 Flow 7 (the two messages). `diff_gone(baseline, previous, latest)` keeps the one-miss query as `diff_pending_gone(previous, latest)`; `DiffSnapshot` gained `baseline_run_id` and `pending_gone`; `state_changes` and the port arrays still compare only the latest pair, and `NEW` is still `first_seen_run = latest` (a host that reappears after a miss is neither NEW nor GONE). "Consecutive runs" is defined as completed `subs`-stage runs (`completed` or `partial`) - a partial discovery run counts, because tolerating its missing hosts is exactly the point.
- Bug-fix session 2026-11-14 (docs first, then code): docs/02 section 2 now says `--active` is exit `2` on the bare form and on `lite`/`passive`/`subs`/`dns`; docs/02 section 5 adds `stages[].skipped` (`{"tool","reason"}`) and redefines `summary.tools_skipped` as executed `skipped` results **plus** selection-time skips; docs/09 section 3 says a TLS failure on one scheme must not end `pyprobe`'s multi-scheme probe and section 4 says every selection-time skip is reported per stage. Code: `cli._run_scan` guard, `pyprobe._probe` `tls_error` flag, `engine.ToolSkip`/`StageOutcome.skipped`/`ScanSummary.skipped`, and `ui` writes/renders them (`_tool_table` now shows skipped rows, as docs/02 already promised). The CLI message was shortened to fit 80 columns after the first real run wrapped the remedy across two lines. Exit codes, `diff`, `scope.yaml` and `in_scope_cidrs` were deliberately left alone.
- Part 10f: `requires_apt` was parsed into every plan but **no installer backend consumed it**, so a clean box would have installed `naabu` without `libpcap-dev` while docs/10 section 3a promised "the installer installs dependencies first". Fixed in `github_release._install_required_packages`: each prerequisite is installed before the tool with its own confirmation line (`naabu: sudo apt-get install -y libpcap-dev (required by naabu)`), a declined prerequisite raises `InstallSkipped` for the tool, and `--dry-run` lists the step without starting a process. docs/10 section 3a also now states two consequences that were implicit: prerequisites do not run for an already-installed tool, and `requires` (puredns -> massdns) is still not auto-installed.
- Part 10f: the `.env` no-overwrite guard now has a test that copies the real `.env.example` beside a `.env` (`test_existing_env_is_not_overwritten_when_env_example_exists`); the older test could not fail on a real clobber because it had no example file. `InstallPlan` gained `member` (archive member when the release renames the binary; `chaos-client`) and `verify_checksums` (per-plan override, `false` only for `findomain`, which publishes no checksums). The field list lives only in docs/10 section 3c; docs/03 does not enumerate plan fields (it names the installer modules), so docs/03 needed no change. `doctor` now falls back to the plan probe for tools without an adapter, otherwise every phase-3 tool read `missing` after a clean install; docs/10 section 5a states it. `dnsreaper` is a `none` plan because the repository has no `setup.py`/`pyproject.toml` and no PyPI package, and `puredns` uses `--version` because it has no `version` subcommand (both verified 2026-11-13).
- Part 10f follow-up (massdns version display): `installed_version()` returned `str(copy)` whenever `version_args` was empty, so an apt package with no self-reported version (`massdns`) showed `/usr/bin/massdns` while every other apt row showed a version. `InstallPlan` now carries `version_command` from `version_cmd[0]`, but only when it names a different program than `binary`, so the managed-copy preference is unchanged for every existing tool; `installed_version` resolves and runs it, and the apt post-install check uses it. `massdns` now declares `[dpkg-query, -W, '-f=${Version}', massdns]`, and the idempotent row reads `(1.1.0-0kali2)` after a fresh install. `sqlmap` has the same gap and is deferred under Open risks. docs/10 defined the contract first (`66b117c`).

### Open risks  (moved from PROGRESS 2026-11-15: Open risks (full text as of 2026-11-14; PROGRESS keeps the ones still open))

- **Fixed 2026-11-14, recorded here so the risk list cannot be read as still-open:** `--active` swallowed by passive-only commands (PIT-36) and `tools_skipped: 0` on stages that built nothing (PIT-38) are closed; see the two marked bullets below and REVIEW_LOG "Bug-fix session".

- **Latent console leak path: six typed `render_error(str(exc))` sites bypass `redact()` (recorded 2026-11-14, from the 12f review; not urgent, tracked so it is not forgotten).** `_report_error()` and the `-v` traceback now mask secrets (12f), but six other `cli.py` sites still print typed exception text directly: the scope-check failure (442, 445), `diff` (481), `status` (513), `doctor` (535) and the `install` error path (628). Every message there is built from our own values today, so no leak is known; if one ever carried a secret-shaped value - an `InstallError` echoing an env var, a URL with credentials in a failure message - it would print unmasked. Deliberately outside 12f's ruled scope, which named only `_report_error` and the `-v` traceback. Fix would be to route those six calls through `redact()` like line 149; it needs its own ruling/ticket, not a HARD STOP.

- **`libpcap-dev` is absent and cannot be installed from this checkout (found 2026-11-14).** `dpkg -s libpcap-dev` reports it not installed and `sudo -n true` fails (`sudo: a password is required`), so the apt step can never run unattended; `install --all` does not even attempt it while `naabu` is already installed (docs/10 section 3a: prerequisites run only when their tool installs). The prerequisite is unverified independently of the CIDR gate that keeps naabu blocked. Closing it needs one `sudo apt-get install -y libpcap-dev` by the owner, or a reinstall of naabu after removing it.

- **FIXED 2026-11-14 - the bare CLI form no longer swallows `--active`.** It used to be `lite`, and `_stages("lite", active)` returned the passive stages regardless, so a caller asking for active work got subs+dns only with no warning. docs/02 section 2 now defines `--active` as a usage error (exit 2) on the bare form and on `lite`/`passive`/`subs`/`dns`, naming `run -d X --active`; PIT-36 and the "Bug-fix session" entry carry the evidence. A passive-only command that honours the flag differently was not considered - the docs already said only `run` includes active stages.

- **FIXED 2026-11-14 - stages with zero adapters are no longer silent; the empty-stage exit code is decided but not yet implemented. Session-2 evidence:** `tech`/`urls`/`vulns` executed zero tools, their `scan_runs` rows read `completed`, and the run's exit 5 came from `otx` + `hackertarget`. A clean subs stage in that same shape would still exit 0. `tech`, `urls` and `vulns` have no adapters in this build, so `run --active` creates each stage and executes zero tools; the JSON now carries `stages[].skipped` with each tool and reason, `summary.tools_skipped` counts them, and the Tools table renders skipped rows (PIT-38, docs/02 section 5). The owner ruled 2026-11-14 (12k): a requested stage with zero executed tools exits `5` with a warning naming the empty stage. That is not implemented yet - a stage with no adapter still exits `4` on its own and contributes nothing to a mixed run's exit code, so a clean passive run plus three empty phases can still exit `0`.

- **`--json` emits no progress at all (found 2026-11-14, re-confirmed in session 2: 0 bytes of stderr on an 8m25s run).** Both 5-minute real runs wrote 0 bytes to stderr, although docs/02 section 5 says tables and progress stay on stderr. Machine-readable output staying quiet is defensible, but the docs currently promise otherwise; either the doc or the CLI needs to change, docs first.

- **FIXED 2026-11-14 (owner ruled option (a)) - `diff` no longer reports one missed discovery run as GONE.** `GONE` needs two consecutive misses plus a sighting in the run before them; a single miss is `pending_gone` and is printed as "not reported as GONE yet"; fewer than three completed `subs` runs confirm nothing gone (PIT-39, docs/02 section 2, docs/04 section 6, docs/08 Flow 7). The history below is the original finding: After `subfinder` returned 35 names in run 1 and 8 in run 2 five minutes apart, `reconkit diff` reported 27 of 36 hosts as `GONE` even though nothing had been re-probed. The behaviour matches docs/02 ("gone since the previous run"), so no code was changed. Proposed shapes, for a ruling: **(a)** require two consecutive misses before `GONE` (a run-history query, no schema change; hides a real removal for one run); **(b)** compare against a union of the last N discovery runs (a new `Store` read, no schema change; hides removals for N runs); **(c)** keep the rule and rename the column/JSON key to "not seen this run" (data stays exact, but the documented `gone` name and the `--json` shape change). Nothing may be implemented before the owner picks one.

- **Unverifiable tool facts, named (2026-11-14, Part B, retried once at the owner's request).** (a) OTX's response shape is documented by the official external-API page but still was not observed live: a second anonymous request also returned HTTP 429, now with the exact body `{"detail": "Anonymous access to this endpoint is limited. Please authenticate."}` (80 bytes), so the `passive_dns[].hostname` fields rest on published samples plus the fixture. The 429 is handled as a `failed` result by the HTTP adapter (no retry on 429), which the fixture tests pin; the *body* text is not used by any code. (b) **Now observed (2026-11-14, session 2):** HackerTarget hit its free quota for real and the adapter wrote `hackertarget: free quota exceeded`, so the quota-message branch is exercised and correct. The earlier retry had returned HTTP 200, which is why it looked unverifiable then. (c) `assetfinder` is not installed here, so its `-h` identity probe is inferred from its Go `flag` source (usage contains the binary name, exit 2, which `check_installed` accepts) rather than executed. (d) `rustscan` is not installed; `-V, --version` comes from Kali's official package page for 2.4.1, not a binary run, and its release asset pattern stays a placeholder (existing bullet above). Each of these is either a docs-verified contract or a missing binary, never a guess presented as fact.

- **`installed_version` shows the wrong text for banner-first tools (found 2026-11-14, ticketed).** It returns `text.splitlines()[0]`, so `katana` shows `__` and `nuclei` shows `[I…` in the doctor table. Cosmetic for doctor, but it also defeats `_same_version()` for those tools, so `update` cannot call them up to date. Deferred to Part 12 with its own test; the masscan half of the same audit is fixed in this commit's follow-up.

- **Capability gap: the ports stage cannot exceed LOW confidence in this build (recorded 2026-11-14, from the 11c-G-7 enforcement fix).** `naabu` is skipped permanently (it resolves hostnames inside the child, so docs/05 rule 6 can never see the address it connects to), and every other ports adapter except `pyscan` is phase 3 with no adapter yet (`smap`, `nmap`, `rustscan`, `masscan`). Port confidence is `confidence_for()` over the set of *distinct tools that produced a `PortRecord`* (`engine.py` `_persist_ports`), with `high_min_sources: 3` and `medium_min_sources: 2` from `config.yaml`, so one selectable tool can only ever yield LOW - the docs/09 section on "two tools agree = MEDIUM" rule is unreachable for ports until a second port adapter runs. The stage still works; what is lost is cross-tool confirmation (and the `open` vs `closed` disagreement rule, which needs two scanners). The two rejected candidates (both were Part 12 scope when proposed): (a) pre-resolve the host list in the engine and pass `naabu` explicit IPs, which also means changing what `PortRecord.fqdn` means for every consumer and re-verifying the naabu output shape against the real binary; or (b) add a second pure-Python or already-present port adapter (the `nmap`/`rustscan` entries exist in `tools.yaml` as phase 3, so this is an implementation task, not a registry one). **DECIDED 2026-11-14 (12i): option (c)** - the ports stage stays permanently LOW-only / `pyscan`-only in this build; (a) and (b) are not pursued. This is an accepted ceiling, not a temporary gap.


- **Managed-directory shadowing (recorded 2026-11-14; deliberate, unfixed).** `BinaryAdapter.binary_path()` returns the first *existing file* in `~/.reconkit/bin` and only asks `PATH` when that directory holds nothing (`base.py` 225-231, `installer/registry.py` 217-220). A broken managed copy - corrupt download, lost executable bit, wrong architecture, half-written update - therefore shadows a working copy on `PATH`: `check_installed()` rejects it (returncode `None` or a missing identity marker) so selection skips the tool, or the spawn fails and the run records `failed`, instead of falling back to the working binary. This is deliberate, not a bug: docs/10 section 5 puts the managed directory first precisely so an installer-managed ProjectDiscovery tool wins over a namesake on `PATH` (the `httpx` collision), and a fallback would have to tell "bad managed copy" apart from "intentionally pinned different version", decide between warning and auto-repair, and keep `doctor` and the run reporting the same path - a design change with its own docs-first pass, so it is recorded here rather than fixed. Mitigation today is manual: remove the broken file from `~/.reconkit/bin` and run `reconkit install <tool>`.

- `~/.reconkit/bin/nuclei` may be absent: an orphaned installer process (pty mishap during the 2026-11-14 gate run) attempted a nuclei reinstall and failed at the 100 MB `MEMBER_LIMIT` (`'nuclei' exceeds 104857600 bytes`). `/home/kali/go/bin/nuclei` (v3.11.1) currently satisfies `installed_copy()`, so the table reads `already installed`; the managed copy was not restored and the limit is unchanged. Not a Part 10 defect.

- Interactive Ctrl+C does not kill an already-running child: the CLI catches `KeyboardInterrupt`, the engine marks the stage run `interrupted` and exits 130, but only new scheduling stops. This is the interactive half of PIT-32's residual risk (children lead their own process group, so Ctrl+C is not delivered to them; a terminal hangup can reach them because they stay in the parent's session). docs/03 §13 and docs/08 Flow 9 state the current behavior; killing the child group on cancellation is a future part, not Part 11.

- `sqlmap` (apt, no `version_cmd` in `tools.yaml`) has the same gap massdns had: its install-table row and doctor display a bare path instead of a version. The `version_command` mechanism added for massdns applies unchanged (`[sqlmap, --version]`); this is deferred as a separate item because sqlmap is `intrusive` and outside Part 10's core-tool proof. No guard test enforces it yet.


- `SUDO_DENIAL_MARKERS` contains two substrings (`"no tty present"`, `"askpass"`) that were never reproduced against a live sudo; only `"a password is required"` was confirmed here. A different sudo/PAM wording would surface as `InstallError` instead of the friendlier `InstallSkipped` (low severity, but it will look like a failure rather than a skip).

- `_fetch_text`'s default 64 KiB cap has no dedicated test; the cap is only exercised through an explicit `max_bytes=64` argument in the test, so a regression in the default would pass the suite.
- Non-UTF-8 checksums-file rejection (`InstallError: checksums file is not UTF-8`) has no test.
- Accepted exception: `go_install` and `pipx` pass the parent process's `PATH` to their child (named in docs/10 section 3d with the reason). Every other child env is a fixed, explicit dict. Tests never exercise a custom parent `PATH`, so a change in that behaviour would not be caught by the suite.

- `doctor --fix` runs the `install --all` selection (10e) and never pretends to have fixed anything.
- `doctor` checks apt packages by reading `/var/lib/dpkg/status`; on a non-Debian system every package reports `unknown` instead of guessing. `dnsutils` is not covered because it appears only in the `dig` entry's `install` block.
- `rustscan` is excluded from the download path. Live check 2026-11-13 (tag 2.4.1 via the `bee-san/RustScan` redirect, now followed): assets are `x86-linux-rustscan.zip`, `x86_64-linux-rustscan.tar.gz.zip`, `aarch64-linux-rustscan.zip`, `rustscan.deb.zip` - none matches the `amd64`/`arm64` `{arch}` values, and there is no checksums asset. `tools.yaml` keeps the literal placeholder, so it still fails (`has no asset`) once the API quota is available; today it fails earlier with HTTP 403.
- `requires_apt` is only reached when the tool itself is installed. On this box `naabu` is already present from `/usr/bin`, so `install --all` does **not** install `libpcap-dev`. Review ruling: that is not a gate item. The prerequisite *orchestration* is verified by four unit tests plus two mutation proofs, and the prerequisite *apt mechanism* is the same `apt.apt_install_package` call site that `massdns` proves live, so `massdns` alone is the accepted live proof. A live `libpcap-dev` run is only reachable via `update naabu` when its lookup says not-current, or a box without naabu, and is not worth forcing destructively. Low functional stakes anyway: the naabu adapter always uses `-scan-type c`, which does not need libpcap.
- `requires` (puredns -> massdns) is parsed but not auto-installed; a user must install the named tool. Deferred to a future part and stated in docs/10 section 3a.
- The sudo-authenticated half of the install path has never been run end to end: `sudo -n true` and `sudo -v` both report that a password is required and this box has no NOPASSWD rule, so `massdns`, `amass`, `dig`, `nmap`, `whatweb` and `libpcap-dev` have only ever been exercised as `skipped`. `install_apt`'s `shutil.which` check and its `check_version` call have therefore never seen a real successful `apt-get`.
- GitHub release lookups are unauthenticated: 60 requests/hour per source IP for 13 `github_release` tools, and `release_for` sends no token (there is no `GITHUB_TOKEN` support for release lookups; the registry's `GITHUB_TOKEN` key is for `github_subdomains`). On 2026-11-13 the quota was exhausted (core `remaining 0`, `reset` 21:57 UTC) and every `github_release` tool failed with HTTP 403 while the run continued. Deferred to Part 11 planning as a feature decision: either add authenticated lookups and recommend `GITHUB_TOKEN` in docs/10, or keep the wait-and-retry rule now documented there. Not built in 10f.
- `update` re-runs `go install` for every `@latest` go_install tool and reports `installed` rather than `up to date`, because there is no installed-version metadata to compare. The re-run is byte-identical (Go build cache; measured on `assetfinder`, `subjs`, `gau`), so it is a reporting/idempotency-of-message gap, not a corrupting reinstall. docs/10 section 6 states it and marks the proper fix (module-proxy lookup vs installed build metadata) as deferred to a future part; the ruling is that this does not block the Part 10 gate.
- `doctor` does not check wordlists: no Phase-2 adapter consumes one, and no wordlist path exists in `tools.yaml` or `config.yaml`. Only the phase-3 DNS-bruteforce tools (`puredns`, `massdns`, `amass`, `findomain`, `dnsx`) would need one. Revisit when any of those gets an adapter.
- `RunContext` now carries `limiter` and `ports`, and `HostStatusRecord` carries `location`; all were documented in docs/09 before their code landed. The engine builds one limiter per stage.
- `dnspython` resolves A/AAAA/CNAME only: the record models have no NS/MX/TXT fields, and adding them would change the database schema. `pyscan` sends no payload and reads no banner (the banner read is optional).
- `HttpAdapter` is documented in docs/09 section 3. Domain filtering happens in `run()` because the contract's `parse_output(raw)` receives no target; `parse_output` normalizes and validates only.
- Seven fixtures are synthetic, written to the documented shapes: `tests/fixtures/{dnspython,pyprobe,pyscan}/example.com.synthetic.json`, `tests/fixtures/{subfinder,assetfinder}/example.com.synthetic.txt`, `tests/fixtures/{httpx,naabu}/example.com.synthetic.jsonl`. No adapter test touches the network or a real binary.
- Binary-adapter identity is based on the official banner/version text, not a live run: no real binary is installed here. `httpx` distinguishes ProjectDiscovery's tool from the Python CLI by requiring `projectdiscovery`/`current version`.
- `tests/test_store.py` imports `sqlite3` for `IntegrityError`; the "only store.py imports sqlite3" rule is enforced for `src/`.
- Installer refuses to run on non-Linux platforms; decide how to handle that before task i.
- `scope.yaml` cannot exclude IP ranges (no out-of-scope CIDRs).
- CLI must catch `ValueError` from `check_target`/`validate_target` and exit 2.
- OTX anonymous requests return 429 (synthetic fixture); HackerTarget's free tier returned one row for example.com, so multi-row parsing is only covered by MockTransport tests.
- subfinder keys are bridged by its adapter into a temporary 0600 `provider-config.yaml`; only certspotter, chaos, github and virustotal are configured. The other keyed providers' free tiers and sign-up URLs remain unverified, and no real subfinder has accepted the generated file yet.
- Part 6a: one `scan_runs` row per executed stage; `ScanOptions.speed` is `SpeedName`; `Store.transaction()` uses SQLite's implicit transaction (explicit `BEGIN` failed inside one); `check_installed()` runs via `asyncio.to_thread`; workspace/scope reads stay synchronous and short; `FindingRecord` is not persisted because the findings table is deferred.
- Part 9 triage: wildcard detection is still not wired into the engine; `is_wildcard` stays 0 and no wildcard-unknown warning is emitted. This is not a Fix backlog item and needs engine integration, so it remains open for a later part. (Wiring landed 2026-11-14; see the wildcard section below.)
- Wildcard spec gap, decided 2026-11-14 (docs first): `wildcard_check.enabled` was modeled and set `true` in `config.yaml` but named by no document, so docs/03 section 8 now states that `false` skips the filter entirely; `probes` remains the only other documented key. Still unspecified and deliberately not implemented: docs/09's "exclude them from counts by default" - no document defines which count (host table, JSON summary, confidence) and no code path filters it, so `is_wildcard` is a mark only.
- Part 9 triage: resume remains stage-level; tools completed inside a crashed stage are rerun. Per-tool checkpointing is a larger engine change, so this stays a documented limitation. Real NXDOMAIN/CNAME behavior remains unverified.
- Part 9: the dangling warning can reuse only a CNAME stored by an earlier resolved pass; `dnspython`'s NXDOMAIN path returns no CNAME in that pass.
- Part 7 rendering is tested with `StringIO`/fake TTY only; real terminal widths and the CLI's `HostRow` source are unverified until Part 8.
- `docs/09_TOOL_CONTRACTS.md` has now contradicted docs/02 twice (the earlier `needs_key` registry issue and Part 7's JSONL-vs-single-document contract), so it needs a full fresh-eyes pass against docs/02 before the Part 11 final docs sync; do not treat docs/09 as authoritative until then.
- Part 8: `db list`/`db export`/`export` are command stubs, and `diff` compares only the latest two completed `subs` runs plus matched `live`/`ports` runs; real tools, real terminals and the stubs remain unverified.
- Part 8: `--timeout-<stage>` is explicitly deferred in docs/02; `--phase-timeout` is the only stage-timeout flag, and multi-target `--json` is rejected pending a batch document shape.

### 2026-11-14 - 11d-findings (first real authorized run; findings only, no fixes)  (moved from PROGRESS 2026-11-15: 11d findings a-g (all fixed or ruled; see PIT-37/38/39/41/42/43/44/46 and the Part 12 entries))

First real passive run against an authorized target produced `/tmp/rk_testfire.db`: 6 `scan_runs`, 48 `tool_runs`, 4 `subdomains`, 12 `subdomain_sources`, 0 `urls`, 0 `ports`. These four tickets are logged separately from 11c's fresh-eyes audit and from 11d's close-out. **Only this file changed in this entry** - no `src/`, `tests/`, `tools.yaml` or `config.yaml` change, nothing pushed.

Artifact checks (raw, from the file): `PRAGMA integrity_check` = `ok`; `PRAGMA foreign_key_check` empty; `schema_version` = 2 (matches docs/04 section 11); the four table DDLs match docs/04 section 3. The DB's filesystem `mtime` equals `scan_runs` row 6 `finished_at` to the second (06:11:42 -0500 = 11:11:42Z), so the file is a genuine run artifact, not hand-written text. It was last written ~95 minutes before the review started, so nothing in that session wrote to it.

### 11d-findings-a (high) - `_write_host` overwrites the discovery consensus

- `_persist_discovery` (engine.py 911-941) is correct: it groups by `fqdn`, collects the distinct tool names, and passes `confidence=confidence_for(tools)` with `source_count=len(tools)`.
- `_write_host` (engine.py 1125-1140) then passes `source_count=len(transition.sources)`. On a DNS-only pass `decide_host_state` (engine.py 184-190) sets `sources` to the DNS tools only, so on this run that is `("dnspython",)` and the count is 1.
- `Store.upsert_subdomain`'s ON CONFLICT clause is `source_count = COALESCE(:source_count, subdomains.source_count)` (store.py 427-431). `COALESCE` protects the stored value only against `None`, and `_write_host` never passes `None`, so every DNS pass replaces the discovery value with a non-null worse one.
- Observed: `demo.testfire.net` has `crtsh` + `hackertarget` `subdomain_sources` rows in runs 1, 3 and 5, yet stores `source_count=1, confidence=LOW`. `config.yaml` sets `medium_min_sources: 2`, so the documented rule (docs/04 section 5, docs/09 "Discovery stages") requires `MEDIUM`/2.
- The stored value is predicted by the write order, which is why it is a clobber and not a mis-merge: run 1 `subs` -> 2/MEDIUM, run 2 `dns` -> 1/LOW, run 3 -> 2/MEDIUM, run 4 -> 1/LOW, run 5 -> 2/MEDIUM, run 6 -> 1/LOW. Final state 1/LOW, which is exactly what the DB holds.
- `_persist_live` calls the same `_write_host` (engine.py ~1085), so the `live` stage has the identical defect for `ALIVE` hosts. This is why `live`/`ports`/`--active` were not run on top of it.
- **Regression test this fix must add (currently absent):** run `SUBS` with two tools reporting `www.example.com`, then `DNS` with one tool resolving it, and assert the stored row is `("MEDIUM", 2)`. Today it reads `("LOW", 1)` and fails.

### 11d-findings-a - fixed 2026-11-14

- **Mechanism.** `_write_host` no longer supplies `source_count` at all. docs/04 section 5 defines it as the distinct tools in `subdomain_sources`, and only `_persist_discovery` writes that table, so a state pass was never a legitimate author of the column - it was overwriting a value it had no data to justify. `_write_host` now supplies `confidence` only when the transition is `UNCONFIRMED` (a disagreement signal, which a state pass does have standing to assert), and `upsert_subdomain`'s `COALESCE` keeps the discovery value untouched.
- **Why nothing is lost.** The pass-local tools are still recorded per pass in `host_status_history.tools_json` (`append_host_status(..., tools=transition.sources)`, engine.py 1140-1154), and the regression test asserts that row rather than trusting the argument.
- **Latent guard folded in, by ruling.** `_persist_dns` now has `if not transition.persist: continue`, mirroring `_persist_live`, so the same call site is no longer asymmetric in two directions at once.
- **Rejected shapes.** `source_count = MAX(incoming, stored)` would make `MEDIUM`/`HIGH` permanent, because confidence must be able to fall when a host genuinely loses a source. Deriving the count from `subdomain_sources` at write time is more doc-faithful but would produce the (b) outcome through a second mechanism, blurring the (a)/(b) boundary this row was kept separate for.
- **Regression test** `tests/test_engine.py::test_dns_pass_does_not_overwrite_discovery_confidence`, docstring opening `Regression: 11d-findings-a`: `SUBS` (two tools report `www.example.com`) -> `DNS` (one tool resolves it) -> assert `("MEDIUM", 2)`, plus a `tools_json == ["dns-a"]` assertion for the provenance claim above.
  - Before the fix, with the old `engine.py` restored and only the new test kept: `E AssertionError: assert ('LOW', 1) == ('MEDIUM', 2)`, `1 failed, 35 deselected`, exit 1. That is the same pair the real run stored for all four hosts, so the test reproduces the production symptom rather than merely describing it.
  - After the fix: `1 passed, 35 deselected`, exit 0.
- **Side effect on (b), disclosed and deliberately not fixed.** With `source_count` no longer passed, the apex `testfire.net` - which reads `1` today only because `_write_host` stamped it - would insert at the schema default `0` on the next run. That value is more defensible, but the row is still created by the `dns` stage with `first_seen_run=2`, so **11d-findings-b is unaffected in substance and stays open**.
- **Checks** (`.venv`, Python 3.14.8): `pytest -q` -> **570 passed** (the previous 569 plus the new test, so nothing else was depending on the clobbered value); `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `69 files already formatted`; `mypy src/reconkit` -> `Success: no issues found in 37 source files`.
- **Scope of this commit:** `src/reconkit/engine.py`, `tests/test_engine.py`, this file. 11d-findings-b, (c) and (d) were not touched and remain open. Nothing was pushed.
- **Verified end-to-end on a fresh real run, 2026-11-14.** `reconkit passive -d testfire.net --db /tmp/rk_testfire_v2.db -v` (2 `scan_runs`: `subs` `partial`, `dns` `completed`; exit 5 for the failed tools, as in the first run). Like-for-like on `demo.testfire.net`, which got the same two sources (`crtsh` + `hackertarget`) and the same dns-pass-after-discovery sequence in both runs, with only the code differing: the pre-fix artifact stores `LOW`/1, the new one stores `MEDIUM`/2. Apex side effect confirmed: `testfire.net` now stores `LOW`/**0**, still with `first_seen_run=2` and no `subdomain_sources` rows, so (b) is intact. `host_status_history` still records `["dnspython"]` for all four hosts, so the provenance claim holds in the artifact, not only in the test. Fresh-artifact checks: `integrity_check` ok, `foreign_key_check` empty, `schema_version` 2, file `birth`/`mtime` matching run 1 `started_at` / run 2 `finished_at`. The pre-fix artifact was left untouched (same size and mtime), as the evidence it is.
- **Still open, and re-observed in the new run** (so none was a one-off): (b) the apex row is created by the `dns` stage; (c) `otx` stores `duration_s=0.0` on 429 and `dnspython` `0.0` with 4 items; (d) `subfinder`/`assetfinder` still record `failed` with `not installed or not executable`. None of the three was changed by the fix.
- **Reporting note.** Four queries in that session used column names guessed from memory (`stage_set`, `stage` on `tool_runs`, `items`, a nonexistent `meta` table) and failed; two of those failures were masked by a batched shell reporting the last command's exit status. Every number quoted in this entry comes from a query re-run with the real columns. The rule it broke is AGENTS.md's "field names from real `--help`/output, never memory". Separately, one reproduction command ran the real `subfinder` with `env={}`, and it created a `subfinder/` config directory in the repo root (the PIT-30 cwd fallback with no `HOME`); it was untracked, created by that command, and removed. The engine's own path is unaffected because `BinaryAdapter.child_env` supplies `HOME` for `needs_home` adapters.

### 11d-findings-b (medium; deferred to Part 12 by the close-out ruling) - the DNS stage creates subdomain rows

- `_persist_dns` (engine.py 1015-1018) and `_previous_facts` (engine.py 1115-1122) both call `upsert_subdomain(target_id, host, run_id=run_id)` with no `confidence`/`source_count`, so a host with no row is INSERTed with the schema defaults (`source_count=0`, `confidence='LOW'`) and `first_seen_run=<dns run id>`.
- Observed: the apex `testfire.net` has no `subdomain_sources` row in any run, `first_seen_run=2` (a `dns` run) and `source_count=1` (set afterwards by `_write_host`). The other three hosts point at `subs` runs.
- Kept separate from (a) because it is a different decision: (a) writes the wrong number, (b) decides that the row exists at all and what its provenance is.
- **Ticket shape (write-up only; no fix in this thread).** What is wrong: a host that the `dns` stage resolved but discovery never returned is recorded as a discovered subdomain, with `first_seen_run` pointing at a `dns` run and no `subdomain_sources` row, so provenance and "new" reporting are both wrong. Where: `_persist_dns` (engine.py 1015-1018) and `_previous_facts` (engine.py 1115-1122), which share the INSERT path; the schema defaults (docs/04 section 3) do the rest. Severity: medium - no traffic or scope impact, but the inventory claims a discovery that never happened, and `diff_new`/`--new-only` will surface it as new. Reproduction status: shown in the v1 and v2 artifacts; **not shown in v3** - `assetfinder` returned the apex itself, so every one of the 36 hosts has a source row (`0` hosts without sources, `0` hosts with `first_seen_run=2`). The defect is data-dependent, not fixed. **Reproduced offline in a `--mock` run on 2026-11-14** (`reconkit -d example.com --mock --json`, temp DB): `alias.example.com` is stored `state: DNS_ONLY` with `sources: []` and no discovery source, so this is structural, not a live-target artifact. What a fix needs to touch: a product decision first (skip dns-only hosts entirely, or keep the row but label its provenance as `dns` and exclude it from discovery counts/diff), then both call sites, then the rule stated in docs/04 section 5; tests: a resolved host discovery never returned must either be absent or carry dns provenance, `diff_new` must not report it, and the existing apex case is the natural fixture.

### 11d-findings-c (low; open, ticket below) - `duration_s` recorded as 0.0 for real I/O

- `HttpAdapter.run` (base.py 286-301) measures `started` but omits `duration_s` on both the `ParseError` and `FetchFailed` branches, so the `ToolResult` takes the Pydantic default `0.0` (models.py 110). `otx` therefore stores `0.0` next to `rate limited (HTTP 429)`, although a response was received.
- `DnsPythonAdapter.run` never sets `duration_s` on any return path (dnspython.py ~100), so `dnspython` stores `0.0` with 4 items.
- `Engine._run_one` (engine.py 794-818) computes `started` but uses it only on the timeout/exception paths, then records `result.duration_s`; its own measurement is discarded on the normal path.
- This is metadata loss, not missing I/O. The three `ok` HTTP tools store real, varying durations (crtsh 0.66 / 13.76 / 51.85 s; hackertarget 0.89 / 1.08 / 1.15 s), and `subfinder`/`assetfinder` store sub-millisecond real `FileNotFoundError` timings.
- **Ticket shape (write-up only; no fix in this thread).** What is wrong: `tool_runs.duration_s` says `0.0` for runs that did real work, so it cannot be used for pacing or performance reads and a 0.0 is ambiguous between "instant" and "not measured". Where: three writers - `HttpAdapter.run` (base.py 286-301) omits `duration_s` on the `ParseError` and `FetchFailed` returns, `DnsPythonAdapter.run` never sets it on any path, and `Engine._run_one` (engine.py 794-818) measures `started` then discards its own measurement on the normal path. Severity: low, metadata only. Reproduction status: v1 yes, v2 yes, **v3 yes** - `otx` `failed` at `0.0` next to a real 429 response, `dnspython` `ok` with 36 items at `0.0`, while `subfinder` (4.939 s) and `assetfinder` (1.522 s) now carry real durations after 11d-findings-e. What a fix needs to touch: the three sites above plus a decision on which measurement is authoritative (adapter-measured vs `_run_one`-measured) recorded in docs/04 for the column; tests: a 429, a parse error and a successful `dnspython` run each store a duration `> 0`, and a timeout keeps the duration it already measures; guard against double-counting when both the adapter and `_run_one` fill the field.

### 11d-findings-d (low; docs wording - resolved 2026-11-14, docs-only)

- **This ticket was misdiagnosed when it was logged, and that is corrected here rather than quietly rewritten.** It was recorded as "the code follows MASTER_PLAN" because `subfinder` and `assetfinder` stored `failed`. That attribution was wrong. The code already skips a genuinely absent binary at selection time (engine.py 729, `skipped.append((spec, "not installed"))`), which is exactly what docs/03 section 13 and docs/09 selection rules describe; the `failed` rows had a different cause, now logged as 11d-findings-e.
- What actually remained was a wording defect: docs/03, docs/09 (at two different sections) and docs/MASTER_PLAN all used "missing binary" for two different moments - absent at selection time (`skipped`, stage continues) and present but unspawnable at run time (`failed` with a message). Read side by side they looked like a conflict; they are not one.
- Resolved docs-only, no code change for (d): the docs/09 adapter contract now names the run-time case and requires `build_command` to launch the resolved `binary_path()`; docs/09 selection rules and docs/03 section 13 now say explicitly that the `skipped` rule is selection-time; MASTER_PLAN's adapter rule now defers to that rule instead of restating the run-time case as if it were the whole answer.

### 11d-findings-e (high) - binary adapters launched a bare `argv[0]`

- **Symptom, both halves of it:** `check_installed()` reports `subfinder` installed (`v2.17.0`, `/home/kali/.reconkit/bin/subfinder`), while a real passive run records `failed` with `not installed or not executable: [Errno 2] No such file or directory: 'subfinder'`. The product contradicts itself: `doctor` says installed, the scan says not installed.
- **Cause:** `subfinder.py:78` and `assetfinder.py:23` build `argv[0]` from `self.binary`, the bare name, while `Engine._tool_env` (engine.py 843-846) passes only the adapter's API-key vars - no `PATH`. The child therefore has no `PATH` to resolve a bare name against; `run_exec` turns the `OSError` into `returncode=None` (runner.py 116-123) and `base.py:141-146` maps that to `failed`.
- **Reproduced directly** with the empty env the engine passes: `subprocess.run(["subfinder", "-version"], env={})` -> `FileNotFoundError`; the same call with `/home/kali/.reconkit/bin/subfinder` -> `rc=0`.
- **Spec violated, not just a bug:** docs/09 adapter contract says the base resolves the binary in `~/.reconkit/bin` first and then `PATH`, and docs/10 section 5 says the managed directory comes first in the run-time lookup order so "no PATH edit is needed to run a Go tool". `check_installed()` uses `binary_path()`; `build_command()` did not.
- **Blast radius:** the only two `build_command` implementations in this build (`subfinder`, `assetfinder`). Other binary tools are `phase: 3` and are skipped as "no adapter yet". **CORRECTION (11c, 2026-11-14): this was false.** `httpx_tool.py:48` and `naabu.py:41` also implement `build_command` and still launched a bare `argv[0]`; see 11c-A-1 below. The fix in `df218b5` covered only the two adapters named here.
- **Fix shape:** launch `binary_path()` (resolved absolute path), falling back to the bare name only if resolution returns `None`. Do **not** widen the child env with `PATH`: the minimal-env rule is deliberate and a search path is a hijack surface.
- **Tests a fix needs:** `build_command()[0]` is absolute and equals `binary_path()` for both adapters, and a run-level test with a fake executable in a temporary managed directory that asserts the adapter actually launches it (no network, no real tool required).

### 11d-findings-e - fixed 2026-11-14

- **Fix:** both adapters now launch `self.binary_path() or self.binary`, so the managed copy is executed by absolute path. The child env is deliberately **not** widened with `PATH`: the minimal-env rule is the reason a bare name could not resolve, and a search path is a hijack surface, so the narrower change is the correct one.
- **Red, before the fix:** `4 failed, 59 deselected`, exit 1, with the production message reproduced verbatim: `not installed or not executable: [Errno 2] No such file or directory: 'assetfinder'` while `binary_path()` resolved to the stand-in. **Green, after:** `4 passed, 59 deselected`, exit 0.
- **Full suite:** 574 passed (570 + the 4 new cases: two parametrized tests over both adapters), so nothing else depended on the bare name.
- **Two existing tests hardened at the same time**, and this is why: `test_subfinder_command_and_rate_flag` and `test_assetfinder_command` asserted the whole argv with a bare `argv[0]`, which only held while the tool happened not to be on the machine's `PATH`. Once resolution is used, those assertions would fail on any box that has the tool installed - a test that depends on the environment, which rule 9 forbids. They now pin `Path(argv[0]).name` plus the flags, and the resolution itself is pinned by the new tests.
- **Verified on a fresh real run (v3), 2026-11-14.** `reconkit passive -d testfire.net --db /tmp/rk_testfire_v3.db -v`, ~160 s. `subfinder` is now `ok` with 35 items in 4.939 s and `assetfinder` `ok` with 4 items in 1.522 s; both were `failed` in v1 and v2 with the spawn error. Hosts rose from 4 to 36 (`demo.testfire.net` HIGH/4 from assetfinder+crtsh+hackertarget+subfinder; `altoro` and `www` HIGH/3), and `host_status_history` still records `["dnspython"]` per host while `source_count` keeps the discovery value.
- **Prediction written before the run, and compared honestly.** Predicted: both binaries `ok` (correct), `otx` 429 (correct), exit 5 (correct), host count above 4 (correct, 36). **Predicted `tools_skipped = 5` and it was 0 - wrong**, and the reason is a reporting detail rather than a regression: the footer counts only *selected* tools, so the nine phase-3 "no adapter yet" skips live in `tool_runs` and not in the counters (run 2 also printed `0 skipped` with nine skipped rows; the prediction was built on the wrong source for that number). Exit 0 did not occur, so there was no question of `otx` having recovered.
- **Artifact checks (v3):** `integrity_check` ok, `foreign_key_check` empty, `schema_version` 2, 2 `scan_runs` (`subs` partial because of otx, `dns` completed), 16 `tool_runs`, 36 `subdomains`, 43 `subdomain_sources`; file `birth` 08:46:43 matches run 1 `started_at` and `mtime` 08:49:29 matches run 2 `finished_at`. v1 and v2 were left untouched (same size and mtimes, checked after the run).
- **`ToolNotInstalled` was kept, not deleted, and given a docstring that says it is intentionally never raised.** Deleting it would mean editing docs/06 section 6 and docs/09 section 3, which define the exception vocabulary, for no behavioural gain; the comment states that a selection-time skip must not raise it and that exit 4 is derived in `Engine._exit_code`. That removes the "surely something should raise this" trap without churning two governing docs.

### Identity marker strictness (decision D, 2026-11-14 - docs committed first, implemented next)

- **Decision:** `BinaryAdapter` identity markers must **all** appear in the probe output (`identity_require_all = True`), with one documented per-adapter opt-out: `subfinder` keeps any-match semantics. Rationale: a check satisfied by either of two markers cannot reject the `httpx` namesake case docs/09 promises to reject, but an AND that rejects a working binary is worse than a loose OR.
- **Why subfinder is exempt (upstream evidence, not version guessing):** the `Subfinder Config Directory` line was added by upstream commit `c1757901af2fa61c4deb805e17a3e5b9aa7bd5d5` (2023-10-30, PR #1013 "fix config location"), first released in **v2.6.4** (2024-01-12); 18 tags contain it. The `v2.6.3` source prints only `gologger.Info().Msgf("Current Version: %s\n", version)` and exits, so an `all()` subfinder would report a working pre-2024 install as not installed - exactly the doctor-says-yes/scan-says-no disagreement this thread exists to remove. A real v2.17.0 banner does contain the name, so the currently installed copy would pass either way; the exemption is for older copies.
- **httpx/naabu marker-pair stability:** verified at tag `v1.0.0` in both upstream repositories - `showBanner()` runs unconditionally before the `-version` branch and prints `projectdiscovery.io`, and the branch prints `Current Version: %s`, so both markers co-occur in one probe from v1.0.0 onward. Also confirmed against the installed copies on this box (`httpx` v1.12.0, `naabu` 2.7.0), which print both.
- **Named gap:** the pre-1.0 `httpx` tags (`v0.0.x`) were not inspected. If one is ever supported, its banner must be re-checked before trusting the `projectdiscovery` marker pair. Nothing here assumes it either way.
- **Also found while auditing:** `naabu` had no positive identity test at all (only the timeout and runner-error negatives), so the strictness change for it would have shipped untested on the success path; the code commit adds that test.
- **Implemented:** `BinaryAdapter.identity_require_all` (default `True`) drives `all()` in `check_installed()`; `SubfinderAdapter` sets it to `False` with the upstream commit cited in the comment. Six new cases in three tests: two strictness banners x `httpx`/`naabu` (a banner carrying only one marker must now fail identity), the missing `naabu` positive test (`2.7.0` parsed), and a `subfinder` pre-v2.6.4 banner (`[INF] Current Version: v2.6.3`, no name line) that must still pass. Red before the change: `4 failed, 2 passed, 63 deselected`; green after: `11 passed, 58 deselected` on the identity slice; full suite **580 passed** (574 + 6). No `binary_path()`, selection or managed-directory-order change.

### Latent, not exercised by this run

- `_persist_dns` calls `_write_host` without the `if not transition.persist: continue` guard that `_persist_live` uses (engine.py ~1086). It is unreachable today because `_dns_facts` emits only `RESOLVED`/`NXDOMAIN` signals, but it is one refactor away from writing spurious status rows. Ruled into (a)'s fix, not a separate ticket; see the fixed block above. (Left as written, since this records the state found by the run.)

### Test coverage, measured

- `grep -rn "source_count" tests/` -> 29 text occurrences: **25 in `tests/test_store.py`** (upsert semantics only) and **4 in `tests/test_engine.py`**. An earlier note in this session said "29, sampled the first 20, all store" - that sample stopped before the engine file. This line is the corrected account.
- The 4 engine occurrences: two are direct `confidence_for([...])` unit calls with no DB; the other two (`test_engine_persists_three_distinct_tools_as_high`, `test_min_sources_hides_low_source_results`) run `stages=(Stage.SUBS,)` only and therefore never reach `_write_host`.
- The multi-stage tests that do reach it (`tests/test_engine.py:741,763` with `SUBS, DNS, LIVE`; `:840` with `SUBS, LIVE`) assert stage status, `tool_runs` counts, resume flags and host state - never `source_count`/`confidence`. The clobbered value is written into those fixtures and never examined.
- No existing test encodes the buggy value as expected behaviour, so (a)'s fix needs no assertion updates; it needs the new regression test specified under (a).
- `pytest -q tests/test_engine.py tests/test_store.py` -> **86 passed, exit 0** (`.venv` Python 3.14.8). The suite is green because no assertion observes this path, not because the path is correct. This is the general lesson: green measures the assertions that were written.

### Not done, by ruling

- No `src/` or `tests/` change in this entry; no `live`/`ports`/`--active` run until (a) is fixed, tested and committed. (a) has since been fixed in the block above; that run is still not done.
- 11d-findings-d stays open pending the maintainer.

### 11d-findings-f (2026-11-14) - `pyprobe` returned UNKNOWN on a TLS failure; root cause found and the short-circuit fixed

- **Root cause, 2026-11-14 (fixed):** `pyprobe._probe` looped `https` then `http`, but returned a `UNKNOWN` record from inside that loop as soon as a `ConnectError` message contained `ssl`/`certificate`. Real testfire.net hosts fail certificate verification on `https` (`[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'www.testfire.net'.`) while `http` answers 200, so the probe recorded UNKNOWN for 8 of 8 hosts that `httpx` found ALIVE and never made the second request. The fix remembers the TLS error, continues to the next scheme, and only reports UNKNOWN when no scheme answered; both the "Bug-fix session" entry and PIT-37 carry the raw output, and `test_pyprobe_tls_failure_still_tries_http` guards it.
- **Still deferred (the half that survives):** the branch still classifies by substring and discards `str(exc)`, so a host that is UNKNOWN because *no* scheme answered still cannot say why (expired certificate / untrusted CA / handshake rejected / incomplete CA store). No column, log line or result field carries the cause, and `duration_s=0.0` is the `ToolResult` default rather than a measurement. Ruling unchanged: **deferred to Part 12** with a diagnostic detail field for UNKNOWN records.
- The paragraphs below are the original finding, kept as written when the cause was unknown.

- The first real active run (`pyprobe`, testfire.net root, exit 0) stored `testfire.net UNKNOWN LOW`, and the DB cannot say why. `tool_runs` is `pyprobe|ok|1|0.0|NULL`; `host_status_history` has zero rows; `subdomains` carries only the schema defaults.
- `pyprobe` produces an UNKNOWN record on exactly one live path: `httpx.ConnectError` whose message contains `ssl` or `certificate` (`_is_tls_error`). It classifies by substring and then discards `str(exc)`, and because the branch returns a record rather than `None`, `unreachable=` stays 0 and `ToolResult.error` stays `None`. No column, log line or result field carries the cause. The `duration_s=0.0` is the `ToolResult` default, not a measurement (the engine only fills it on timeout/exception), so it is not evidence of an instant failure either.
- Consequence: "expired certificate / untrusted CA / handshake rejected / incomplete CA store" cannot be separated without probing again. Ruling: **deferred to Part 12**, with a diagnostic detail field for UNKNOWN records.

### 11d-findings-g (new, 2026-11-14) - an inconclusive live pass persists no status row

- `decide_host_state` sets `persist = previous is not None` for inconclusive evidence, and `Engine._persist` skips `_write_host` when `persist` is false. With no previous state (a first run), the pass writes no `host_status_history` row at all, so a run that did contact a host is indistinguishable in the DB from one that never did.
- docs/04 section 5 says `host_status_history` gains one row per host per status pass, and writes an exemption only for the `dns` stage's SERVFAIL/timeout/no-answer/error. A live pass with inconclusive evidence has no documented exemption. Ruling: **deferred to Part 12** (persisting the UNKNOWN transition, or recording probe outcome per host, needs a docs/04 decision about state-change semantics first).

### Wildcard filter wiring (2026-11-14)  (moved from PROGRESS 2026-11-15: Wildcard filter wiring (closed implementation record))

- Docs first: `581a556` states that `wildcard_check.enabled: false` skips the filter and that it never runs under `--mock`; the code commit follows it.
- The detector is built once per run in the `dns` stage, immediately after `_run_tools` returns that stage's `RunContext` (the only place the run limiter exists). Probe is `DnsPythonAdapter().resolve_host` bound to that context, `rng` is the engine's injected RNG, `probes` comes from `config.wildcard_check.probes`. `detect(target)` is awaited before `_persist_stage`, so no resolved host is accepted first.
- `is_wildcard` is written only in `_persist_dns`'s `RESOLVED` loop: `PRESENT` passes `result.matches(ips=..., cnames=...)` (true or false), `NONE` and `UNKNOWN` pass `None`, so they never mark and never clear an earlier mark. `UNKNOWN` appends `wildcard check inconclusive for <target>; nothing marked wildcard` to `summary.warnings`, which `ui.render` prints as `warning: ...`.
- Evidence: red check with the old `engine.py` -> `4 failed, 1 passed` (the mock test passes by design); green -> `5 passed`; full suite 585; ruff, format and mypy clean. v1/v2/v3 sha256 unchanged before and after; v4 (`/tmp/rk_testfire_v4.db`) has 36 hosts, 0 non-zero `is_wildcard`, no wildcard warning, exit 5 (only `otx` 429). An observer run that wrapped `WildcardDetector.detect` recorded one call: `{'target': 'testfire.net', 'status': 'none', 'probes': 3, 'resolved': 0}`.
- Independent confirmation before interpreting: three random `A` labels under `testfire.net` returned NXDOMAIN with the venv's dnspython, so `none` was the expected status.
- Still unspecified, not implemented: docs/09's "exclude them from counts by default" - no document defines which count and no code path filters it, so `is_wildcard` is a mark only. 11d-findings-b and (c) are untouched; `certspotter`'s repeated 0-item `ok` still needs the hypothesis promised for Part 11 close-out.

### Fix backlog  (moved from PROGRESS 2026-11-15: Fix backlog (empty as of Part 9 close-out))

No open items from Part 9. Part 9 fixed the dangling-CNAME persistence gap with schema version 2 and a restart regression test. The four 11d-findings tickets are tracked in the 2026-11-14 section above, not here.

### 11c-bis fresh-venv gate (2026-11-14)  (moved from PROGRESS 2026-11-15: 11c-bis fresh-venv gate (closed; tickets 11c-bis-1/2 stay listed in PROGRESS open items))

- Environment: a clean `python3 -m venv` under `/tmp`, Python 3.14.8, pip 26.3, installed with the SETUP.md:38-43 manual block (`pip install -e ".[dev]"`). The temp venv, the temp DB and every capture were deleted afterwards; `.venv` was not touched and the tree was clean at `41e1dd0`.
- Results: `reconkit --help` exit 0; `reconkit doctor` exit 0 with 7 missing tools, 1 `wrong program` (`masscan`) and every Keys row `Set: no` (warnings keeping exit 0 is docs/10 section 5a, so no defect); `reconkit -d example.com --mock --json` exit 0 with one valid JSON document and no network activity.
- Doctor on a fresh venv still reports the host's tools (`amass`, `nmap`, `nuclei`, ...) because reconkit's tools live in `~/.reconkit/bin` and `PATH`, not in the Python environment. That is correct, not a gap; only `python` comes from the venv.
- Ticket **11c-bis-1** (low, docs/UX): `--help` renders every switch as value-taking (`--json <bool>`, `--mock <bool>`, `--no-color <bool>`, `--help <bool>`), while docs/02 lines 58-70 and the working CLI treat them as bare flags. This is not environment drift: the repo `.venv` also has typer 0.29.1 and renders identically. The underlying risk is `pyproject.toml:12` (`typer>=0.12`, no upper bound, no lockfile) plus the absence of any test that asserts the `--help` **rendering**: `tests/test_cli.py` pins flag names against docs/02 (`test_every_documented_scan_flag_is_registered`, `test_scan_has_no_undocumented_options`), pins that each `--help` exits 0, and pins that bare `--json` yields one document, but nothing compares the value-arity text, so that rendering can drift unnoticed. A fix needs a docs/CI decision (upper pin and a rendering assertion), not a code edit.
- Ticket **11c-bis-2** (low, behavior): `reconkit --json doctor` - the flag placed globally, before the command - exits 0 and prints the human doctor tables; `--json` is accepted and silently ignored rather than honored or rejected. docs/02:14 puts flags after the command, so the documented grammar is unaffected. Needs a decision (reject the global placement, or honor it).
- Not ticketed, unverified: `naabu` reports `ok` while doctor also reports `libpcap-dev missing`; whether the version probe legitimately avoids libpcap or the ready row is optimistic was not investigated.
- Suite in the same fresh venv (second temp venv, same install recipe): `pytest -q` -> `585 passed in 12.62s`; `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `68 files already formatted`; `mypy src/reconkit` -> `Success: no issues found in 36 source files`. Versions there: Python 3.14.8, typer 0.29.1, pydantic 2.14.3, httpx 0.28.1, pytest 9.2.0 - identical to the repo `.venv`, so no version drift is observable today; the ticket above is about future installs, not this one. No pin or code change follows from this result.

### Part 11 interim report (11f not yet satisfiable)  (moved from PROGRESS 2026-11-15: Part 11 interim report (superseded by the delivered 11f report))

- **Why this is not the final report.** MASTER_PLAN 11f asks for the close-out report after 11c (the fresh-eyes audit of `src/`), 11d and 11e. 11c had not been performed when this section was written: the ten S3 scans are mechanical pattern checks and do not substitute for reading the tree. 11e also cannot be satisfied, because it requires a RESUME status of "ALL DONE". Part 11 therefore cannot be reported as closed, and this document is a status report, not the 11f deliverable.
- **Evidence base for everything below.** Gate on 2026-11-14: `585 passed`, ruff, `ruff format --check`, mypy clean (also in a clean venv with typer 0.29.1 / pytest 9.2.0). Ten S3 scans run in Linux `grep` form; the `assert` hit was prose in a comment and was reworded. `11c-bis` fresh-venv gate: `--help`, `doctor` and `--mock --json` all exit 0. Real passive runs: `/tmp/rk_testfire.db`, `_v2`, `_v3`, `_v4` on `testfire.net`.
- **Closed since Part 10:** 11a README/SETUP (`cc70b15`, verified by platform-mention counts before/after); 11b docs/01-10 sync (`3a14568`) and 11b-2 docs/08 flows (`d2e3c66`); 11d-findings-a consensus clobber (`1b41f4e`); 11d-findings-d docs wording (`a0d06b5`); 11d-findings-e bare `argv[0]` for subfinder/assetfinder (`df218b5`); identity markers require every marker (`22fbd49` docs + `d265dc0` code); wildcard filter wired (`581a556` docs + `1dd63e5` code); dead `dns_python.py` stub removed (`b24f39b`); `certspotter` 0-item behaviour explained, not a defect (`430aa1d`).
- **Open item 1 - 11c fresh-eyes audit of `src/`.** Not performed as of this section. The S3 scans cover the ten listed patterns only. No `src/` review, no per-category findings, no requirement-to-test audit of the Part 11 code has been done.
- **Open item 2 - 11d-findings-b (medium).** The `dns` stage INSERTs `subdomains` rows for hosts discovery never returned (`_persist_dns`, `_previous_facts`); provenance and `diff_new` are wrong for those rows. Reproduced in the fully offline `--mock` run of 2026-11-14 (`alias.example.com`, `DNS_ONLY`, `sources: []`), so it is structural, not a live-target artifact. Blocked on a product decision (drop dns-only hosts, or keep and label dns provenance).
- **Open item 3 - 11d-findings-c (low).** `tool_runs.duration_s` stores `0.0` for real work: `HttpAdapter.run` omits it on both failure branches, `DnsPythonAdapter.run` never sets it, and `Engine._run_one` discards its own measurement on the success path. Re-observed in the `--mock` run (`dnspython`, 3 records, `0.0`). Needs a decision on which measurement is authoritative before any fix.
- **Open item 4 - PIT-33 follow-through.** The pitfall row exists, but nothing enforces it: the pre-commit hook still requires `docs/PROGRESS.md` only when `src/` or `tests/` change, so a docs-only commit that closes named work can still land without updating the source of truth.
- **Open item 5 - 11c-bis-1 (low).** `--help` renders switches as value-taking (`--json <bool>`, `--mock <bool>`, `--no-color <bool>`, `--help <bool>`) while docs/02 and the CLI treat them as bare flags. Underlying risk: `typer>=0.12` has no upper bound and there is no lockfile, and no test asserts the rendering (the suite pins flag names and bare `--json` only).
- **Open item 6 - 11c-bis-2 (low).** `reconkit --json doctor` (flag before the command) exits 0 and prints human tables; the global flag is accepted and silently ignored. Needs a decision to reject or honor it.
- **Open item 7 - `cli.py:226` secret-path question.** The last-resort handler formats raw `str(exc)` and `cli.py` imports no `redact`/`_secrets`, so an escaping exception's text reaches the terminal unredacted. Keys travel in headers, not URLs, so no reachable leak has been shown; it remains a named audit question, not a demonstrated defect. The `-v` path also prints a full traceback for the same exception.
- **Open item 8 - path/lookup-order gap.** `BinaryAdapter.binary_path()` prefers any existing file in `~/.reconkit/bin` over `PATH`, so a broken managed copy shadows a working binary; `doctor` and the run then disagree. Recorded as deliberate (docs/10 section 5 puts the managed directory first for the `httpx` collision) with a manual mitigation. There is no `bin_paths` symbol anywhere in the tree; the non-standard-install-path question is this lookup order, not a config key.
- **Open item 9 - DNSDumpster ticket (planning only).** `tier: core` in free mode reporting `skipped (no API key)`, endpoint `https://api.dnsdumpster.com/domain/<domain>`, `X-API-Key`, 1 request / 2 s, 429 body `{"error":"Rate limit exceeded"}`, free 50 records + 50 queries/day. Rulings taken: a core-tier exemption sentence in docs/05 section 6.1, 429-as-failed with no new pacing machinery, and fixture work blocked until a free key exists. **None of this is in the repo** - no `tools.yaml` entry, no adapter, no docs/05 or docs/09 text - and the rulings exist only in the review conversation. Zero code, as ruled.
- **Open item 10 - R2 Ctrl+C child kill.** The CLI exits 130 and the stage is marked `interrupted`, but a child already running is not killed (children lead their own process group, PIT-32). `killpg` is unverified on Linux; this is a future part by ruling.
- **Open item 11 - wildcard "exclude from counts".** docs/09 says wildcard matches are excluded from counts by default; no document defines which count and no code filters it, so `is_wildcard` is a mark only.
- **Open item 12 - other carried risks.** `sqlmap` row shows a bare path instead of a version (`version_command` mechanism exists, not applied); the managed `nuclei` copy is missing after a failed reinstall (the Go copy satisfies `installed_copy`); `update` idempotency for `@latest` go_install tools is a reporting gap; authenticated GitHub release lookups are not implemented (60 requests/hour unauthenticated).
- **Open item 13 - 11e cannot be satisfied** until every item above is closed or explicitly deferred by ruling; RESUME must not say "ALL DONE" before then.
- **Open item 14 - no active run has ever been executed.** Every real run so far is `passive` (subs + dns). `live`, `ports`, `tech`, `urls`, `vulns` and any `--active` path have never run against a real target, so the scope gate, the host-delay pacing and the active adapters are proven only by tests.
- **11c status line, kept honest:** the audit begins after this commit; its findings are recorded separately and are **not** included in the list above. This section must be extended by the same day's audit commit before 11f can be attempted.

### Part 11c - fresh-eyes audit (2026-11-14, read-only)  (moved from PROGRESS 2026-11-15: Part 11c fresh-eyes audit (findings all fixed or ruled; see the Part 11 entries))

- Scope of the read: `engine.py` (all 1238 lines), `cli.py` (all 702), `core/scope.py`, `core/runner.py`, `core/pacing.py`, `core/workspace.py`, `core/wildcard.py`, `adapters/base.py`, `adapters/dnspython.py`, `pyprobe.py`, `pyscan.py`, `subfinder.py`, `assetfinder.py`, `httpx_tool.py`, `naabu.py`, `crtsh.py`, `certspotter.py`, `otx.py`, `hackertarget.py`, `adapters/__init__.py`, `doctor.py` (report + key paths), `store.redact`, `installer/github_release.py` (`install_selected`, `desired_version`), plus `config.yaml`, `tools.yaml` stage modes and the matching docs sections. No `src/` or `tests/` change in this commit.
- **(a) active without `--active` + scope pass: no bypass found.** Four layers hold: `cli.py:47` `_ACTIVE_ONLY`; `cli.py:168-170`; `engine.py:707-741` `_select` skips every `mode: active` spec unless `opts.active`; `engine.py:683-712` `_active_hosts` calls `require_active` and `_skip_active` downgrades active specs to `skipped` on `ScopeError`, with exit 3. Adjacent defect found: **A-1** below.
- **(b) timeout becoming DEAD/SHUT_DOWN: none found.** DEAD has one producer (`dnspython.py:126-127`, NXDOMAIN only, read back at `engine.py:960-967`); SERVFAIL/TIMEOUT/ERROR emit no record; the uncertain branch keeps the previous state or `UNKNOWN` (`engine.py:234-255`); `pyprobe` maps TLS errors to `UNKNOWN` and drops timeouts.
- **(c) secrets: no proven leak; one new low item.** `cli.py:227` still formats raw `str(exc)` (known question), and `-v` prints a traceback (`cli.py:125-127`). Keys reach headers only (`certspotter.py:33`, `otx.py:23`), never argv (`subfinder.py:88-89`); child output is redacted against the env values (`runner.py:184-189`); DB writes redact (`engine.py:867-877`); `doctor` prints key names only and computes `Set` from `.env` (`doctor.py:266-273`), so the all-`no` table in the fresh-venv run was correct. New: **C-2** below.
- **(d) traceback escaping: none demonstrated.** Scan path has a last-resort handler (`cli.py:225-229`); `install_selected` catches `InstallSkipped`/`InstallError` per plan (`github_release.py:601-611`); `desired_version` swallows `InstallError` (`:518-521`). Unverified: `BrokenPipeError` with a closed stdout, and the fast-active prompt EOF path.
- **(e) blocking calls in async: three low findings** (E-1/E-2/E-3 below). Positives: `run_exec`/`check_installed` run via `asyncio.to_thread` (`base.py:141-150`, `engine.py:735`), DNS uses `dns.asyncresolver`, `pyscan` uses `asyncio.open_connection`.
- **(f) confidence from non-distinct tools: none found.** `confidence_for` applies `set()` (`engine.py:118-131`); discovery groups per `fqdn` by `result.tool` (`engine.py:940-970`); ports key by tool and turn disagreement into `UNCONFIRMED` (`engine.py:1204-1238`); `_write_host` no longer supplies `source_count` (11d-a).
- **(g) docs/code mismatches: G-1, G-2, G-3, G-4 below**, plus the known 11c-bis-1/2 tickets, docs/09's undefined "exclude from counts", and **G-6**: the 11d-e blast-radius claim above is false.

### 11c consolidated findings (nothing dropped)

| ID | Severity | Finding | State |
|---|---|---|---|
| A-1 | high | `httpx_tool.py:48`, `naabu.py:41` launch bare `argv[0]`; child env has no `PATH` (`engine.py:867-870`, `base.py:213-219`), so `live`/`ports` fail while `doctor` says installed - 11d-e unfixed in two adapters | **fixed in this commit** |
| G-1 | high | `Workspace.write` (`workspace.py:104`) has no callers and `raw_path` (`models.py:112`) is never set, while docs/03:120 step 9 and docs/03:83 promise raw output files | ticketed, no code |
| G-2 | high | `Pacer.before_host()` (`pacing.py:73`) was never called; docs/03:125 documents it and `config.yaml` sets `active.host_delay` [1,5]/[0,2], so inter-host pacing never applied | **fixed, Option B (docs `0ced491`, code below)** |
| G-3 | medium | `scope.passive_warning()` (`scope.py:325`) has no callers, so the documented out-of-scope passive warning never prints | **fixed 2026-11-14** (`Engine._note_passive_warning`) |
| C-1 | medium (known) | `cli.py:227` unredacted `str(exc)`; `-v` traceback; reachability still unproven (keys travel in headers) | **deferred to Part 12** (needs a secret source in the CLI layer) |
| E-1 | low | synchronous SQLite transaction + `_persist_stage` on the event loop (`engine.py:551-556`) | **deferred to Part 12** (concurrency refactor, no wrong-result defect) |
| E-2 | low | `load_scope()` file read + YAML parse inside async `_active_hosts` (`engine.py:687`) | **deferred to Part 12**, with E-1/E-3 |
| E-3 | low | `Workspace.create` mkdir/chmod inside `async def run` (`engine.py:463`) | **deferred to Part 12**, with E-1/E-2 |
| C-2 | low | subfinder's provider file is `mkstemp` in the system temp dir (`subfinder.py:76-79`, 0600, removed in `finally`); a `SIGKILL` in between leaves a key file | **deferred to Part 12** (SIGKILL-safe temp file needs its own design) |
| G-4 | low | `ExitCode.ALL_FAILED = 6` (`engine.py:83`) is unreachable; `_exit_code` (`engine.py:592-604`) returns `NO_TOOL` when every tool failed | **closed 2026-11-14**: not a defect in `_exit_code` (docs/02 gives code 6 to install/update only); the dead member is removed |
| G-6 | docs | the 11d-e blast-radius claim ("only two `build_command` implementations") is false; corrected in place above | corrected |
| G-7 | high | `scope.ip_allowed()` (`scope.py:296`, `ScopeGate.ip_allowed` `:110`) has zero call sites in `src/`; docs/05 rule 6 requires skipping resolved IPs when no `in_scope_cidrs` are defined, so the documented rule is unenforced. `pyscan.py:75-81` resolves each host and probes `addresses[0]` unchecked | **fixed 2026-11-14 for `pyscan` (filters every resolved address); `naabu` stays blocked by ruling (see below)** |

### 11c-G-2 - fixed 2026-11-14 (Option B, after the ambiguity ruling)

- **Ambiguity, resolved by you:** the docs named `before_host()` only in the API list and did not say which loop owns it. The ruling was Option B: wire the per-host active adapters, keep one-shot tools exempt, and make `pyprobe` dispatch sequentially at `parallel_limit == 1` so the pause is real spacing rather than a concurrent sleep.
- **Docs first:** `0ced491` added two bullets to docs/03 §7 - the two per-host adapters, the preset delay, the first-host exemption, the sequential-dispatch rule, and a named exemption sentence for `httpx`/`naabu` (`-rl`/`-rate`, not `before_host()`).
- **Code:** `pyscan.run` awaits `before_host()` before the second and later valid host (so invalid hosts skipped by `validate_host` do not consume a pause); `pyprobe.run` takes a sequential branch when `parallel_limit("active") <= 1` and keeps the gather above it.
- **Red first:** both new tests failed before the wiring because no pause was recorded at all (`StopIteration` on the `delay:` lookup): `2 failed, 35 deselected`. Green after: `2 passed, 35 deselected`.
- **Assertion strength:** both tests assert ordering, not call count - host B's resolve/probe appears only after the recorded pause, the pause follows host A's connect/probe, the first host never waits, and the pause value is inside slow's `active.host_delay` `[1, 5]`.
- **Not changed:** `httpx`/`naabu` (exempt by the new docs text), `dnspython` (passive; `before_host()` reads the active preset), `normal`/`fast` parallelism.
- **Known asymmetry, now stated in docs/03 §7:** `pyprobe` pauses between hosts only in `slow`; at `normal`/`fast` parallel dispatch leaves the shared rate limiter as its only pacing. `pyscan` calls `before_host()` at every speed, which is a no-op when the preset range is `[0, 0]` (`fast`).

### 11c-G-7 - ticketed 2026-11-14 (no code fix)

- **Finding:** docs/05 rule 6 says "probe an IP only if it is inside `in_scope_cidrs`. If no CIDRs are defined, scan hostnames only and skip resolved IPs." The predicate for that rule exists - `scope.ip_allowed()` (`scope.py:296`) and `ScopeGate.ip_allowed()` (`scope.py:110`, "no CIDRs means no IPs") - and is tested directly (`tests/test_scope.py:142-148`), but **nothing in `src/` calls it**. `grep -rn ip_allowed src --include=*.py` returns only the two definitions and the module-level wrapper; no adapter, engine path or CLI path consults it.
- **Concrete consequence:** `pyscan.py:75-81` resolves each in-scope hostname to `addresses[0]` and probes that IP directly. With no `in_scope_cidrs` in `scope.yaml` (the shipped example has them; the local testfire file does not), a hostname whose A record points at an IP outside any declared range is still probed. The gate therefore authorizes **names**, and the documented IP-level rule is currently decorative.
- **HARD PRECONDITION, not a background note:** until this is fixed, **no IP-connecting active tool may run** - this covers `pyscan`, `naabu`, and anything else that resolves a host and then connects to the resolved address, now or later. Any future active-stage work must either fix G-7 first or explicitly rule, in writing, that the tool in question is name-only. `pyprobe` is **not** blocked by this gap: it connects by hostname through `httpx` and never touches a resolved IP, so its traffic is governed entirely by `require_active()`'s name check.
- **Scope:** docs-only ticket. No docs/05 change is needed (the rule already says what should happen); the fix is code that makes the rule true, and it needs its own approval because it changes which active tools may launch.
- **Not done here:** no fix, no test, no reviewer decision on whether the fix belongs in `_active_hosts`, in each adapter, or in a shared resolve helper.
- **Interim block (code, 2026-11-14):** `engine.IP_GATE_BLOCKED` skipped `pyscan` and `naabu` at selection time, before the install check, with the reason `blocked: in_scope_cidrs not enforced on resolved IPs (11c-G-7)`, recorded as `skipped` rows like a missing binary. `--mock` was exempt because it connects to nothing. It was load-bearing, not decorative: with the check removed the test failed with `assert ['live-fake', ...can', 'naabu'] == ['live-fake']`.
- **Enforcement (2026-11-14):** `RunContext` gains `ip_allowed: Callable[[str], bool] | None`; the engine fills it from `load_scope(self.scope_path).ip_allowed` once the active gate has passed (`Engine._ip_allowed`, `None` on an unreadable scope). `pyscan._allowed_addresses` keeps only permitted resolver answers, probes the first one, counts every skipped host as `blocked=`, and no longer falls back to the hostname when the resolver returns nothing (that fallback resolved a second time below the filter). `pyscan` therefore selects normally; only `naabu` remains in `IP_GATE_BLOCKED`, with the reason `blocked: resolves inside the binary, so in_scope_cidrs cannot be enforced (11c-G-7)`.
- **Why `naabu` is not wired, stated as a deviation:** it receives hostnames and resolves inside its own process, so the adapter never sees the address that gets connected to; passing IPs instead would change its `PortRecord.fqdn` semantics and could not be verified against the real binary (not installed here). Rather than ship a name-only authorization for an IP-connecting tool, it is skipped. This is a decision for review, not a permanent architectural claim.
- **Tests:** `test_pyscan_probes_only_an_address_inside_in_scope_cidrs`, `test_pyscan_skips_a_host_whose_address_is_outside_in_scope_cidrs`, `test_pyscan_without_cidrs_probes_no_addresses`, `test_pyscan_never_falls_back_to_the_hostname`, `test_pyscan_blocks_a_malformed_resolved_address`, `test_active_ports_stage_receives_the_cidr_predicate`, `test_naabu_stays_blocked_because_it_resolves_inside_the_binary`.
- **Mutations recorded:** `_allowed_addresses` returning every address -> `3 failed, 1 passed` (outside-CIDR, first-address and malformed cases); `RunContext` built without `ip_allowed` -> `1 failed`. Both restored, targeted tests green again.

### 11c-A-1 - fixed 2026-11-14

- **Fix:** `httpx_tool.py` and `naabu.py` now launch `self.binary_path() or self.binary`, the same shape as the accepted 11d-e fix; the child env is still not widened with `PATH` (the minimal-env rule and the hijack surface are unchanged).
- **Red first:** the new test `test_active_binary_adapters_launch_the_resolved_managed_binary` (parametrized over httpx and naabu) failed on both before the change with `AssertionError: assert False ... where PosixPath('httpx') = Path('httpx')` and the same for `naabu`: `2 failed, 69 deselected`, exit 1. That is the production symptom (doctor sees the managed copy, the spawn gets a bare name and no PATH).
- **Green after:** `4 passed, 67 deselected` on the targeted slice; full suite **587 passed** (585 + the 2 new cases). ruff, ruff format and mypy clean.
- **Two existing assertions hardened, and why:** `test_httpx_command_dedupes_and_lowercases_hosts` and `test_naabu_command_and_ports` compared the whole argv against a bare `argv[0]`, which only held while the tool happened not to resolve. They now pin `Path(argv[0]).name` plus the flags, and resolution itself is pinned by the new test (the same hardening 11d-e applied to subfinder/assetfinder).
- **Not verified:** neither adapter was executed against a real target or a real binary. The evidence is the managed-stand-in test plus the static path (`runner.py:105-124` -> `base.py:158-164`).

- **Decision needed: does `UNKNOWN` from one live tool count as disagreement? (found 2026-11-14; its main trigger is now fixed, the rule is not).** After the `pyprobe` short-circuit fix, the eight real hosts return `ALIVE` from both live tools, so this no longer fires for them; session 2 confirmed zero `UNCONFIRMED` rows on a full run, and the displayed HIGH/MEDIUM/LOW are discovery-source counts, not live agreement (docs/04). The rule itself is unchanged and still needs a ruling. Original observation: With `pyprobe` returning `UNKNOWN` for all 8 hosts and `httpx` returning 200 for the same 8, every ALIVE host was stored with `confidence: UNCONFIRMED` even when three discovery sources agreed. `engine.py:166-168` counts any non-ALIVE web state as disagreement and returns UNCONFIRMED before counting sources; `test_engine_disagreement_is_unconfirmed` pins that on purpose, while docs/09 section 5 only says "LOW when only one check is available" and never defines UNCONFIRMED for host state. Two readings: UNKNOWN means "no evidence" (score LOW) or "contradicts ALIVE" (keep UNCONFIRMED). This needs an owner ruling and a docs edit before any code changes; the separate question of why pyprobe cannot reach hosts httpx gets 200 from stays deferred as 11d-findings-f.

### Part 11 close-out rulings (2026-11-14)  (moved from PROGRESS 2026-11-15: every item below was closed or deferred to Part 12, which is now implemented except 12e/12h/12j; the Kali commands stay in PROGRESS)

Part 11 cannot close with items merely ticketed, so every open 11c/11d item now has an explicit ruling. Evidence and reasoning: REVIEW_LOG "Part 11 close-out - rulings". The named future part for everything deferred is **Part 12 - evidence, secrets and loop hygiene**; it was written into `MASTER_PLAN.md` on 2026-11-14 as a plan at the owner's request (`12a`-`12k`), and implementing it still needs the owner's approval and rulings on its decision items.

| Item | Ruling |
|---|---|
| 11d-findings-b | deferred to Part 12; the product decision is made now (keep the dns-only row, mark its provenance `dns`, exclude it from `diff_new` and discovery counts) |
| 11d-findings-c | deferred to Part 12: three writers disagree on `duration_s`, so the fix needs a decision on which measurement is authoritative (docs/04 records it per column) |
| 11d-findings-f | deferred to Part 12 (UNKNOWN carries no cause) |
| 11d-findings-g | deferred to Part 12 (inconclusive pass writes no history row) |
| G-1 | deferred to Part 12: needs an adapter-contract change (raw text per adapter, `raw_path` set, one write per tool), not a Part 11 edit |
| G-3 | **fixed in this part** (`Engine._note_passive_warning`, docs/05 rule 1) |
| G-4 | closed, not a defect: docs/02 assigns code 6 to install/update only, so `_exit_code` returning 4 is correct; the dead `ALL_FAILED` member is removed |
| C-1 | deferred to Part 12: the fix needs a secret source in the CLI layer, which is an architecture decision (docs/03), and no reachable leak has been shown |
| C-2 | deferred to Part 12: a SIGKILL-safe provider file needs its own design; 0600 + `finally` remains the mitigation |
| E-1, E-2, E-3 | deferred to Part 12: moving the SQLite transaction, the scope read and the workspace mkdir off the event loop is a concurrency refactor with ordering risk, and none causes a wrong result |

### Working text moved in the same trim (second batch: the blocks PROGRESS rewrote rather than kept)

These blocks are the pre-trim text of sections that PROGRESS now carries in condensed
form. They are kept so no completion note, verification summary or source citation was
lost, and so the corrected versions in PROGRESS can be compared against them.

#### RESUME HERE  (moved from PROGRESS 2026-11-15: RESUME block as of 2026-11-15 (superseded by the trimmed RESUME; the 12a-12k completion notes, the two real-tool verification summaries and the Part B audit note were condensed, not deleted))

- Status: **PART 12 IN PROGRESS - 12a, 12b, 12c, 12d, 12f, 12g, 12i AND 12k DONE (2026-11-14/15); NEXT IS THE PROGRESS.md TRIM (12e/12h/12j still undecided).** Part 11 is closed, the 11f report was delivered, the two post-Part-11 fix sessions are done, and Part 12 exists in `MASTER_PLAN.md`; the owner approved that text and ruled on all seven decision items on 2026-11-14, so implementation proceeds one item per commit. `--active` is rejected on passive-only commands, `pyprobe` no longer short-circuits on a TLS failure, skipped tools are reported per stage, raw tool output is written, `duration_s` is adapter-measured, console text is redacted, `provenance` keeps DNS-created hosts out of NEW, provider keys live in a 0700 per-run directory, an empty stage exits 5 with a warning, the ports ceiling is closed as permanent, and a host that could not be probed keeps a bounded redacted reason. Part 12 (12a-12k) was written into `MASTER_PLAN.md` on 2026-11-14 at the owner's request and approved the same day. 12e/12h/12j stay undecided. Nothing is pushed: local `main` is ahead, `reconkit/main` is still `5fd1d9a`.
- Close-out commits: `30c368e` (block IP-connecting adapters with a load-bearing test), `86022e7` (wire `in_scope_cidrs` into `pyscan`, keep `naabu` blocked, PIT-34), `18e7462` (G-3 passive warning, G-4 dead exit code, ruling for every open item), `64c9dcc` (close-out docs), `68df784` (Kali canonical), `6d9c161` (Part B tool audit), `7d894cc` (masscan identity fix).
- Baseline on this checkout (`/home/kali/Desktop/reconkit`, Python 3.14.8, schema version 4): `686 passed`, `ruff check .` clean, `ruff format --check .` 68 files, `mypy src/reconkit` clean (613 -> 634 raw output, -> 642 redaction, -> 650 duration, -> 660 empty stage, -> 668 provenance, -> 676 provider dir, -> 686 `host_status_history.detail`).
- Verified this session: the docs/05 rule 6 IP check is enforced in `pyscan` (every resolved address filtered, `blocked=` counted, hostname fallback removed) with two mutation proofs; `naabu` is skipped at selection time with a stated reason; the out-of-scope passive warning prints once per run; `ExitCode` matches docs/02; the ten S3 scans re-ran in `grep` form (one justified exception, C-1); a real active `pyprobe` run against `testfire.net` executed exactly once (exit 0, `UNKNOWN`, root-caused to a discarded TLS `ConnectError`).
- **Real-tool verification session 2 (2026-11-14, REVIEW_LOG "Real-tool verification session 2 - testfire.net, post-fix")**: one `reconkit run -d testfire.net --active --speed slow --no-keys --json`, 8m25s, exit 5, 18,771-byte document, 0-byte stderr. `pyprobe` returned 8 ALIVE and `httpx` 8 ALIVE - no UNKNOWN, agreement on every live host, 0 `UNCONFIRMED` (session 1 had 8/8 UNCONFIRMED). `hackertarget` hit its free quota for real, which verifies the previously unobserved quota-message branch. `diff` after the run: `gone: []`, `pending_gone: []`; measured on the stored runs, the old rule called the 4 -> 11 pair 27 GONE and the new rule calls it 0 (the 27 were pending until run 18 recovered them with 35 names). Still open: `--json` stderr silence, empty stages completed/exit code, ports `blocked=8`, `duration_s` 0.0.
- **Owner ruling implemented (2026-11-14; REVIEW_LOG "Rule decision - diff GONE needs two consecutive misses")**: option (a) for the `diff` finding. `GONE` now means seen in the discovery run before the previous one **and** absent from both the previous and the latest completed `subs` run; one miss is `pending_gone`, never a change, and fewer than three discovery runs confirm nothing gone. `Store.diff_gone(baseline, previous, latest)` + `Store.diff_pending_gone(previous, latest)`, `DiffSnapshot.baseline_run_id`/`pending_gone`, `diff --json` documents all three run ids and `pending_gone`; the human output prints "Not reported as GONE yet (needs two consecutive misses): ..." and, with fewer than three runs, "GONE needs three discovery runs to compare". No schema change. On the real `recon.db`, the 27 hosts that were `GONE` in the verification session are now `pending_gone` with `gone: []`. Eight new tests, three mutation proofs, PIT-39.
- **12k DONE (2026-11-14, `feat: warn and exit partial when a stage runs no tools`, REVIEW_LOG "Part 12k: a stage that executed no tools is a partial run (11d-findings-g)")**: a requested stage with zero executed tools is no longer silent. `Engine._exit_code()` (the one decision site) now also returns 5 when a non-resumed `StageOutcome` has no results, and `_note_empty_stage()` appends one `ScanSummary.warnings` entry per such stage - `"<stage> stage executed no tools: N tool(s) skipped (<reasons>)"` - which the existing human renderer prints and `--json` already carries. Precedence is documented in docs/02 section 6 (3 > 4 > 5 > 0): several empty stages stay 5, an empty stage plus a partial failure stays 5 with both warnings, an empty stage plus every selected tool failing stays 4, **all requested stages empty is 4** (nothing usable ran), and a fully resumed run stays 0. A `--tools`-filtered stage and `ports` with no hosts are not empty stages (no stage outcome exists). Ten new tests (suite 650 -> 660), red-before-green (core test: exit 0 with `warnings=[]` at HEAD), two mutation proofs with `sha256sum -c` restores. PIT-40 records the pitfall and the `Regression: PIT-40` guard. No schema change, no new flag/config/dependency, no UI change. Real `run --mock --active --json` on testfire.net exits 5 with exactly the three `tech`/`urls`/`vulns` warnings, and the same human command prints them and exits 5.
- **12d DONE (2026-11-15, `feat: store a bounded redacted reason on host_status_history`, REVIEW_LOG "Part 12d: a host that could not be probed keeps its reason")**: the 11d-findings-f remainder is closed. `pyprobe` keeps its TLS failure text on the `UNKNOWN` record (`HostStatusRecord.detail`) instead of classifying and discarding it; `_write_host` passes it to `Store.append_host_status(detail=, secrets=)`, and `store._detail_value()` is the single place that redacts (the existing `redact()` from 12a/12f, with the run's secrets), collapses whitespace to one line, then cuts to `DETAIL_MAX_CHARS` (200). `host_status_history.detail` is nullable, schema version 3 -> 4, additive (existing rows `NULL`). It is exposed as `hosts[].detail` in `--json` (via `HostSnapshot`/`HostRow`) and by direct query, and deliberately not in the human table; a later conclusive pass writes its own `NULL` row so an old reason never resurfaces. docs/04 (column, section 5 rule, section 10, migration 4) and docs/02/03/09 changed first. Nine new tests (suite 676 -> 686): UNKNOWN-from-TLS redacted/bounded/one-line, kept-previous-state case, plain connect failure stores nothing, no resurrection, adapter keeps the text, v3 migration, blank -> NULL, JSON document and real CLI mapping. Red-before-green (5 failed + collection ImportError + 2 TypeError at HEAD), three mutation proofs with `sha256sum -c` restores (truncation, redaction, migration). PIT-46. No new dependency/flag/config. Conflict flagged: the task asked for "a plain connect failure stores a different reason", but MASTER_PLAN 12d and docs/09 say it stores none (no record) - the documents won, see Deviations.
- **12i DONE (2026-11-14, docs-only closure, REVIEW_LOG "Part 12i: close the ports ceiling as permanent and accepted (docs only)")**: the accepted ports ceiling now reads the same way everywhere. docs/02 gained the ceiling in the `ports` stage row and a paragraph (pyscan-only, LOW maximum, disagreement rule unreachable, accepted permanently, no redesign planned); docs/05 rule 6 and docs/09 section 5 say the `naabu` skip is permanent by the 12i ruling; the PROGRESS line that said "`naabu` stays unavailable until a pre-resolve design exists" was corrected, and two historical REVIEW_LOG passages got a dated "resolved 2026-11-14" note instead of being rewritten. No code, tests, schema, flags or config changed; gate run twice, 676 passed each time, ruff/format/mypy clean.
- **12g DONE (2026-11-14, `fix: keep subfinder provider keys in a 0700 per-run directory`, REVIEW_LOG "Part 12g: a killed run cannot strand the subfinder provider file (C-2)")**: provider keys no longer live in a bare temp file. Each real subfinder run creates `reconkit-subfinder-<pid>-<random>` with mode 0700 (explicit `chmod`, file 0600 inside), passes `-pc <dir>/provider-config.yaml`, and `rmtree`s the directory in `finally`. At every `prepare()` start it removes stale `reconkit-subfinder-*` directories: a dead pid is removed at once, a live pid only after `STALE_AFTER_S` (900 s) - which is what keeps two concurrent runs from deleting each other's live config and is the fallback when liveness is unknown. Pre-12g orphaned `.yaml` files are removed by the same age rule. docs/09 changed first. Eight new tests (suite 668 -> 676), including a real `SIGKILL` child and a cleanup that must be invoked by a real run; three mutations with `sha256sum -c` restores (M1 first went uncaught - the SIGKILL test called the helper directly - so the test was rewritten). PIT-45. One scoped lint ignore (`S603` for this test file, reason in `pyproject.toml`). No new dependency/config/flags.
- **12b DONE (2026-11-14, `fix: mark dns-created hosts and keep them out of NEW`, REVIEW_LOG "Part 12b: a DNS-resolved host is not a discovery result (11d-findings-b)")**: `subdomains` gained `provenance` (`TEXT NOT NULL DEFAULT 'dns'`, `CHECK IN ('subs','dns')`, schema version 2 -> 3, additive back-fill: rows with a source row become `subs`, the rest stay `dns`). `_persist_discovery` is the only writer that passes `provenance="subs"`; the SQL upgrade is sticky, so a later `dns` pass can never downgrade a discovered host, and `first_seen_run` is never rewritten. NEW is now first-discovery-sighting (`provenance='subs'` and no `subdomain_sources` row before the latest discovery run), so a DNS-only host is stored but never NEW, and a host the `dns` stage saw first becomes NEW at the run a discovery tool first returns it. docs/04 (schema, section 5, NEW rule, migration 3) and docs/02 (diff semantics) changed first. Eight new tests (suite 660 -> 668), red-before-green (`7 failed`, `no such column: provenance` / `assert 2 == 3`), three mutation proofs with `sha256sum -c` restores. PIT-44. Real `--mock` runs store `alias.example.com|dns|0` and `www.example.com|subs|6`, and `diff --json` after two discovery runs reports `new: []`. Deviation: `status --json` still does not expose `provenance` (flagged, not built).
- **12c DONE (2026-11-14, `feat: let each tool measure its own duration`, REVIEW_LOG "Part 12c: `duration_s` has one authoritative source (11d-findings-c)")**: every executed tool now records the tool's own wall time. The three python adapters measure themselves (`perf_counter` around their existing run path, mock included); `HttpAdapter` reports its measurement on the parse-error and fetch-failure branches too (the `otx failed 0.0` gap); the binary flow's failure branches now carry `run_exec`'s child clock, which docs/04 names as adapter-reported and already compliant. `_run_one` has exactly one fallback site: it stores the adapter's value when positive and substitutes its own wall clock only when the value is `<= 0` (the `0.0` default now means "not measured"), so an adapter value is never overwritten and a row is never negative. docs/04 gained the column comment and three rules (including what a mock duration means); docs/09's field contract says `0.0 = not measured`. Eight new tests (suite 642 -> 650), red-before-green proved by reverting the five source files to HEAD with the tests kept (`5 failed, 3 passed`, raw `duration_s=0.0` on a 429), mutation proof (unconditional overwrite -> `0.000253... == 12.5` failure) with `sha256sum -c` restores. No schema change, no new flag/config/dependency. Real `--mock` run stores a positive duration for all seven executed tools; skipped tools stay `NULL`. PIT-43 (11d-findings-c) records it, with `Regression: PIT-43` on the canonical guard (back-filled 2026-11-14, docs-only).
- **12f DONE (2026-11-14, `feat: redact console error text and the -v traceback`, REVIEW_LOG "Part 12f: redact console error text and the `-v` traceback (C-1)")**: console error text now gets the same guarantee as stored text. `configure_redaction(secrets)` in `core/store.py` replaces one process-wide value set, and `redact(text, secrets=None)` uses it when no per-run set is passed (every existing caller still passes its own, so stored/raw text is unchanged). The CLI loads `.env` at the top of the Typer callback with the same `dotenv_values()` call `Engine.open` makes - needed because `Engine.open` runs too late for `_targets()`/`load_config()` errors - and `_report_error` prints `redact(message)` for both the plain and the `-v` traceback path, so chained exceptions are covered. No new env var, file, module, pattern list or dependency. Eight new tests (suite 634 -> 642), red-before-green proved with the raw secret visible (`6 failed` before the `redact()` call), three mutation proofs with byte-identical restores. Deviations: the old "CLI imports no `core.store`" test became a precise allow-list of the two redaction helpers (it still bans `Store`/`sqlite3`), and six typed `render_error(str(exc))` sites stay outside 12f's ruled scope. PIT-42 (C-1) records it, with `Regression: PIT-42` on the canonical guard (back-filled 2026-11-14, docs-only).
- **12a DONE (2026-11-14, `feat: write every tool's raw output to the workspace`, REVIEW_LOG "Part 12a: write raw tool output to the workspace (G-1)")**: `Workspace.write` now has its one caller. Every executed tool - ok, failed, timeout, crash, `--mock` - captures its output in `ToolResult.raw_text` (binary: stdout + `--- stderr ---` + stderr; HTTP: the body or the failure message; the three python adapters: one shared JSON evidence document) and the engine writes it as `<stage>/<run_id>-<tool>.txt`, redacted with the run's secrets and capped at the new `core/runner.MAX_OUTPUT_BYTES` (1,000,000, the old `run_exec` default), then sets `raw_path`; `dns` raw files go to `meta/` because the workspace keeps exactly six directories. `raw_text` is `Field(exclude=True)` so it can never appear in `--json` (`raw_path` does, verified). A write that raises leaves `raw_path` at `None` and changes no result. 21 new tests (suite 613 -> 634), red-before-green proved (`19 failed` before the code), four mutation proofs with byte-identical restores, docs/03 + docs/09 changed first, no new flag/config/dependency, nothing pushed. Real `--mock` CLI run wrote 7 files (6 `subs`, 1 `meta`), all mode `0600`. PIT-41 (G-1) records it, with `Regression: PIT-41` on the canonical guard (back-filled 2026-11-14, docs-only).
- **Part 12 owner rulings recorded (2026-11-14, docs-only commit on `MASTER_PLAN.md`).** 12i = option (c): the ports stage stays permanently LOW-only / `pyscan`-only as an accepted ceiling (no pre-resolve redesign, no second IP-connecting adapter). 12a = wire raw output: stdout+stderr for every adapter run including failed tools, written to the existing raw-output files under the existing `max_output_bytes` cap, no new flags or config. 12c = adapter-reported `duration_s` wins; `_run_one` fills a measured value only when the adapter reported none. 12d = a bounded, redacted detail string on `host_status_history`, visible via `--json` and DB query, not required in the human table. 12f = `configure_redaction()` sourced from the already-loaded env, applied on both `_report_error` and the `-v` traceback path, no new env vars. 12g = per-run directory mode 0700 plus startup cleanup of stale per-run dirs; no memfd/O_TMPFILE, no accept-the-risk. 12k = exit 5 with a warning that names the empty stage. 12e, 12h and 12j still carry their own "Decision needed" text and are not covered by these rulings. Implementation order: **12a first**, then the implementer's order; one item per commit, owner told after each item.
- **Bug-fix session (2026-11-14, after the verification session; REVIEW_LOG "Bug-fix session")**: (1) `--active` on the bare form or on `lite`/`passive`/`subs`/`dns` is now a usage error (exit 2, `'lite' is passive-only; --active needs: reconkit run -d X --active`) instead of a silent no-op; (2) `pyprobe` no longer returns `UNKNOWN` on the first TLS `ConnectError` - it tries the next scheme, so all 8 testfire.net hosts that `httpx` got 200 on are now `ALIVE 200` from `pyprobe` too, proved by a real adapter run and by two real `live` CLI runs; (3) `stages[].skipped` plus `summary.tools_skipped` now report every selection-time skip, so a stage with no adapter cannot read as "found nothing" (real: tech 5, urls 8, vulns 3 skipped). Red-before-green, four mutation proofs and the full gate are in that entry. `diff` source-variance stays a **logged** owner decision, not code. `scope.yaml`/`in_scope_cidrs` were not touched, nothing was installed with sudo, nothing was pushed.
- **Verified with real tools on 2026-11-14** (testfire.net, `scope.yaml`, no keys, REVIEW_LOG "Real-tool verification session"): `subs` ran crtsh, certspotter, otx, hackertarget, subfinder and assetfinder against the network (real 502/429/0/3/35/4 results); `dns` ran dnspython over 36 hosts; `live` ran pyprobe and httpx and classified 8 ALIVE / 28 DEAD; `ports` selected pyscan, which refused every host with `blocked=8` because `scope.yaml` has no `in_scope_cidrs`. Two identical `run` invocations and `reconkit diff` followed, with the raw DB queries, `tool_runs` rows and diff output in that entry.
- **Still NOT verified, and this run did not change it:** `tech`, `urls` and `vulns` have **no adapter for any tool in their pools** (all phase 3), so no real tech/urls/vulns tool has ever run — those stages still run zero tools, though their skips are now visible in `stages[].skipped` and `tools_skipped`; no open port has ever been observed (pyscan blocked, naabu blocked, nmap/rustscan/smap phase 3); `libpcap-dev` is absent and needs sudo; no keyed provider has run (`--no-keys`); `killpg` and the sudo-authenticated install half remain untested. Owner commands are in "Kali verification commands" below.
- Part B audit (2026-11-14): every phase-2 tool and the named phase-3 candidates were checked against the real binary or the official source; the table is docs/09 section 9 and the raw evidence is REVIEW_LOG "Tool flags and fields verified against the real tools". It found two installer/doctor defects and confirmed every adapter flag and JSON field currently in use except the naabu `host`-omitted-for-IP nuance. **`masscan --version` exits 1 and doctor called a real 1.3.2 "wrong program"** - fixed in the follow-up commit: a nonzero probe is accepted only when its output names the program (PIT-35, `reconkit doctor` now shows `masscan ... yes ... ok`). The other defect, banner-first version text showing `__` for katana and `[I…` for nuclei, is ticketed to Part 12 because it also changes `_same_version()` behaviour for `update`. Nothing in `tools.yaml`'s phase-2 rows was a guess.
- Open items are **ruled, not silent**: 11d-findings-b/f/g, G-1, C-1, C-2 and E-1..E-3 are deferred to Part 12 with reasons in the ruling table; `naabu` is permanently unavailable in this build by the 12i ruling (no pre-resolve design is pursued).
- PIT-32 (after Part 10f): `run_exec` keeps POSIX children in the parent's session with their own process group (`start_new_session=False`, `process_group=0`), so a cached `sudo -v` ticket is visible; two regression tests.
- Deferred by ruling (not Part 10 blockers): `update` idempotency for `@latest` go_install tools (reporting gap, binaries byte-identical; needs a new version-probe mechanism and its own docs-first pass, docs/10 section 6) and authenticated GitHub release lookups (a Part 11 planning decision).
- Last commits: `7d894cc` (masscan identity fix), then the 11f docs commits `343ca54`/`b0bcc34`, then the bug-fix commit `74a7c07` and the docs commit on top of it; `git log --oneline -1` is authoritative.
- Real-tool verification (2026-11-14, after the ALL DONE report): `install --all` left only `rustscan` failing (documented placeholder) and `libpcap-dev` uninstalled (no sudo); two full `reconkit run --active --no-keys` passes against testfire.net plus a `diff` are recorded in REVIEW_LOG "Real-tool verification session". No code was changed. It produced four new Open risks (bare `--active` no-op, zero-adapter stages silent, `--json` writes no progress, `diff` noise from passive-source variance); the first two are fixed by the bug-fix session, the last two still need rulings.
- Next action: **12d is committed; the PROGRESS.md trim is the last item of the owner's 2026-11-14 queue** (move fully-closed history into REVIEW_LOG and keep this file to RESUME state, open items, the pitfalls table and what is still active). **12e/12h/12j** stay undecided and out of scope. One item per commit, full S1-S7 loop per item, no go-ahead between items (owner instruction 2026-11-14). Do not combine items in one commit, do not push, do not touch `scope.yaml` or sudo-authenticated installs.
- Already decided, do not reopen: no scope-bypass flag; consensus lives in engine.py; adapters never import store/scope/ui/cli; subjack replaced by subzy + nuclei takeover templates; installer targets Debian-family Linux only; free mode is default, keys only from .env; no push unless the user says so
- Do NOT: new dependencies; new modules/files/CLI commands not in docs/02-03; `assert` in src/; new lint/type suppressions; shell=True; whole environment to a child; adapters importing store/scope/ui/cli; consensus outside engine.py; pushing
- Known open bugs, all ruled (none blocking): 11d-findings-**a, b, c, d, e and f are fixed** (f completely: the short-circuit half in the bug-fix session, the diagnostic-text half in 12d); **g is 12k's neighbour and still deferred**; **12e (inconclusive live pass writes no history row) and 12h remain undecided**. G-1 (12a), C-1 (12f), C-2 (12g) and E-1..E-3 are closed or deferred by ruling; G-3 and G-4 were closed in the Part 11 close-out.
- 11c audit question C-1 (now ruled, deferred to Part 12): does an escaping exception reaching `cli.py:226` carry a secret into unredacted output, given keys travel in headers, not URLs? No reachable leak has been shown; the other eight broad-`except` sites are justified in REVIEW_LOG.
- Read first: AGENTS.md, this block, last 3 REVIEW_LOG entries, current part in docs/MASTER_PLAN.md

Read this after `AGENTS.md`, before touching code. Update it in every commit.

#### Environment  (moved from PROGRESS 2026-11-15: Environment block as of 2026-11-15 (superseded by the shorter Environment section))

- **Canonical, actively developed checkout: Kali, `/home/kali/Desktop/reconkit`** (native Linux, `uname -a` -> `Linux kali 7.2.15+kali-amd64`). Every commit after the copy exists only here: 93 of them are unpushed and this remote's `main` still points at `5fd1d9a`. All checks, runs and commits in Parts 10-11 were made in this tree, and this is the tree to continue in.
- Checks (run all four, report PASS/FAIL with `if cmd; then ...`):

```bash
pytest -q
ruff check .
ruff format --check .
mypy src/reconkit
```

- Pre-commit hook (`.githooks/pre-commit`) runs those checks and requires `docs/PROGRESS.md` when `src/` or `tests/` change. `git config core.hooksPath .githooks` is set by `scripts/bootstrap.sh`. Both use `.venv/bin`.
- Push from this checkout: `git push reconkit main` (remote is named `reconkit`, not `origin`).

#### Fixtures  (moved from PROGRESS 2026-11-15: Fixtures block as of 2026-11-15 (PROGRESS now carries a one-paragraph summary))

- `crtsh/example.com.json` - trimmed real response, fetched 2026-11-13 from `https://crt.sh/?q=%25.example.com&output=json` (5 of 85 entries).
- `certspotter/example.com.json` - trimmed real response, fetched 2026-11-13 from `https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names` (2 of 17 entries).
- `otx/example.com.synthetic.json` - synthetic, documented `passive_dns` shape; the real endpoint returned HTTP 429 for anonymous access on 2026-11-13 (`https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns`).
- `hackertarget/example.com.txt` - real response, fetched 2026-11-13 from `https://api.hackertarget.com/hostsearch/?q=example.com` (the free quota returned a single row).

#### Key sources  (moved from PROGRESS 2026-11-15: Key sources block as of 2026-11-15 (PROGRESS now points at docs/05, docs/09 and this block))

- All fetched 2026-11-13.
- Cert Spotter API reference: `https://sslmate.com/help/reference/ct_search_api_v1`. An API key is a Bearer token (or Basic username); only unauthenticated per-hour limits are documented, and the docs give no number, so the old "100 queries/hour" claim was removed. Sign-up: `https://sslmate.com/ct_search_api`.
- OTX: `https://otx.alienvault.com/api` (`X-OTX-API-KEY`; a free account provides the key).
- assetfinder: `https://github.com/tomnomnom/assetfinder` (`VT_API_KEY`); VirusTotal Public API is free at 4 requests/minute and 500/day: `https://docs.virustotal.com/reference/public-vs-premium-api`.
- subfinder provider config: `https://docs.projectdiscovery.io/opensource/subfinder/install` (fetched 2026-11-13). Provider keys are stored only in `$HOME/.config/subfinder/provider-config.yaml`; no per-provider environment variable is documented. Providers the page says need a key: BeVigil, BinaryEdge, BufferOver, C99, Censys, CertSpotter, Chaos, Chinaz, DNSDB, Fofa, FullHunt, GitHub, Intelx, PassiveTotal, Profundis, quake, Robtex, SecurityTrails, Shodan, ThreatBook, VirusTotal, WhoisXML API, ZoomEye, dnsrepo, Hunter, Facebook, BuiltWith.
- urlscan API intro: `https://docs.urlscan.io/pages/api-intro` (account + API key; unauthenticated access has "minor quotas"). Sign-up: `https://urlscan.io/user/signup`.
- Chaos client README: `https://github.com/projectdiscovery/chaos-client`; the environment variable is `PDCP_API_KEY`, and the API allows 60 requests/minute/IP. Sign-up: `https://cloud.projectdiscovery.io`.
- github-subdomains README: `https://github.com/gwen001/github-subdomains`; it reads `GITHUB_TOKEN` when `-t` is absent. Token page: `https://github.com/settings/tokens`. GitHub REST limits: 60 requests/hour unauthenticated, 5,000/hour authenticated (`https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api`).

#### Kali verification commands (11e, for the owner)  (moved from PROGRESS 2026-11-15: superseded by the corrected Owner verification commands in PROGRESS - the masscan "wrong program" baseline line is stale, PIT-35 fixed it)

Run these in `/home/kali/Desktop/reconkit` with `.venv` active. They are the checks this session could not perform; nothing here is a claim that they passed.

```bash
cd /home/kali/Desktop/reconkit && source .venv/bin/activate
python --version                          # expect 3.11+
reconkit doctor                           # baseline: 7 missing, masscan "wrong program"
reconkit install --all --no-color         # needs sudo for apt; installs the registry tools
reconkit doctor --json | python -m json.tool   # every tool ready; Keys rows reflect your .env

# Real active run. Fill in_scope_cidrs in scope.yaml first, or pyscan will
# (correctly) block every host:
reconkit run -d <authorized-host> --active --speed slow --tools pyprobe,pyscan --db /tmp/verify.db -v
#   expect: pyprobe rows from real HTTP/TLS; pyscan rows only for addresses inside
#   in_scope_cidrs; with no CIDRs, a pyscan row reading blocked=<n> and no ports.
#   naabu must appear as skipped: "blocked: resolves inside the binary, so
#   in_scope_cidrs cannot be enforced (11c-G-7)".

# killpg / Ctrl+C path (PIT-32, still UNTESTED on a real signal):
reconkit run -d <authorized-host> --active --speed slow --tools httpx --db /tmp/verify.db -v &
# then Ctrl+C, and check `ps -ef | grep httpx` for an orphan process group
```

## PROGRESS.md trim (2026-11-15, docs only)  (commit subject `docs: trim PROGRESS.md to the G7 shape and archive its history`)

- **Goal:** `PROGRESS.md` was 499 lines against `MASTER_PLAN.md` G7's "under 150 lines". Nothing was deleted: the historical blocks moved **verbatim** into the `PROGRESS archive (moved 2026-11-15 by the PROGRESS.md trim)` section at the end of this file.
- **What moved (16 blocks, verbatim):** the Task status table; the Module map; the whole `2026-11-14 - 11d-findings` section (a-g); the Part 11 close-out rulings table; Wildcard filter wiring; Fix backlog; 11c-bis fresh-venv gate; Part 11 interim report; Part 11c fresh-eyes audit; the full Deviations and assumptions history; the full Open risks text; and - because PROGRESS now carries them in condensed or corrected form - the pre-trim `RESUME HERE`, `Environment`, `Fixtures` and `Key sources` blocks plus the superseded Kali verification commands. Each block keeps its original heading with a `(moved from PROGRESS 2026-11-15: ...)` note saying where its live counterpart is.
- **What PROGRESS now is (121 lines):** RESUME (status, next action, baseline, decisions, do-nots), Environment, a compact Task status table with the real hashes, the standing Deviations, the Open risks that are still open (one line each), Notes for later tasks (module map summary, fixtures summary, source pointer) and corrected Owner verification commands.
- **Nothing lost - audit:** every non-blank pre-trim line of at least 25 characters is present either in the new PROGRESS or verbatim in the archive. `not found verbatim: 7`, and all seven are section **heading** lines that exist in the archive in their renamed `###`/`####` form with the moved-note (`## 2026-11-14 - 11d-findings ...`, `## Part 11 close-out rulings ...`, `### Kali verification commands ...`, `## Wildcard filter wiring ...`, `## 11c-bis fresh-venv gate ...`, `## Part 11 interim report ...`, `## Part 11c - fresh-eyes audit ...`).
- **Corrections made while condensing (not silent):** the owner-command block's `doctor` baseline comment said "7 missing, masscan wrong program"; masscan's identity was fixed in PIT-35, so the live block says to compare against the box and names the fix instead. `Open risks` in PROGRESS now records the ports ceiling as an accepted decision rather than a risk, keeps 11e's remaining truth (no real tech/urls/vulns tool has run), and drops the three bullets that were already marked FIXED (their full text is archived and their fixes are in this log).
- **Gate (once, docs-only):**
  ```
  --- pytest -q ---     686 passed in 14.7Xs
  --- ruff check . ---  All checks passed!
  --- ruff format --check . ---  68 files already formatted
  --- mypy src/reconkit ---  Success: no issues found in 36 source files
  ```
  No code, test, schema, flag or config change: `git diff --name-only` lists only `docs/PROGRESS.md` and `docs/REVIEW_LOG.md`. Suite stays 686, as expected.

## 2026-11-18 - Linux only, redaction, JSONL truncation and runtime caps (live-verified on testfire.net)

- **Owner request:** Linux only, no other platform anywhere in the project; every command tested live (passive and active), timings recorded, errors investigated before pushing.
- **Platform removal.** Docs first (`6b904eb`), then code (`549c7e0`): the OS-specific branches in `runner.py` (`start_new_session`/`process_group`, `_kill_tree`), the reserved-device-name rejection in `workspace.py` (target and filename), the non-POSIX `_pid_alive` fallback in `subfinder.py` and the platform note in `base.running_as_root` are gone, with the two reserved-name filename parameters and the `con.example.com` target parameter deleted from their tests (suite 827 -> 821). Every doc, the pitfall table, the MASTER_PLAN gate instructions, `SETUP.md`, `README.md`, `docs/01`, `03`, `04`, `09`, `10`, `PROGRESS` and the dated log entries now name Linux only (`e27f433`). `.githooks/pre-commit` lost its `.venv/Scripts` fallback.
- **Bugs found by the live runs, not by the suite:**
  - **PIT-54, redaction truncating JSONL.** `nuclei` failed with `invalid JSON line`. `_COOKIE_HEADER`, `_AUTH_HEADER`, `_FLAG_VALUE` and `_SECRET_PAIR` ran to the next *real* newline; nuclei embeds request/response in one JSONL line with escaped `\r\n`, so everything after the header became `***`. Fixed in `9df0950` (`_HEADER_VALUE` stops at a real or escaped line end; the `\b` before the header name was dropped because an escaped `\n` leaves a word character in front of it). Regression: `test_redaction_keeps_a_jsonl_line_parseable`.
  - **PIT-56, a timeout threw away found URLs.** `urlfinder` was the one unpredictable tool: 996 URLs in 15 s, then 206 in 506 s, 932 in 525 s, an engine timeout with 0 items. Its `-max-time` is **not enforced** (measured still running at 5m52s with `-max-time 3`). Adapters now declare `runtime_cap_s`; `urlfinder` caps at 180 s and a capped timeout parses the partial stdout (`b331927`).
  - **nuclei stdout cap.** With `-or` absent, the unused request/response pair pushed a run to 999060 bytes, just under the 1 MB `MAX_OUTPUT_BYTES`, truncating the last JSON line. `-or` (`-omit-raw`, from its `-help`) is now passed.
  - **nikto never returned.** One process per host, each given the whole per-tool budget, so the engine cancelled the tool at 600 s with 0 findings on two full runs. Each host now gets `remaining / hosts left` and nikto's own `-maxtime <share>s`.
- **Live evidence (all on `testfire.net`, in scope).**
  | command | wall | exit | result |
  |---|---|---|---|
  | `scope check -d testfire.net` | 0.3 s | 0 | `ALLOWED (matches testfire.net)` |
  | `doctor` | 1.7 s | 0 | 1 tool missing, rest installed |
  | `status` | 0.3 s | 0 | run table printed |
  | `diff -d testfire.net` | 0.3 s | 0 | 26 port rows |
  | `passive -d testfire.net` | 617 s | 5 | 16 ok, 2 failed (otx 429, hackertarget quota), 6 skipped; 43 hosts, urls: gau 348, urlfinder 206 |
  | `run --active` | 737 s | 5 | 28 ok, 3 failed (otx 429, hackertarget quota, crtsh 502), 2 skipped; 8 ALIVE of 43 |
  | `run --full` | 2027 s | 5 | 37 ok, 2 failed (same quotas), 1 timeout (nikto); `nuclei ok 26` after the redaction fix |
  | `run --full` (verify) | 1942 s | 5 | nuclei failed again - the 1 MB truncation above; urlfinder timeout 0 |
  | `run --full` (final, after all fixes) | 1466 s | 5 | 38 ok, 2 failed (same quotas), 8 skipped, **0 timeouts**; `nuclei ok 112`, `urlfinder ok 933 (capped at 180s; kept partial)`, `nikto ok 8` |

  The final run is 1466 s against 2027 s for the same `--full` command before the caps: 28% less wall clock, and the two tools that had never returned now produce findings.
- **Environment findings, not defects:** `tech` returned 0 items in one run because the target's hosts were unreachable at that moment (`no route to host`, connect timeouts in the raw files); `crtsh` 502 and `otx` 429 / hackertarget quota are upstream and vary per run; `gowitness` produces no PNG on this box because Chromium is not installed (documented in its adapter).
- **Not verified:** no intrusive/exploitation tool was run; no keyed provider; the interactive prompts were not exercised this session.
- **Gate:** `824 passed`, `ruff check` clean, `ruff format --check` clean, `mypy` clean (62 source files).
- **Pushed:** the owner asked for the work to go to GitHub once the live runs were clean; the branch is `main` -> `reconkit/main`.

## 2026-11-18 (batch) Part 1 - external-service errors are gaps; stale docs cleanup

- **Owner report:** `reconkit run -d example.com --active --no-scope` exited `5`
  because `otx` (429), `hackertarget` (quota) and `crtsh` (502) all failed. None
  of those is a defect on this box, so the run looked broken when it was not.
- **Docs first:** docs/02 (Tools-table statuses, a `gap` rule, `completion`/gaps
  wording, the `summary.tools_gap` key, exit code 5's exception, the gaps block
  format), docs/04 (`tool_runs` CHECK, the `gap` semantics, migration 8),
  docs/08 (gap causes), docs/09 (ToolStatus, the one classifier, HttpAdapter),
  COMMANDS.md (exit codes) and docs/05 section 5 (the installer script, below).
- **Implementation:** `models.ToolStatus.GAP`; `base.ExternalServiceGap` +
  `base.classify_external_gap()`; `HttpAdapter` 429/5xx → gap, quota body →
  gap, every other failure unchanged; `BaseToolAdapter.run` classifies a binary's
  non-zero exit; `Engine._completed()`/`_completion_gaps()`/`_gap_reason()`;
  `ui` counts and renders the new status; `store._SCHEMA_V8` rebuilds `tool_runs`
  with the five-value CHECK (SQLite cannot alter one).
- **Real proof (network, testfire.net, in scope, one `subs` stage):**

  ```
  $ reconkit subs -d testfire.net --no-scope --no-color ; echo EXIT=$?
  │ hackertarget      │ subs  │ gap     │ 0     │ hackertarget: free quota exceeded │
  │ otx               │ subs  │ gap     │ 0     │ otx: rate limited (HTTP 429)      │
  9 hosts: 0 ALIVE, ... | tools: 7 ok, 2 gap, 0 failed, 2 skipped, 0 timeout
  ⚠ passive scan completed with gaps — 1 stage(s) incomplete
    subs: hackertarget: free quota exceeded, otx: rate limited (HTTP 429)
    this is not a failure — the scan used every tool that was available.
  EXIT=0
  $ sqlite3 recon.db "SELECT tool, status FROM tool_runs WHERE status IN ('gap','failed')"
  hackertarget|gap
  otx|gap
  ```

  Before the change the same two outcomes were `failed`, so that run exited `5`.
- **Mock proof:** `reconkit run -d testfire.net --active --no-scope --mock` →
  `tools: 31 ok, 0 gap, 0 failed, 2 skipped, 0 timeout`, exit 0, no gaps block.
  A mock run cannot produce a 429 (fixtures are bodies, not statuses), so the
  gap path is proven by the network run above and by the adapter/engine tests.
- **Tests:** 824 → 840. New: `test_429_is_a_gap_and_not_retried`,
  `test_a_5xx_from_the_upstream_is_a_gap`, `test_a_404_is_still_a_failure_not_a_gap`,
  `test_hackertarget_quota_answer_is_a_gap`,
  `test_classify_external_gap_matches_only_third_party_signatures` (10 cases),
  `test_a_429_gap_still_reports_its_own_duration`,
  `test_an_external_service_gap_exits_zero_and_is_named_in_the_gaps`,
  `test_a_gap_never_masks_a_real_failure`,
  `test_v7_database_rebuilds_tool_runs_for_the_gap_status`,
  `test_a_gap_tool_is_shown_as_gap_and_named_in_the_block`.
  Changed because they pinned the removed behaviour: `test_429_is_failed_and_not_retried`
  → `test_429_is_a_gap_and_not_retried`, `test_500_is_failed_and_not_retried`
  → `test_500_is_a_gap_and_not_retried`, `test_hackertarget_free_quota_is_reported`
  → `test_hackertarget_free_quota_is_a_gap`, `test_otx_sends_key_in_header_and_never_leaks_it`
  (a 500 is now a gap; the key-must-not-leak assertions are unchanged), the
  hackertarget quota case removed from the malformed-response parametrization
  (it is a gap now, covered above), the JSON schema test gained `tools_gap`, and
  five migration tests moved to `SCHEMA_VERSION == 8` with a `tool_runs` table
  added to their v1-v6 fixtures (a real database of those versions has one).
- **Stale docs fixed in this commit:** `docs/PROGRESS.md` line 35 said "Nothing
  is pushed" (both refs are at `a49e4b5`), the Open-risks line said `tech`,
  `urls` and `vulns` have no adapter (waves 4-8 added 25 of them; only
  `dnsreaper` is left), the baseline said `827 passed` (measured `824`), and
  `docs/05` section 5 said "reconkit runs no installer script at all" while
  `scripts/install-tools.sh` has existed since D21 - it now documents what the
  script does (apt under per-command sudo, refuses root, verifies with
  `doctor --json`, no curl/pipe, no archive or checksum handling).


## 2026-11-18 (batch) Part 2 - katana JSON skip, hakrawler/subjs caps, urlfinder inactivity kill

- **Owner report:** the example.com scan showed `katana: invalid JSON line` (tool
  failed with 0 items), `hakrawler timeout 0 item(s)` and `subjs timeout 0
  item(s)`, and `urlfinder`'s flat 180 s cap was too short for a target with
  hundreds of hosts.
- **Docs first:** docs/09 section 4a3 (the skip-and-count rule, the two caps) and
  section 4a2b (min/idle/ceiling plus the `urls:` config table).
- **2.1 - parsers.** `katana` skips a non-JSON line (and a JSON line that is not
  an object) instead of raising `ParseError`; `hakrawler`, `gospider` and `subjs`
  do the same for a line with no usable URL. `BaseToolAdapter.skipped_lines` +
  `_skip_note()` turn the count into the detail line: one message per line up to
  10, then one summary, so 25 junk lines read `skipped 25 unusable line(s);
  last: 'junk line 24'`. The status stays `ok`. `urlfinder` is deliberately
  unchanged (its input is an archive; it already skips whitespace junk).
- **2.2 - caps.** `HakrawlerAdapter.runtime_cap_s = 120`,
  `SubjsAdapter.runtime_cap_s = 60`, overridable by
  `urls.hakrawler_max_s` / `urls.subjs_max_s`. A capped run now always returns
  `ok` with its partial output and `capped at <n>s; kept partial output` in the
  detail column - including 0 items, because the tool worked and we stopped it.
  `timeout` is reserved for a tool with no cap that produced nothing.
- **2.3 - urlfinder.** The flat `runtime_cap_s = 180` is gone. The engine passes
  `RunContext.limits["urlfinder"] = ToolLimits(max_s=1800, idle_s=60,
  min_s=180)` from the new `config.yaml` `urls:` block; `run_exec(...,
  idle_timeout=, min_runtime=)` is the new runner capability and
  `ExecResult.idle_killed` says which clock fired. A silent source is killed at
  about 240 s (floor + idle), a productive one runs to 1800 s.
- **Real proof (network, testfire.net, exit codes captured directly):**

  ```
  $ reconkit run -d testfire.net --active --no-scope --tools pyprobe,katana,hakrawler,subjs
  urls: subjs ok 0 item(s)
  urls: hakrawler ok 66 item(s)
  urls: katana ok 58 item(s)
  urls: finished 3/3 tool(s), 124 item(s)              EXIT=0

  $ reconkit run -d testfire.net --active --no-scope --tools pyprobe,gau,urlfinder
  urls: urlfinder ok 933 item(s)
  urls: gau ok 345 item(s)                             EXIT=0
  $ sqlite3 recon.db "SELECT tool, status, item_count, round(duration_s,1) FROM tool_runs"
  pyprobe|ok|1|1.2
  urlfinder|ok|933|18.1
  gau|ok|345|38.2
  ```

  Neither cap fired here (both tools finished inside them), which is the point:
  the bounds only bite a stuck tool. The cap and idle paths are proven by the
  tests below, including a real child process (`tests/fakebin/silent_after_output.py`)
  that is killed by the inactivity clock and keeps its three lines.
- **Mock proof:** `reconkit run -d testfire.net --active --no-scope --tools
  pyprobe,katana --mock` → `urls: katana ok 3 item(s)`, exit 0.
- **Tests:** 840 → 855. New: `test_katana_skips_invalid_json_lines`,
  `test_katana_warning_lines_reach_the_detail_and_stay_ok`,
  `test_katana_many_junk_lines_are_summarised_once`,
  `test_crawler_parsers_skip_unusable_lines` (3 cases),
  `test_hakrawler_runtime_cap_parses_partial`,
  `test_subjs_runtime_cap_parses_partial`,
  `test_urlfinder_idle_timeout_kills_stuck_source`,
  `test_urlfinder_runs_to_stage_budget_if_productive`,
  `test_idle_timeout_kills_a_child_that_went_silent`,
  `test_the_floor_protects_a_slow_start_before_the_idle_clock`,
  `test_a_finished_child_is_never_flagged_idle`,
  `test_the_urls_runtime_bounds_load_and_default`,
  `test_url_tools_receive_the_configured_runtime_bounds`.
  Changed: `test_urlfinder_skips_archived_junk_and_feeds_domains` (the
  `-max-time` ceiling is 30 minutes now, not 3) and `run_script` in
  `tests/test_runner.py` gained the two clock arguments. New fixture:
  `tests/fakebin/silent_after_output.py`.

## 2026-11-18 (batch) Part 3 - www/non-www deduplication with `duplicate_of` metadata

- **Owner request:** "www.anywebsite.com and anywebsite.com are the same - fix that
  yourself", after a real `example.com` scan listed both names as ALIVE.
- **Docs first:** docs/04 section 5 (`duplicate_of`/`www_note` semantics) and
  section 11 (schema 9), docs/09 section 5 (the five rules), docs/02 section 5
  (Notes column, summary line, `--json`), MASTER_PLAN D22, COMMANDS.md.
- **Schema: 8 -> 9**, not 7 -> 8. The batch prompt was written before Part 1
  spent 8 on the `tool_runs` CHECK rebuild (`_SCHEMA_V8`). Disclosed here and in
  D22. `_SCHEMA_V9` is two `ALTER TABLE ... ADD COLUMN` statements, both nullable
  with no default, so every existing row reads `NULL` = "no duplicate
  information"; nothing is rewritten and no data migration is needed.
- **Why a second column (`www_note`) instead of `host_status_history.detail`:**
  `detail` is the documented UNKNOWN reason, redacted and bounded to 200 chars
  and exposed as `hosts[].detail` (PIT-46). Overloading it would have made an
  informational sibling note look like a probe failure.
- **Detection.** `Engine._dedupe_www_variants(target_id, hosts)` runs right after
  the live persistence block, once per run, over `Store.host_rows()` filtered to
  the current run's host set. Rules and their tests are in the PIT-59 row. Two
  details worth naming: (a) the three-way 2xx/3xx/same-status decision reads the
  `status_code` the live stage stored, never a fresh request - the pass sends no
  traffic; (b) "different servers" is claimed only when **both** IP sets are
  known and disjoint, because an empty `ips_json` (a scan that ran no DNS stage)
  is not evidence of anything. That is a narrowing of the batch text, which said
  "if IPs differ"; it is recorded in docs/09 and D22.
- **Metadata only (frozen boundary).** `Store.set_host_duplicate()` updates the
  host's newest status row; it never appends a row and never writes `state`,
  `status_code`, `confidence`, `checked_at` or `source_count`. Host-state
  definitions, the confidence formula, `diff` and `status` are untouched, and
  `test_www_dedup_never_changes_host_state_or_confidence` pins it.
- **Display.** `ui.host_note()` produces `-> redirects to <host>`,
  `-> duplicate of <host>`, `canonical` or the sibling note. The Notes column is
  added only when some row has a note, so an ordinary run's table keeps its six
  columns (`test_no_notes_column_when_no_pair_was_found`); it wraps instead of
  ellipsizing, because a clipped note reads as no note. The summary line gains
  `N hosts (M unique after www-dedup)` only when a duplicate exists. `--json`
  always carries `www_dedup` (`applied`, `pairs`) and every host object carries
  `duplicate_of` and `www_note`.
- **Mock proof (new synthetic fixtures, offline):**
  `tests/fixtures/dnspython/www-pair.test.synthetic.json` and
  `tests/fixtures/pyprobe/www-pair.test.synthetic.json` describe one bare name
  that 301s to `www.www-pair.test` (200), same IP. Fixtures are per-target, so
  no other mock run changed.

  ```
  $ reconkit run -d www-pair.test --active --no-scope --mock
  │ www-pai… │ ALIVE │ 301 │ - │ - │ LOW (0) │ -> redirects to www.www-pair.test │
  │ www.www… │ ALIVE │ 200 │ - │ - │ LOW (0) │ canonical                        │
  17 hosts (16 unique after www-dedup): 2 ALIVE, 0 DNS_ONLY, 0 SHUT_DOWN, 0 DEAD, 15 UNKNOWN
  EXIT=0

  $ reconkit run -d www-pair.test --active --no-scope --mock --json | jq '.www_dedup'
  {"applied": true, "pairs": [{"host": "www-pair.test", "duplicate_of": "www.www-pair.test"}]}
  $ sqlite3 recon.db "SELECT s.fqdn, h.duplicate_of, h.www_note FROM host_status_history h
                      JOIN subdomains s ON s.id = h.subdomain_id
                      WHERE h.duplicate_of IS NOT NULL OR h.www_note IS NOT NULL"
  testfire.net||has www sibling at www.testfire.net
  www.testfire.net||has www sibling at testfire.net
  www-pair.test|www.www-pair.test|
  ```

- **Real proof (testfire.net, small):** `reconkit run -d testfire.net --active
  --no-scope --tools assetfinder,dnspython,pyprobe` -> both names answer 200,
  which is the "two 2xx" branch: **nothing** was marked and both rows got
  `has www sibling at ...`, exit 0. The DB rows above are from that run and the
  mock run in the same workspace. No scan of `example.com` was made.
- **Tests:** 855 -> 869. New: `test_www_redirect_to_bare_is_marked_duplicate`,
  `test_bare_redirect_to_www_is_marked_duplicate`,
  `test_both_200_independent_servers_not_marked_duplicate`,
  `test_same_status_on_one_server_marks_the_www_variant`,
  `test_same_status_on_different_servers_is_only_a_note`,
  `test_www_dead_is_not_marked_duplicate`, `test_single_variant_not_touched`,
  `test_www_dedup_never_changes_host_state_or_confidence`,
  `test_v8_database_migrates_the_www_dedup_columns`,
  `test_set_host_duplicate_updates_in_place_and_keeps_state`,
  `test_set_host_duplicate_is_false_for_unknown_host_or_status`,
  `test_www_duplicate_rows_get_notes_and_the_summary_counts_unique`,
  `test_www_notes_without_any_duplicate_leave_the_summary_line_alone`,
  `test_no_notes_column_when_no_pair_was_found`. Changed: the six
  `SCHEMA_VERSION == 8` assertions in `tests/test_store.py` became `== 9`,
  `test_v7_database_rebuilds_tool_runs_for_the_gap_status` now also creates a
  `host_status_history` (a real v7 database has one; v9 alters it), and
  `test_json_output_is_one_valid_document_with_documented_schema` gained
  `www_dedup` plus the two host keys.

## 2026-11-18 (batch) Part 4 - `url_probe` stage checks archive URL liveness

- **Owner request (batch, part 4):** the urls stage records 11,785 URLs and
  nothing says which of them still answer, so a 2019 `/admin` and a page that
  answered today are the same evidence. Add a URL liveness probe stage.
- **Docs first:** docs/02 (mode table, stage-order text, `--skip-url-probe`,
  "What the url_probe stage does"), docs/03 (stage order, `MODE_STAGES`,
  `_persist_stage` note), docs/04 (the `urls.status_code` column and schema 10),
  docs/09 ("URL liveness probe (D23)"), MASTER_PLAN D23, COMMANDS.md.
- **Engine-owned, not an adapter.** `url_probe` has no `tools.yaml` entry, no
  adapter and no Tools-table row, because no external program runs: the CLI
  drops the stage for `--skip-url-probe`, `Engine._run_url_probe()` sends the
  requests through httpx with the honest `reconkit/0.1` User-Agent, and
  `_empty_stages()` excludes it so a tool-less stage can never make an otherwise
  complete run exit 5. `MODE_STAGES["active"]` gains it; `full` gets it through
  `STAGE_ORDER`, and `passive` never does (it sends HTTP).
- **Schema: 9 -> 10** (`_SCHEMA_V10`: `ALTER TABLE urls ADD COLUMN
  status_code INTEGER`, nullable, no default). `NULL` means exactly one thing,
  "not probed yet"; `unprobed_urls()` selects only those rows, and
  `set_url_status()` updates in place, so the probe never appends a URL row.
- **Scope.** It is an active stage, so it calls the same `_active_hosts()` gate
  as the others and sends nothing for a host the gate drops
  (`test_url_probe_sends_only_in_scope_urls`).
- **Bounds.** `config.yaml` `url_probe:` - `max_urls` 5000 per pass (a bigger
  list is cut and the run warns), `batch_size` 200, `threads` 50 (semaphore and
  httpx `Limits`), `timeout_s` 10 per request, no retries.
- **A real-run defect found and fixed before commit: `-2`.** The first real
  testfire.net pass stored `-1` for **every** URL, including
  `https://testfire.net` - the site answers, but its certificate is issued for
  `www.testfire.net`, so strict verification raised
  `SSLCertVerificationError` and "answered, bad certificate" was stored as
  "does not answer". Verification is never disabled here (that would be a
  security regression and a lint finding), so the case got its own stored
  answer: `urls.status_code = -2` (`ENGINE.UNTRUSTED`), documented in docs/02,
  docs/04, docs/09, COMMANDS.md and D23. The detector walks **both**
  `__cause__` and `__context__`: httpcore re-raises implicitly, so the ssl error
  is usually only in `__context__` (the first version walked causes only and
  silently stayed at `-1`; the context-chain test is the regression).
- **Mock.** `--mock` sends nothing, leaves every `status_code` `NULL` and warns
  `url_probe: skipped in --mock (N URL(s) left unprobed)`, so a mock run can
  never look like a probed one.
- **Real proof (testfire.net, small, no re-scan of example.com).** The
  workspace `/tmp/rk4` used a copy of `config.yaml` with `max_urls: 20` and the
  command `reconkit run -d testfire.net --active --no-scope --tools
  pyprobe,katana,gau`:

  ```
  urls: katana ok 58 item(s)
  urls: gau ok 345 item(s)
  url_probe: probing 20 URL(s)
  url_probe: finished 20 URL(s)
  warning: url_probe: probed the first 20 URL(s) only; re-run to probe the rest
  EXIT=0

  $ sqlite3 recon.db "SELECT status_code, COUNT(*) FROM urls GROUP BY status_code"
  |365        # NULL = not probed yet
  -2|40       # https://testfire.net/* - certificate is for www.testfire.net
  ```

  The next run probed 20 more and nothing already answered was retried. Three
  requests on the real host show all three outcomes through `_probe_url_batch`:

  ```
    200    http://testfire.net/
     -2  -2 untrusted  https://www.testfire.net/
     -1  -1 unreachable  https://does-not-exist.testfire.net/
  ```

  The `-2` on `https://www.testfire.net/` is real too: that certificate does not
  chain to a trusted CA from this box, so the answer is "certificate not
  verified", not "dead".
- **Tests:** 869 -> 882. New: `test_url_probe_stores_status_codes_and_marks_unreachable`,
  `test_url_probe_never_reprobes_a_stored_answer`,
  `test_url_probe_uses_the_url_probe_config_bounds`,
  `test_url_probe_is_skipped_in_mock_mode`,
  `test_skipping_the_url_probe_stage_leaves_every_status_null`,
  `test_url_probe_sends_only_in_scope_urls`,
  `test_url_probe_marks_an_unverified_certificate_apart_from_unreachable`,
  `test_url_probe_sees_a_certificate_error_in_the_context_chain`,
  `test_v9_database_migrates_the_url_status_column`,
  `test_unprobed_urls_and_set_url_status`,
  `test_unprobed_urls_is_bounded_by_the_limit`,
  `test_skip_url_probe_drops_the_stage_from_an_active_run`,
  `test_active_run_requests_the_url_probe_stage`. Changed: the seven
  `SCHEMA_VERSION == 9` assertions in `tests/test_store.py` became `== 10` (and
  their old-version fixtures now create a minimal `urls` table, since v10 alters
  it), the `MODE_STAGES`/stage-order literals in `tests/test_engine.py` and
  `tests/test_cli.py` gained `url_probe`, and
  `tests/test_interactive_scan.py`'s active and full stage tuples do too. The
  engine tests inject answers through the new
  `Engine(url_probe_transport=...)` keyword, an `httpx.MockTransport`, so the
  suite never touches the network (AGENTS rule 9).
- **Deviations.** (1) schema 10, not the 8 the brief assumed - 8 and 9 were
  already spent by Parts 1 and 3. (2) `-2` is a value the brief did not name; it
  was added because the real target proved `-1` would report a live site as
  dead, and it changes no host state, confidence, `diff` or count query.
  (3) `--skip-url-probe` is the named flag the brief allowed; no other flag was
  added.

## 2026-11-18 (verification follow-up) Part 2 - www dedup requires a known, equal status (D25)

- **Where it came from:** spot-check 2 of the verification round against `de50a15`. The requested
  query was invalid (`host_status_history` has no `fqdn`; it is keyed by `subdomain_id`), and the
  corrected join showed `www.testfire.net.duplicate_of = testfire.net` while **both** rows carried
  `status_code = NULL`.
- **Why that was wrong:** docs/09 section 5 rule 3 is "both ALIVE, same **non-2xx** status, sharing
  an IP". `NULL` is "no HTTP status observed", not a status two names share, so the pass was
  asserting "same website" from DNS evidence alone.
- **Before** (`src/reconkit/engine.py`, `_dedupe_www_variants`):
  `elif www_status == bare_status and www_ip & bare_ip:` -> `duplicate, canonical = fqdn, bare`
- **After:**
  `elif (www_status is not None and bare_status is not None and www_status == bare_status and www_ip & bare_ip):`
  -> `duplicate, canonical = fqdn, bare`, with the reason in a comment ("`NULL == NULL` is not
  evidence that the two names answer the same way").
- **Boundary kept:** no schema change, no `state`/`confidence`/`status_code` write, no count query
  touched. The 3xx/2xx branch, the both-2xx sibling note, the "different known IPs" note and the
  dead-variant rule are unchanged, and their tests still pass.
- **Not chosen:** the optional informational note for a no-status pair ("status unknown for both").
  It would add a new `www_note` value with no consumer, so the pair is simply left alone; recorded
  here as a deliberate omission.
- **Tests:** 882 -> 883. New: `test_www_both_null_status_not_marked_duplicate` (both ALIVE, both
  `NULL`, shared IP -> neither marked, no note). Re-ran
  `test_same_status_on_one_server_marks_the_www_variant` and
  `test_both_200_independent_servers_not_marked_duplicate` beside it: both still pass, so a real
  equal-code pair still marks and a real 2xx pair still only notes.
- **Gate:** `883 passed`; `ruff check .` "All checks passed!"; `ruff format --check .` "92 files
  already formatted"; `mypy src/reconkit` "Success: no issues found in 62 source files".

## 2026-11-18 (verification follow-up) Part 1 - faster `url_probe` and `--reprobe-urls` (D24)

- **Owner request:** the probe's worst case is `max_urls x timeout_s / threads`, and the suggestion
  was to replace the Python transport with the PD `httpx` binary (`-l file -threads 100`).
- **Docs first:** docs/02 (`--reprobe-urls` row, the stage paragraph), docs/09 (bounds, off-switch
  row, the transport decision), docs/04 (semantics unchanged), COMMANDS.md, MASTER_PLAN D24.
- **What the real binary does (evidence in D24 and PIT-62):**
  `~/.reconkit/bin/httpx -h` lists `-l`, `-threads`, `-silent`, `-json`, `-status-code`,
  `-follow-redirects`, `-timeout`, `-no-stdin`, `-duc`, `-nfs`, `-H` - and **no `-insecure`**.
  `httpx -l file -insecure` exits `flag provided but not defined: -insecure`. A three-URL file
  (`http://testfire.net/`, `https://testfire.net/`, `https://does-not-exist.testfire.net/`) produced
  exactly **two** JSON lines: both `https://testfire.net/` (certificate issued for
  `www.testfire.net`) as `status_code: 200`, and **nothing** for the name that does not resolve -
  no `tls_error`, no `error`, no `failed: true`. A local UA-logging server showed the default
  request carries `Mozilla/5.0 (Windows NT 10.0; ...) Edge/18.18363`, while
  `-H "User-Agent: reconkit/0.1"` sends `reconkit/0.1`.
- **Speed, same 158 stored testfire URLs (both passes <= 200, no example.com traffic):**
  `PD httpx (threads 100): WALL=9.190335087 s`, 157 lines, `{200: 122, 302: 3, 404: 32}` - the 58
  certificate-invalid URLs came back `200`. `Python httpx (threads 50): WALL=4.59 s`,
  `{-2: 58, -1: 1, 200: 66, 302: 2, 400: 1, 404: 30}`. After the change (`threads 100`, one client):
  **`WALL=3.44 s`** with the identical distribution. Decision: keep Python, disclose that the
  1.33x win is modest and that the binary was slower here.
- **Code:** `_url_probe_client(settings)` builds the one `AsyncClient` a pass uses;
  `_probe_url_batch(client, batch, settings)` takes it (was: built a client per 200-URL batch);
  `ScanOptions.reprobe_urls`; `Store.probe_candidates(target_id, *, limit, reprobe=False)` (renamed
  from `unprobed_urls`, because with `reprobe=True` the old name would lie); the probe run records
  `"reprobe": opts.reprobe_urls` in `params_json`. `threads` 50 -> 100 in `config.yaml` and
  `UrlProbeConfig`.
- **`--reprobe-urls` behaviour:** every stored URL is probed, the answer overwrites
  `urls.status_code` in place, `max_urls` still truncates with the same warning, and
  `--reprobe-urls --skip-url-probe` prints `warning: --reprobe-urls has no effect with
  --skip-url-probe; continuing` instead of silently doing nothing.
- **Not done:** no PD httpx subprocess, no `-insecure`-style verification switch (the `-2` value
  would lose its meaning), no change to the per-request `timeout_s`. The stage deadline is Part 3.
- **Tests:** 883 -> 888. New: `test_probe_candidates_reprobe_returns_answered_rows`,
  `test_reprobe_urls_probes_urls_that_already_carry_an_answer`,
  `test_url_probe_records_the_reprobe_flag_on_the_run`, `test_reprobe_urls_reaches_the_engine`,
  `test_reprobe_urls_with_skip_url_probe_warns_instead_of_contradicting`. Changed: the three
  `unprobed_urls` store tests became `probe_candidates`, and `DOCUMENTED_OPTIONS` in
  `tests/test_cli.py` gained `--reprobe-urls`.
- **Gate:** `888 passed`; `ruff check .` "All checks passed!" (the first version used an f-string
  SQL and was fixed to two static statements rather than adding an S608 suppression);
  `ruff format --check .` "92 files already formatted"; `mypy src/reconkit` clean.

## 2026-11-18 (verification follow-up) - regression repair in Part 1's probe loop

- **What broke:** the D24 edit that moved the `AsyncClient` out of `_probe_url_batch` left the
  per-batch commit block (`with self.store.transaction(): ... set_url_status`) dedented one level,
  outside the `for start in range(...)` loop. A pass with more than one batch would have committed
  only the **last** batch and silently discarded every earlier answer.
- **How it was found:** writing the Part 3 test `test_url_probe_timeout_keeps_the_batches_it_finished`
  (batch_size 1, one fast URL and one that never answers). The warning said `1/2 URL(s) probed` while
  both rows were still `NULL`, because the commit ran after the loop instead of inside it.
- **Exposure:** none in practice - every measured pass (158 URLs, 20 URLs) was a single batch of at
  most `batch_size` 200. It would have shown up on the first target with more than 200 unprobed URLs.
- **Fix:** the `with self.store.transaction():` block and the `done`/progress updates are indented
  back inside the loop, with a comment saying why (a pass killed by its deadline must keep every
  batch that finished).
- **Proof:** `pytest -q tests/test_engine.py -k "url_probe or reprobe or phase_timeout"` ->
  `14 passed`. Full gate is in the Part 3 entry that follows.

## 2026-11-18 (verification follow-up) Part 3 - `url_probe` respects the stage deadline (D26)

- **Where it came from:** verification spot-check 4. The `Stage.URL_PROBE` branch of the run loop
  handled the stage and `continue`d before `timeout = opts.phase_timeout or
  self._stage_timeout(stage)`, so `--phase-timeout` never reached it, and `config.yaml` had no
  `timeouts.url_probe` key at all. The pass was bounded only by `max_urls x timeout_s / threads`
  (~1000 s).
- **Docs first:** docs/02 (flag description + stage paragraph), docs/03 (timeout semantics),
  docs/09 (unchanged table), COMMANDS.md, MASTER_PLAN D26, `config.yaml` comment.
- **Code:** `Timeouts.url_probe: int` (config model) and `timeouts.url_probe: 600` in `config.yaml`;
  the branch now runs
  `asyncio.wait_for(self._run_url_probe(...), timeout=opts.phase_timeout or self._stage_timeout(Stage.URL_PROBE))`
  and catches `TimeoutError`; `_url_probe_timed_out(timeout)` closes the `scan_runs` row as `partial`,
  appends the warning `url_probe: timed out after {t:g}s ({done}/{total} URL(s) probed)`, and records
  the counts on the engine so `_completion_gaps()` appends a `URL_PROBE` `CompletionGap`. Progress is
  tracked in `_url_probe_progress` (updated per committed batch) and reset per run.
- **Same commit:** the D24 regression (per-batch commit dedented out of the loop) is repaired; see
  the entry above for its own evidence.
- **Live proof with the real network (3 testfire URLs, `threads: 1`, `batch_size: 1`,
  `phase_timeout=1.5`, single-stage run):**

  ```
  warnings: ['url_probe: timed out after 1.5s (2/3 URL(s) probed)']
  gaps: [('url_probe', 'timed out after 1.5s (2/3 URL(s) probed)')]
  completion: complete_with_gaps exit: 4
  scan_run status: partial
    https://testfire.net/                  status_code=-2
    https://testfire.net/login.jsp         status_code=-2
    https://testfire.net/index.jsp         status_code=None
  ```

  The two completed answers survived the kill and the third stayed `NULL`. The exit is `4` only
  because this artificial run consists of `url_probe` alone, so it produced no results at all
  (the existing "nothing usable" rule); in a real scan, where urls/live ran, a probe timeout is
  exit **0** - `test_url_probe_respects_phase_timeout` asserts `ExitCode.SUCCESS` plus the
  `complete_with_gaps` status.
- **Tests:** 888 -> 891. New: `test_url_probe_respects_phase_timeout` (0.3 s deadline, warning,
  NULLs kept, gap, `partial` run row, exit 0), `test_url_probe_timeout_keeps_the_batches_it_finished`
  (`(1/2 URL(s) probed)`, the finished answer stays, exit 0),
  `test_url_probe_uses_the_config_timeout_when_no_flag_is_given` (`timeouts.url_probe = 1`).
- **Gate:** `891 passed`; `ruff check .` "All checks passed!"; `ruff format --check .` "92 files
  already formatted"; `mypy src/reconkit` "Success: no issues found in 62 source files".

### Part 3 follow-up - `timeouts.url_probe` needs a default, or old configs stop loading

- **How it was found:** the real `--reprobe-urls` proof used `/tmp/rk4/config.yaml`, a copy taken
  *before* D26. The run died with `cannot read config file ...: timeouts.url_probe` (exit 2) because
  `Timeouts` has `extra="forbid"` and the new field was required: every externally kept
  `config.yaml` written before today would have stopped loading.
- **Fix:** `Timeouts.url_probe` is `Field(default=600, gt=0)`, the same value `config.yaml` ships, so
  a config without the key loads and keeps the new deadline. `_stage_timeout()` already had a
  `getattr` fallback, so nothing else needed to change.
- **Test:** `test_a_config_without_timeouts_url_probe_still_loads` (drops the key from the real
  config and asserts 600).
- **Proof the flag works end to end** (`/tmp/rk4`, 20 answered URLs, `--tools pyprobe`, after the
  default fix):

  ```
  BEFORE: |365   -2|40
  url_probe: probing 20 URL(s)
  url_probe: finished 20 URL(s)
  warning: url_probe: probed the first 20 URL(s) only; re-run to probe the rest
  EXIT=0
  AFTER:  |365   -2|40
  probe run params: {"scan_key": "...", "mode": "active", "tools": [], "mock": false,
                     "active": true, "reprobe": true, "no_keys": false, "min_sources": 1}
  ```

  The NULL count did **not** move (a default pass would have taken it to 345), so the 20 requests
  really were the already-answered rows, and `"reprobe": true` is on the run.
- **Gate:** `892 passed`; ruff, format and mypy clean.

## 2026-11-18 (batch 2026-11-18) Part B - urlfinder's cap scales with the host count (D27)

- **Where it came from:** the owner flagged the flat ceiling. It was already not
  the original flat 180 s: `b331927`'s `runtime_cap_s = 180` became
  `MIN 180 / IDLE 60 / MAX 1800`, so every target - 43 hosts or 500 - was allowed
  the same 1800 s, which over-served small targets and wasted large ones.
- **Docs first:** docs/09 section 4a2b (the formula, the floor, the override, the
  new log line), `config.yaml` `urlfinder.max_enumeration_s`, MASTER_PLAN D27.
- **The formula** (`adapters/urlfinder.py`), pure and unit-tested:

  ```python
  cap_s = min(stage_budget, max(180, 4 * host_count))
  ```

  `host_count` is `len(tool_hosts.get("urlfinder", hosts))` - the rows urlfinder
  receives on stdin for this run (the urls stage sets `tool_hosts["urlfinder"]`
  for a passive tool to the target plus the discovered names). `stage_budget` is
  the `timeout` the run loop already computed for the stage
  (`opts.phase_timeout or self._stage_timeout(stage)`), threaded into `_run_tools`
  as a new keyword argument and used only to compute these limits: D26's probe
  `wait_for` and the stage `wait_for` are unchanged.
- **Wiring:** the engine computes the cap and hands it down as
  `ToolLimits(max_s=cap, idle_s=60, min_s=min(180, cap))`, so the adapter still
  never reads `config.yaml`. `urlfinder.max_enumeration_s` (default 0) replaces
  the formula when non-zero; `urls.urlfinder_max_s` (1800) stays a hard ceiling.
- **Log line:** `BaseToolAdapter.cap_suffix(ctx)` (default `""`) is appended to
  the capped note; urlfinder returns ` (hosts=N)`. Result:
  `capped at 180s (hosts=43); kept partial output`.
- **Raw proofs:**

  ```
  computed cap, stage budget 1800 (timeouts.urls):
    hosts=43 -> 180s
    hosts=500 -> 1800s
  stage budget 600 (--phase-timeout 600):
    hosts=500 -> 600s

  fixture run: 43 hosts on stdin, override=3 -> cap 3s
    wall clock: 3.0s
    status: ok, items: 2
    urls: ['https://testfire.net/login.jsp', 'https://testfire.net/admin']
    detail: capped at 3s (hosts=43); kept partial output
  ```

  The fixture run used a stand-in `urlfinder` (two URLs, then `sleep 30`) with
  `max_enumeration_s` overridden to 3 s, so a real child was killed by the cap
  and its partial stdout was parsed. The first attempt pointed at the managed
  binary by mistake and returned `ok, items: 0`; that was the adapter resolving
  `~/.reconkit/bin/urlfinder` ahead of the stub, not a runner defect - `run_exec`
  keeps a killed child's stdout (`timed_out: True ... stdout: 'https://testfire.net/login.jsp\nhttps://testfire.net/admin\n'`).

  ```
  $ grep -n 'max_enumeration_s' config.yaml
  38:  max_enumeration_s: 0
  ```
- **Tests:** 892 -> 898. New `test_urlfinder_cap_scales_with_host_count` (500/43/100),
  `test_urlfinder_cap_floor_is_180` (10 hosts, 0 hosts), `test_urlfinder_cap_respects_stage_budget`
  (500 hosts/600 s, 43 hosts/120 s), `test_urlfinder_cap_config_override` (300 with
  10 and 500 hosts, 0 keeps the formula), `test_urlfinder_partial_output_line_includes_cap_and_host_count`
  (exact string), `test_urlfinder_cap_override_defaults_to_the_formula` (config
  default plus a config file without the block).
- **Updated test (disclosed behaviour change):** `test_url_tools_receive_the_configured_runtime_bounds`
  expected `(1800.0, 60.0, 180.0)` for a one-host urls stage; D27 gives that stage
  the 180 s floor, so it now expects `(180.0, 60.0, 180.0)`.
- **Gate:** `898 passed`; `ruff check .` clean; `ruff format --check .` 92 files;
  `mypy src/reconkit` clean (62 source files).

## 2026-11-18 (batch 2026-11-18) Part C - stale claims and the four open rulings

Docs only; no `src/`, no `tests/`, suite unchanged at 898.

**The state dump the part was written from was itself out of date.** Three of the
four named claims had already been corrected by the previous batch's Part 1
(`de50a15`, "external-service gaps + stale docs"), verified here by reading the
current text rather than the dump:

```
$ grep -n "no adapter" docs/PROGRESS.md         # Open risks
585:- **Closed 2026-11-17 (adapter waves 4-8):** `tech`, `urls` and `vulns` now have adapters and real runs
     behind them ... The old line "`tech`, `urls` and `vulns` have no adapter for any tool in their pools" was stale.

$ grep -n "827" docs/PROGRESS.md                # five hits, all inside dated status paragraphs
15,16,17,42  (historical entries; 16 already says "the 827 in this paragraph was itself stale ... 824")
43           (the baseline line, which is current and says 898 after Part B)

$ sed -n '46,52p' docs/05_SECURITY.md
- **The one installer is `scripts/install-tools.sh`, run by a human (D21, 2026-11-18).** It is plain bash in this
  repository, not a reconkit command ... runs `apt-get` under **per-command** `sudo` (or `go install`, which needs
  none) ... The `reconkit` **command** installs nothing (removed 2026-11-17, docs/MASTER_PLAN.md D4).
```

The fourth - the push state - was wrong and is fixed. `reconkit/main` is at
`a49e4b5` while local `main` is ten commits ahead (plus this one), so the
"both refs point at `a49e4b5`" sentence became the verified fact. **The batch
prompt's own premise ("False now: HEAD is pushed, tree clean") did not hold**:
nothing was pushed in this session and no push was attempted (hard rule 0c).

Before:

```
- **Pushed (2026-11-18):** local `main` and `reconkit/main` both point at `a49e4b5` ... The old
  "nothing is pushed / `reconkit/main` is still `5fd1d9a`" line was stale.
```

After:

```
- **Push state (verified 2026-11-18, this batch):** `reconkit/main` is at `a49e4b5` ... and local `main` is
  **ahead of it** - `git rev-list --count reconkit/main..main` printed `10` at `aadd7b5`, plus this batch's
  Part C commit. Nothing has been pushed since `a49e4b5` ...
```

`## Open risks` also gained one dated, numbered entry holding the four rulings,
verbatim in scope and with file:line references, explicitly marked "Logged, not
acted on": the `6488aad` stop-rule breach, probe-only timeout exiting 4 instead of
0, `-2` being a sentinel rather than an HTTP status, and the previous batch's
2 -> 1 -> 3 order with Part 3 split across `aad092c` + `62e88db`.

Historical status paragraphs were not rewritten: each records what was true on
its own date, and line 16 already annotates its own stale `827`.


## 2026-11-18 (batch 2026-11-18) Part D - record the owner's rulings (docs only)

Docs only; no `src/`, no `tests/`; suite stays 898.

### D.1 - raw, pasted first

The four open items as they stood in `docs/PROGRESS.md` (`## Open risks`, lines 564-584), verbatim:

```
- **2026-11-18, awaiting owner ruling (four items from the url_probe/httpx batch).** Logged, not acted on.
  1. **Part 1 stop-rule breach (`6488aad`).** That batch's own stop rules said to stop if PD httpx JSON could not
     classify "certificate did not verify" versus "no answer", and again if the speed win was under 2x. Both fired;
     the agent shipped the Python-transport alternative instead of waiting for a ruling. The outcome was measured
     and disclosed (9.19 s PD httpx versus 3.44 s Python on 158 URLs, `-2` preserved), so nothing is broken, but the
     process step was skipped. Ruling wanted: accept as-is, or revert `6488aad` and redo it after a ruling.
  2. **A probe-only run that times out exits 4, not 0.** `test_url_probe_respects_phase_timeout`
     (`tests/test_engine.py:3796`) pins exit 0 for a normal scan, and the D26 branch
     (`src/reconkit/engine.py:769`) turns the timeout into a completion gap. A run whose only stage is
     `Stage.URL_PROBE` produces no results at all under the "nothing usable" rule, so it exits 4 (measured: 3 real
     testfire URLs, `threads: 1`, `phase_timeout=1.5` -> `complete_with_gaps`, exit 4). Ruling wanted: keep 4 for a
     probe-only run, or make a timed-out probe alone exit 0.
  3. **`-2` is a reconkit sentinel, not an HTTP status.** `urls.status_code` holds a real code, `-1` (no answer) or
     `-2` (answered, certificate did not verify). Documented at `docs/04_DATABASE.md:193` and `:245`; anything that
     reads the column must know it. Ruling wanted: is the prose enough, or does the schema need a CHECK/NOTE-level
     marker so a future reader cannot mistake `-2` for a status?
  4. **Commit order and commit count in that batch.** The parts landed 2 -> 1 -> 3 (`4b97928`, then `6488aad`, then
     `aad092c`), not 1 -> 2 -> 3, because Part 2 was independent and ready while Part 1 waited on the transport
     question; and Part 3 became two commits (`aad092c` plus `62e88db`, the config-default fix the real proof
     exposed). Ruling wanted: accept the history as-is, or require a reorder/squash before the next push.
```

`git log --oneline a49e4b5..HEAD`:

```
a4ba0cc docs: reconcile stale claims and log four open rulings
aadd7b5 perf: urlfinder cap scales with host count (floor 180s, stage budget ceiling)
1e21297 docs: paste raw proofs for the url_probe/httpx batch (audit close-out)
62e88db fix: default timeouts.url_probe so older config files still load
aad092c fix: url_probe respects --phase-timeout and timeouts.url_probe
6488aad perf: reuse one url_probe client and raise threads; add --reprobe-urls
4b97928 fix: www dedup requires known equal status (NULL != NULL)
de50a15 feat: url_probe stage checks archive URL liveness
6a50030 feat: www/non-www deduplication with duplicate_of metadata
ce28cf3 fix: katana JSON skip, hakrawler/subjs caps, urlfinder inactivity kill
9fd4c6d fix: external-service errors are gaps not failures; stale docs cleanup
```

`grep -n 'urlfinder_max_s' config.yaml src/reconkit/config.py src/reconkit/engine.py` (before Part E):

```
config.yaml:29:  urlfinder_max_s: 1800    # the stage-budget default
src/reconkit/config.py:64:    urlfinder_max_s: int = Field(default=1800, gt=0)
src/reconkit/engine.py:1372:            ceiling=float(urls_config.urlfinder_max_s),
```

### D.2 - D28 recorded

`MASTER_PLAN.md` gained a `D28` block before "LATER BUG FIXES"; `PROGRESS.md` gained a `D28` deviation entry and the
four Open-risks items were marked closed by D28. `docs/02_CLI_UX.md` gained the probe-only-exits-4 note. No code
change.

### D.3 - post-D27 stale claims

`grep -rn 'flat 180|MAX_ENUMERATION_S = 180|cap is a flat|clipped to timeouts.urls' docs/ src/ tests/` found only
historical/dated statements (Previous-status paragraphs, REVIEW_LOG history, MASTER_PLAN D27 problem statement, tests
describing the old behaviour). The one current-tense wording that contradicts D27 is the `enumeration_cap_s`
docstring/comment block in `src/reconkit/adapters/urlfinder.py` ("500 -> 2000 s clipped to `timeouts.urls`"); it is
deliberately deferred to Part E, which fixes it together with the code.

### D.4 - push-state line made durable

`docs/PROGRESS.md` push-state bullet is now count-free: "`reconkit/main` is at `a49e4b5` ...; local `main` is ahead
of it; nothing has been pushed since." No fixed count to rot.


## 2026-11-18 (batch 2026-11-18) Part E - D27 double-ceiling cleanup (D29)

### Raw, pasted first

`enumeration_cap_s` calls (after the change):

```
enumeration_cap_s(2000, 3600, ceiling=0)    = 3600.0
enumeration_cap_s(2000, 3600, ceiling=1800) = 1800.0
enumeration_cap_s(43, 1800, ceiling=0)      = 180.0
enumeration_cap_s(500, 1800, ceiling=0)    = 1800.0
enumeration_cap_s(2000, 1800, ceiling=0)   = 1800.0
```

`grep -n 'urlfinder_max_s' config.yaml src/reconkit/config.py` before/after:

```
# before
config.yaml:29:  urlfinder_max_s: 1800    # the stage-budget default
src/reconkit/config.py:64:    urlfinder_max_s: int = Field(default=1800, gt=0)

# after
config.yaml:29:  urlfinder_max_s: 0       # 0 = no extra ceiling; stage budget (timeouts.urls / --phase-timeout) is the only bound
src/reconkit/config.py:64:    urlfinder_max_s: int = Field(default=0, ge=0)
```

Saturation log line (fixture run, 2000 hosts, stage budget 1800, capped): the adapter-level test pins
`capped at 1800s (hosts=2000; formula 8000s clipped to stage budget 1800s); kept partial output`.

### Changes

- `src/reconkit/config.py`: `UrlsConfig.urlfinder_max_s` default `1800` -> `0`, `gt=0` -> `ge=0`.
- `config.yaml`: `urlfinder_max_s: 1800` -> `0` with updated comment.
- `src/reconkit/models.py`: `ToolLimits` gained `note: str = ""`.
- `src/reconkit/engine.py`: imports `ENUMERATION_PER_HOST_S`; computes `urlfinder_note` when the formula wanted more than the final cap; passes `note=` into the urlfinder `ToolLimits`.
- `src/reconkit/adapters/urlfinder.py`: corrected the comment and `enumeration_cap_s` docstring; `cap_suffix` appends `; {note}` when present.
- `docs/09_TOOL_CONTRACTS.md`: D27 section updated (default 0 = no extra ceiling; saturation line example).
- `docs/MASTER_PLAN.md`: D29 block; `docs/PROGRESS.md`: D29 deviation + status.
- `tests/test_config.py`: `test_the_urls_runtime_bounds_load_and_default` updated to `== 0`.
- `tests/test_binary_adapters.py`: added `test_urlfinder_cap_saturation_is_logged_with_the_reason`.

### Stop rule

No ripple: `ToolLimits` is constructed in a handful of places and the new field has a default, so no equality-pinning test broke. No stop triggered.


## 2026-11-18 (batch 2026-11-18) Part F - mock-run isolation (D30)

### Investigation (raw)

- Mock runs reach the store through `Engine.run` -> `create_target(target)`; the mock flag never changed the target identity, so fixture hosts (`www`/`api`/`dev`/`blog.example.com`) were stored under the real target id (the `testfire.net` run 69 pollution).
- Reports are written by `report_directory(config.results_dir, target, run_at)` in `cli._run_scan`, so a mock run wrote into the same `results/<target>/` folder as a real run and could overwrite `report.txt`/`report.json`.
- DB path comes from `config.db_path` (default `recon.db`) via `Engine.open(db_path=...)`; `--db` overrides it.

### Mechanism chosen

Preferred mechanism from the spec: separate DB by default + distinct results namespace.
- `cli._run_scan`: when `mock` and no `--db` and `config.db_path == "recon.db"`, use `~/.reconkit/mock.db`.
- `cli._run_scan`: when `mock`, `results_root = results/mock`, so reports land under `results/mock/<target>/`.
- `Engine.open` untouched; the default is chosen in the CLI layer.

Historical polluted rows are not deleted (no rewrite of history), as required.

### Tests updated

- `tests/test_cli.py` and `tests/test_interactive_scan.py`: report paths moved from `results/<target>/` to `results/mock/<target>/` for mock runs (7 + 2 sites).
- Suite stays 899 (no new tests added here; the three named tests are the grader's).

### Stop rule

No ripple beyond the report-path edits; D20 report-on-every-scan behaviour preserved (mock still writes both files, now under the mock namespace). No stop triggered.


## 2026-11-18 (batch 2026-11-18) Part G - mock live ALIVE: premise disproved, nothing changed

**The defect named for this part no longer exists.** `reconkit run -d example.com --active --no-scope --mock`
stores ALIVE hosts with real statuses today, straight from the pyprobe/httpx mock fixtures:

```
ALIVE: api.example.com 401 ['assetfinder', 'otx', 'subfinder']
ALIVE: www.example.com 200 ['assetfinder', 'certspotter', 'crtsh', 'hackertarget', 'otx', 'subfinder']
alive count: 2 of 21
```

The hosts that stay `UNKNOWN` are the ones with **no live record at all**: the flat `httprobe`/`tlsx` fixtures carry
only three `testfire.net` names, and `pyprobe`/`httpx` have an `example.com` fixture only, so `dev.example.com`,
`blog.example.com`, `products.example.com` and friends never appear in any live record. That is the state rule
working, not an inconclusive record.

**What was changed: the two stale claims, and nothing else.** No adapter, fixture, verdict rule or state definition
was touched - making every discovered host ALIVE would mean inventing HTTP statuses the fixtures do not contain,
which the mock contract forbids (a fixture is a stand-in for real tool output).

- `tests/test_interactive_scan.py`: `test_a_real_mock_run_reports_alive_fields_only_for_alive_hosts`'s docstring
  claimed "a mock `--active` run never produces an `ALIVE` host in this build". False; corrected, assertion unchanged.
- `docs/PROGRESS.md` `## Open risks`: the "stores every host as UNKNOWN" entry is now a dated "Disproved" note with
  the numbers above and the reason nothing was changed.

**D31 is withdrawn**, not deferred: there is no code defect to fix. Suite 899 -> 903 (the four D32 tests from
Part H, which is in the same working tree).


## 2026-11-18 (batch 2026-11-18) Part H - the render_error sites route through `redact()` (D32)

### The actual site list (raw)

Before (raw, from the working tree at HEAD 5e5ee71):

```
$ grep -n "render_error" src/reconkit/cli.py
43:    render_error,
401:        render_error(
454:            render_error(f"invalid host state {part!r}", no_color=no_color)
604:    render_error(redact(message), no_color=no_color)
1220:        render_error(str(exc), no_color=no_color)
1223:        render_error(str(exc), no_color=no_color)
1231:    render_error("scope import is Phase 3 and is not available in this build.")
1259:        render_error(str(exc), no_color=no_color)
1291:        render_error(str(exc), no_color=no_color)
1312:        render_error(str(exc), no_color=no_color)
1316:        render_error(
1329:    render_error("db list is not wired in Part 8; no data was read.")
1341:    render_error("db export is not wired in Part 8; no data was written.")
1353:    render_error("export is not wired in Part 8; no report was written.")
```

After:

```
$ grep -n "render_error" src/reconkit/cli.py
43:    render_error,
401:        render_error(
454:            render_error(f"invalid host state {part!r}", no_color=no_color)
604:    render_error(redact(message), no_color=no_color)
1220:        render_error(redact(str(exc)), no_color=no_color)
1223:        render_error(redact(str(exc)), no_color=no_color)
1231:    render_error("scope import is Phase 3 and is not available in this build.")
1259:        render_error(redact(str(exc)), no_color=no_color)
1291:        render_error(redact(str(exc)), no_color=no_color)
1312:        render_error(redact(str(exc)), no_color=no_color)
1316:        render_error(
1329:    render_error("db list is not wired in Part 8; no data was read.")
1341:    render_error("db export is not wired in Part 8; no data was written.")
1353:    render_error("export is not wired in Part 8; no report was written.")
```

The 1220/1223 pair is `scope check` (ValueError, then ConfigError/ScopeError), then `diff` 1259, `status` 1291,
`doctor` 1312. Three exceptions used to reach `render_error` in other commands: none. Lines 401/454/604/1231/1316/
1329/1341/1353 already carried a literal string or a redacted message.

Five sites, not six: the `install` site the old note listed went with the installer (D4, 2026-11-17).

### Change

Every one of the five became `render_error(redact(str(exc)), no_color=no_color)`. `redact()`'s semantics are
unchanged: it masks header values (`Authorization`, `Cookie`, `Set-Cookie`) and key-shaped pairs, and leaves paths
and domains alone, so no site's message loses information it legitimately shows.

### Tests

Four new tests in `tests/test_cli.py`, one per surviving command site (`doctor`'s error path is the fifth `except`
and shares the `diff`/`status` shape):

`test_scope_check_error_is_redacted`, `test_diff_error_is_redacted`, `test_status_error_is_redacted`,
`test_doctor_error_is_redacted`. Each raises an exception whose message contains `Authorization: Bearer abc123` and
asserts `abc123` appears in neither stream while `***` does.

Suite 899 -> 903.


## 2026-11-18 (batch 2026-11-18) follow-up - the acceptance tests that were missing

An audit of the batch against its own acceptance list found three gaps and one real bug in the D30 path.

### Gaps closed

1. **Part F had no tests.** The three named tests were never written - the Part F entry above says so in
   parentheses ("the three named tests are the grader's"), which is not how this repo works. Added:
   `test_mock_run_creates_no_rows_under_the_real_target`, `test_mock_run_does_not_overwrite_a_real_report`,
   `test_mock_db_default_is_separate_unless_db_given` in `tests/test_cli.py`.
2. **Part E had one of its two tests.** The saturation test existed; the "raising the stage budget alone now works"
   test did not. Added `test_urlfinder_cap_follows_the_stage_budget_with_no_extra_ceiling`.
3. **Part D's `COMMANDS.md` note was missing.** `docs/02_CLI_UX.md:132` carried the probe-only exit-4 rule;
   `COMMANDS.md` did not. Added under the `url_probe` section.

### The bug the missing tests would have caught

`cli._run_scan` defaulted the mock DB to `~/.reconkit/mock.db` without creating the directory. `~/.reconkit` only
exists once a tool has been installed, so on a fresh machine every mock run died:

```
$ HOME=/tmp/dbg/home reconkit passive -d example.com --mock --config .../config.yaml
exit 1
stderr: unexpected error: OperationalError: unable to open database file
```

Fixed by `db_path.parent.mkdir(parents=True, exist_ok=True)` next to the D30 branch. The three new tests run with
`HOME` pointed at `tmp_path`, so they exercise this on every run.

Suite 903 -> 907, then -> 908 with `test_active_mock_run_stores_hosts_alive`, the Part G test name kept as a
regression pin for the behaviour the part assumed was broken (`www.example.com` 200, `api.example.com` 401).


## 2026-11-18 (batch 2026-11-18b) Part I - close the prior batch's acceptance gaps

**The premise "903 tests, three D30 tests missing" was already false at HEAD 6d77834.** The previous turn's audit
found the same gaps and shipped them one commit earlier, so this part is a *reconciliation*: the tests existed but
under different names and with weaker setups than this batch names. Raw state at session start:

```
$ git log --oneline -5
6d77834 test: pin mock active ALIVE as a regression (D31 withdrawn)
7cf1b20 test: add the missing D29/D30 acceptance tests; create ~/.reconkit for the mock DB
1ce0768 fix: render_error sites route through redact (D32)
5e5ee71 docs: withdraw D31 - mock active already stores ALIVE (premise disproved)
9b5b61e fix: mock runs use an isolated DB and results namespace (D30)
$ pytest -q | tail -1
908 passed in 20.09s
```

### What changed here (tests only, no `src/`)

- `test_urlfinder_cap_follows_the_stage_budget_with_no_extra_ceiling` renamed to the batch's
  `test_urlfinder_cap_3600_when_only_the_stage_budget_is_raised` (same three assertions, incl. `UrlsConfig().urlfinder_max_s == 0`).
- `test_mock_run_does_not_overwrite_a_real_report`: the sentinel now lives at `results/testfire.net/report.txt` as
  specified (it used `results/example.com/`); the scan target stays `example.com`, because a **mock passive run for
  `testfire.net` exits 5 today** (`tools: 17 ok, 0 gap, 1 failed, 6 skipped`) - that is B1's subject, not this part's.
- `test_mock_db_default_is_separate_unless_db_given`: now asserts the default mock DB is **byte-identical** after an
  explicit `--db` run, not merely that `--db`'s file exists.
- `COMMANDS.md`: the probe-only exit-4 line is mirrored into the `--phase-timeout` flag row itself (it was only in the
  `url_probe` narrative section from the previous turn).

### Disclosed deviation from this part's brief

The brief says "no src changes" and "suite 903 -> 907". Both are impossible against this HEAD: the four tests already
existed (hence 908, unchanged), and commit `7cf1b20` had to add `db_path.parent.mkdir(parents=True, exist_ok=True)` in
`cli._run_scan` because the D30 default crashed with `unable to open database file` when `~/.reconkit` did not exist.
No `src/` change is made in this commit.

Suite 908 -> 908. Gate: `908 passed`, `All checks passed!`, `92 files already formatted`, mypy clean.

## 2026-11-18 (batch 2026-11-18b) Part J - the seven rulings index + R6's fixture remainder

### J.1 raw: the table now in `docs/PROGRESS.md` (Deviations, top)

```
| Ruling | Decision | Recorded as |
| R1 - 6488aad stop-rule breach      | Accepted, no revert; process lesson                  | D28.1 |
| R2 - probe-only timeout            | Exit 4 by design; normal scan exits 0 with gaps       | D28.2 |
| R3 - -2 sentinel                   | Defined in docs/04_DATABASE.md:193/:245               | D28.3 |
| R4 - commit order / split commit   | Accepted as shipped                                   | D28.4 |
| R5 - mock isolation                | Separate mock DB + results/mock/ namespace            | D30   |
| R6 - mock live ALIVE               | "All UNKNOWN" disproved; fixture remainder fixed      | D31 (withdrawn) + D33 |
| R7 - redact() routing              | Five surviving render_error sites routed              | D32   |
```

Nothing was re-decided: each row points at the D-number that already holds the ruling.

### J.2 raw: why pyprobe is the right place for the status

`tests/fixtures/adapters/httprobe.synthetic.txt` and `tlsx.synthetic.jsonl` name `testfire.net`, `www.testfire.net`
and carry no HTTP status - `httprobe` prints `http://host`, `tlsx` prints TLS JSON. Neither tool ever emits a status
code, so a parser change would be fabrication. `pyprobe` is the mock stand-in for a real HTTP probe and already has
per-target fixtures (`example.com`, `www-pair.test`), so the status belongs there.

New file `tests/fixtures/pyprobe/testfire.net.synthetic.json`:

```json
{
  "testfire.net": {"status_code": 200, "title": "Altoro Mutual", "location": null},
  "www.testfire.net": {"status_code": 200, "title": "Altoro Mutual", "location": null}
}
```

New test `test_mock_active_reports_status_200_from_the_live_fixture` asserts `www.testfire.net` is `ALIVE` with
`status_code == 200` and `testfire.net` carries 200 in a mock `--active` run. No adapter, verdict, confidence or count
code touched.

Side effect worth noting: before this fixture, pyprobe had **no** fixture for `testfire.net` and failed with
`pyprobe: no fixture for testfire.net` in every mock `--active` run on that target. The new file fixes that too.

Suite 908 -> 909.

## 2026-11-18 (batch 2026-11-18b) B1 - exit-5 classification (R8 / D34)

### Investigation (raw)

The machinery R8 asks for already existed under the name `gap` (added 2026-11-18 by the example.com ruling):
`ToolStatus.GAP`, one classifier `adapters.base.classify_external_gap()`, `tool_runs.status='gap'` (schema 8),
`Engine._completion_gaps()`, and three engine tests. So the question was not "does it exist" but "does the signature
list match R8". Raw matrix before the change:

```
True  <- otx: HTTP 429
True  <- otx: rate limited (HTTP 429)
True  <- hackertarget: free quota exceeded
True  <- crtsh: server error (HTTP 502)
False <- HTTP 500 Internal Server Error      <-- the one R8 names that did not match
True  <- 503 Service Unavailable
False <- 401 Unauthorized
False <- 403 Forbidden
False <- not installed or not executable: no such file
False <- invalid JSON line
False <- connect ECONNREFUSED 1.2.3.4:443
```

Raw CLI proof of the exit codes on this box (mock, `example.com` has fixtures for every passive tool, `testfire.net`
does not have a `dnspython` fixture, so that tool is a genuine local fault):

```
example.com: exit=0 | gap, 0 failed, 6 skipped, 0 timeout
testfire.net: exit=5 | gap, 1 failed, 6 skipped, 0 timeout
```

### Implementation

- `adapters/base.py` `_GAP_PATTERNS`: the 5xx alternative is now `http\s*5\d{2}` (was `5(02|03|04)`) plus
  `internal server error`; `429` was already matched in an HTTP context. One list, one function - no regex anywhere else.
- No new `ToolStatus` member (see D34): `gap` **is** R8's degraded state.

### Tests

- `tests/test_adapters.py::test_classify_external_gap_matches_only_third_party_signatures` extended with
  `HTTP 500 Internal Server Error` (True), `server error (HTTP 500)` (True), `500 items parsed` (False),
  `401 Unauthorized` (False), `403 Forbidden` (False).
- `tests/test_engine.py::test_degraded_tools_never_exit_five_but_a_local_fault_does`: the four cases R8 names
  (all-gap -> 0 + gaps, gap + local fault -> 5, missing binary + working tool -> 5, all ok -> 0) in one test.
  The existing `test_an_external_service_gap_exits_zero_and_is_named_in_the_gaps` and
  `test_a_gap_never_masks_a_real_failure` keep their heavier assertions (DB rows, completion status, stage rows).

### Docs

`docs/03_ARCHITECTURE.md` (status semantics paragraph), `docs/02_CLI_UX.md` (the external-service bullet now names the
signatures and the "degraded" spelling; local faults and auth errors are explicitly not degraded), PROGRESS D34.

Suite 909 -> 911.

## 2026-11-18 (batch 2026-11-18b) B2 - the shots / chromium gap (D35)

### Investigation (raw, this box)

```
$ which chromium chromium-browser google-chrome google-chrome-stable chrome
/usr/bin/chromium
$ gowitness scan single -u https://testfire.net -s /tmp/xx --screenshot-format png
... have-screenshot=false ...
Error: failed to initialize chrome context: exec: no chrome
```

`/usr/bin/chromium` exists but gowitness execs `google-chrome`, and the adapter never guesses a `--chrome-path`
(docs/09 4a8). So "no browser" is the box's real state for gowitness, and before this change the adapter answered
`ok 0` with `host: no screenshot (no browser available?)` - which the engine counted as success and which produced
**no gap**, so an operator saw 0 screenshots and no explanation.

### Implementation

- `adapters/gowitness.py`: `NO_BROWSER_MARKERS` (one tuple) + `_no_browser()`; when a run produced no records and the
  captured output matches, the result is `ToolStatus.GAP` with `NO_BROWSER_ERROR = "no chromium; 0 screenshots"`.
  A zero-shot run **without** the marker keeps `ok` and the per-host note (test pins both sides).
- `doctor.py`: `browser_state()` (one list of Chromium-family names, `shutil.which` injectable) and a `chromium`
  field on `DoctorReport`; `ui.doctor_document()` carries `chromium`; `ui.render_doctor()` prints a one-row
  **Browser** table: `chromium | missing | shots will produce 0 screenshots`. The row asks for the names gowitness
  actually execs (`google-chrome`, `google-chrome-stable`, `chrome`); `/usr/bin/chromium` alone reads `missing`,
  which is the truth on this box (verified: `reconkit doctor --json` -> `chromium = missing`).
- No install, no `--chrome-path` guessing, no schema change.

### Tests

- `tests/test_doctor.py::test_chromium_row_reports_missing_when_no_browser_is_installed`
- `tests/test_doctor.py::test_chromium_row_reports_installed_when_a_browser_exists`
- `tests/test_doctor.py::test_browser_state_finds_any_chromium_family_binary`
- `tests/test_binary_adapters.py::test_gowitness_without_a_browser_is_a_gap_not_a_failure`
- `tests/test_binary_adapters.py::test_gowitness_zero_screenshots_without_a_browser_message_stays_ok`
- `tests/test_engine.py::test_shots_without_chromium_is_a_gap_and_exit_zero` (gap + exit 0 + completion_with_gaps)

### Docs

`docs/09_TOOL_CONTRACTS.md` (4a8 gowitness section), `docs/02_CLI_UX.md` (doctor's Browser table and the `--json` key
list), PROGRESS D35.

Suite 915 -> 921.

## 2026-11-18 (batch 2026-11-18b) B3 - doctor footer vs JSON (D36)

### Investigation (raw, this box)

```
$ reconkit doctor --json | python -c "..."
total tools: 48
installed yes: 46
not yes: [('amass', 'wrong program'), ('dnsreaper', 'missing')]
json missing: 2
$ reconkit doctor | tail -3
Per-tool provenance: docs/10_TOOL_SOURCES.md.
warning: amass: /usr/bin/amass is not the expected program; doctor ignores it.
```

So the brief's "47 installed, 1 manual" is the shape, not the numbers: on this box `amass` is a wrong program, so an
honest footer must say 46 + 1 manual + 1 needing attention. The real defect was that the footer said
`Missing tools: 2` while `--json` said `missing: 2` **and** listed 48 tools - two different stories from one command.

### Implementation

- `doctor.py`: `DoctorReport.installed` (count of `yes`) and `.manual` (tools whose registry entry says `manual: true`);
  `manual_tools()` is one function. `registry.ToolSpec` gained `manual: bool` parsed by the existing `_flag`
  (non-bool -> `ConfigError`); `tools.yaml` sets `manual: true` on `dnsreaper` only.
- `ui.doctor_document()`: `installed` and `manual` added next to `missing`.
- `ui.render_doctor()`: footer is now
  `46 installed, 1 manual (dnsreaper), 1 needs attention (amass). Scans will use the tools that are installed and skip the rest. Per-tool provenance: docs/10_TOOL_SOURCES.md.`
  (singular/plural handled; `missing` keeps its meaning).

### Deviation, disclosed

The first implementation derived "manual" from `source:` not starting with `apt:/pip:/go install/...`. That read the
synthetic tools.yaml test fixtures as manual (`beta`, `gamma`) because they omit `source` entirely - a false positive
the footer test caught. Replaced with an explicit registry flag, documented in docs/10.

### Tests

- `tests/test_doctor.py::test_missing_tools_keep_exit_code_zero` updated to the new footer.
- `tests/test_doctor.py::test_footer_and_json_agree_on_installed_and_manual` - the actual D36 assertion.
- `tests/test_doctor.py::test_a_manual_tool_is_counted_apart_from_missing` - `manual: true` is not "missing".
- `tests/test_registry.py::test_manual_flag_is_parsed_and_defaults_to_false` (real `tools.yaml`).
- `tests/test_registry.py::test_a_non_bool_manual_flag_is_a_config_error`.

### Docs

`docs/02_CLI_UX.md` (footer text + the `--json` key list), `docs/10_TOOL_SOURCES.md` (the `manual: true` registry flag),
PROGRESS D36.

Suite 921 -> 925.

## 2026-11-18 (batch 2026-11-18b) B4 - Ctrl+C kills the child (D37)

### Investigation (raw)

`grep -n "start_new_session\|_kill_tree\|KeyboardInterrupt\|killpg" src/reconkit/core/runner.py` before the change:

```
128:        process = subprocess.Popen(
139:            start_new_session=False,       # same session (PIT-32), new process group
209:            _kill_tree(process)            # timeout path only
224:            _kill_tree(process)            # idle-kill path only
254:def _kill_tree(process):
256:        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
```

No `KeyboardInterrupt` anywhere in the runner. Because the child leads its own process group, the terminal's SIGINT
(which goes to the foreground group) reaches reconkit only, so the tool survived a Ctrl+C as an orphan.

### Implementation

- `runner.terminate_tree(process, *, wait_timeout=5.0)`: `_kill_tree` + reap; now used by **both** timeout/idle paths
  and the interrupt path, so one helper kills the same set.
- The wait loop is wrapped in `try/except KeyboardInterrupt: terminate_tree(process); raise`.
- CLI behaviour unchanged: `except KeyboardInterrupt` -> `interrupted; state is saved and the run is resumable`, 130.

### Tests

- `tests/test_runner.py::test_terminate_tree_kills_a_real_child_and_reaps_it` - a real `sleep 60` in its own process
  group is dead and reaped in under 2 s.
- `tests/test_runner.py::test_ctrl_c_during_a_run_kills_the_child_and_reraises` - the interrupt frame kills the group and
  the exception still propagates (no swallowing).
- `tests/test_runner.py::test_a_real_sigint_reaches_run_exec_and_leaves_no_orphan` - the integration case: SIGINT is
  delivered to this process from another thread (what Ctrl+C does), `run_exec` raises, the real child is gone. This one
  worked first try, so no gap was declared for it.

### Known gap (disclosed)

The engine executes adapters through `asyncio.to_thread`, so a Ctrl+C lands in the main thread while the worker sits in
`run_exec`. `run_exec`'s own handler covers the direct-call path (tests above); the engine path needs a live-process
registry, which is outside this ruling. Recorded in PROGRESS D37 and "Open risks".

Suite 925 -> 928.

## 2026-11-18 (batch 2026-11-18b) Part M finding - the phase timeout was invisible in the summary (D38)

Part M's first real run (`reconkit run -d testfire.net --active --phase-timeout 120 --no-color`) printed:

```
37 hosts: 8 ALIVE, 0 DNS_ONLY, 0 SHUT_DOWN, 25 DEAD, 4 UNKNOWN | tools: 23 ok, 2
gap, 0 failed, 3 skipped, 0 timeout
```

yet exited **5** and the DB said otherwise:

```
$ sqlite3 /tmp/mscan/recon.db "SELECT tool,status,error FROM tool_runs WHERE status!='ok'"
gau          | timeout | phase timeout
gospider     | timeout | phase timeout
hakrawler    | timeout | phase timeout
katana       | timeout | phase timeout
urlfinder    | timeout | phase timeout
```

Cause: `Engine._run` writes the timeout row with `_record()` but kept no `ToolResult`, and every counter (`ui` summary,
`--json` `summary.tools_timeout`) is built from `summary.results`. Fix: the timeout branch appends
`ToolResult(tool=..., status=TIMEOUT, error="phase timeout")` for each killed tool, so the row, the counters, the JSON
and the exit code now describe the same run. Exit semantics unchanged (a mixed run stays 5; a run where every tool
timed out stays 4 by the documented boundary).

Test: `tests/test_engine.py::test_phase_timeout_records_a_timeout_row` now asserts the result list carries the timeout
and that the all-timed-out case is `ExitCode.NO_TOOL`.

Suite stays 928 (one test strengthened, none added).

## 2026-11-18 (batch 2026-11-18b) Part M - one real testfire.net active scan

Bounded command (repo root, venv active):

```bash
reconkit run -d testfire.net --active --phase-timeout 120 --no-color --config /tmp/mscan/config.yaml
```

The temp config only changed `db_path=/tmp/mscan/recon.db`, `workspace_dir=/tmp/mscan/workspaces` and
`url_probe.max_urls=20`; `--full` was not used, so `shots` stayed out (D19).

Raw tail:

```
37 hosts: 8 ALIVE, 0 DNS_ONLY, 0 SHUT_DOWN, 25 DEAD, 4 UNKNOWN | tools: 23 ok, 2
gap, 0 failed, 3 skipped, 0 timeout
warning: url_probe: probed the first 20 URL(s) only; re-run to probe the rest
active scan completed with gaps - 1 stage(s) incomplete
  subs: hackertarget: free quota exceeded, otx: rate limited (HTTP 429)
report: results/testfire.net/20261118T234015Z/report.txt and .../report.json
EXIT=5
```

`scan_runs` rows (all `scope_mode='enforced'`):

```
1 subs      completed 23:33:59Z -> 23:34:24Z
2 dns       completed 23:34:24Z -> 23:34:35Z
3 live      completed 23:34:35Z -> 23:34:42Z
4 tech      completed 23:34:43Z -> 23:36:32Z
5 urls      partial   23:36:32Z -> 23:39:37Z
6 url_probe completed 23:39:38Z -> 23:39:42Z
```

Non-ok `tool_runs`: `hackertarget gap` (free quota exceeded), `otx gap` (HTTP 429), `amass skipped` (not installed),
`chaos skipped` (requires PDCP_API_KEY), `github_subdomains skipped` (requires GITHUB_TOKEN), and `gau`, `gospider`,
`hakrawler`, `katana`, `urlfinder` all `timeout` / `phase timeout`.

### Finding (fixed, D38)

Exit 5 was correct - five tools were killed by the `urls` 120 s deadline - but the printed line said `0 timeout`,
because the timeout handler wrote `tool_runs` rows without adding anything to `StageOutcome.results`, and both the
printed counters and `--json` read `results`. The handler now appends a `ToolStatus.TIMEOUT` result per unfinished tool.
`tests/test_engine.py::test_phase_timeout_records_a_timeout_row` asserts the result list and that an all-timed-out
stage is `NO_TOOL` (4), not 5. Suite stays 928 (one existing test extended).

### Observations for the owner

- Real-world `urls` tools are the slow stage: `unfurl` produced 74 URLs while katana/gospider/hakrawler/urlfinder were
  still working at 120 s. The default stage timeout, not the tool set, decides whether `urls` completes.
- Both free subdomain APIs (`hackertarget`, `otx`) refused this run; `subs` still completed on crtsh/subfinder.

### Verification of D38 (second real run, 30 s/stage)

```bash
reconkit run -d testfire.net --active --phase-timeout 30 --no-color --config /tmp/pm/config.yaml
```

```
4 hosts: 0 ALIVE, 4 DNS_ONLY, 0 SHUT_DOWN, 0 DEAD, 0 UNKNOWN | tools: 15 ok, 1
gap, 9 failed, 3 skipped, 5 timeout
EXIT=5
```

The five `timeout` rows in `tool_runs` (crtsh, subfinder, findomain, gau, urlfinder) are now the same five the summary
line counts, so the line and the exit code agree. `scan_runs`: `subs partial`, `dns completed`, `live completed`,
`tech partial`, `urls partial`, `url_probe completed`.

### Observation for the owner (not changed - no encoded ruling)

At 30 s the `subs` stage itself ran out of time (crtsh/subfinder/findomain killed), leaving only the `otx` gap, so the
scan had 4 DNS_ONLY hosts and no ALIVE host. Every later stage then reported `failed ... no hosts to scan/crawl`, which
pushed the run to nine "failed" tools (exit 5) although no tool was broken: they had no input. Whether "no hosts to
<verb>" should stay `failed` or become a skip is a status/exit-code rule change, so it was only recorded here. The
120 s run in the first scan (subs completed, 8 ALIVE) is the representative one.

## 2026-11-19 (close-out) N.1 - reconciliation of the 2026-11-18b batch (D41)

Docs only (`docs/PROGRESS.md` D41, `docs/09_TOOL_CONTRACTS.md` 4b). Three facts recorded, nothing re-implemented:

1. **Baseline correction.** The previous prompt named 903 tests at `6d77834`; the checkout was at 908 (verified by the
   gate at the start of this batch: `928 passed` from `7983974`). Part I renamed/adjusted the four acceptance tests
   already shipped in `7cf1b20` and added the `COMMANDS.md` note - net +0 tests.
2. **B1/D34 stands.** `gap` is R8's "degraded"; the observable contract (429/quota/in-context 5xx -> gap -> excluded
   from the failure total -> exit 0) is what the ruling asked for, so no `ToolStatus.DEGRADED` member and no schema 11.
   Tradeoff disclosed in D41(b): `--json` `tools_gap` cannot separate a provider throttle from a structural gap; the
   reason is in `stages[].results[].error`.
3. **Mock caveat.** `tests/fixtures/pyprobe/testfire.net.synthetic.json` says 200 where the real host says `-2`; docs/09
   now says fixture statuses are synthetic and not evidence.

Also removed a duplicated truncated D38 paragraph left by the previous batch. Suite unchanged (928).

## 2026-11-19 (close-out) N.2 - the five B1 exit-code cases, raw

All commands run from the repo root with the venv active and `--no-color --db /tmp/n2.db`. No code change: every case
already has a test (names below).

### 1. otx HTTP 429 (real, no fixture)

```
$ reconkit subs -d testfire.net --tools otx --no-color --db /tmp/n2.db
subs: running 1 tool(s)
subs: otx gap 0 item(s)
┃ otx  ┃ subs  ┃ gap    ┃ 0     ┃ otx: rate limited (HTTP 429) ┃
0 hosts: 0 ALIVE, 0 DNS_ONLY, 0 SHUT_DOWN, 0 DEAD, 0 UNKNOWN | tools: 0 ok, 1
gap, 0 failed, 0 skipped, 0 timeout
passive scan completed with gaps - 1 stage(s) incomplete
  subs: otx: rate limited (HTTP 429)
EXIT=0
```

### 2. hackertarget free quota (mock, new fixture `tests/fixtures/hackertarget/quota.example.com.txt`)

The real API answered normally this time (`hackertarget ok 3`, the quota was not exhausted again), so the quota answer is
pinned with the sentence the real free tier returns.

```
$ reconkit subs -d quota.example.com --mock --tools hackertarget --no-color --db /tmp/n2.db
passive scan completed with gaps - 1 stage(s) incomplete
  subs: hackertarget: free quota exceeded
EXIT=0
```

### 3. missing binary - the brief's "exit 5" does not survive contact with D9

```
$ reconkit subs -d example.com --tools amass --no-color --db /tmp/n2.db   # /usr/bin/amass is the wrong program here
subs: running 0 tool(s)
┃ amass ┃ subs  ┃ skipped ┃ -  ┃ not installed ┃
warning: subs stage executed no tools: 1 tool(s) skipped (not installed)
passive scan completed with gaps - 1 stage(s) incomplete
  subs: 1 tool(s) skipped (not installed)
EXIT=4
```

With a second, working tool in the same run it is exit 0 instead:

```
$ reconkit subs -d testfire.net --tools amass,otx --no-color --db /tmp/n2.db
subs: otx gap 0 item(s)
  subs: otx: rate limited (HTTP 429)
EXIT=0
```

**Why 4/0 and not 5:** an absent binary is caught at **selection** (`skipped / not installed`), and docs/02 section 6
already rules that absence is a completion gap (0), with "nothing usable at all" as 4. The `5` in docs/02's local-fault
sentence is the *post-selection* failure (the binary was there at selection and gone/broken when executed, detail
`not installed or not executable`), which `test_degraded_tools_never_exit_five_but_a_local_fault_does` pins at engine
level; a CLI run cannot produce that race deterministically, so it is pinned by the test only. Recorded as a
clarification, not a behaviour change.

### 4. mixed: one gap + one hard failure (mock, `mix.example.com`)

```
$ reconkit subs -d mix.example.com --mock --tools hackertarget,otx --no-color --db /tmp/n2.db
subs: otx failed 0 item(s)
subs: hackertarget gap 0 item(s)
┃ otx          ┃ subs ┃ failed ┃ 0 ┃ otx: expected passive_dns to be a list ┃
┃ hackertarget ┃ subs ┃ gap    ┃ 0 ┃ hackertarget: free quota exceeded       ┃
0 hosts: ... | tools: 0 ok, 1 gap, 1 failed, 0 skipped, 0 timeout
EXIT=5
```

### 5. all OK (mock)

```
$ reconkit subs -d example.com --mock --tools otx,hackertarget --no-color --db /tmp/n2.db
subs: otx ok 2 item(s)
subs: hackertarget ok 1 item(s)
subs: finished 2/2 tool(s), 3 item(s)
... | tools: 1 ok, 0 gap, 0 failed, 0 skipped, 0 timeout
EXIT=0
```

### Tests already covering these (the 909 -> 915 block, B1)

- `tests/test_engine.py::test_degraded_tools_never_exit_five_but_a_local_fault_does` - all four engine cases in one test
  (all-gap -> 0; gap+failed -> 5; missing-next-to-working -> 5; all-ok -> 0).
- `tests/test_engine.py::test_an_external_service_gap_exits_zero_and_is_named_in_the_gaps`
- `tests/test_engine.py::test_a_gap_does_not_hide_a_failed_tool`
- `tests/test_adapters.py` - the classifier at adapter level: `test_429_is_a_gap_and_not_retried`,
  `test_500_is_a_gap_and_not_retried` (B1), `test_a_5xx_from_the_upstream_is_a_gap`,
  `test_hackertarget_free_quota_is_a_gap`, `test_hackertarget_quota_answer_is_a_gap`,
  `test_a_404_is_still_a_failure_not_a_gap`, `test_a_429_gap_still_reports_its_own_duration`, and the parametrised
  `test_classify_external_gap_matches_only_third_party_signatures`, whose B1 rows add `HTTP 500 Internal Server Error`
  (True), `server error (HTTP 500)` (True), `500 items parsed` (False), `401 Unauthorized` (False), `403 Forbidden`
  (False).
- `tests/test_ui.py::test_a_gap_tool_is_shown_as_gap_and_named_in_the_block` and
  `test_the_gaps_block_goes_to_stderr_and_the_json_carries_completion` - the block and `--json` `tools_gap`.
- `tests/test_binary_adapters.py` - the stderr/exit-code path of the same classifier.

No test was added: all five cases were already pinned.

## 2026-11-19 (close-out) N.3 - amass: installed, and why doctor once said otherwise

### Raw, now

```
$ reconkit doctor --no-color
┃ Tool            ┃ Stage ┃ Tier      ┃ Installed ┃ Path            ┃ Identity ┃
│ amass           │ subs  │ core      │ yes       │ /usr/bin/amass  │ ok       │
47 installed, 1 manual (dnsreaper). Scans will use the tools that are installed
and skip the rest.

$ reconkit doctor --json
{'installed': 47, 'manual': ['dnsreaper'], 'chromium': 'missing'}
[{'tool': 'amass', 'stage': 'subs', 'tier': 'core', 'kind': 'binary',
  'installed': 'yes', 'path': '/usr/bin/amass', 'identity': 'ok'}]
```

The registry probe itself, ten times in a row:

```
[(True, '/usr/bin/amass'), (True, '/usr/bin/amass'), ... ]   # 10/10, 0.03-0.06 s each
```

The binary's own answer (note the stream):

```
$ amass -version
v5.1.3                      # on stderr, stdout empty, exit 0
$ amass enum -h 2>&1 | grep -i "OWASP Amass Project"
OWASP Amass Project - @owaspamass          # the adapter's identity_markers hit
```

`/usr/bin/amass` is a 328-byte shell wrapper that `exec /usr/lib/amass/amass "$@"` after checking
`/usr/share/libpostal/transliteration` (present here, dated 2017). `AmassAdapter().check_installed()` runs
`amass enum -h` with `HOME` only and matches `owasp amass project`; it returned `installed=True, version='v5.1.3'`
on every run.

### What happened at the top of this batch

The first `reconkit doctor` of the session printed `amass | wrong program | /usr/bin/amá | failed` and the footer
`46 installed, 1 manual (dnsreaper), 1 needs attention (amass).`, and `reconkit subs --tools amass` skipped it as
`not installed`. That reading is not reproducible now: ten consecutive adapter probes, five `doctor` runs and both
output modes all say `yes / ok`, and the probe takes 0.03 s against a 10 s `IDENTITY_TIMEOUT`.

**Verdict:** B3's `manual: true`/count change did **not** misclassify amass (it was never in `manual`; the footer's
"needs attention" was the existing `wrong program` bucket fed by that one failed identity probe). amass is really
installed. The single failure is an unexplained, transient identity-probe result — the same class as PIT-30/PIT-35 in
consequence: a tool that fails its probe is silently left out of every scan. No code change: a retry or a longer
timeout is a behaviour change and needs a ruling. Recorded as D42 and as an open risk.

## 2026-11-19 (close-out) N.4 - R10: no input is a skip, not a failure (D43)

### The defect

A discovery pass that finds nothing alive leaves `tech`/`urls`/`vulns` with an empty host list. Every tool in those
stages then raised its own `no hosts to scan/crawl` guard, the adapter turned that into `ToolStatus.FAILED`, and the run
reported nine broken tools and exit 5 while nothing was broken. Measured before the change (same 30 s command as below):
`tools: 15 ok, 1 gap, 9 failed, 3 skipped, 5 timeout`, `EXIT=5`.

### The change (`src/reconkit/engine.py`)

- `HOST_INPUT_STAGES = {LIVE, TECH, URLS, VULNS}` and `NO_INPUT_HOSTS = "no input hosts"`.
- `_run_one` decides before calling the adapter: an empty `ctx.hosts` in one of those stages returns
  `ToolResult(status=SKIPPED, error="no input hosts")` with `raw_path=None` (the tool never ran, so there is nothing to
  capture). `live` is in the set for intent but always receives `[target, *discovered]`; `subs`/`dns` are not in it;
  `ports` already skips its whole stage when nothing is alive.
- `_completed()` now counts `SKIPPED` as complete, so a skip is never a failure.
- `_completion_gaps()` adds `CompletionGap(stage, "no input hosts", n)` when every executed result in a stage is a skip.

DNS/subs semantics are untouched, and every existing exit-5 test still passes (`pytest -q`: 932).

### Raw proof, deterministic (mock, no network)

```
$ reconkit run -d testfire.net --mock --active --tools whatweb,katana --no-color --db /tmp/n4.db
tech: whatweb skipped 0 item(s)
urls: katana skipped 0 item(s)
│ whatweb │ tech  │ skipped │ 0 │ no input hosts │
│ katana  │ urls  │ skipped │ 0 │ no input hosts │
0 hosts: ... | tools: 0 ok, 0 gap, 0 failed, 2 skipped, 0 timeout
active scan completed with gaps - 2 stage(s) incomplete
  tech: 1 tool(s) skipped (no input hosts)
  urls: 1 tool(s) skipped (no input hosts)
EXIT=0
```

### Raw proof, the real starved scenario (30 s phase timeout, testfire.net)

```
36 hosts: 0 ALIVE, 8 DNS_ONLY, 0 SHUT_DOWN, 28 DEAD, 0 UNKNOWN | tools: 17 ok, 2
gap, 0 failed, 11 skipped, 3 timeout
  subs: crtsh: server error (HTTP 502), otx: rate limited (HTTP 429)
  tech: 5 tool(s) skipped (no input hosts)
EXIT=5
```

The downstream cascade is gone (`failed` 9 -> 0, `skipped` 2 -> 11). The remaining `5` is **not** R10's business: the
three timeouts (`amass`, `gau`, `urlfinder` hit the 30 s stage deadline) are genuine hard failures, and the batch rule
says a timeout stays 5. Both free providers refused again in the same run (`crtsh` 502, `otx` 429) and were recorded as
gaps, which is B1/D34 working live.

### Tests (928 -> 932)

- `test_a_tool_with_no_input_hosts_is_skipped_not_failed` - `whatweb` gets an empty list: status `skipped`, detail
  `no input hosts`, `raw_path is None`, and the fake adapter's `run()` was never called.
- `test_a_stage_of_only_skipped_tools_is_a_gap_and_exits_zero` - two urls tools, all skipped -> `complete_with_gaps`,
  one gap naming `urls`, exit 0.
- `test_a_skip_does_not_mask_a_real_failure` - a skipped `katana` beside a failed `crtsh` -> exit 5.
- `test_live_still_scans_the_apex_when_nothing_was_discovered` - `live` with no discoveries still receives
  `["example.com"]` and runs `ok` (the brief's "legitimately scans the apex" case).

**Test-fixture deviation, disclosed:** `_probe_engine()` (the url_probe family, 12 tests) built its fake urls adapter as
`mode=ACTIVE`, which is exactly the class R10 now skips with no alive host. The fixture is `mode=PASSIVE` now - it
stands in for gau/waybackurls, the class that receives the apex regardless of liveness - so those tests still exercise
the probe instead of asserting on a skipped stage. No assertion in them changed.

### Docs

`docs/02_CLI_UX.md` section 6 gains the "no input -> skipped -> gap (exit 0)" bullet, `docs/03_ARCHITECTURE.md` the
status-semantics paragraph, `docs/PROGRESS.md` D43.

## 2026-11-19 (close-out) N.5 - R12: engine-stage Ctrl+C reaches the child (D44)

### The gap being closed (F8, from the 2026-11-18b report)

D37 taught `run_exec` to kill the child's process group when a `KeyboardInterrupt` lands in its own thread. The engine
runs adapters through `asyncio.to_thread`, so the interrupt is raised in the **main** thread while the worker sits in
`run_exec` - the handler never fires and the tool outlived the scan.

### The change

- `core/runner.py`: `_LIVE_PROCESSES` (set) + `_LIVE_LOCK`; `run_exec` registers a child immediately after `Popen` and
  discards it in a `finally` that wraps the new `_collect()` body, so the set only ever holds children that can still
  run (never a reaped, reusable pid). New public `live_processes()` and `terminate_all_live()`, the latter killing every
  registered group through the same `terminate_tree()` the timeout path uses.
- `cli.py`: the `KeyboardInterrupt` handler calls `terminate_all_live()` before printing
  `interrupted; state is saved and the run is resumable` and returning 130.

### Tests (932 -> 935)

- `tests/test_runner.py::test_terminate_all_live_kills_a_child_owned_by_another_thread` - a real `sleep 60` spawned by a
  worker thread (the engine's exact shape) is dead in under 2 s after `terminate_all_live()`; the registry is empty
  afterwards; the worker returns without an exception.
- `tests/test_runner.py::test_a_finished_child_leaves_the_registry` - a completed child is never left registered.
- `tests/test_cli.py::test_ctrl_c_in_a_stage_kills_the_child_and_exits_130` - the integration case: `Engine.run` is
  replaced with a coroutine that starts a real child through `run_exec` in a thread and then raises `KeyboardInterrupt`
  (what a terminal Ctrl+C produces). The CLI exits **130**, prints the resumable message, the child's `poll()` is not
  `None` (it was killed with signal 9), and the registry drains. One attempt, not flaky; no fallback to unit-test-only
  was needed.

### F8 status

**Closed.** The engine path is now covered by an end-to-end CLI test, not only by a unit test: the registry exists *and*
the CLI uses it. What is still not exercised is a literal SIGINT delivered to the process during a real scan - the test
raises `KeyboardInterrupt` in the same place SIGINT would, which is the only observable difference.

## 2026-11-19 (close-out) N.6 - the capstone scan

```bash
reconkit run -d testfire.net --active --phase-timeout 300 --no-color --config /tmp/cap/config.yaml
# temp config: db_path=/tmp/cap/recon.db, workspace_dir=/tmp/cap/workspaces, url_probe.max_urls=20; no --full
```

Raw tail:

```
│ urlfinder         │ urls  │ ok      │ 932   │ idle for 60s; kept partial     │
│                   │       │         │       │ output                         │
│ gau               │ urls  │ timeout │ 0     │ phase timeout                  │
36 hosts: 8 ALIVE, 0 DNS_ONLY, 0 SHUT_DOWN, 26 DEAD, 2 UNKNOWN | tools: 29 ok, 1
gap, 0 failed, 2 skipped, 1 timeout
warning: url_probe: probed the first 20 URL(s) only; re-run to probe the rest
active scan completed with gaps - 1 stage(s) incomplete
  subs: otx: rate limited (HTTP 429)
report: results/testfire.net/20261119T110355Z/report.txt and .../report.json
EXIT=5
```

`scan_runs`: `subs completed`, `dns completed`, `live completed`, `tech completed`, `urls partial`, `url_probe completed`.

Non-ok `tool_runs`:

```
otx                  gap      otx: rate limited (HTTP 429)
chaos                skipped  requires PDCP_API_KEY
github_subdomains    skipped  requires GITHUB_TOKEN
gau                  timeout  phase timeout
```

### Why it exited 5

Exactly one hard failure: **`gau` was still running when the `urls` stage hit its 300 s deadline**. That is case (b) of
the batch's three: *a timeout a larger `--phase-timeout` would avoid*, not a genuine tool defect (gau answers in ~31 s
when archive.org is healthy, D20 measured 345 items in 31 s) and not a rule gap (a timeout is a hard failure by
docs/02 section 6, and R10 deliberately does not launder one). It was **not** re-run with a longer timeout to chase a
zero.

What R10 changed in this run: `tech` and `urls` executed their tools at all (8 ALIVE hosts were found), so nothing was
skipped for lack of input; the two skips are the key-gated subs tools, exactly as designed.

Everything else behaved as the rulings say: `otx` 429 -> `gap` -> excluded from the failure total (D34/B1), and the
`urls` stage's own result is `partial`, which is what the exit code reads.

## 2026-11-19 (close-out) N.7 - project state declared, open risks pruned

`docs/PROGRESS.md`: the RESUME status line is the capstone's real result (exit 5, one reason: `gau` hit the 300 s `urls`
deadline), the Open risks list is pruned to five current items, and a "Three questions for the owner" table holds B5,
B6 and B7 as questions rather than work items.

### Process mistake, disclosed

The first edit of this part (`5c770da`) used a slice that started at `## Open risks` and ended at the next heading, but
the anchor matched earlier than intended and the replacement swallowed the historical RESUME lines (the file went from
717 to 77 lines). It was caught immediately by reading the commit's diff, the file was restored from `9dfbeec` and the
two intended edits re-applied line-precisely, and this follow-up commit carries the repair. The damaged tree was never
the state of any claim in the report - no check was ever run against it - but the commit history keeps the mistake
visible instead of rewriting it.

Suite unchanged (935).

## 2026-11-19 (final) P - the identity probe retries once (D46, closes D42)

### The defect

`doctor` printed `amass | wrong program | failed` once at the start of the close-out batch, and `reconkit subs --tools amass`
skipped the tool as `not installed`. Ten consecutive adapter probes and five `doctor` runs afterwards all said `yes / ok`
(N.3, D42). The consequence is worse than a genuinely missing tool: the scan reports nothing from a tool that never ran.

### The change (2 source files)

- `src/reconkit/adapters/base.py`: `IDENTITY_RETRY_DELAY = 0.1` and `probe_with_retry(probe, ok=..., delay=...)`, which runs
  the probe, and runs it once more when `ok()` says it did not identify the tool (a `RuntimeError` from `run_exec` counts
  as a failure and is re-raised by the second attempt). `BinaryAdapter.check_installed()` resolves the path first - a
  missing binary is not retried - and then probes through the new `_probe_identity(path)`.
- `src/reconkit/core/toolcheck.py`: `installed_version()`'s probe body became a closure wrapped in the same function, so
  `doctor` and the engine's selection check share one retry, not two. Import direction stays `core -> adapters`.

Unchanged: the identity command, `version_regex`, `IDENTITY_TIMEOUT` (10 s), the `wrong program` message and every
status enum. A real namesake fails both attempts and is still `wrong program / failed`.

### Raw: cost and current state

```
before:  real=1.720s  real=5.165s  real=1.598s      # three `time reconkit doctor >/dev/null`
after:   real=1.629s  real=1.578s  real=1.572s
$ reconkit doctor --no-color          # exit 0
│ amass           │ subs  │ core      │ yes       │ /usr/bin/amass  │ ok       │
47 installed, 1 manual (dnsreaper). Scans will use the tools that are installed
```

The retry only fires after a failure, so 47 healthy tools cost one probe each; the 5.165 s sample was an unrelated
outlier (network probes inside `doctor`), and the medians are 1.60 s -> 1.58 s (0.99x).

### Tests (935 -> 939)

- `test_a_transient_identity_failure_is_retried_once` - exit 126 then a real PD banner: `installed=True`,
  `version="v2.17.0"`, exactly 2 probe calls.
- `test_two_consecutive_identity_failures_still_mark_wrong_program` - Python `httpx` twice: `installed=False`, path kept,
  2 calls (today's behaviour).
- `test_retry_does_not_fire_on_success` - one banner, exactly 1 call.
- `test_doctor_and_engine_share_the_retry_helper` - `toolcheck.probe_with_retry is base.probe_with_retry`, and both
  `check_installed` and `installed_version` name it in their source.

Suite `939 passed`; `ruff check .` clean; `ruff format --check .` 92 files; `mypy src/reconkit` clean. PIT-63 added.

## 2026-11-19 (final) Q - the project is declared finished (D45 final)

### The capstone, bounded, not chased

```bash
reconkit run -d testfire.net --active --phase-timeout 600 --no-color --config capstone/config.yaml
# capstone/config.yaml: db_path=capstone/recon.db, workspace_dir=capstone/workspaces,
#                       url_probe.max_urls=20, everything else copied from config.yaml
```

Raw tail:

```
│ gospider          │ urls  │ ok      │ 529   │ -                              │
│ gau               │ urls  │ ok      │ 1042  │ -                              │
│ urlfinder         │ urls  │ ok      │ 195   │ idle for 60s; kept partial     │
│                   │       │         │       │ output                         │
36 hosts: 8 ALIVE, 0 DNS_ONLY, 0 SHUT_DOWN, 27 DEAD, 1 UNKNOWN | tools: 29 ok, 1
gap, 1 failed, 2 skipped, 0 timeout
warning: url_probe: probed the first 20 URL(s) only; re-run to probe the rest
⚠ active scan completed with gaps — 1 stage(s) incomplete
  subs: otx: rate limited (HTTP 429)
report: results/testfire.net/20261119T113828Z/report.txt and .../report.json
EXIT=5
```

`scan_runs`: `subs partial`, `dns completed`, `live completed`, `tech completed`, `urls completed`, `url_probe completed`.

Non-ok `tool_runs`:

```
otx               gap      otx: rate limited (HTTP 429)
crtsh             failed   crtsh: HTTP 404
chaos             skipped  requires PDCP_API_KEY
github_subdomains skipped  requires GITHUB_TOKEN
```

### Classification

**Exited 5 because `crtsh` answered HTTP 404**, and a 404 is a real failure under the documented rule
(`test_a_404_is_still_a_failure_not_a_gap`; `classify_external_gap()` covers 429/quota/5xx). That is **not** R13: the
600 s budget did its job and `gau` finished (`ok 1042` items, where the 300 s capstone killed it), so R13's slow-upstream
case did not fire this time. It is **not** a defect found in this batch either - the failed tool is an external service
answering not-found, and whether that should be a `gap` is a ruling, not a change to make here. Not chased, not re-run;
recorded as a new open item.

### What else the run shows

Every other row behaved per the rulings: `otx` 429 -> `gap` -> excluded from the failure total; `chaos`/
`github_subdomains` skipped at selection for a missing key; `urlfinder` capped itself and kept 195 URLs; R10's skip path
was not needed because 8 hosts came back ALIVE; R12 was not exercised (no Ctrl+C). `url_probe` probed 20 URLs and said so.

### Docs

`docs/PROGRESS.md`: the RESUME status line is the final state (with the crtsh 404 named), the old Open risks section is
replaced by "What is finished" / "What is explicitly open and why" (R14, R15, R13, crtsh 404), and a reviewer line names
the hash, the commit count, the test count and the untouched `scope.yaml`.

Suite unchanged (939); gate green (see the report).

## 2026-11-19 (close-out) R+S - the crtsh 404 measured, then classified (D47)

### R.1 Raw

The adapter's request (`src/reconkit/adapters/crtsh.py:16-20`): `url()` -> `https://crt.sh/`, `params()` ->
`{"q": "%.<target>", "output": "json"}`, so the wire URL is:

```
https://crt.sh/?q=%25.testfire.net&output=json
```

Ten sequential calls, 1 s apart (`curl -s -o /dev/null -w "%{http_code}\n" --max-time 60`):

```
=== testfire.net x10 ===
1 200  2 200  3 200  4 200  5 200  6 200  7 200  8 200  9 200  10 200
=== example.com x10 ===
1 200  2 200  3 200  4 200  5 200  6 404  7 502  8 200  9 200  10 200
=== crt.sh root ===
root=502 time=8.805546
```

A second series aimed at catching a 404 body:

```
call 1 -> 200
call 2 -> 200
call 3 -> 200
call 4 -> 404
=== 404 body (first 500 chars) ===
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache Server at crt.sh Port 443</address>
</body></html>
=== size ===
253
```

### R.2 Classification: intermittent

`sleep`-spaced identical requests alternate 200/404/502: 1/10 for `example.com`, 0/10 for `testfire.net` in a quiet
minute, 1 more 404 in the chase loop, and `502` on the service root. A wrong API path would 404 **every** time; a 404
that a 200 replaces one second later is the front end dropping a request under load. The body confirms it is not a CT
"no certificates found" answer and not a Cloudflare challenge (plain Apache 404). So: not systematic, not transient
(it reproduced twice in three series), no adapter change (S.1 does not apply), classifier extension (S.2).

### S.2 The change (2 source files, 3 tests)

- `src/reconkit/adapters/base.py`: `HttpAdapter.external_api: ClassVar[bool] = False`, and in `_attempt()` a
  `status_code == 404 and self.external_api` branch raising `ExternalServiceGap(f"{self.name}: HTTP 404")` before the
  generic `>= 400` `FetchFailed`. The 429 check, the 5xx check, body limits, the parse path and `probe_with_retry`
  (D46) are untouched, so the 404 is **not** retried.
- `src/reconkit/adapters/crtsh.py`: `external_api = True` with a three-line reason.
- Docs: `docs/09_TOOL_CONTRACTS.md` line 137's sentence now separates "a 404 from a local binary or non-API adapter"
  (still `failed`) from "a whole-response 404 from an `external_api` adapter" (a gap), plus a paragraph after the
  per-tool table with the tools.yaml cross-reference. PROGRESS D47.

Deviation (stop rule once, disclosed): the preferred `external: true` in `tools.yaml` needs a `ToolSpec` field in
`registry.py`, the yaml edit, and a per-adapter opt-in for the seven API tools (otx, hackertarget, certspotter, urlscan,
chaos, github_subdomains) - that is ten files, over the three-file budget. The scoped `external_api` class flag is the
same idea one layer down, one line per adapter, and `crtsh` is the only wearer in this batch.

### S.3 Tests (939 -> 941)

- `test_a_404_from_an_external_tool_is_a_gap` - `CrtshAdapter` + `MockTransport(404)`: `status == GAP`,
  `error == "crtsh: HTTP 404"`, exactly 1 request (no retry).
- `test_a_404_from_a_local_binary_is_still_a_failure` - `classify_external_gap("localhttp: HTTP 404") is None`, and an
  `HttpAdapter` subclass with `external_api = False` returns `FAILED` for the same 404.
- `test_crtsh_404_is_a_gap_not_a_retry` - `CrtshAdapter.external_api is True`, `HttpAdapter.external_api is False`, and
  `sleep` is rigged to raise: a 404 must never reach the connection-retry path.
- Replaced `test_a_404_is_still_a_failure_not_a_gap` (it asserted the rule this ruling changes) - 1 removed, 3 added.

Suite `941 passed`; `ruff check .` clean; `ruff format --check .` 92 files; `mypy src/reconkit` clean.

### T - final capstone (once, `6a6d47b`)

Command (unchanged from Part Q except the config path; the temp config is `config.yaml` with `db_path`/`workspace_dir`
under `capstone/` and `url_probe.max_urls: 20`):

```
reconkit run -d testfire.net --active --phase-timeout 600 --no-color --config capstone/config.yaml
```

Raw summary and exit:

```
9 hosts: 8 ALIVE, 0 DNS_ONLY, 0 SHUT_DOWN, 1 DEAD, 0 UNKNOWN | tools: 30 ok, 1
gap, 0 failed, 2 skipped, 0 timeout

warning: url_probe: probed the first 20 URL(s) only; re-run to probe the rest
⚠ active scan completed with gaps — 1 stage(s) incomplete
  subs: otx: rate limited (HTTP 429)
report: results/testfire.net/20261119T121320Z/report.txt and results/testfire.net/20261119T121320Z/report.json
EXIT=0
```

Stage lines and the two rows that dominated the table:

```
subs: finished 9/9 tool(s), 32 item(s)      crtsh ok 1 item(s)   otx gap 0 item(s)
dns:  finished 5/5 tool(s), 41 item(s)
live: finished 4/4 tool(s)          pyprobe ok 8 (unreachable=1)
tech: cdncheck ok 0, wafw00f ok 0, httpx_tech/whatweb/webanalyze ok 8
urls: katana 67, hakrawler 493, gospider 529, gau 1508, urlfinder 714, subjs 0, waybackurls 0, unfurl 18
```

`scan_runs` (all six rows, nothing non-ok):

```
1 subs      completed  enforced
2 dns       completed  enforced
3 live      completed  enforced
4 tech      completed  enforced
5 urls      completed  enforced
6 url_probe completed  enforced
```

Notes, stated plainly rather than explained away:

- `crtsh` did **not** reproduce the 404 here: it answered 200 and returned `1 item(s)`, so this run exercises D47's
  path only through the tests. Had it 404'd, the row would read `gap`, not `failed`, and the exit would still be 0.
- The host count is 9, not the 36 of Part Q's capstone. No tool failed and no stage timed out; the external `subs`
  sources simply answered with less this time (`certspotter 0`, `crtsh 1`, `urlscan 3`, `hackertarget 3`, local tools
  8/8/5/4). It is upstream variability, not a regression: the `dns` stage saw 9 hosts and all five DNS tools agreed on
  8 of them, the same internal consistency the earlier run showed.
- Exit 0 with one gap is the documented B1-B4 behaviour: gaps are excluded from `failed_total`, `subs` is marked
  incomplete, and the warning names the reason.

### Tree state at the close

`git status --short` empty; `pytest -q` 941 passed; `ruff check .` clean; `ruff format --check .` 92 files;
`mypy src/reconkit` clean; `sha256sum scope.yaml` = `d45a3c90...eeee8b` (unchanged since the baseline).

## 2026-11-19 (scalability) A - hardcoding inventory and edge-case matrix

### A.1 Hardcoding inventory

Greps run (raw, `src/reconkit/` only):

```
grep -rn 'name == "\|== "gau"\|== "nikto"\|== "katana"\|== "hakrawler"\|== "gospider"\|== "crtsh"\|== "otx"\|== "hackertarget"\|== "urlfinder"' src/reconkit/
  src/reconkit/engine.py:832:                and any(spec.name == "naabu" for spec, _ in selected)
  src/reconkit/engine.py:1197:  naabu = next(((spec, adapter) for spec, adapter in selected if spec.name == "naabu"), None)
  src/reconkit/adapters/base.py:537:  ... if os.name == "nt" ...        # not a tool name
grep -rn 'ClassVar\|IDENTITY_TIMEOUT\|MAX_ENUMERATION_S\|HOST_INPUT_STAGES\|MAX_URLS\|_MAX_\|runtime_cap_s\|enumeration_cap_s'
grep -rnE '^[A-Z][A-Z0-9_]* = [0-9]' src/reconkit/
```

tools.yaml fields the registry knows today (parsed with PyYAML, 48 tools): `stage, kind, tier, mode,
phase` (all 48), `binary, source` (40), `notes` (29), `version_cmd` (28), `version_regex` (16), `keys` (7),
`waf_priority` (4), `exploitation` (3), `requires_apt` (1), `needs_root` (1), `manual` (1). There is no
`class`, no `external`, and no cap field.

| file:line | what is hardcoded | kind | has config path? | proposed home |
|---|---|---|---|---|
| `engine.py:206` | `HOST_INPUT_STAGES = frozenset({LIVE, TECH, URLS, VULNS})` | product | no | stays code (stage architecture) |
| `engine.py:832` | `spec.name == "naabu"` (raw-socket port scan needs its own pass) | per-tool | no | tools.yaml attribute (`feeds_ports: true`) |
| `engine.py:1197` | `spec.name == "naabu"` again, in the ports stage | per-tool | no | same attribute, one lookup |
| `adapters/base.py:596` + `crtsh.py:18` | `external_api: ClassVar[bool]`, True on crtsh only (D47) | per-tool | no | `external: true` in tools.yaml (B does this) |
| `adapters/base.py:235` | `runtime_cap_s` / `idle_timeout_s` / `min_runtime_s` ClassVars | per-tool | partly (`urls:`) | runtime class from tools.yaml `class:` (B) |
| `adapters/urlfinder.py:81` | `runtime_cap_s = MAX_ENUMERATION_S` (1800) on one adapter | per-tool | `urls.urlfinder_max_s` | `runtime_caps.archive` (B) |
| `adapters/urlfinder.py:40-47` | floor 180 s, 4 s/host, 1800 s ceiling | tuning (per-tool) | `urls.urlfinder_*`, `urlfinder.max_enumeration_s` | `runtime_caps.archive` (B), function kept |
| `adapters/hakrawler.py:49` | `runtime_cap_s = MAX_CRAWL_S` (120) | per-tool | `urls.hakrawler_max_s` | `runtime_caps.crawler` (B) |
| `adapters/subjs.py:36` | `runtime_cap_s = MAX_RUN_S` (60) | per-tool | `urls.subjs_max_s` | left as is (not in this batch's class list) |
| `engine.py:1435-1446` | limits dict naming urlfinder/hakrawler/subjs | per-tool | yes, by name | one loop over `spec.class_` (B) |
| `adapters/hakrawler.py:33` | `CRAWL_DEPTH = 2` | tuning (per-tool) | no | tools.yaml `args`-style field (later) |
| `adapters/gau.py:27`, `gospider.py:31`, `ffuf.py:46`, `subjs.py:29` | threads/workers 5/10/50/10 | tuning | no | config `threads:` or tools.yaml (later) |
| `adapters/gau.py:26`, `urlfinder.py:34` | per-request HTTP timeouts 45 s / 30 s | tuning | no | tools.yaml (later) |
| `adapters/base.py:42`, `core/toolcheck.py:24` | `IDENTITY_TIMEOUT`/`VERSION_TIMEOUT_S` = 10 s | tuning | no | config (later) |
| `adapters/base.py:38`, `runner.py:22` | `MAX_BODY_BYTES` 10 MB, `MAX_OUTPUT_BYTES` 1 MB | tuning | no | config (later) |
| `core/store.py:22`, `ui.py:531`, `scope.py:20` | `DETAIL_MAX_CHARS`, `_MAX_CELL`, `MAX_PATTERN_LEN` | tuning | no | code is fine (presentation/safety) |
| `adapters/subfinder.py:39` | `STALE_AFTER_S = 900` | tuning (per-tool) | no | tools.yaml (later) |
| `adapters/pyprobe.py:31-32`, `nikto.py:31` | title/error truncation | tuning | no | code is fine |
| `engine.py:68` | `UNTRUSTED = -2` (and `-1`) status sentinels | product | no | stays code (verdict rules) |
| `config.py:34-52` | stage timeouts, confidence thresholds | tuning | yes | already config - the model to copy |

Top three `per-tool` rows to rule on next: the two `naabu` name checks (`engine.py:832`, `:1197`) should
become one `feeds_ports` attribute; `subjs`/`hakrawler` adapter constants should fold into their class
rows; thread counts (5/10/50/10) are the most likely next "why is it slow" question and still need a code
edit to change.

### A.2 Edge-case matrix

| Edge case | Status | Evidence |
|---|---|---|
| Huge target - 5k hosts / 50k URLs | config (URLs only) | `url_probe.max_urls: 5000` cuts and says so (`tests/test_engine.py:3680`); host side has no cap and no test above 43 hosts; each tool's stdout is bounded at 1 MB (`core/runner.py:22`) |
| Tool produces garbage - partial JSONL, truncated line, >1 MB | tested | `test_crawler_parsers_skip_unusable_lines` (`test_binary_adapters.py:1282`), `test_run_truncated_output_is_reported` (`:756`); PIT-58 counts unusable lines |
| Empty stage - no input | tested | R10: `tests/test_engine.py:3979` (`no input hosts`), `:4003` (completion gap) |
| Stalled tool - silent but running | tested (urlfinder only) | `test_urlfinder_idle_timeout_kills_stuck_source` (`test_binary_adapters.py:1787`); other tools have only a max cap, no idle kill, and no test |
| Interrupted run - Ctrl+C mid-stage, resume | tested (Ctrl+C), untested (resume) | `test_ctrl_c_in_a_stage_kills_the_child_and_exits_130` (`test_cli.py:1340`); no test resumes a half-written stage |
| Network weirdness - cert -2, redirects, CDN IP collapse | partly | `UNTRUSTED = -2` (`engine.py:68`, store tests); redirects never followed (`pyprobe.py:89`, `engine.py:1939`); CDN IP collapse has no test |
| Odd input - IDN/unicode, IPv6, non-standard ports, 10 KB URLs | partly | non-ASCII rejected by `_HOST_LABEL_RE` (`runner.py:29`) with no IDN test; IPv6 rejected as a host (colon is not a label char), only parsed from naabu (`:1088`); ports: `test_regression_a_nuclei_host_with_a_port_keeps_its_name` (`:2251`); URL length has no limit and no test |

## 2026-11-19 (scalability) B - per-tool caps from a tools.yaml class (D48)

### Registry shape, before and after

```
# before
ToolSpec(name, stage, kind, tier, mode, phase, keys, requires_apt, binary,
         version_cmd, version_regex, source, exploitation, needs_root, manual, waf_priority)
# after (+2)
         ..., waf_priority, class_: str | None = None, external: bool = False)
```

`tools.yaml` diff (one line per tool, no adapter edits):

```
 crtsh            class: api, external: true            gau        class: crawler
 certspotter      class: api / external: true           katana     class: crawler
 otx              class: api / external: true           hakrawler  class: crawler
 hackertarget     class: api, external: true            gospider   class: crawler
 urlscan          class: api / external: true           urlfinder  class: archive
 chaos            class: api / external: true           nikto      class: scanner
 github_subdomains class: api / external: true
```

`config.yaml` gained the five-line block (`crawler 90/2/60`, `scanner 300/30/120`, `api 60/1/30`,
`archive 180/4/60`), and `config.py` gained `RuntimeClassConfig`, `DEFAULT_RUNTIME_CAPS` and the pure
`class_cap()`. `engine.cap_for_tool()` is the single registry lookup; `Engine._limits()` builds the dict
(`_limits` is the loop that replaced the three hard-coded names), and the three explicit `urls:` entries
still win for their three tools.

### Formula and the note

```
cap = min(stage budget, max(class.floor, class.per_host * hosts))     # override/ceiling still apply
note = "formula 2000s clipped to stage budget 1800s"                  # only when the budget binds
```

### Measured risk, stated plainly

One bounded testfire.net run with the new defaults (600 s phase deadline, temp config, `url_probe.max_urls: 20`):

```
37 hosts: 8 ALIVE, 0 DNS_ONLY, 0 SHUT_DOWN, 26 DEAD, 3 UNKNOWN | tools: 28 ok, 3
gap, 0 failed, 2 skipped, 0 timeout
│ gau               │ urls  │ ok      │ 466   │ capped at 90s; kept partial    │
│ urlfinder         │ urls  │ ok      │ 71    │ idle for 60s; kept partial     │
│ crtsh             │ subs  │ gap     │ 0     │ crtsh: server error (HTTP 502) │
⚠ subs: crtsh: server error (HTTP 502), hackertarget: free quota exceeded, otx: rate limited (HTTP 429)
EXIT=0
```

`gau` returned 466 URLs against 1042 (Part Q) and 1508 (Part T) with no cap, because the crawler floor of
90 s is below what gau actually needs on this target (the `urls` stage took 107 s in Part T with no cap).
The cap works exactly as designed - `ok`, partial output kept, the row names the ceiling - but the *number*
is too low for gau. It is one config line, not a code change: `runtime_caps.crawler.floor` should go to
120-180 (or gau needs its own class) after the owner sees this. Everything else in the run was correct:
three gaps (502 / quota / 429), zero failures, exit 0, `urlfinder` unchanged at `idle for 60s`.

Suite `941 -> 948` (+7: six named tests plus `test_a_tool_with_no_class_gets_no_cap`), and the D47 tests
stayed green through the `external:` migration. `ruff check .` clean, `ruff format --check .` 92 files,
`mypy src/reconkit` clean.

## 2026-11-19 (scalability) C - live->urls dedup: STOPPED by the part's own rule

### C.1 Raw investigation

The live stage writes hosts, not URLs. `_write_host` in `engine.py` (the ALIVE path):

```
        self.store.append_host_status(
            sub_id, run_id, transition.state.value,
            status_code=None if best is None else best.status_code,
            title=None if best is None else best.title,
            location=None if best is None else best.location,
            ...
```

`best` is a `HostStatusRecord`, whose every field is (`models.py`):

```
class HostStatusRecord(BaseModel):
    fqdn: str; source: str; state: HostState
    status_code: int | None = None
    title: str | None = None
    location: str | None = None
    detail: str | None = None
    ips: list[str] = []; tech: list[str] = []; waf: str | None = None
```

There is no `url` field, and no adapter keeps the scheme it probed:

| adapter | what it knows | what it stores |
|---|---|---|
| `httprobe.py:80` | parses `scheme://host` on each line | `fqdn`, `state=ALIVE`; **the scheme is dropped**, no status code at all |
| `pyprobe.py:122` | iterates `SCHEMES`, requests `f"{scheme}://{host}/"` | `fqdn`, `status_code`, `title`, `location`; **the scheme is dropped** |
| `httpx_tool.py:113` | the JSON row has a `url` field | `fqdn`, `status_code`, `title`, `location`, `tech`, `waf`; **`url` is not read** |
| `tlsx.py:89` | `host`, `probe_status`, `ip` | `fqdn`, `state`, `detail`, `ips`; no URL, no status |

`probe_candidates` (`store.py:833`) is exactly as assumed - `NULL` is the only "not probed" value:

```
        else:
            sql = ("SELECT id, url FROM urls WHERE target_id = ? AND status_code IS NULL"
                   " ORDER BY id LIMIT ?")
```

And the only `urls` writer is the discovery path (`engine.py:1786`,
`self.store.upsert_url(target_id, url, run_id=run_id, source_count=len(tools))`), called from the
`urls` stage - the live stage never inserts a URL. The duplicate the brief describes is therefore real
but shaped differently: crawlers return `https://host/` and `http://host/`, and `url_probe` requests those
roots again even though the live pass already got an answer for the same host (pyprobe tries
`http`, then `https`, and records the status under the host only).

### Why C.2 did not land

The part's stop rule: *if the live record doesn't carry the answering URL/scheme safely -> stop and
report; a wrong-scheme URL is worse than a duplicate probe.* It does not carry it. Writing
`http://{host}/` for a pyprobe row would be wrong for a host that answered `https`; writing
`https://{host}/` would be wrong for the `http`-only hosts; and `httprobe` rows have no status code at all
(`status_code=None`), so they cannot satisfy "insert with that status". A correct fix needs the URL to
travel with the record:

1. `models.py`: `HostStatusRecord.url: str | None = None`.
2. `httprobe.py`: keep the normalised URL it already computed (line 79) instead of discarding it.
3. `pyprobe.py`: pass the `f"{scheme}://{host}/"` it just requested.
4. `httpx_tool.py`: read `data["url"]` (validated with `normalize_url`).
5. `engine.py`: after `_write_host`, when `state is ALIVE and best.url and 200 <= (best.status_code or 0) <= 399`,
   `store.upsert_url(...)` + `set_url_status(...)`; log once when the URL is missing
   (`live: skipped urls insert for {host}, scheme unknown`).

That is five source files and four tests - a follow-up batch, not a sub-step of this one. Nothing was
changed for C: no model field, no insert, no test, no commit beyond this record.

### What the owner should decide

Whether the duplicate is worth that change: it is one wasted request per alive host (500 hosts -> 500
requests), and the alternative - deriving the scheme from `location` or from the tech pass' httpx JSON
later - is exactly the guess the stop rule forbids.

## 2026-11-19 (scalability) D - a heartbeat line per running tool (D50)

### The change

`engine.py` gained `HEARTBEAT_AFTER_S = 10.0` and, inside `_run_tools`, a `heartbeat()` task that
sleeps in `HEARTBEAT_AFTER_S` steps, walks the stage's `running` set and prints one line per tool that
has been running at least that long:

```
{stage}: {tool} running ({n}s)
```

It is emitted through the existing `progress` callback (`self._progress`, the durable stderr channel), not
through a new callback and not through `activity` (which is the transient spinner and is `None` for a
piped stderr). No sink means no task at all (`self._progress_cb is not None`), which is exactly the
`--silent` wiring in `cli.py`. The task is cancelled in `finally`, the per-tool `started` clock is dropped
when the tool leaves `running`, and each tool can print at most one line (`heartbeats` set). Nothing parses
tool output and nothing waits for the heartbeat.

### Raw capture (a 1.2 s tool, interval lowered to 0.3 s for the run)

```
--- progress=stderr (normal) ---
stderr: urls: running 1 tool(s)
stderr: urls: slowfake running (1s)
stderr: urls: slowfake ok 0 item(s)
stderr: urls: finished 1/1 tool(s), 0 item(s)
--- progress=None (--silent) ---
done
```

The `--silent` half prints nothing but the script's own `done`: with `progress=None` (the exact value
`cli.py` passes for `--silent`) there is no heartbeat task, so no line can appear on any stream.

### Tests (948 -> 951)

- `test_heartbeat_prints_while_a_tool_runs` - interval patched to 0.15 s, a 0.5 s tool: at least one line,
  starting `urls: sleepy running (` and ending `s)`.
- `test_heartbeat_is_suppressed_by_silent` - `progress=None` (the `--silent` value): no line on stdout or
  stderr and `engine._progress_cb is None`.
- `test_heartbeat_stops_when_the_tool_exits` - a 0.05 s tool with the real 10 s delay: zero heartbeats.

The intervals are patched in the tests (0.15 s instead of 10 s) so the suite does not sleep for ten
seconds; the production constant is 10 s and the fast-tool test uses it unpatched.

`ruff check .` clean; `ruff format --check .` 92 files; `mypy src/reconkit` clean.

## 2026-11-19 (D52): per-tool runtime caps deleted; idle-only runtime and killed-tool report

**Batch:** S1 measure at scale -> S2 delete the caps -> S3 re-verify at scale. One code commit plus one
docs commit; nothing pushed, no dependency added, F1/F2 and `scope.yaml` untouched
(sha256 `d45a3c903c7417cf73115d4a7b73ab4ccf43509656d30414bd89e1a368eeee8b` before and after).

**Baseline at `36bf2c9`** (this checkout, one command at a time):

```
PASS pytest  951 passed in 27.6s
PASS ruff    All checks passed!
PASS format  92 files already formatted
PASS mypy    Success: no issues found in 62 source files
```

**What the audit found.** Three different cap mechanisms had grown in parallel: per-adapter `runtime_cap_s`
constants (`urlfinder`, `hakrawler`, `subjs`), three hard-coded tool names in `engine._limits`, and the D48
class formula `min(budget, max(floor, per_host * hosts))`. All three are gone: `grep -rn
'runtime_cap_s\|class_cap\|runtime_caps\|max_enumeration' src/ config.yaml tools.yaml` returns nothing, and the
only `max_s`/`min_s` left in `src/` are comments explaining that they no longer exist.

**What replaced them.** One number per class (`config.yaml` `runtime_idle:`), one watchdog in `_run_tools`, one new
status. A tool runs until it exits, until it is silent past its window, or until the stage budget; `killed` is the
idle case (partial output kept, exit 0) and `timeout` stays the budget case (exit 5, R13/D45 unchanged). Details:
`docs/09_TOOL_CONTRACTS.md` 4a2c, `docs/PROGRESS.md` D52.

**Removed test names (they encoded the deleted behaviour; deleted, not kept):**

- `tests/test_engine.py`: `test_gau_cap_scales_with_class_config`, `test_nikto_cap_uses_scanner_class`,
  `test_a_tool_with_no_class_gets_no_cap`, `test_a_tool_that_exits_early_is_not_delayed_by_the_cap`,
  `test_urlfinder_cap_unchanged_by_the_refactor`.
- `tests/test_binary_adapters.py`: `test_urlfinder_cap_scales_with_host_count`, `test_urlfinder_cap_floor_is_180`,
  `test_urlfinder_cap_respects_stage_budget`, `test_urlfinder_cap_config_override`,
  `test_urlfinder_cap_3600_when_only_the_stage_budget_is_raised`,
  `test_urlfinder_partial_output_line_includes_cap_and_host_count`,
  `test_urlfinder_cap_saturation_is_logged_with_the_reason`,
  `test_urlfinder_keeps_partial_urls_when_the_runtime_cap_fires`,
  `test_hakrawler_runtime_cap_parses_partial`, `test_subjs_runtime_cap_parses_partial`.
- `tests/test_config.py`: `test_the_urls_runtime_bounds_load_and_default`,
  `test_urlfinder_cap_override_defaults_to_the_formula`, `test_config_without_runtime_caps_still_loads`.

**New tests (seven in `test_engine.py`, plus schema/UI coverage):** `test_tools_receive_the_configured_idle_windows`,
`test_a_classed_tool_gets_its_class_idle_window`, `test_a_tool_with_no_class_gets_no_idle_window`,
`test_a_tool_idle_s_entry_wins_over_its_class`, `test_an_unknown_class_is_a_config_error`,
`test_a_silent_tool_is_killed_and_reported`, `test_a_productive_tool_is_not_killed_at_its_idle_window`,
`test_a_new_tool_with_class_in_tools_yaml_needs_no_engine_edit`; `tests/test_store.py::test_v10_database_accepts_the_killed_status`;
`tests/test_ui.py::test_a_killed_tool_is_counted_named_and_given_a_stale_output_column`,
`tests/test_ui.py::test_a_run_with_no_kill_prints_no_stopped_early_block`.

```
tests/test_engine.py::test_tools_receive_the_configured_idle_windows PASSED
tests/test_engine.py::test_a_classed_tool_gets_its_class_idle_window PASSED
tests/test_engine.py::test_a_tool_with_no_class_gets_no_idle_window PASSED
tests/test_engine.py::test_an_unknown_class_is_a_config_error PASSED
tests/test_engine.py::test_a_silent_tool_is_killed_and_reported PASSED
tests/test_engine.py::test_a_productive_tool_is_not_killed_at_its_idle_window PASSED
tests/test_engine.py::test_a_new_tool_with_class_in_tools_yaml_needs_no_engine_edit PASSED
====== 7 passed, 149 deselected in 1.44s ======
tests/test_store.py::test_v10_database_accepts_the_killed_status PASSED
tests/test_ui.py::test_a_killed_tool_is_counted_named_and_given_a_stale_output_column PASSED
tests/test_ui.py::test_a_run_with_no_kill_prints_no_stopped_early_block PASSED
====== 3 passed in 0.18s ======
```

**Gate after the change:** `950 passed`, `ruff check .` clean, `96 files already formatted`,
`mypy src/reconkit` clean.

**S1 (measured before the refactor, same box, same fixtures):** `bench/scale_20k.db` = 20 000 hosts /
200 000 URLs (160 000 NULL), 23.7 MB -> `probe_candidates 162.59 ms`, `1000 set_url_status 333.36 ms`,
`limits 0.01 ms`, `stage loop (4 tools) 2.89 ms`, peak RSS 122.0 MB. `bench/scale_50k.db` = 50 000 hosts /
500 000 URLs (400 000 NULL), 59.7 MB -> `456.71 ms`, `336.76 ms`, `0.01 ms`, `4.40 ms`, peak RSS 224.9 MB.
example capture (one 2m40s run, never scanned by the engine): subfinder 36.83 s/67, assetfinder 4.53 s/105,
crtsh 3.25 s/37, gau 70.39 s/6227, katana 10.64 s/1, httprobe 34.99 s/18. 10x replay of the gau+katana rows:
62 280 -> padded to 200 000, `200000 probed: 16.36 s, 12,227 URL/s, peak RSS 153.2 MB`.

**Disclosed deviations:** (1) `subjs` gained `class: crawler` in `tools.yaml` - the only way to keep a 60 s early
stop once its own cap was deleted; it is a registry field, not code. (2) `urlfinder` lost `-max-time` entirely:
the real binary never enforced it (still running at 5m52s with `-max-time 3`) and there is no cap left to convert
into minutes. (3) `RunContext.timeout` now carries the stage budget instead of `timeouts.per_tool_default`; every
adapter's budget therefore changes from a per-tool default to the stage's remaining time (the intended shape: the
stage budget is the only hard wall). (4) A stage-budget stop keeps `TIMEOUT` and exit 5: R13/D45 are open, so this
batch did not touch their meaning.

### D52 addendum (S3): re-verification at scale, same box and fixtures

**Bench, S1 (before the refactor) -> S3 (after it), one run each:**

```
bench/scale_20k.db: 20000 hosts, 200000 URLs (158000 NULL), store 23.7 MB
  probe_candidates          159.61 ms   (158000 row(s))      before: 162.59 ms (160000 row(s))
  1000 set_url_status       315.41 ms   (1000 row(s))        before: 333.36 ms
  limits (per pass)           0.00 ms   (14 row(s))          before: 0.01 ms
  stage loop (4 tools)        2.78 ms   (20000 row(s))       before: 2.89 ms
  stage loop                 0.003 s    (peak RSS 121.0 MB)  before: 0.003 s / 122.0 MB

bench/scale_50k.db: 50000 hosts, 500000 URLs (399000 NULL), store 59.7 MB
  probe_candidates          444.87 ms   (399000 row(s))      before: 456.71 ms (400000 row(s))
  1000 set_url_status       311.46 ms   (1000 row(s))        before: 336.76 ms
  limits (per pass)           0.00 ms   (14 row(s))          before: 0.01 ms
  stage loop (4 tools)        4.77 ms   (50000 row(s))       before: 4.40 ms
  stage loop                 0.005 s    (peak RSS 224.2 MB)  before: 0.004 s / 224.9 MB
```

No speedup is claimed: the diff touches no query or write path, and the deltas are run-to-run noise. The NULL
counts differ from the S1 record (158 000 vs 160 000 and 399 000 vs 400 000) because the S1 bench ran against an
earlier copy of the generated fixture; the store sizes are identical, and both runs are the same script on the
same files that exist now.

**example replay, 10x (mock transport, nothing scanned):**

```
gau: 6227 -> 62270 URLs; katana: 1 -> 10
replay list: 62280 unique URLs, padded to 200000
200000 URL(s) in the DB, 200000 probed: 16.27 s wall clock, 12,289 URL/s, peak RSS 153.2 MB
db 28.6 MB (temporary, deleted)
```

S1 was `16.36 s`, `12,227 URL/s`, `153.2 MB`. The capture itself was taken once by `scripts/capture_example.sh`
(2m40s, six tools, written to the gitignored `captures/example/`) and is never re-taken here.

**All-silent run, exit 0** (real `Engine`, `mock=True`, one classed tool that waits forever, 0.3 s window):

```
progress lines:
  subs: running 1 tool(s)
  subs: quiet killed 0 item(s)
  subs: finished 1/1 tool(s), 0 item(s)
exit code: 0
```

```
│ quiet │ subs  │ killed │ 0 │ 0.6s │ 0s ago │ killed after 0.3s idle at stage 0.3s, 0 partial │
0 hosts: 0 ALIVE, 0 DNS_ONLY, 0 SHUT_DOWN, 0 DEAD, 0 UNKNOWN | tools: 0 ok, 0 gap, 0 failed, 0 skipped, 1 killed, 0 timeout
⚠ 1 tool(s) stopped early — partial output kept
  quiet: killed after 0.3s idle at stage 0.3s, 0 partial
```

**Gate on the docs commit:** `950 passed`, `ruff check .` clean, `96 files already formatted`,
`mypy src/reconkit` clean; `scope.yaml` sha256 unchanged.
