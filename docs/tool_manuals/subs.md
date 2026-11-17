# Tool manuals - subs

Stage `subs` of `reconkit`. Verified on the canonical Kali checkout
(`/home/kali/Desktop/reconkit`, Python 3.14.8) on **2026-11-16**. Every
`--help` block and every test block below is the tool's own raw output,
captured on that machine; nothing here is written from memory.

Authorized target used for the one safe test: **testfire.net** (already in
`scope.yaml`). One command per tool, no payloads, no brute force.

Tools from the `vulns` stage are deliberately absent - see
`docs/tool_manuals/README.md` ("Skipped").

| Tool | Kind | Tier | Mode | Phase | Adapter in this build |
|---|---|---|---|---|---|
| `crtsh` | http | core | passive | 2 | yes |
| `certspotter` | http | core | passive | 2 | yes |
| `otx` | http | core | passive | 2 | yes |
| `hackertarget` | http | core | passive | 2 | yes |
| `urlscan` | http | core | passive | 3 | no |
| `subfinder` | binary | core | passive | 2 | yes |
| `assetfinder` | binary | core | passive | 2 | yes |
| `findomain` | binary | core | passive | 3 | no |
| `chaos` | binary | core | passive | 3 | no |
| `github-subdomains` | binary | core | passive | 3 | no |
| `amass` | binary | core | passive | 3 | no |



---

## `crtsh`

- **Registry:** http, core, passive, phase 2, `stage: subs`
- **Adapter in this build:** `src/reconkit/adapters/crtsh.py`
- **Official source used:** https://crt.sh/
- **Installed on this box:** n/a - HTTP source, no binary
- **Install command:** nothing to install (`install: {method: none}`)
- **Multi-domain input:** n/a - the adapter sends one query per target

#### Real request

```
curl -sS -o crtsh.body -w "%{http_code}" 'https://crt.sh/?q=%25.testfire.net&output=json'
```

Output (raw summary, exit 0):

```
HTTP 200, 8343 bytes, 24 entries
keys: ['common_name', 'id', 'issuer_ca_id', 'issuer_name', 'name_value', 'not_after', 'not_before', 'result_count']
first name_value: demo.testfire.net
```

#### What a normal exit code looks like

`curl` exits 0 on any HTTP status; the adapter treats only a 200 with a JSON
array as data, and 429/5xx/timeouts as a failed `ToolResult`.

#### Gotchas

- crt.sh 404s when `%` is not percent-encoded (`q=%.example.com`); the adapter
  uses httpx params, which encode it.
- No API key exists and none is needed.


---

## `certspotter`

- **Registry:** http, core, passive, phase 2, `stage: subs`
- **Adapter in this build:** `src/reconkit/adapters/certspotter.py`
- **Official source used:** https://sslmate.com/help/reference/ct_search_api_v1
- **Installed on this box:** n/a - HTTP source, no binary
- **Install command:** nothing to install (`install: {method: none}`)
- **Multi-domain input:** n/a - one domain per request

#### Real request

```
curl -sS -o certspotter.body -w "%{http_code}"   'https://api.certspotter.com/v1/issuances?domain=testfire.net&include_subdomains=true&expand=dns_names'
```

Output (raw, exit 0):

```
HTTP 200, body: []
```

An unauthenticated call answers 200 with an empty array (the free evaluation
limit). With `CERTSPOTTER_API_KEY` in `.env` the adapter sends
`Authorization: Bearer <key>` and gets entries carrying `dns_names`.

#### What a normal exit code looks like

Exit 0 with a JSON array. `[]` means "no certificates returned", not an error.
A 429/5xx is a failed `ToolResult`.

#### Gotchas

- The `expand=dns_names` parameter is what makes the array carry `dns_names`;
  without it the response has no names field to parse.


---

## `otx`

- **Registry:** http, core, passive, phase 2, `stage: subs`
- **Adapter in this build:** `src/reconkit/adapters/otx.py`
- **Official source used:** https://otx.alienvault.com/assets/static/external_api.html
- **Installed on this box:** n/a - HTTP source, no binary
- **Install command:** nothing to install (`install: {method: none}`)
- **Multi-domain input:** n/a - one domain per request

#### Real request

```
curl -sS -o otx.body -w "%{http_code}"   'https://otx.alienvault.com/api/v1/indicators/domain/testfire.net/passive_dns'
```

Output (raw, exit 0):

```
HTTP 429 {"detail": "Anonymous access to this endpoint is limited. Please authenticate."}
```

This reproduces the risk already recorded in `docs/09` section 9 and in
`PROGRESS.md` "Open risks": the anonymous response shape has never been
observed. With `OTX_API_KEY` in `.env` the adapter sends `X-OTX-API-KEY`.

#### What a normal exit code looks like

Exit 0 for any HTTP status. A 429 is a failed `ToolResult` carrying the status;
it is never treated as "no subdomains".

#### Gotchas

- Anonymous access is effectively closed now (two separate sessions, both 429).


---

## `hackertarget`

- **Registry:** http, core, passive, phase 2, `stage: subs`
- **Adapter in this build:** `src/reconkit/adapters/hackertarget.py`
- **Official source used:** https://api.hackertarget.com/hostsearch/?q=<domain> (the endpoint itself; the old docs page hackertarget.com/host-search/ is 404, recorded 2026-11-14)
- **Installed on this box:** n/a - HTTP source, no binary
- **Install command:** nothing to install (`install: {method: none}`)
- **Multi-domain input:** n/a - one domain per request

#### Real request

```
curl -sS -o hackertarget.body -w "%{http_code}" 'https://api.hackertarget.com/hostsearch/?q=testfire.net'
```

Output (raw, exit 0):

```
HTTP 200, 97 bytes:
altoro.testfire.net,65.61.137.117
demo.testfire.net,65.61.137.117
www.testfire.net,65.61.137.117
```

#### What a normal exit code looks like

Exit 0. One `host,ip` per line is data; the text `API count exceeded` means the
free daily quota is gone and is a failed result.

#### Gotchas

- The free tier has a very low daily limit; the quota branch is still
  unexercised (the quota was not hit in this session).


---

## `urlscan`

- **Registry:** http, core, passive, phase 3, `stage: subs`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://urlscan.io/docs/api/
- **Installed on this box:** n/a - HTTP source, no binary
- **Install command:** nothing to install (`install: {method: none}`)
- **Multi-domain input:** n/a - one query per domain

#### Real request

```
curl -sS -o urlscan.body -w "%{http_code}" 'https://urlscan.io/api/v1/search/?q=domain:testfire.net'
```

Output (raw summary, exit 0):

```
HTTP 200, 63413 bytes, total 41 results
result keys: ['_id', '_score', 'canonical', 'labels', 'page', 'result']
```

A future adapter would read the `page.domain` / `page.url` of each result.
`URLSCAN_API_KEY` (free signup) is only needed for submissions, not for search.

#### What a normal exit code looks like

Exit 0 with a JSON object carrying `results` and `total`.

#### Gotchas

- No adapter exists, so `reconkit` reports it as `no adapter yet (phase 3)`.


---

## `subfinder`

- **Registry:** binary, core, passive, phase 2, `stage: subs`
- **Adapter in this build:** `src/reconkit/adapters/subfinder.py`
- **Official source used:** https://github.com/projectdiscovery/subfinder
- **Installed on this box:** `/home/kali/go/bin/subfinder`, `[INF] Current Version: v2.17.0`
- **Install command:** `reconkit install subfinder` (github_release, fallback `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`)
- **Multi-domain input:** **yes** - `-dL, -list string` (file containing list of domains)

#### Real `--help` (raw, full)

Captured with `subfinder -h` (exit 0, wrote to stdout):

```
Subfinder is a subdomain discovery tool that discovers subdomains for websites by using passive online sources.

Usage:
  subfinder [flags]

Flags:
INPUT:
   -d, -domain string[]  domains to find subdomains for
   -dL, -list string     file containing list of domains for subdomain discovery

SOURCE:
   -s, -sources string[]           specific sources to use for discovery (-s crtsh,github). Use -ls to display all available sources.
   -recursive                      use only sources that can handle subdomains recursively rather than both recursive and non-recursive sources
   -all                            use all sources for enumeration (slow)
   -es, -exclude-sources string[]  sources to exclude from enumeration (-es alienvault,zoomeyeapi)

FILTER:
   -m, -match string[]     subdomain or list of subdomain to match (file or comma separated)
   -f, -filter string[]     subdomain or list of subdomain to filter (file or comma separated)
   -match-regex string[]   regex or list of regex to match on output subdomain (cli, file)
   -filter-regex string[]  regex or list of regex to filter on output subdomain (cli, file)

RATE-LIMIT:
   -rl, -rate-limit int      maximum number of http requests to send per second (global)
   -rls, -rate-limits value  maximum number of http requests to send per second for providers in key=value format (-rls hackertarget=10/m) (default ["github=30/m", "fullhunt=60/m", "pugrecon=10/s", "robtex=18446744073709551615/ms", "securitytrails=1/s", "shodan=1/s", "virustotal=4/m", "hackertarget=2/s", "waybackarchive=15/m", "whoisxmlapi=50/s", "securitytrails=2/s", "sitedossier=8/m", "netlas=1/s", "github=83/m", "hudsonrock=5/s", "urlscan=1/s"])
   -t int                    maximum concurrent domains and active DNS lookups (default 10)

UPDATE:
   -up, -update                 update subfinder to latest version
   -duc, -disable-update-check  disable automatic subfinder update check

OUTPUT:
   -o, -output string       file to write output to
   -oJ, -json               write output in JSONL format
   -oD, -output-dir string  directory to write output (-dL only)
   -cs, -collect-sources    include all sources in the output (-json only)
   -oI, -ip                 include host IP in output (-active only)

CONFIGURATION:
   -config string                flag config file (default "/home/kali/.config/subfinder/config.yaml")
   -pc, -provider-config string  provider config file (default "/home/kali/.config/subfinder/provider-config.yaml")
   -r string[]                   comma separated list of resolvers to use
   -rL, -rlist string            file containing list of resolvers to use
   -nW, -active                  display active subdomains only
   -proxy string                 http proxy to use with subfinder
   -ei, -exclude-ip              exclude IPs from the list of domains
   -mr, -max-results int         limit the number of results per source (0 = unlimited; honored by paginating sources)

DEBUG:
   -silent             show only subdomains in output
   -version            show version of subfinder
   -v                  show verbose output
   -nc, -no-color      disable color in output
   -ls, -list-sources  list all available sources (-oJ for JSON)
   -stats              report source statistics

OPTIMIZATION:
   -timeout int                   seconds to wait before timing out (default 30)
   -max-time int                  minutes to wait for enumeration results (default 10)
   -rsr, -response-size-read int  max response body size to read in bytes from passive sources (0 = unlimited)
```


#### Real test on testfire.net

Command:

```
subfinder -d testfire.net -silent -nc -duc
```


Output (raw, exit code 0):

```
www.altoro.testfire.net
mvaas.testfire.net
msu-swu.testfire.net
mylci.testfire.net
mcdss2.testfire.net
localhost9.testfire.net
tienda.testfire.net
mysotidev.testfire.net
lotmt2qcakb2z4os.testfire.net
www.demo.testfire.net
mypay.testfire.net
demo.testfire.net
... (23 more lines, 35 total)
```


---

## `assetfinder`

- **Registry:** binary, core, passive, phase 2, `stage: subs`
- **Adapter in this build:** `src/reconkit/adapters/assetfinder.py`
- **Official source used:** https://github.com/tomnomnom/assetfinder
- **Installed on this box:** `/home/kali/.reconkit/bin/assetfinder` (no version flag; identity probe is `-h`)
- **Install command:** `reconkit install assetfinder` (`go install github.com/tomnomnom/assetfinder@latest`)
- **Multi-domain input:** **no** - the domain is a single positional argument; run once per domain

#### Real `--help` (raw, full)

Captured with `assetfinder -h` (exit 0, wrote to stderr):

```
Usage of assetfinder:
  -subs-only
    	Only include subdomains of search domain
```


#### Real test on testfire.net

Command:

```
assetfinder --subs-only testfire.net
```


Output (raw, exit code 0):

```
altoro.testfire.net
demo.testfire.net
www.testfire.net
testfire.net
```


---

## `findomain`

- **Registry:** binary, core, passive, phase 3, `stage: subs`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/Findomain/Findomain
- **Installed on this box:** `/home/kali/.reconkit/bin/findomain`, `findomain 11.0.0`
- **Install command:** `reconkit install findomain` (github_release `findomain-linux.zip`, `verify_checksums: false` - the release publishes no checksums asset)
- **Multi-domain input:** **yes** - `-f, --file <FILES>`

#### Real `--help` (raw, full)

Captured with `findomain --help` (exit 0, wrote to stdout):

```
The fastest and cross-platform subdomain enumerator, do not waste your time.

Usage: findomain [OPTIONS]

Options:
  -t, --target <TARGET>
          Target host
  -r, --resolved
          Show/write only resolved subdomains
  -i, --ip
          Show/write the ip address of resolved subdomains
  -f, --file <FILES>
          Use a list of subdomains writen in a file as input
  -o, --output
          Write to an automatically generated output file. The name of the output file is generated using the format: target.txt. If you want a custom output file name, use the -u/--unique-output option
  -u, --unique-output <UNIQUE_OUTPUT>
          Write all the results for a target or a list of targets to a specified filename
  -m, --monitoring-flag
          Activate Findomain monitoring mode
      --postgres-user <POSTGRES_USER>
          Postgresql username
      --postgres-password <POSTGRES_PASSWORD>
          Postgresql password
      --postgres-host <POSTGRES_HOST>
          Postgresql host
      --postgres-port <POSTGRES_PORT>
          Postgresql port
      --postgres-database <POSTGRES_DATABASE>
          Postgresql database
  -q, --quiet
          Remove informative messages but show fatal errors or subdomains not found message
      --query-database
          Query the findomain database to search subdomains that have already been discovered
      --webhook-max-wait <WEBHOOK_MAX_WAIT>
          Seconds to keep waiting on a webhook's rate limit for one message before dropping it. 0 waits for as long as the service asks. Default 0
      --import-subdomains <IMPORT_SUBDOMAINS>...
          Import subdomains from one or multiple files. Subdomains need to be one per line in the file to import
      --enable-dot
          Enable DNS over TLS for resolving subdomains IPs
      --ipv6-only
          Perform a IPv6 lookup only
      --threads <THREADS>
          Number of threads to use for lightweight tasks such as IP discovery and HTTP checks. Deprecated option, use --lightweight-threads instead. This would be removed in the future
      --lightweight-threads <LIGHTWEIGHT_THREADS>
          Number of threads to use for lightweight tasks such as IP discovery and HTTP checks. Default is 50
      --screenshots-threads <SCREENSHOTS_THREADS>
          Number of threads to use to use for taking screenshots. Default is 10
      --resolvers <CUSTOM_RESOLVERS>
          Path to a file (or files) containing a list of DNS IP address. If no specified then Google, Cloudflare and Quad9 DNS servers are used
      --aempty
          Send alert to webhooks still when no new subdomains have been found
  -x, --as-resolver
          Use Findomain as resolver for a list of domains in a file
  -w, --wordlist <WORDLISTS>
          Wordlist file to use in the bruteforce process. Using it option automatically enables bruteforce mode
      --no-wildcards
          Disable wilcard detection when resolving subdomains
      --filter <STRING_FILTER>
          Filter subdomains containing specifics strings
      --exclude <STRING_EXCLUDE>
          Exclude subdomains containing specifics strings
      --exclude-sources <EXCLUDE_SOURCES>
          Exclude sources from searching subdomains in [possible values: ahrefs, alienvault, anubis, arquivo, bevigil, binaryedge, bufferover_free, bufferover_paid, builtwith, c99, censys, certcentral, certspotter, chaos, circl, commoncrawl, crtname, crtsh, deepinfo, detectify, dnsdb, dnslytics, dnsrepo, facebook, fofa, fullhunt, hackertarget, hunter, intelx, leakix, maltiverse, mnemonic, netlas, onyphe, passivedns360, passivetotal, pentesttools, publicwww, pulsedive, quake, securitytrails, shodan, socradar, spamhaus, subdomaincenter, sublist3r, threatbook, threatminer, ukwebarchive, urlscan, virustotalapikey, wayback, whoisxmlapi, zetalytics, zoomeye]
      --source-timeout <SOURCE_TIMEOUT>
          Timeout in seconds for a single request to a source. Default 30
      --source-budget <SOURCE_BUDGET>
          Seconds the search across all sources may take, 0 for no limit. Default 300
      --archive-budget <ARCHIVE_BUDGET>
          Seconds the archive indexes may spend, 0 to hold them to the source budget. Default 20
      --http-status
          Check the HTTP status of subdomains
  -c, --config <CONFIG_FILE>
          Use a configuration file. The default configuration file is findomain and the format can be toml, json, ini or yml
      --rate-limit <RATE_LIMIT>
          Set the rate limit in seconds for each target during enumeration
      --nmap-arg <NMAP_ARGS>
          Extra argument passed to nmap verbatim. Repeat it once per argument
      --pscan
          Enable port scanner
      --iport <INITIAL_PORT>
          Initial port to scan. Default 1
      --lport <LAST_PORT>
          Last port to scan. Default 1000
  -v, --verbose
          Enable verbose mode (useful to debug problems)
      --mtimeout
          Allow Findomain to insert data in the database when the webhook returns a timeout error
      --no-monitor
          Disable monitoring mode while saving data to database
  -s, --screenshots <SCREENSHOTS_PATH>
          Path to save the screenshots of the HTTP(S) website for subdomains with active ones
      --sandbox
          Enable Chrome/Chromium sandbox. It is disabled by default because a big number of users run the tool using the root user by default. Make sure you are not running the program as root user before using this option
  -j, --jobname <JOBNAME>
          Use an database identifier for jobs. It is useful when you want to relate different targets into a same job name. To extract the data by job name identifier, use the query-jobname option
      --query-jobname
          Extract all the subdomains from the database where the job name is the specified using the jobname option
      --http-timeout <HTTP_TIMEOUT>
          Value in seconds for the HTTP Status check of subdomains. Default 5
      --stdin
          Read from stdin instead of files or aguments
      --ua <USER_AGENTS_FILE>
          Path to file containing user agents strings
      --randomize
          Enable randomization when reading targets from files
      --no-resolve
          Disable pre-screenshotting jobs (http check and ip discover) when used as resolver to take screenshots
      --validate
          Validate all the subdomains from the specified file
      --list-keys
          List every source that takes an API key, how to set it, and whether one is configured. Values are never shown
      --resolver-timeout <RESOLVER_TIMEOUT>
          Timeout in seconds for the resolver. Default 3
      --http-retries <HTTP_RETRIES>
          Number of retries for the HTTP Status check of subdomains. Default 2
      --double-dns-check
          Enable double DNS check. This means that the subdomains that report an IP address are checked again using a list of trustable resolvers to avoid false-positives. Only applies when using custom resolvers
  -n, --no-discover
          Prevent findomain from searching subdomains itself. Useful when you are importing subdomains from other tools
      --max-http-redirects <MAX_HTTP_REDIRECTS>
          Maximum number of HTTP redirects to follow. Default 0
      --reset-database
          Reset the database. It will delete all the data from the database
      --sqlite <FILE>
          SQLite file to store results in. Defaults to findomain.db; naming any PostgreSQL option uses PostgreSQL instead
      --nmap-full
          Run nmap with service detection and NSE scripts instead of a plain port sweep
      --nmap-syn
          Use a SYN scan. Needs root privileges
      --min-rate <MIN_RATE>
          nmap --min-rate, the packets per second floor
      --nmap-host-timeout <NMAP_HOST_TIMEOUT>
          Seconds nmap may spend on a single host. Default 900
      --nuclei
          Run nuclei against the subdomains with an active HTTP server
      --nuclei-templates <NUCLEI_TEMPLATES>
          Path to the nuclei templates to run
      --nuclei-severity <NUCLEI_SEVERITY>
          Severities to report, comma separated
      --nuclei-tags <NUCLEI_TAGS>
          Template tags to run, comma separated
      --nuclei-exclude-templates <NUCLEI_EXCLUDE_TEMPLATES>
          Templates to skip, comma separated
      --nuclei-arg <NUCLEI_ARGS>
          Extra argument passed to nuclei verbatim. Repeat it once per argument
      --nuclei-rate-limit <NUCLEI_RATE_LIMIT>
          nuclei rate limit in requests per second
      --nuclei-timeout <NUCLEI_TIMEOUT>
          Seconds nuclei may run before it is stopped, keeping what it found by then. 0 for no limit. Default 0
      --ffuf
          Run ffuf against the subdomains with an active HTTP server
      --ffuf-wordlist <FFUF_WORDLIST>
          Path wordlist for ffuf. Implies --ffuf
      --ffuf-arg <FFUF_ARGS>
          Extra argument passed to ffuf verbatim. Repeat it once per argument
      --ffuf-threads <FFUF_THREADS>
          Concurrent ffuf requests. Default 40
      --ffuf-recursion
          Let ffuf recurse into the directories it finds
      --ffuf-recursion-depth <FFUF_RECURSION_DEPTH>
          How deep ffuf may recurse. Default 2
      --smtp-server <SMTP_SERVER>
          SMTP server used to email the report
      --smtp-port <SMTP_PORT>
          SMTP port. Default 587
      --smtp-user <SMTP_USER>
          SMTP username, also used as the sender address
      --smtp-password <SMTP_PASSWORD>
          SMTP password
      --email-to <EMAIL_TO>
          Address to email the report to. Repeat for several recipients
      --cname
          Track the CNAME each resolved subdomain points at
      --permutations
          Derive extra candidate subdomains from the ones discovered and resolve them
      --permutations-wordlist <PERMUTATIONS_WORDLIST>
          Wordlist used to build permutations. Implies --permutations
  -h, --help
          Print help
  -V, --version
          Print version
```


#### Real test on testfire.net

Command:

```
findomain -t testfire.net --quiet
```


Output (raw, exit code 0):

```
tv.testfire.net
ma-all-automation44-alb.testfire.net
mysotidev.testfire.net
www.demo.testfire.net
partners.testfire.net
tienda.testfire.net
myaksclust-myresourcegroup-dfd7fe-3e803225.testfire.net
myspectra--rg-myspectra-ofc-0e8a82-804da6d1.testfire.net
evil.testfire.net
www.testfire.net
demo.testfire.net
my-store.testfire.net
... (25 more lines, 37 total)
```


---

## `chaos`

- **Registry:** binary, core, passive, phase 3, `stage: subs`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/projectdiscovery/chaos-client
- **Installed on this box:** `/home/kali/.reconkit/bin/chaos`, `[INF] Current Version: 0.5.2`
- **Install command:** `reconkit install chaos` (github_release `chaos-client`, member `chaos-client`)
- **Multi-domain input:** **yes** - `-dL string` (file containing domains)

#### Real `--help` (raw, full)

Captured with `chaos -h` (exit 0, wrote to stdout):

```


Usage:
  chaos [flags]

Flags:
   -key string                  projectdiscovery cloud (pdcp) api key
   -d string                    domain to search for subdomains
   -count                       show statistics for the specified domain
   -silent                      make the output silent
   -o string                    file to write output to (optional)
   -dL string                   file containing domains to search for subdomains (optional)
   -json                        print output as json
   -version                     show version of chaos
   -v, -verbose                 verbose mode
   -up, -update                 update chaos to latest version
   -duc, -disable-update-check  disable automatic chaos update check
```


#### Real test on testfire.net

Command:

```
chaos -d testfire.net -silent
```


Output (raw, exit code 1):

```

--- stderr ---
[[1;31mFTL[0m] PDCP_API_KEY not specified
```


#### Notes and errors hit

**Result: cannot run without a key.** The command fails immediately:

```
[FTL] PDCP_API_KEY not specified
exit 1
```

`PDCP_API_KEY` is a free ProjectDiscovery Cloud account key. There is no key in
`.env` on this box, so the tool has no runnable path here. The adapter contract
already expects this (`keys: PDCP_API_KEY` in `tools.yaml`); no code change is
needed - a user with a free key can run it.


---

## `github-subdomains`

- **Registry:** binary, core, passive, phase 3, `stage: subs`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/gwen001/github-subdomains
- **Installed on this box:** `/home/kali/.reconkit/bin/github-subdomains` (no version flag; `-h` prints usage)
- **Install command:** `reconkit install github_subdomains` (`go install github.com/gwen001/github-subdomains@latest`)
- **Multi-domain input:** **no** - `-d string` takes one domain

#### Real `--help` (raw, full)

Captured with `github-subdomains -h` (exit 0, wrote to stderr):

```
Usage of github-subdomains:
  -d string
    	domain you are looking for (required)
  -e	extended mode, also look for <dummy>example.com
  -k	exit the program when all tokens have been disabled
  -o string
    	output file, default: <domain>.txt
  -q	quick mode, avoid extra searches with languages and noise added
  -raw
    	raw output
  -t string
    	github token (required), can be:
    	  • a single token
    	  • a list of tokens separated by comma
    	  • a file (.tokens) containing 1 token per line
    	if the options is not provided, the environment variable GITHUB_TOKEN is readed, it can be:
    	  • a single token
    	  • a list of tokens separated by comma
```


#### Real test on testfire.net

Command:

```
github-subdomains -d testfire.net
```


Output (raw, exit code 255):

```

token not found
--- stderr ---
Usage of github-subdomains:
  -d string
    	domain you are looking for (required)
  -e	extended mode, also look for <dummy>example.com
  -k	exit the program when all tokens have been disabled
  -o string
... (12 more lines, 18 total)
```


#### Notes and errors hit

**Result: cannot run without a token.** The command prints its usage to
stderr and then `token not found`, exiting **255**:

```
Usage of github-subdomains:
  -d string
    	domain you are looking for (required)
  -e	extended mode, also look for <dummy>example.com

token not found
```

It reads `GITHUB_TOKEN` (or finds no token and stops). No token is present in
`.env` here, so this tool also has no runnable path on this box. The registry
entry already declares `GITHUB_TOKEN`; nothing to fix.


---

## `amass`

- **Registry:** binary, core, passive, phase 3, `stage: subs`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/owasp-amass/amass
- **Installed on this box:** `/usr/bin/amass`, `v5.1.3`
- **Install command:** `reconkit install amass` (`apt install amass`, needs sudo)
- **Multi-domain input:** not in the top-level `-h`; subcommand flags not verified here

#### Real `--help` (raw, full)

Captured with `amass -h` (exit 0, wrote to stderr):

```

        .+++:.            :                             .+++.
      +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+
     &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&
    +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8
    8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:
    WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:
    #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8
    o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.
     WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o
     :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+
      :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&
        +o&&&&+.                                                    +oooo.

                                                                      v5.1.3
                                           OWASP Amass Project - @owaspamass
                         In-depth Attack Surface Mapping and Asset Discovery


Usage: amass [assoc|engine|enum|subs|track|viz] [options]

  -h	Show the program usage message
  -help
    	Show the program usage message
  -version
    	Print the Amass version number

Subcommands: 

	assoc	Query the OAM along the walk defined by the triples
	engine	Run the Amass collection engine to populate the OAM database
	enum 	Interface with the engine that performs enumerations
	subs 	Analyze and present discovered subdomains and associated data
	track	Analyze OAM data to identify newly discovered assets
	viz  	Analyze OAM data to generate graph visualizations
```


#### Real test on testfire.net

Command:

```
timeout 150 amass enum -d testfire.net -passive -timeout 2
```


Output (raw, exit code 0):

```

Session Scope

FQDN:

testfire.net
--- stderr ---
0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s0 / 1 [________________________________________________________________________________] 0.00% ? p/s18 / 73 [------------------>__________________________________________________________] 24.66% ? p/s18 / 73 [------------------>_________________________________________________________] 24.66% 30 p/s18 / 73 [------------------>_________________________________________________________] 24.66% 30 p/s18 / 73 [------------------>_________________________________________________________] 24.66% 30 p/s18 / 73 [------------------>_________________________________________________________] 24.66% 28 p/s18 / 73 [------------------>_________________________________________________________] 24.66% 28 p/s18 / 73 [------------------>_________________________________________________________] 24.66% 28 p/s18 / 73 [------------------>_________________________________________________________] 24.66% 26 p/s18 / 73 [------------------>_________________________________________________________] 24.66% 26 p/s18 / 73 [------------------>_________________________________________________________] 24.66% 26 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 25 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 25 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 25 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 24 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 24 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 24 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 22 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 22 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 22 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 21 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 21 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 21 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 19 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 19 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 19 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 18 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 18 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 18 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 17 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 17 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 17 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 16 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 16 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 16 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 15 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 15 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 15 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 14 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 14 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 14 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 13 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 13 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 13 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 12 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 12 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 12 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 11 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 11 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 11 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 11 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 11 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 11 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 10 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 10 p/s24 / 75 [------------------------>___________________________________________________] 32.00% 10 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 9 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 9 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 9 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 9 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 9 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 9 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 8 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 8 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 8 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 8 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 8 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 8 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 7 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 7 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 7 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 7 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 7 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 7 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 6 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 6 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 6 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 6 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 6 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 6 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 5 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 5 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 5 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 5 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 5 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 5 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 5 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 5 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 5 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s24 / 75 [------------------------>____________________________________________________] 32.00% 4 p/s50 / 99 [-------------------------------------->______________________________________] 50.51% 6 p/s50 / 99 [-------------------------------------->______________________________________] 50.51% 6 p/s50 / 99 [-------------------------------------->______________________________________] 50.51% 6 p/s50 / 99 [-------------------------------------->______________________________________] 50.51% 6 p/s50 / 99 [-------------------------------------->______________________________________] 50.51% 6 p/s50 / 99 [-------------------------------------->______________________________________] 50.51% 6 p/s50 / 99 [-------------------------------------->______________________________________] 50.51% 5 p/s50 / 99 [-------------------------------------->______________________________________] 50.51% 5 p/s50 / 99 [-------------------------------------->______________________________________] 50.51% 5 p/s50 / 99 [-------------------------------------->______________________________________] 50.51% 5 p/s60 / 99 [---------------------------------------------->______________________________] 60.61% 5 p/s60 / 99 [---------------------------------------------->______________________________] 60.61% 5 p/s60 / 99 [---------------------------------------------->______________________________] 60.61% 6 p/s60 / 99 [---------------------------------------------->______________________________] 60.61% 6 p/s60 / 99 [---------------------------------------------->______________________________] 60.61% 6 p/s60 / 99 [---------------------------------------------->______________________________] 60.61% 5 p/s60 / 99 [---------------------------------------------->______________________________] 60.61% 5 p/s60 / 99 [---------------------------------------------->______________________________] 60.61% 5 p/s60 / 99 [---------------------------------------------->______________________________] 60.61% 5 p/s60 / 99 [---------------------------------------------->______________________________] 60.61% 5 p/s68 / 99 [---------------------------------------------------->________________________] 68.69% 5 p/s68 / 99 [---------------------------------------------------->________________________] 68.69% 6 p/s68 / 99 [---------------------------------------------------->________________________] 68.69% 6 p/s68 / 99 [---------------------------------------------------->________________________] 68.69% 6 p/s68 / 99 [---------------------------------------------------->________________________] 68.69% 5 p/s68 / 99 [---------------------------------------------------->________________________] 68.69% 5 p/s68 / 99 [---------------------------------------------------->________________________] 68.69% 5 p/s68 / 99 [---------------------------------------------------->________________________] 68.69% 5 p/s68 / 99 [---------------------------------------------------->________________________] 68.69% 5 p/s68 / 99 [---------------------------------------------------->________________________] 68.69% 5 p/s69 / 99 [----------------------------------------------------->_______________________] 69.70% 5 p/s69 / 99 [----------------------------------------------------->_______________________] 69.70% 5 p/s69 / 99 [----------------------------------------------------->_______________________] 69.70% 5 p/s69 / 99 [----------------------------------------------------->_______________________] 69.70% 4 p/s69 / 99 [----------------------------------------------------->_______________________] 69.70% 4 p/s69 / 99 [----------------------------------------------------->_______________________] 69.70% 4 p/s69 / 99 [----------------------------------------------------->_______________________] 69.70% 4 p/s69 / 99 [----------------------------------------------------->_______________________] 69.70% 4 p/s69 / 99 [----------------------------------------------------->_______________________] 69.70% 4 p/s69 / 99 [----------------------------------------------------->_______________________] 69.70% 4 p/s70 / 99 [------------------------------------------------------>______________________] 70.71% 4 p/s70 / 99 [------------------------------------------------------>______________________] 70.71% 4 p/s70 / 99 [------------------------------------------------------>______________________] 70.71% 4 p/s70 / 99 [------------------------------------------------------>______________________] 70.71% 4 p/s70 / 99 [------------------------------------------------------>______________________] 70.71% 4 p/s70 / 99 [------------------------------------------------------>______________________] 70.71% 3 p/s70 / 99 [------------------------------------------------------>______________________] 70.71% 3 p/s70 / 99 [------------------------------------------------------>______________________] 70.71% 3 p/s70 / 99 [------------------------------------------------------>______________________] 70.71% 3 p/s70 / 99 [------------------------------------------------------>______________________] 70.71% 3 p/s84 / 114 [------------------------------------------------------->____________________] 73.68% 3 p/s84 / 114 [------------------------------------------------------->____________________] 73.68% 5 p/s84 / 114 [------------------------------------------------------->____________________] 73.68% 5 p/s84 / 114 [------------------------------------------------------->____________________] 73.68% 5 p/s84 / 114 [------------------------------------------------------->____________________] 73.68% 4 p/s84 / 114 [------------------------------------------------------->____________________] 73.68% 4 p/s84 / 114 [------------------------------------------------------->____________________] 73.68% 4 p/s84 / 114 [------------------------------------------------------->____________________] 73.68% 4 p/s84 / 114 [------------------------------------------------------->____________________] 73.68% 4 p/s84 / 114 [------------------------------------------------------->____________________] 73.68% 4 p/s92 / 114 [------------------------------------------------------------->______________] 80.70% 5 p/s92 / 114 [------------------------------------------------------------->______________] 80.70% 5 p/s92 / 114 [------------------------------------------------------------->______________] 80.70% 5 p/s92 / 114 [------------------------------------------------------------->______________] 80.70% 4 p/s92 / 114 [------------------------------------------------------------->______________] 80.70% 4 p/s92 / 114 [------------------------------------------------------------->______________] 80.70% 4 p/s92 / 114 [------------------------------------------------------------->______________] 80.70% 4 p/s92 / 114 [------------------------------------------------------------->______________] 80.70% 4 p/s92 / 114 [------------------------------------------------------------->______________] 80.70% 4 p/s92 / 114 [------------------------------------------------------------->______________] 80.70% 4 p/s122 / 149 [------------------------------------------------------------->_____________] 81.88% 4 p/s122 / 149 [------------------------------------------------------------->_____________] 81.88% 4 p/s122 / 149 [------------------------------------------------------------->_____________] 81.88% 7 p/s122 / 149 [------------------------------------------------------------->_____________] 81.88% 7 p/s122 / 149 [------------------------------------------------------------->_____________] 81.88% 7 p/s122 / 149 [------------------------------------------------------------->_____________] 81.88% 6 p/s122 / 149 [------------------------------------------------------------->_____________] 81.88% 6 p/s122 / 149 [------------------------------------------------------------->_____________] 81.88% 6 p/s122 / 149 [------------------------------------------------------------->_____________] 81.88% 6 p/s122 / 149 [------------------------------------------------------------->_____________] 81.88% 6 p/s140 / 153 [-------------------------------------------------------------------->______] 91.50% 6 p/s140 / 153 [-------------------------------------------------------------------->______] 91.50% 7 p/s140 / 153 [-------------------------------------------------------------------->______] 91.50% 7 p/s140 / 153 [-------------------------------------------------------------------->______] 91.50% 7 p/s140 / 153 [-------------------------------------------------------------------->______] 91.50% 7 p/s140 / 153 [-------------------------------------------------------------------->______] 91.50% 7 p/s140 / 153 [-------------------------------------------------------------------->______] 91.50% 7 p/s140 / 153 [-------------------------------------------------------------------->______] 91.50% 7 p/s140 / 153 [-------------------------------------------------------------------->______] 91.50% 7 p/s140 / 153 [-------------------------------------------------------------------->______] 91.50% 7 p/s149 / 153 [------------------------------------------------------------------------->_] 97.39% 7 p/s149 / 153 [------------------------------------------------------------------------->_] 97.39% 7 p/s149 / 153 [------------------------------------------------------------------------->_] 97.39% 7 p/s149 / 153 [------------------------------------------------------------------------->_] 97.39% 7 p/s149 / 153 [------------------------------------------------------------------------->_] 97.39% 7 p/s149 / 153 [------------------------------------------------------------------------->_] 97.39% 7 p/s149 / 153 [------------------------------------------------------------------------->_] 97.39% 6 p/s149 / 153 [------------------------------------------------------------------------->_] 97.39% 6 p/s149 / 153 [------------------------------------------------------------------------->_] 97.39% 6 p/s149 / 153 [------------------------------------------------------------------------->_] 97.39% 6 p/s154 / 161 [----------------------------------------------------------------------->___] 95.65% 6 p/s154 / 161 [----------------------------------------------------------------------->___] 95.65% 6 p/s154 / 161 [----------------------------------------------------------------------->___] 95.65% 6 p/s154 / 161 [----------------------------------------------------------------------->___] 95.65% 6 p/s154 / 161 [----------------------------------------------------------------------->___] 95.65% 6 p/s154 / 161 [----------------------------------------------------------------------->___] 95.65% 6 p/s154 / 161 [----------------------------------------------------------------------->___] 95.65% 6 p/s154 / 161 [----------------------------------------------------------------------->___] 95.65% 6 p/s154 / 161 [----------------------------------------------------------------------->___] 95.65% 5 p/s154 / 161 [----------------------------------------------------------------------->___] 95.65% 5 p/s158 / 163 [------------------------------------------------------------------------>__] 96.93% 5 p/s158 / 163 [------------------------------------------------------------------------>__] 96.93% 5 p/s158 / 163 [------------------------------------------------------------------------>__] 96.93% 5 p/s158 / 163 [------------------------------------------------------------------------>__] 96.93% 5 p/s158 / 163 [------------------------------------------------------------------------>__] 96.93% 5 p/s158 / 163 [------------------------------------------------------------------------>__] 96.93% 5 p/s158 / 163 [------------------------------------------------------------------------>__] 96.93% 5 p/s158 / 163 [------------------------------------------------------------------------>__] 96.93% 5 p/s158 / 163 [------------------------------------------------------------------------>__] 96.93% 5 p/s158 / 163 [------------------------------------------------------------------------>__] 96.93% 5 p/s161 / 171 [---------------------------------------------------------------------->____] 94.15% 5 p/s161 / 171 [---------------------------------------------------------------------->____] 94.15% 5 p/s161 / 171 [---------------------------------------------------------------------->____] 94.15% 5 p/s161 / 171 [---------------------------------------------------------------------->____] 94.15% 4 p/s161 / 171 [---------------------------------------------------------------------->____] 94.15% 4 p/s161 / 171 [---------------------------------------------------------------------->____] 94.15% 4 p/s161 / 171 [---------------------------------------------------------------------->____] 94.15% 4 p/s161 / 171 [---------------------------------------------------------------------->____] 94.15% 4 p/s161 / 171 [---------------------------------------------------------------------->____] 94.15% 4 p/s161 / 171 [---------------------------------------------------------------------->____] 94.15% 4 p/s169 / 176 [------------------------------------------------------------------------>__] 96.02% 4 p/s169 / 176 [------------------------------------------------------------------------>__] 96.02% 4 p/s169 / 176 [------------------------------------------------------------------------>__] 96.02% 4 p/s169 / 176 [------------------------------------------------------------------------>__] 96.02% 4 p/s169 / 176 [------------------------------------------------------------------------>__] 96.02% 4 p/s169 / 176 [------------------------------------------------------------------------>__] 96.02% 4 p/s169 / 176 [------------------------------------------------------------------------>__] 96.02% 4 p/s169 / 176 [------------------------------------------------------------------------>__] 96.02% 4 p/s169 / 176 [------------------------------------------------------------------------>__] 96.02% 4 p/s169 / 176 [------------------------------------------------------------------------>__] 96.02% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 4 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 3 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 3 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 3 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 3 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 3 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 3 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 3 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 3 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 3 p/s173 / 177 [------------------------------------------------------------------------->_] 97.74% 3 p/s173 / 179 [------------------------------------------------------------------------>__] 96.65% 3 p/s173 / 179 [------------------------------------------------------------------------>__] 96.65% 3 p/s173 / 179 [------------------------------------------------------------------------>__] 96.65% 3 p/s173 / 179 [------------------------------------------------------------------------>__] 96.65% 3 p/s173 / 179 [------------------------------------------------------------------------>__] 96.65% 3 p/s173 / 179 [------------------------------------------------------------------------>__] 96.65% 2 p/s173 / 179 [------------------------------------------------------------------------>__] 96.65% 2 p/s173 / 179 [------------------------------------------------------------------------>__] 96.65% 2 p/s173 / 179 [------------------------------------------------------------------------>__] 96.65% 2 p/s173 / 179 [------------------------------------------------------------------------>__] 96.65% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s176 / 179 [------------------------------------------------------------------------->_] 98.32% 2 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 2 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 2 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 2 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 2 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 2 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 2 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 2 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 2 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 1 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s177 / 179 [-------------------------------------------------------------------------->] 98.88% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s178 / 179 [-------------------------------------------------------------------------->] 99.44% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [------------------------------------------------------------------------->] 100.00% 0 p/s179 / 179 [--------------------------------------------------------------------------] 100.00% 2 p/s
```


#### Notes and errors hit

**Result: runs, but is not quick and prints no names on stdout in 150 s.**
Exit 0 after roughly 2 minutes, with a carriage-return progress meter on stderr
and a session report on stdout:

```
(exit 0, 6 stdout lines)
<blank>
Session Scope
<blank>
FQDN:
<blank>
```

The progress meter rewrites one line with `\r`, so captured stderr is one very
long line (that is why the raw capture is summarised here rather than pasted).

**Mismatch (closed 2026-11-17):** `tools.yaml` used to record `notes: "Always
run in passive mode (-passive). Slow."` against **v5.1.3**, whose CLI surface
changed a lot from v4 (`assoc|engine|enum|subs|track|viz` subcommands). The note
now says passive is the default in v5 and that `enum -passive` is deprecated.
Measured: `amass enum -h` lists `-passive` / `Deprecated since passive is the
default setting`, and `amass -h` prints `Usage:
amass [assoc|engine|enum|subs|track|viz] [options]`. Any adapter built from this
note must still be checked against `amass enum -h` first. `version_cmd: [amass,
-version]` works and prints `v5.1.3`.

