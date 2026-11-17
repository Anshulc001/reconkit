# Tool manuals - urls

Stage `urls` of `reconkit`. Verified on the canonical Kali checkout
(`/home/kali/Desktop/reconkit`, Python 3.14.8) on **2026-11-16**. Every
`--help` block and every test block below is the tool's own raw output,
captured on that machine; nothing here is written from memory.

Authorized target used for the one safe test: **testfire.net** (already in
`scope.yaml`). One command per tool, no payloads, no brute force.

Tools from the `vulns` stage are deliberately absent - see
`docs/tool_manuals/README.md` ("Skipped").

| Tool | Kind | Tier | Mode | Phase | Adapter in this build |
|---|---|---|---|---|---|
| `gau` | binary | core | passive | 3 | no |
| `waybackurls` | binary | core | passive | 3 | no |
| `katana` | binary | core | active | 3 | no |
| `hakrawler` | binary | core | active | 3 | no |
| `gospider` | binary | core | active | 3 | no |
| `subjs` | binary | core | active | 3 | no |
| `unfurl` | binary | core | passive | 3 | no |
| `urlfinder` | binary | core | passive | 3 | no |



---

## `gau`

- **Registry:** binary, core, passive, phase 3, `stage: urls`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/lc/gau
- **Installed on this box:** `/home/kali/.reconkit/bin/gau`, `gau version: 2.2.4`
- **Where it comes from:** github.com/lc/gau (v2) - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes, as multiple positional arguments** (no list-file flag)

#### Real `--help` (raw, full)

Captured with `gau --help` (exit 0, wrote to stderr):

```
Usage of gau:
      --blacklist strings   list of extensions to skip
      --config string       location of config file (default $HOME/.gau.toml or %USERPROFILE%\.gau.toml)
      --fc strings          list of status codes to filter
      --fp                  remove different parameters of the same endpoint
      --from string         fetch urls from date (format: YYYYMM)
      --ft strings          list of mime-types to filter
      --json                output as json
      --mc strings          list of status codes to match
      --mt strings          list of mime-types to match
      --o string            filename to write results to
      --providers strings   list of providers to use (wayback,commoncrawl,otx,urlscan)
      --proxy string        http proxy to use
      --retries uint        retries for HTTP client
      --subs                include subdomains of target domain
      --threads uint        number of workers to spawn (default 1)
      --timeout uint        timeout (in seconds) for HTTP client (default 45)
      --to string           fetch urls to date (format: YYYYMM)
      --verbose             show verbose output
      --version             show gau version
```


#### Real test on testfire.net

Command:

```
gau --threads 2 testfire.net
```


Output (raw, exit code 0):

```
http://www.testfire.net:80/
http://www.testfire.net:80/admin
http://testfire.net:80/admin.aspx
http://testfire.net:80/admin/admin.%20aspx
http://www.testfire.net:80/admin/admin.asp
http://www.testfire.net:80/admin/admin.aspx
http://testfire.net:80/admin/admin.jsp
http://www.testfire.net:80/admin/%2Fadmin%2Flogin.aspx
http://www.testfire.net:80/admin/application.aspx
http://testfire.net/admin/captcha.aspx
http://testfire.net/admin/clients.xls
http://testfire.net:80/admin/index.jsp
... (473 more lines, 485 total)
--- stderr ---
time="2026-11-16T08:57:01-05:00" level=warning msg="error reading config: Config file /home/kali/.gau.toml not found, using default config"
```


#### Notes and errors hit

Output (exit 0, 485 lines; first three):

```
http://www.testfire.net:80/
http://www.testfire.net:80/admin
http://testfire.net:80/admin.aspx
```

It prints a warning on stderr when no config exists:
`error reading config: Config file /home/kali/.gau.toml not found, using default
config`. That is normal, not a failure.


---

## `waybackurls`

- **Registry:** binary, core, passive, phase 3, `stage: urls`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/tomnomnom/waybackurls
- **Installed on this box:** `/home/kali/.reconkit/bin/waybackurls` (no version flag; `-h` prints usage)
- **Where it comes from:** github.com/tomnomnom/waybackurls - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes, as multiple positional arguments or stdin**

#### Real `--help` (raw, full)

Captured with `waybackurls -h` (exit 0, wrote to stderr):

```
Usage of waybackurls:
  -dates
    	show date of fetch in the first column
  -get-versions
    	list URLs for crawled versions of input URL(s)
  -no-subs
    	don't include subdomains of the target domain
```


#### Real test on testfire.net

Command:

```
waybackurls testfire.net
```


Output (raw, exit code 0):

```
http://testfire.net/
http://testfire.net/default.aspx?content=personal_savings.htm
http://testfire.net/robots.txt
http://demo.testfire.net/
http://demo.testfire.net/admin/admin.aspx
http://demo.testfire.net/admin/login.aspx
http://demo.testfire.net/default.aspx?content=business.htm
http://demo.testfire.net/default.aspx?content=inside.htm
http://demo.testfire.net/default.aspx?content=inside_benefits.htm
http://demo.testfire.net/default.aspx?content=inside_community.htm
http://demo.testfire.net/default.aspx?content=inside_contact.htm
http://demo.testfire.net/default.aspx?content=inside_executives.htm
... (15 more lines, 27 total)
```


#### Notes and errors hit

Output (exit 0, 27 lines; first three):

```
http://testfire.net/
http://testfire.net/default.aspx?content=personal_savings.htm
http://testfire.net/robots.txt
```

Queries the Wayback CDX API; no traffic to the target.


---

## `katana`

- **Registry:** binary, core, active, phase 3, `stage: urls`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/projectdiscovery/katana
- **Installed on this box:** `/home/kali/go/bin/katana`, `[INF] Current version: v1.8.0`
- **Where it comes from:** https://github.com/projectdiscovery/katana/releases - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes** - `-u, -list string[]` (target url / list)

#### Real `--help` (raw, full)

Captured with `katana -h` (exit 0, wrote to stdout):

```
Katana is a fast crawler focused on execution in automation pipelines offering both headless and non-headless crawling.

Usage:
  katana [flags]

Flags:
INPUT:
   -u, -list string[]     target url / list to crawl
   -resume string         resume scan using resume.cfg
   -e, -exclude string[]  exclude host matching specified filter ('cdn', 'private-ips', cidr, ip, regex)

CONFIGURATION:
   -r, -resolvers string[]              list of custom resolver (file or comma separated)
   -d, -depth int                       maximum depth to crawl (default 3)
   -jc, -js-crawl                       enable endpoint parsing / crawling in javascript file
   -jsl, -jsluice                       enable jsluice parsing in javascript file (memory intensive)
   -ct, -crawl-duration value           maximum duration to crawl the target for (s, m, h, d) (default s)
   -kf, -known-files value              enable crawling of known files (all,robotstxt,sitemapxml), a minimum depth of 3 is required to ensure all known files are properly crawled.
   -mrs, -max-response-size int         maximum response size to read (default 4194304)
   -timeout int                         time to wait for request in seconds (default 10)
   -time-stable int                     time to wait until the page is stable in seconds (default 1)
   -aff, -automatic-form-fill           enable automatic form filling (experimental)
   -fx, -form-extraction                extract form, input, textarea & select elements in jsonl output
   -retry int                           number of times to retry the request (default 1)
   -proxy string                        http/socks5 proxy to use
   -td, -tech-detect                    enable technology detection
   -H, -headers string[]                custom header/cookie to include in all http request in header:value format (file)
   -config string                       path to the katana configuration file
   -fc, -form-config string             path to custom form configuration file
   -flc, -field-config string           path to custom field configuration file
   -s, -strategy string                 Visit strategy (depth-first, breadth-first) (default "depth-first")
   -iqp, -ignore-query-params           Ignore crawling same path with different query-param values
   -fsu, -filter-similar                filter crawling of similar looking URLs (e.g., /users/123 and /users/456)
   -fst, -filter-similar-threshold int  number of distinct values before a path position is treated as parameter (default 10) (default 10)
   -tlsi, -tls-impersonate              enable experimental client hello (ja3) tls randomization
   -dr, -disable-redirects              disable following redirects (default false)
   -pc, -path-climb                     enable path climb (auto crawl parent paths)
   -kb, -knowledge-base                 enable knowledge base classification
   -kb-secrets                          enable secrets extractor in the knowledge base
   -kb-validate-secrets                 validate detected secrets against their provider (sends live API calls)
   -kb-endpoints                        enable endpoints extractor (classifies REST/GraphQL/SOAP/XHR requests)
   -mdp, -max-domain-pages int          maximum number of pages to crawl per domain (default unlimited)

DEBUG:
   -health-check, -hc        run diagnostic check up
   -elog, -error-log string  file to write sent requests error log
   -pprof-server             enable pprof server

HEADLESS:
   -hl, -headless                         enable headless crawling (experimental)
   -hh, -hybrid                           enable headless hybrid crawling (experimental)
   -sc, -system-chrome                    use local installed chrome browser instead of katana installed
   -sb, -show-browser                     show the browser on the screen with headless mode
   -ho, -headless-options string[]        start headless chrome with additional options
   -nos, -no-sandbox                      start headless chrome in --no-sandbox mode
   -cdd, -chrome-data-dir string          path to store chrome browser data
   -scp, -system-chrome-path string       use specified chrome browser for headless crawling
   -noi, -no-incognito                    start headless chrome without incognito mode
   -cwu, -chrome-ws-url string            use chrome browser instance launched elsewhere with the debugger listening at this URL
   -xhr, -xhr-extraction                  extract xhr request url,method in jsonl output
   -mfc, -max-failure-count int           maximum number of consecutive action failures before stopping (default 10)
   -ed, -enable-diagnostics               enable diagnostics
   -pls, -page-load-strategy string       page load strategy (heuristic, load, domcontentloaded, networkidle, none) (default "heuristic")
   -dwt, -dom-wait-time int               time in seconds to wait after page load when using domcontentloaded strategy (default 5)
   -csp, -captcha-solver-provider string  captcha solver provider (e.g. capsolver)
   -csk, -captcha-solver-key string       captcha solver provider api key
   -al, -auto-login string                automatic login with username:password (headless only)
   -rf, -recorded-flow string             chrome DevTools Recorder JSON (or explicit steps) to replay before crawl (headless only)

SCOPE:
   -cs, -crawl-scope string[]       in scope url regex to be followed by crawler
   -cos, -crawl-out-scope string[]  out of scope url regex to be excluded by crawler
   -fs, -field-scope string         pre-defined scope field (dn,rdn,fqdn) or custom regex (e.g., '(company-staging.io|company.com)') (default "rdn")
   -ns, -no-scope                   disables host based default scope
   -do, -display-out-scope          display external endpoint from scoped crawling

FILTER:
   -mr, -match-regex string[]                     regex or list of regex to match on output url (cli, file)
   -fr, -filter-regex string[]                    regex or list of regex to filter on output url (cli, file)
   -f, -field string                              field to display in output (url,path,fqdn,rdn,rurl,qurl,qpath,file,ufile,key,value,kv,dir,udir) (Deprecated: use -output-template instead)
   -sf, -store-field string                       field to store in per-host output (url,path,fqdn,rdn,rurl,qurl,qpath,file,ufile,key,value,kv,dir,udir)
   -em, -extension-match string[]                 match output for given extension (eg, -em php,html,js,none)
   -ef, -extension-filter string[]                filter output for given extension (eg, -ef png,css)
   -ndef, -no-default-ext-filter                  remove default extensions from the filter list
   -mdc, -match-condition string                  match response with dsl based condition
   -fdc, -filter-condition string                 filter response with dsl based condition
   -duf, -disable-unique-filter                   disable duplicate content filtering
   -pcs, -page-content-similar                    enable page content similarity filtering (after exact content dedup)
   -sdd, -similarity-deduplication                alias for -pcs (page content similarity)
   -pcsm, -page-content-similar-mode string       similarity mode: simhash, tfidf, or bm25 (default "simhash")
   -pcsd, -page-content-similar-distance int      simhash max hamming distance (default 3) (default 3)
   -pcst, -page-content-similar-threshold string  tfidf/bm25 min score 0-1 (default 0.85) (default "0.85")
   -pcsn, -page-content-similar-budget int        pages to fully process per similarity cluster (default 1) (default 1)
   -fpt, -filter-page-type string[]               filter response with page type (e.g. error,captcha,parked)

RATE-LIMIT:
   -c, -concurrency int                number of concurrent fetchers to use (default 10)
   -p, -parallelism int                number of concurrent inputs to process (default 10)
   -rd, -delay int                     request delay between each request in seconds
   -rl, -rate-limit int                maximum requests to send per second (default 150)
   -rlm, -rate-limit-minute int        maximum number of requests to send per minute
   -hrl, -host-rate-limit int          maximum requests to send per second per host
   -hrlm, -host-rate-limit-minute int  maximum number of requests to send per minute per host

UPDATE:
   -up, -update                 update katana to latest version
   -duc, -disable-update-check  disable automatic katana update check

OUTPUT:
   -o, -output string                     file to write output to
   -ot, -output-template string           custom output template
   -sr, -store-response                   store http requests/responses
   -srd, -store-response-dir string       store http requests/responses to custom directory
   -ncb, -no-clobber                      do not overwrite output file
   -sfd, -store-field-dir string          store per-host field to custom directory
   -or, -omit-raw                         omit raw requests/responses from jsonl output
   -ob, -omit-body                        omit response body from jsonl output
   -lof, -list-output-fields              list of fields to output in jsonl format
   -eof, -exclude-output-fields string[]  exclude fields from jsonl output
   -j, -jsonl                             write output in jsonl format
   -nc, -no-color                         disable output content coloring (ANSI escape codes)
   -silent                                display output only
   -v, -verbose                           display verbose output
   -debug                                 display debug output
   -version                               display project version
```


#### Real test on testfire.net

Command:

```
katana -u https://testfire.net -d 1 -silent -nc -duc -rl 5
```


Output (raw, exit code 0):

```
https://testfire.net
https://testfire.net/style.css
https://testfire.net/status_check.jsp
https://testfire.net/index.jsp
https://testfire.net/login.jsp
https://testfire.net/index.jsp?content=inside_contact.htm
https://testfire.net/feedback.jsp
https://testfire.net/login.jsp
https://testfire.net/index.jsp?content=personal.htm
https://testfire.net/index.jsp?content=business.htm
https://testfire.net/index.jsp?content=inside.htm
https://testfire.net/index.jsp?content=personal.htm
... (1120 more lines, 1132 total)
```


#### Notes and errors hit

Output (exit 0, 1132 lines; first three):

```
https://testfire.net
https://testfire.net/style.css
https://testfire.net/status_check.jsp
```

This is a real crawl of the authorized target at rate limit 5/s, depth 1. The
`-rl` flag was the registry's `rate_flag` until 2026-11-17; the `rate_flag`
field and the pacer were removed with all speed control (docs/MASTER_PLAN.md
D3), so reconkit no longer passes `-rl` and the limit above was typed by hand.


---

## `hakrawler`

- **Registry:** binary, core, active, phase 3, `stage: urls`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/hakluke/hakrawler
- **Installed on this box:** `/home/kali/.reconkit/bin/hakrawler` (no version flag; `--help` prints usage and `-h` takes an argument)
- **Where it comes from:** github.com/hakluke/hakrawler - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes, via stdin** - one URL per line

#### Real `--help` (raw, full)

Captured with `hakrawler -h` (exit 2, wrote to stderr):

```
flag needs an argument: -h
Usage of hakrawler:
  -d int
    	Depth to crawl. (default 2)
  -dr
    	Disable following HTTP redirects.
  -h string
    	Custom headers separated by two semi-colons. E.g. -h "Cookie: foo=bar;;Referer: http://example.com/" 
  -i	Only crawl inside path
  -insecure
    	Disable TLS verification.
  -json
    	Output as JSON.
  -proxy string
    	Proxy URL. E.g. -proxy http://127.0.0.1:8080
  -s	Show the source of URL based on where it was found. E.g. href, form, script, etc.
  -size int
    	Page size limit, in KB. (default -1)
  -subs
    	Include subdomains for crawling.
  -t int
    	Number of threads to utilise. (default 8)
  -timeout int
    	Maximum time to crawl each URL from stdin, in seconds. (default -1)
  -u	Show only unique urls.
  -w	Show at which link the URL is found.
```


#### Real test on testfire.net

Command:

```
echo https://testfire.net | hakrawler -d 1
```


Output (raw, exit code 0):

```

--- stderr ---
No URLs were found. This usually happens when a domain is specified (https://example.com), but it redirects to a subdomain (https://www.example.com). The subdomain is not included in the scope, so the no URLs are printed. In order to overcome this, either specify the final URL in the redirect chain or use the -subs option to include subdomains.
```


#### Notes and errors hit

Output (exit 0, **0 URLs**), with its own explanation on stderr:

```
No URLs were found. This usually happens when a domain is specified (https://example.com),
but it redirects to a subdomain (https://www.example.com). The subdomain is not included
in the scope, so the ...
```

`testfire.net` redirects to `www.testfire.net` and hakrawler refuses to leave the
given scope, so the empty result is correct behaviour, not a failure. Note
`-h` is **not** help here (it takes an argument); use `--help`.


---

## `gospider`

- **Registry:** binary, core, active, phase 3, `stage: urls`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/jaeles-project/gospider
- **Installed on this box:** `/home/kali/.reconkit/bin/gospider`, `v1.1.6`
- **Where it comes from:** github.com/jaeles-project/gospider - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** not verified from `-h`; `-S`/`--site` takes a list

#### Real `--help` (raw, full)

Captured with `gospider -h` (exit 0, wrote to stdout):

```
Fast web spider written in Go - v1.1.6 by @thebl4ckturtle & @j3ssiejjj

Usage:
  gospider [flags]

Flags:
  -s, --site string               Site to crawl
  -S, --sites string              Site list to crawl
  -p, --proxy string              Proxy (Ex: http://127.0.0.1:8080)
  -o, --output string             Output folder
  -u, --user-agent string         User Agent to use
                                  	web: random web user-agent
                                  	mobi: random mobile user-agent
                                  	or you can set your special user-agent (default "web")
      --cookie string             Cookie to use (testA=a; testB=b)
  -H, --header stringArray        Header to use (Use multiple flag to set multiple header)
      --burp string               Load headers and cookie from burp raw http request
      --blacklist string          Blacklist URL Regex
      --whitelist string          Whitelist URL Regex
      --whitelist-domain string   Whitelist Domain
  -L, --filter-length string      Turn on length filter
  -t, --threads int               Number of threads (Run sites in parallel) (default 1)
  -c, --concurrent int            The number of the maximum allowed concurrent requests of the matching domains (default 5)
  -d, --depth int                 MaxDepth limits the recursion depth of visited URLs. (Set it to 0 for infinite recursion) (default 1)
  -k, --delay int                 Delay is the duration to wait before creating a new request to the matching domains (second)
  -K, --random-delay int          RandomDelay is the extra randomized duration to wait added to Delay before creating a new request (second)
  -m, --timeout int               Request timeout (second) (default 10)
  -B, --base                      Disable all and only use HTML content
      --js                        Enable linkfinder in javascript file (default true)
      --sitemap                   Try to crawl sitemap.xml
      --robots                    Try to crawl robots.txt (default true)
  -a, --other-source              Find URLs from 3rd party (Archive.org, CommonCrawl.org, VirusTotal.com, AlienVault.com)
  -w, --include-subs              Include subdomains crawled from 3rd party. Default is main domain
  -r, --include-other-source      Also include other-source's urls (still crawl and request)
      --subs                      Include subdomains
      --debug                     Turn on debug mode
      --json                      Enable JSON output
  -v, --verbose                   Turn on verbose
  -q, --quiet                     Suppress all the output and only show URL
      --no-redirect               Disable redirect
      --version                   Check version
  -l, --length                    Turn on length
  -R, --raw                       Enable raw output
  -h, --help                      help for gospider
```


#### Real test on testfire.net

Command:

```
gospider -s https://testfire.net -d 1 -q
```


Output (raw, exit code 0):

```
https://testfire.net
```


#### Notes and errors hit

Output (exit 0, 1 line):

```
https://testfire.net
```

Depth 1 with `-q` returned only the seed URL. Its output prefixes each line with
a tag such as `[url] -` in the default format, which a parser must strip.


---

## `subjs`

- **Registry:** binary, core, active, phase 3, `stage: urls`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/lc/subjs
- **Installed on this box:** `/home/kali/.reconkit/bin/subjs`, `subjs version: 1.0.1`
- **Where it comes from:** github.com/lc/subjs - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes, via stdin**

#### Real `--help` (raw, full)

Captured with `subjs -h` (exit 0, wrote to stderr):

```
Usage of subjs:
  -c int
    	Number of concurrent workers (default 10)
  -i string
    	Input file containing URLS
  -t int
    	Timeout (in seconds) for http client (default 15)
  -ua string
    	User-Agent to send in requests
  -version
    	Show version number
```


#### Real test on testfire.net

Command:

```
echo https://testfire.net | subjs
```


Output (raw, exit code 0):

```

```


#### Notes and errors hit

Output (exit 0, **0 lines**): the page it fetched referenced no
separate `.js` files. An empty result here means "no JS URLs found", not a
failure; `katana` found 1132 URLs for the same host, so the crawler and this
extractor see different pages.

Version command is `-version`.


---

## `unfurl`

- **Registry:** binary, core, passive, phase 3, `stage: urls`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/tomnomnom/unfurl
- **Installed on this box:** `/home/kali/.reconkit/bin/unfurl` (no version flag; `-h` prints usage)
- **Where it comes from:** github.com/tomnomnom/unfurl - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes, via stdin**

#### Real `--help` (raw, full)

Captured with `unfurl -h` (exit 0, wrote to stderr):

```
Format URLs provided on stdin

Usage:
  unfurl [OPTIONS] [MODE] [FORMATSTRING]

Options:
  -u, --unique   Only output unique values
  -v, --verbose  Verbose mode (output URL parse errors)

Modes:
  keys     Keys from the query string (one per line)
  values   Values from the query string (one per line)
  keypairs Key=value pairs from the query string (one per line)
  domains  The hostname (e.g. sub.example.com)
  paths    The request path (e.g. /users)
  apexes   The apex domain (e.g. example.com from sub.example.com)
  json     JSON encoded url/format objects
  format   Specify a custom format (see below)

Format Directives:
  %%  A literal percent character
  %s  The request scheme (e.g. https)
  %u  The user info (e.g. user:pass)
  %d  The domain (e.g. sub.example.com)
  %S  The subdomain (e.g. sub)
  %r  The root of domain (e.g. example)
  %t  The TLD (e.g. com)
  %P  The port (e.g. 8080)
  %p  The path (e.g. /users)
  %e  The path's file extension (e.g. jpg, html)
  %q  The raw query string (e.g. a=1&b=2)
  %f  The page fragment (e.g. page-section)
  %@  Inserts an @ if user info is specified
  %:  Inserts a colon if a port is specified
  %?  Inserts a question mark if a query string exists
  %#  Inserts a hash if a fragment exists
  %a  Authority (alias for %u%@%d%:%P)

Examples:
  cat urls.txt | unfurl keys
  cat urls.txt | unfurl format %s://%d%p?%q
```


#### Real test on testfire.net

Command:

```
echo "https://testfire.net/login.jsp?uid=1&pw=2" | unfurl keys
```


Output (raw, exit code 0):

```
pw
uid
```


#### Notes and errors hit

Output (exit 0):

```
pw
uid
```

Pure local string work - no traffic at all. `unfurl keys` prints one parameter
name per line, which is what a parameter-candidate feature would consume.


---

## `urlfinder`

- **Registry:** binary, core, passive, phase 3, `stage: urls`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/projectdiscovery/urlfinder
- **Installed on this box:** `/home/kali/.reconkit/bin/urlfinder`, `[INF] Current Version: v0.0.3`
- **Where it comes from:** https://github.com/projectdiscovery/urlfinder/releases - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes** - `-d, -list string[]` (target domain / list)

#### Real `--help` (raw, full)

Captured with `urlfinder -h` (exit 0, wrote to stdout):

```
A streamlined tool for discovering associated urls.

Usage:
  urlfinder [flags]

Flags:
INPUT:
   -d, -list string[]  target domain / list to find urls for

SOURCE:
   -s, -sources string[]           specific sources to use for discovery (-s alienvault,commoncrawl). Use -ls to display all available sources.
   -es, -exclude-sources string[]  sources to exclude from enumeration (-es alienvault,commoncrawl)
   -all                            use all sources for enumeration (slow)

SCOPE:
   -us, -url-scope string[]       in scope url regex to be followed by urlfinder
   -uos, -url-out-scope string[]  out of scope url regex to be excluded by urlfinder
   -fs, -field-scope string       pre-defined scope field (dn,rdn,fqdn) or custom regex (e.g., '(company-staging.io|company.com)') (default "rdn")
   -ns, -no-scope                 disables host based default scope
   -do, -display-out-scope        display external endpoint from scoped crawling

FILTER:
   -m, -match string[]   url or list of url to match (file or comma separated)
   -f, -filter string[]   url or list of url to filter (file or comma separated)

RATE-LIMIT:
   -rl, -rate-limit int      maximum number of http requests to send per second (global)
   -rls, -rate-limits value  maximum number of http requests to send per second four providers in key=value format (-rls hackertarget=10/m) (default ["waybackarchive=15/m"])

UPDATE:
   -up, -update                 update urlfinder to latest version
   -duc, -disable-update-check  disable automatic urlfinder update check

OUTPUT:
   -o, -output string       file to write output to
   -j, -jsonl               write output in JSONL(ines) format
   -od, -output-dir string  directory to write output file
   -cs, -collect-sources    include all sources in the output (-json only)

CONFIGURATION:
   -config string                flag config file (default "/home/kali/.config/urlfinder/config.yaml")
   -pc, -provider-config string  provider config file (default "/home/kali/.config/urlfinder/provider-config.yaml")
   -proxy string                 http proxy to use with urlfinder

DEBUG:
   -silent             show only urls in output
   -version            show version of urlfinder
   -v                  show verbose output
   -nc, -no-color      disable color in output
   -ls, -list-sources  list all available sources
   -stats              report source statistics

OPTIMIZATION:
   -timeout int   seconds to wait before timing out (default 30)
   -max-time int  minutes to wait for enumeration results (default 10)
```


#### Real test on testfire.net

Command:

```
urlfinder -d testfire.net -silent -nc -duc
```


Output (raw, exit code 0):

```
https://demo.testfire.net/]
https://demo.testfire.net/robots.txt
http://testfire.net/.HTTP/HTTP.db
http://testfire.net/api/v1/license/keys-status/cgi.exe
https://demo.testfire.net/swagger/swagger-ui-bundle.js
http://demo.testfire.net/login.jsp
http://testfire.net/api/v1/
http://testfire.net/api/v1/cav/admin/
https://demo.testfire.net/static/
http://demo.testfire.net/
http://demo.testfire.net/1234567890*~1*/cgi.exe
http://testfire.net/javadoc/releases/reposilite.db
... (61 more lines, 73 total)
```


#### Notes and errors hit

Output (exit 0, 73 lines; first three):

```
https://demo.testfire.net/]
https://demo.testfire.net/robots.txt
http://testfire.net/.HTTP/HTTP.db
```

Note the malformed first line (`/]`) - it is raw source data, so an adapter
must validate URLs before storing them.

