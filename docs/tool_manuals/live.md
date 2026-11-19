# Tool manuals - live

Stage `live` of `reconkit`. Verified on the canonical Kali checkout
(`/home/kali/Desktop/reconkit`, Python 3.14.8) on **2026-11-16**. Every
`--help` block and every test block below is the tool's own raw output,
captured on that machine; nothing here is written from memory.

Authorized target used for the one safe test: **testfire.net** (already in
`scope.yaml`). One command per tool, no payloads, no brute force.

Tools from the `vulns` stage are deliberately absent - see
`docs/tool_manuals/README.md` ("Skipped").

| Tool | Kind | Tier | Mode | Phase | Adapter in this build |
|---|---|---|---|---|---|
| `pyprobe` | python | core | active | 2 | yes |
| `httpx` | binary | core | active | 2 | yes |
| `httprobe` | binary | core | active | 3 | yes (wave 2, 2026-11-17) |
| `tlsx` | binary | core | active | 3 | yes (wave 1, 2026-11-17) |



---

## `pyprobe`

- **Registry:** python, core, active, phase 2, `stage: live`
- **Adapter in this build:** `src/reconkit/adapters/pyprobe.py`
- **Official source used:** https://docs.python.org/3/library/ssl.html + asyncio (standard library only)
- **Installed on this box:** stdlib in the venv
- **Install command:** nothing to install (`install: {method: none}`)
- **Multi-domain input:** n/a - the adapter probes one host at a time from `ctx.hosts`

#### Real test

A raw TLS connect + `HEAD /`, which is what the adapter does (redirects are
never followed, and the honest User-Agent is sent):

```
python - <<'EOF'
import socket, ssl
ctx = ssl._create_unverified_context()
with socket.create_connection(("testfire.net", 443), timeout=10) as s:
    with ctx.wrap_socket(s, server_hostname="testfire.net") as t:
        t.sendall(b"HEAD / HTTP/1.1\r\nHost: testfire.net\r\nUser-Agent: reconkit/1.0.0\r\nConnection: close\r\n\r\n")
        print(t.recv(200).split(b"\r\n")[0].decode())
EOF
```

Output (exit 0):

```
pyprobe-equivalent status line: HTTP/1.1 200 OK
```

#### A real certificate failure on this target

With a verifying context the same connect fails:

```
ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
Hostname mismatch, certificate is not valid for 'testfire.net'. (_ssl.c:1127)
```

That is why PIT-37 exists: a TLS failure on one scheme must not end the probe -
the `http` scheme is still tried, and `UNKNOWN` needs "no scheme answered" plus
a TLS error.

#### What a normal exit code looks like

Exit 0; the record carries `status_code=200`. A plain connect failure on every
scheme writes no record at all (`unreachable=`), never `DEAD`.


---

## `httpx`

- **Registry:** binary, core, active, phase 2, `stage: live`
- **Adapter in this build:** `src/reconkit/adapters/httpx_tool.py`
- **Official source used:** https://github.com/projectdiscovery/httpx
- **Installed on this box:** `/home/kali/.reconkit/bin/httpx` and `/home/kali/go/bin/httpx`, `[INF] Current Version: v1.12.0`
- **Where it comes from:** https://github.com/projectdiscovery/httpx/releases - Kali ships it as `httpx-toolkit`, and the Python `httpx` CLI is a different program (PIT-14) - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes** - `-l, -list string` (input file of hosts)

#### Real `--help` (raw, full)

Captured with `httpx -h` (exit 0, wrote to stdout):

```
httpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library.

Usage:
  httpx [flags]

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
   -mcdn, -match-cdn string[]         match host with specified cdn provider (gocache, kinx, 百度云加速, arvancloud, cafe24, cdnetworks, gcore, google, skbroadband, 云盾, 加速乐, 腾讯云, cloudfront, fastly, lgtelecom, qrator)
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
   -fcdn, -filter-cdn string[]            filter host with specified cdn provider (gocache, kinx, 百度云加速, arvancloud, cafe24, cdnetworks, gcore, google, skbroadband, 云盾, 加速乐, 腾讯云, cloudfront, fastly, lgtelecom, qrator)
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


#### Real test on testfire.net

Command:

```
httpx -u testfire.net -silent -sc -title -location -td -cdn -nc -duc
```


Output (raw, exit code 0):

```
https://testfire.net [200] [] [Altoro Mutual] [Apache Tomcat,Java]
```


#### Notes and errors hit

Output (exit 0, one JSON-less line with `-silent`):

```
https://testfire.net [200] [] [Altoro Mutual] [Apache Tomcat,Java]
```

Format: `url [status] [location] [title] [tech]`. The `[]` is the empty
`location` (no redirect). With `-json` the adapter reads the keys `input`,
`url`, `status_code`, `title`, `location`, `tech`, `cdn_name` (verified
2026-11-14, docs/09 section 9).


---

## `httprobe`

- **Registry:** binary, core, active, phase 3, `stage: live`
- **Adapter in this build:** `src/reconkit/adapters/httprobe.py` (wave 2, 2026-11-17); runs as `-t <milliseconds>` with the host list on **stdin** (`runner.run_exec(..., stdin_text=...)`), parses one `scheme://host` per line into `HostStatusRecord(ALIVE)`, and has no `-prefer-https` flag - the default probes (http:80 and https:443) stay untouched. Identity is `-h` + two markers, because `-version` exits 2
- **Official source used:** https://github.com/tomnomnom/httprobe
- **Installed on this box:** `/home/kali/.reconkit/bin/httprobe` (no version flag; `-h` prints usage)
- **Where it comes from:** github.com/tomnomnom/httprobe - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes, via stdin** - one host per line

#### Real `--help` (raw, full)

Captured with `httprobe -h` (exit 0, wrote to stderr):

```
Usage of httprobe:
  -c int
    	set the concurrency level (default 20)
  -p value
    	add additional probe (proto:port)
  -s	skip the default probes (http:80 and https:443)
  -t int
    	timeout (milliseconds) (default 10000)
  -v	output errors to stderr
```


#### Real test on testfire.net

Command:

```
echo testfire.net | httprobe
```


Output (raw, exit code 0):

```
http://testfire.net
https://testfire.net
```


#### Notes and errors hit

Output (exit 0):

```
http://testfire.net
https://testfire.net
```

It reads hosts from stdin and prints only the URLs that answered - no status
code, no title. A future adapter gets liveness only.


---

## `tlsx`

- **Registry:** binary, core, active, phase 3, `stage: live`
- **Adapter in this build:** `src/reconkit/adapters/tlsx.py` (wave 1, 2026-11-17); runs as `-silent -json -san -duc -nc -u <host>` (one `-u` per host), liveness-only by ruling: `probe_status: true` becomes `ALIVE`, `false` becomes `UNKNOWN` with `detail="tls probe failed"`, and every SAN becomes a `SubdomainRecord` with `source="tlsx:san"` (the engine then persists it, PIT-49). Cert expiry/issuer/self-signed are **not** stored - that would need schema 7 and new `HostStatusRecord` fields
- **Official source used:** https://github.com/projectdiscovery/tlsx
- **Installed on this box:** `/home/kali/.reconkit/bin/tlsx`, `v1.4.0`
- **Where it comes from:** https://github.com/projectdiscovery/tlsx/releases - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes** - `-l, -list string` (target list file)

#### Real `--help` (raw, full)

Captured with `tlsx -h` (exit 0, wrote to stdout):

```
TLSX is a tls data gathering and analysis toolkit.

Usage:
  tlsx [flags]

Flags:
INPUT:
   -u, -host string[]  target host to scan (-u INPUT1,INPUT2)
   -l, -list string    target list to scan (-l INPUT_FILE)
   -p, -port string[]  target port to connect (default 443)

SCAN-MODE:
   -sm, -scan-mode string     tls connection mode to use (ctls, ztls, openssl, auto) (default "auto")
   -ps, -pre-handshake        enable pre-handshake tls connection (early termination) using ztls
   -sa, -scan-all-ips         scan all ips for a host (default false)
   -iv, -ip-version string[]  ip version to use (4, 6) (default 4)

PROBES:
   -san                     display subject alternative names
   -cn                      display subject common names
   -so                      display subject organization name
   -tv, -tls-version        display used tls version
   -cipher                  display used cipher
   -hash string             display certificate fingerprint hashes (md5,sha1,sha256)
   -jarm                    display jarm fingerprint hash
   -ja3                     display ja3 fingerprint hash (using ztls)
   -ja3s                    display ja3s fingerprint hash (using ztls)
   -wc, -wildcard-cert      display host with wildcard ssl certificate
   -tps, -probe-status      display tls probe status
   -ve, -version-enum       enumerate and display supported tls versions
   -ce, -cipher-enum        enumerate and display supported cipher
   -ct, -cipher-type value  ciphers types to enumerate. possible values: all/secure/insecure/weak (comma-separated) (default all)
   -ch, -client-hello       include client hello in json output (ztls mode only)
   -sh, -server-hello       include server hello in json output (ztls mode only)
   -se, -serial             display certificate serial number

CERTIFICATE TRANSPARENCY LOGS:
   -ctl, -ct-logs             enable certificate transparency logs streaming mode
   -cb, -ctl-beginning        start streaming each CT log from index 0
   -cti, -ctl-index string[]  custom start index per log using source ID: <sourceID>=<index> (e.g. google_xenon2025h2=12345)

MISCONFIGURATIONS:
   -ex, -expired      display host with host expired certificate
   -ss, -self-signed  display host with self-signed certificate
   -mm, -mismatched   display host with mismatched certificate
   -re, -revoked      display host with revoked certificate (warning: downloads full CRLs/OCSP per cert; high memory/network cost at scale — off by default)
   -un, -untrusted    display host with untrusted certificate

CONFIGURATIONS:
   -config string               path to the tlsx configuration file
   -r, -resolvers string[]      list of resolvers to use
   -cc, -cacert string          client certificate authority file
   -ci, -cipher-input string[]  ciphers to use with tls connection
   -sni string[]                tls sni hostname to use
   -rs, -random-sni             use random sni when empty
   -rps, -rev-ptr-sni           perform reverse PTR to retrieve SNI from IP
   -min-version string          minimum tls version to accept (ssl30,tls10,tls11,tls12,tls13)
   -max-version string          maximum tls version to accept (ssl30,tls10,tls11,tls12,tls13)
   -cert, -certificate          include certificates in json output (PEM format)
   -tc, -tls-chain              include certificates chain in json output
   -vc, -verify-cert            enable verification of server certificate
   -ob, -openssl-binary string  OpenSSL Binary Path
   -hf, -hardfail               treat revocation check errors as revoked (requires -revoked)
   -proxy string                socks5 proxy to use for tlsx

OPTIMIZATIONS:
   -c, -concurrency int           number of concurrent threads to process (default 300)
   -cec, -cipher-concurrency int  cipher enum concurrency for each target (default 10)
   -timeout int                   tls connection timeout in seconds (default 5)
   -retry int                     number of retries to perform for failures (default 3)
   -delay string                  duration to wait between each connection per thread (eg: 200ms, 1s)

UPDATE:
   -up, -update                 update tlsx to latest version
   -duc, -disable-update-check  disable automatic tlsx update check

OUTPUT:
   -o, -output string  file to write output to
   -j, -json           display json format output
   -dns                display unique hostname from SSL certificate response
   -ro, -resp-only     display tls response only
   -silent             display silent output
   -nc, -no-color      disable colors in cli output
   -v, -verbose        display verbose output
   -version            display project version

PDCP:
   -pd, -dashboard                 upload or view output in the PDCP UI dashboard
   -pdu, -dashboard-upload string  upload tlsx output file (JSONL format) to the PDCP UI dashboard
   -auth string                    PDCP API key for authentication
   -tid, -team-id string           upload asset results to a specified team ID
   -aid, -asset-id string          upload new assets to an existing asset ID
   -aname, -asset-name string      asset group name

DEBUG:
   -health-check, -hc  run diagnostic check up
```


#### Real test on testfire.net

Command:

```
tlsx -u testfire.net -silent -nc -duc
```


Output (raw, exit code 0):

```
testfire.net:443
```


#### Notes and errors hit

Output (exit 0):

```
testfire.net:443
```

Silent mode prints `host:port` only; `-san`/`-cn` reveal certificate names
(useful for finding subdomains).

