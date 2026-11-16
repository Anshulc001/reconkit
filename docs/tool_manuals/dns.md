# Tool manuals - dns

Stage `dns` of `reconkit`. Verified on the canonical Kali checkout
(`/home/kali/Desktop/reconkit`, Python 3.14.8) on **2026-11-16**. Every
`--help` block and every test block below is the tool's own raw output,
captured on that machine; nothing here is written from memory.

Authorized target used for the one safe test: **testfire.net** (already in
`scope.yaml`). One command per tool, no payloads, no brute force.

Tools from the `vulns` stage are deliberately absent - see
`docs/tool_manuals/README.md` ("Skipped").

| Tool | Kind | Tier | Mode | Phase | Adapter in this build |
|---|---|---|---|---|---|
| `dnspython` | python | core | passive | 2 | yes |
| `dnsx` | binary | core | passive | 3 | no |
| `puredns` | binary | core | passive | 3 | no |
| `massdns` | binary | core | passive | 3 | no |
| `dig` | binary | core | passive | 3 | no |



---

## `dnspython`

- **Registry:** python, core, passive, phase 2, `stage: dns`
- **Adapter in this build:** `src/reconkit/adapters/dnspython.py`
- **Official source used:** https://dnspython.readthedocs.io/
- **Installed on this box:** library in the venv, `dns.version.version == 2.9.2`
- **Install command:** nothing to install (`install: {method: none}`); it is a Python dependency
- **Multi-domain input:** n/a - the adapter resolves one host at a time through `ctx.hosts`

#### Real test

```
python -c 'import dns.resolver; print(sorted(r.address for r in dns.resolver.resolve("testfire.net", "A")))'
```

Output (exit 0):

```
dnspython A: ['65.61.137.117']
dnspython version: 2.9.2
```

#### What a normal exit code looks like

Exit 0. The adapter distinguishes `NXDOMAIN`, `NoAnswer`, `SERVFAIL`, timeout
and error as separate `DnsResult.outcome` values; only `NXDOMAIN` can later
produce `DEAD` (PIT-01).

#### Gotchas

- There is no command line; every "run" is a library call inside the process.


---

## `dnsx`

- **Registry:** binary, core, passive, phase 3, `stage: dns`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/projectdiscovery/dnsx
- **Installed on this box:** `/usr/bin/dnsx`, `[INF] Current Version: 1.3.1`
- **Install command:** `reconkit install dnsx` (github_release)
- **Multi-domain input:** **yes** - `-l, -list` (file, comma separated, or stdin)

#### Real `--help` (raw, full)

Captured with `dnsx -h` (exit 0, wrote to stdout):

```
dnsx is a fast and multi-purpose DNS toolkit allow to run multiple probes using retryabledns library.

Usage:
  dnsx [flags]

Flags:
INPUT:
   -l, -list string      list of sub(domains)/hosts to resolve (file or comma separated or stdin)
   -d, -domain string    list of domain to bruteforce (file or comma separated or stdin)
   -w, -wordlist string  list of words to bruteforce (file or comma separated or stdin)

QUERY:
   -a                       query A record (default)
   -aaaa                    query AAAA record
   -cname                   query CNAME record
   -ns                      query NS record
   -txt                     query TXT record
   -srv                     query SRV record
   -ptr                     query PTR record
   -mx                      query MX record
   -soa                     query SOA record
   -any                     query ANY record
   -axfr                    query AXFR
   -caa                     query CAA record
   -all, -recon             query all the dns records (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa)
   -e, -exclude-type value  dns query type to exclude (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa) (default none)

FILTER:
   -re, -resp                          display dns response
   -ro, -resp-only                     display dns response only
   -rc, -rcode string                  filter result by dns status code (eg. -rcode noerror,servfail,refused)
   -rtf, -response-type-filter string  return entries with no records for the specified query types (e.g., a, cname)

PROBE:
   -cdn  display cdn name
   -asn  display host asn information

RATE-LIMIT:
   -t, -threads int      number of concurrent threads to use (default 100)
   -rl, -rate-limit int  number of dns request/second to make (disabled as default) (default -1)

UPDATE:
   -up, -update                 update dnsx to latest version
   -duc, -disable-update-check  disable automatic dnsx update check

OUTPUT:
   -o, -output string            file to write output
   -j, -json                     write output in JSONL(ines) format
   -omit-raw, -or                omit raw dns response from jsonl output
   -ot, -output-template string  custom output template (e.g. -ot '{{host}} {{a}}')

DEBUG:
   -hc, -health-check  run diagnostic check up
   -silent             display only results in the output
   -v, -verbose        display verbose output
   -raw, -debug        display raw dns response
   -stats              display stats of the running scan
   -version            display version of dnsx
   -nc, -no-color      disable color in output

OPTIMIZATION:
   -retry int                number of dns attempts to make (must be at least 1) (default 2)
   -hf, -hostsfile           use system host file
   -trace                    perform dns tracing
   -trace-max-recursion int  Max recursion for dns trace (default 255)
   -resume                   resume existing scan
   -stream                   stream mode (wordlist, wildcard, stats and stop/resume will be disabled)
   -timeout value            maximum time to wait for a DNS query to complete (default 3s)

CONFIGURATIONS:
   -auth                         configure ProjectDiscovery Cloud Platform (PDCP) api key (default true)
   -r, -resolver string          list of resolvers to use (file or comma separated)
   -wt, -wildcard-threshold int  wildcard filter threshold (default 5)
   -auto-wildcard                automatically detect wildcard domains for filtering
   -wd, -wildcard-domain string  domain name for manual wildcard filtering (mutually exclusive with -auto-wildcard; other flags will be ignored - json output recommended)
   -proxy string                 proxy to use (eg socks5://127.0.0.1:8080)
```


#### Real test on testfire.net

Command:

```
printf 'testfire.net\nwww.testfire.net\n' | dnsx -silent -a
```


Output (raw, exit code 0):

```
testfire.net
www.testfire.net
```


#### Notes and errors hit

Two things a future adapter must know, both found the hard way:

1. `dnsx -d testfire.net` is **brute-force** mode and refuses to run without a
   wordlist: `[FTL] missing wordlist(w) flag required with domain(d) input`
   (exit 1).
2. Plain resolution is `-l`/stdin, which works:

```
$ printf 'testfire.net\nwww.testfire.net\n' | dnsx -silent -a
testfire.net
www.testfire.net
exit 0
```


---

## `puredns`

- **Registry:** binary, core, passive, phase 3, `stage: dns`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/d3mondev/puredns
- **Installed on this box:** `/home/kali/.reconkit/bin/puredns`, `puredns version v2.1.1`
- **Install command:** `reconkit install puredns` (`go install github.com/d3mondev/puredns/v2@latest`); needs `massdns` on `PATH`
- **Multi-domain input:** **yes** - takes a file of domains (`puredns resolve domains.txt`)

#### Real `--help` (raw, full)

Captured with `puredns --help` (exit 0, wrote to stdout):

```
puredns v2.1.1

A subdomain bruteforce tool that wraps around massdns to quickly resolve
a massive number of DNS queries. Using its heuristic algorithm, it can filter out
wildcard subdomains and validate that the results are free of DNS poisoning
by using trusted resolvers.

Usage:
  puredns [command]

Examples:
  puredns resolve domains.txt
  puredns bruteforce wordlist.txt domain.com --resolvers public.txt
  cat domains.txt | puredns resolve

Available Commands:
  bruteforce  Bruteforce subdomains using a wordlist
  resolve     Resolve a list of domains
  sponsors    Show the active sponsors <3

Flags:
      --debug     keep intermediate files
  -q, --quiet     quiet mode
  -h, --help      help for puredns
  -v, --version   version for puredns

Use "puredns [command] --help" for more information about a command.
```


#### Real test on testfire.net

Command:

```
puredns resolve d.txt -r res.txt -q
```


Output (raw, exit code 0):

```
testfire.net
www.testfire.net
```


#### Notes and errors hit

`d.txt` held `testfire.net` and `www.testfire.net`; `res.txt` held
`8.8.8.8` and `1.1.1.1`. Output (exit 0):

```
testfire.net
www.testfire.net
```

Note `--version` (not `version`) and that `resolve` needs `-r <resolvers file>`
or it has no resolvers to ask. It prints a banner on stderr even with `-q`.


---

## `massdns`

- **Registry:** binary, core, passive, phase 3, `stage: dns`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/blechschmidt/massdns
- **Installed on this box:** `/usr/bin/massdns`, `dpkg-query` version `1.1.0-0kali2`
- **Install command:** `reconkit install massdns` (`apt install massdns`, needs sudo)
- **Multi-domain input:** **yes** - a domain-list file as the positional argument (or stdin)

#### Real `--help` (raw, full)

Captured with `massdns -h` (exit 0, wrote to stderr):

```
Usage: massdns [options] [domainlist]
  -b  --bindto           Bind to IP address and port. (Default: 0.0.0.0:0)
      --busy-poll        Use busy-wait polling instead of epoll.
  -c  --resolve-count    Number of resolves for a name before giving up. (Default: 50)
      --drop-group       Group to drop privileges to when running as root. (Default: nogroup)
      --drop-user        User to drop privileges to when running as root. (Default: nobody)
      --extended-input   Input names are followed by a space-separated list of resolvers.
                         These are used before falling back to the resolvers file.
      --filter           Only output packets with the specified response code.
      --flush            Flush the output file whenever a response was received.
  -h  --help             Show this help.
      --ignore           Do not output packets with the specified response code.
  -i  --interval         Interval in milliseconds to wait between multiple resolves of the same
                         domain. (Default: 500)
  -l  --error-log        Error log file path. (Default: /dev/stderr)
      --norecurse        Use non-recursive queries. Useful for DNS cache snooping.
  -o  --output           Flags for output formatting.
      --predictable      Use resolvers incrementally. Useful for resolver tests.
      --processes        Number of processes to be used for resolving. (Default: 1)
  -q  --quiet            Quiet mode.
      --rand-src-ipv6    Use a random IPv6 address from the specified subnet for each query.
      --rcvbuf           Size of the receive buffer in bytes.
      --retry            Unacceptable DNS response codes.
                         (Default: All codes but NOERROR or NXDOMAIN)
  -r  --resolvers        Text file containing DNS resolvers.
      --root             Do not drop privileges when running as root. Not recommended.
  -s  --hashmap-size     Number of concurrent lookups. (Default: 10000)
      --sndbuf           Size of the send buffer in bytes.
      --status-format    Format for real-time status updates, json or ansi (Default: ansi)
      --sticky           Do not switch the resolver when retrying.
      --socket-count     Socket count per process. (Default: 1)
  -t  --type             Record type to be resolved. (Default: A)
      --verify-ip        Verify IP addresses of incoming replies.
  -w  --outfile          Write to the specified output file instead of standard output.

Output flags:
  L - domain list output
  S - simple text output
  F - full text output
  B - binary output
  J - ndjson output

Advanced flags for the domain list output mode:
  0 - Include NOERROR replies without answers.

Advanced flags for the simple output mode:
  d - Include records from the additional section.
  i - Indent any reply record.
  l - Separate replies using a line feed.
  m - Only output reply records that match the question name.
  n - Include records from the answer section.
  q - Print the question.
  r - Print the question with resolver IP address, Unix timestamp and return code prepended.
  s - Separate packet sections using a line feed.
  t - Include TTL and record class within the output.
  u - Include records from the authority section.

Advanced flags for the ndjson output mode:
  e - Write a record for each terminal query failure.
```


#### Real test on testfire.net

Command:

```
massdns -r res.txt -t A -o S d.txt
```


Output (raw, exit code 0):

```
testfire.net. A 65.61.137.117
www.testfire.net. CNAME testfire.net.
--- stderr ---
[H[2JConcurrency: 10000
Processed queries: 0
Received packets: 0
Progress: 0.00% (00 h 00 min 00 sec / 00 h 00 min 00 sec)
Current incoming rate: 0 pps, average: 0 pps
Current success rate: 0 pps, average: 0 pps
... (24 more lines, 30 total)
```


#### Notes and errors hit

Output (exit 0, stdout is the result stream, stderr is a progress meter):

```
testfire.net. A 65.61.137.117
www.testfire.net. CNAME testfire.net.
```

`-o S` is the simple text format; massdns has **no JSON** output format (S/L/F/B
only), so a future adapter must parse text. Note the trailing dots on names.


---

## `dig`

- **Registry:** binary, core, passive, phase 3, `stage: dns`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://bind9.readthedocs.io/en/latest/manpages.html#dig
- **Installed on this box:** `/usr/bin/dig`, `DiG 9.20.30-1-Debian`
- **Install command:** `reconkit install dig` (`apt install dnsutils`, needs sudo)
- **Multi-domain input:** **yes** - `-f filename` (batch mode reads a file of queries)

#### Real `--help` (raw, full)

Captured with `dig -h` (exit 0, wrote to stdout):

```
Usage:  dig [@global-server] [domain] [q-type] [q-class] {q-opt}
            {global-d-opt} host [@local-server] {local-d-opt}
            [ host [@local-server] {local-d-opt} [...]]
Where:  domain	  is in the Domain Name System
        q-class  is one of (in,hs,ch,...) [default: in]
        q-type   is one of (a,any,mx,ns,soa,hinfo,axfr,txt,...) [default:a]
                 (Use ixfr=version for type ixfr)
        q-opt    is one of:
                 -4                  (use IPv4 query transport only)
                 -6                  (use IPv6 query transport only)
                 -b address[#port]   (bind to source address/port)
                 -c class            (specify query class)
                 -f filename         (batch mode)
                 -k keyfile          (specify tsig key file)
                 -m                  (enable memory usage debugging)
                 -p port             (specify port number)
                 -q name             (specify query name)
                 -r                  (do not read ~/.digrc)
                 -t type             (specify query type)
                 -u                  (display times in usec instead of msec)
                 -x dot-notation     (shortcut for reverse lookups)
                 -y [hmac:]name:key  (specify named base64 tsig key)
        d-opt    is of the form +keyword[=value], where keyword is:
                 +[no]aaflag         (Set AA flag in query (+[no]aaflag))
                 +[no]aaonly         (Set AA flag in query (+[no]aaflag))
                 +[no]additional     (Control display of additional section)
                 +[no]adflag         (Set AD flag in query (default on))
                 +[no]all            (Set or clear all display flags)
                 +[no]answer         (Control display of answer section)
                 +[no]authority      (Control display of authority section)
                 +[no]badcookie      (Retry BADCOOKIE responses)
                 +[no]besteffort     (Try to parse even illegal messages)
                 +bufsize[=###]      (Set EDNS0 Max UDP packet size)
                 +[no]cdflag         (Set checking disabled flag in query)
                 +[no]class          (Control display of class in records)
                 +[no]cmd            (Control display of command line -
                                      global option)
                 +[no]coflag         (Set compact denial of existence ok flag)
                                      in query)
                 +[no]comments       (Control display of packet header
                                      and section name comments)
                 +[no]cookie         (Add a COOKIE option to the request)
                 +[no]crypto         (Control display of cryptographic
                                      fields in records)
                 +[no]defname        (Use search list (+[no]search))
                 +[no]dns64prefix    (Get the DNS64 prefixes from ipv4only.arpa)
                 +[no]dnssec         (Request DNSSEC records)
                 +domain=###         (Set default domainname)
                 +[no]edns[=###]     (Set EDNS version) [0]
                 +ednsflags=###      (Set undefined EDNS flag bits)
                 +[no]ednsnegotiation (Set EDNS version negotiation)
                 +ednsopt=###[:value] (Send specified EDNS option)
                 +noednsopt          (Clear list of +ednsopt options)
                 +[no]expandaaaa     (Expand AAAA records)
                 +[no]expire         (Request time to expire)
                 +[no]fail           (Don't try next server on SERVFAIL)
                 +[no]header-only    (Send query without a question section)
                 +[no]https[=###]    (DNS-over-HTTPS mode) [/]
                 +[no]https-get      (Use GET instead of default POST method
                                      while using HTTPS)
                 +[no]http-plain[=###] (DNS over plain HTTP mode) [/]
                 +[no]http-plain-get (Use GET instead of default POST method
                                      while using plain HTTP)
                 +[no]identify       (ID responders in short answers)
                 +[no]idn            (convert international domain names)
                 +[no]ignore         (Don't revert to TCP for TC responses.)
                 +[no]keepalive      (Request EDNS TCP keepalive)
                 +[no]keepopen       (Keep the TCP socket open between queries)
                 +[no]multiline      (Print records in an expanded format)
                 +ndots=###          (Set search NDOTS value)
                 +[no]nsid           (Request Name Server ID)
                 +[no]nssearch       (Search all authoritative nameservers)
                 +[no]onesoa         (AXFR prints only one soa record)
                 +[no]opcode=###     (Set the opcode of the request)
                 +padding=###        (Set padding block size [0])
                 +[no]proxy[=src_addr[#src_port]-dst_addr[#dst_port]]
                                     (Add PROXYv2 headers to the queries. If
                                      addresses are omitted, LOCAL PROXYv2
                                      headers are added)
                 +[no]proxy-plain[=src_addr[#src_port]-dst_addr[#dst_port]]
                                     (The same as'+[no]proxy', but send PROXYv2
                                      headers ahead of any encryption if an
                                      encrypted transport is used)
                 +qid=###            (Specify the query ID to use when sending
                                      queries)
                 +[no]qr             (Print question before sending)
                 +[no]question       (Control display of question section)
                 +[no]raflag         (Set RA flag in query (+[no]raflag))
                 +[no]rdflag         (Recursive mode (+[no]recurse))
                 +[no]recurse        (Recursive mode (+[no]rdflag))
                 +retry=###          (Set number of UDP retries) [2]
                 +[no]rrcomments     (Control display of per-record comments)
                 +[no]search         (Set whether to use searchlist)
                 +[no]short          (Display nothing except short
                                      form of answers - global option)
                 +[no]showbadcookie  (Show BADCOOKIE message)
                 +[no]showbadvers    (Show BADVERS message)
                 +[no]showsearch     (Search with intermediate results)
                 +[no]split=##       (Split hex/base64 fields into chunks)
                 +[no]stats          (Control display of statistics)
                 +subnet=addr        (Set edns-client-subnet option)
                 +[no]tcflag         (Set TC flag in query (+[no]tcflag))
                 +[no]tcp            (TCP mode (+[no]vc))
                 +timeout=###        (Set query timeout) [5]
                 +[no]tls            (DNS-over-TLS mode)
                 +[no]tls-ca[=file]  (Enable remote server's TLS certificate
                                      validation)
                 +[no]tls-hostname=hostname (Explicitly set the expected TLS
                                      hostname)
                 +[no]tls-certfile=file (Load client TLS certificate chain from
                                      file)
                 +[no]tls-keyfile=file (Load client TLS private key from file)
                 +[no]trace          (Trace delegation down from root [implies
                                      +dnssec])
                 +tries=###          (Set number of UDP attempts) [3]
                 +[no]ttlid          (Control display of ttls in records)
                 +[no]ttlunits       (Display TTLs in human-readable units)
                 +[no]unknownformat  (Print RDATA in RFC 3597 "unknown" format)
                 +[no]vc             (TCP mode (+[no]tcp))
                 +[no]yaml           (Present the results as YAML)
                 +[no]zflag          (Set Z flag in query)
        global d-opts and servers (before host name) affect all queries.
        local d-opts and servers (after host name) affect only that lookup.
        -h                           (print help and exit)
        -v                           (print version and exit)
```


#### Real test on testfire.net

Command:

```
dig testfire.net A +short
```


Output (raw, exit code 0):

```
65.61.137.117
```


#### Notes and errors hit

Output (exit 0):

```
65.61.137.117
```

`+short` is the parseable form. The version command is `-v`, not `--version`.

