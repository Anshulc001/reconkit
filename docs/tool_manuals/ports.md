# Tool manuals - ports

Stage `ports` of `reconkit`. Verified on the canonical Kali checkout
(`/home/kali/Desktop/reconkit`, Python 3.14.8) on **2026-11-16**. Every
`--help` block and every test block below is the tool's own raw output,
captured on that machine; nothing here is written from memory.

Authorized target used for the one safe test: **testfire.net** (already in
`scope.yaml`). One command per tool, no payloads, no brute force.

Tools from the `vulns` stage are deliberately absent - see
`docs/tool_manuals/README.md` ("Skipped").

| Tool | Kind | Tier | Mode | Phase | Adapter in this build |
|---|---|---|---|---|---|
| `pyscan` | python | core | active | 2 | yes |
| `naabu` | binary | core | active | 2 | yes |
| `nmap` | binary | core | active | 3 | no |
| `masscan` | binary | opt_in | active | 3 | no |
| `rustscan` | binary | core | active | 3 | no |
| `smap` | binary | core | passive | 3 | no |



---

## `pyscan`

- **Registry:** python, core, active, phase 2, `stage: ports`
- **Adapter in this build:** `src/reconkit/adapters/pyscan.py`
- **Official source used:** https://docs.python.org/3/library/asyncio-stream.html (standard library only)
- **Installed on this box:** stdlib in the venv
- **Install command:** nothing to install (`install: {method: none}`)
- **Multi-domain input:** n/a - the adapter scans one host at a time from `ctx.hosts`

#### Real test

Resolve, filter through the `in_scope_cidrs` predicate, then one TCP connect:

```
python - <<'EOF'
import ipaddress, socket
ip = "65.61.137.117"
pred = ipaddress.ip_network("65.61.137.0/24").__contains__
print("pyscan cidr predicate allows", ip, "->", pred(ipaddress.ip_address(ip)))
with socket.create_connection((ip, 80), timeout=10):
    print("pyscan connect", ip + ":80 -> OPEN")
EOF
```

Output (exit 0):

```
pyscan cidr predicate allows 65.61.137.117 -> True
pyscan connect 65.61.137.117:80 -> OPEN
```

#### What a normal exit code looks like

Exit 0, and `ToolResult.error` counts `timeouts=`, `errors=` and `blocked=`.
A host whose every resolved address is outside `in_scope_cidrs` is skipped and
counted as `blocked`, never connected to (PIT-34).

#### Gotchas

- `pyscan` is the only selectable ports adapter in this build; `naabu` is
  skipped at selection time and the ports confidence ceiling is `LOW` (12i,
  permanent).


---

## `naabu`

- **Registry:** binary, core, active, phase 2, `stage: ports`
- **Adapter in this build:** `src/reconkit/adapters/naabu.py` (present but blocked at selection time)
- **Official source used:** https://github.com/projectdiscovery/naabu
- **Installed on this box:** `/usr/bin/naabu`, `[INF] Current Version: 2.7.0`
- **Install command:** `reconkit install naabu` (github_release; `requires_apt: [libpcap-dev]`)
- **Multi-domain input:** **yes** - `-list, -l string` (list of hosts, file)

#### Real `--help` (raw, full)

Captured with `naabu -h` (exit 0, wrote to stdout):

```
Naabu is a port scanning tool written in Go that allows you to enumerate open ports for hosts in a fast and reliable manner.

Usage:
  naabu [flags]

Flags:
INPUT:
   -host string[]              hosts to scan ports for (comma-separated)
   -list, -l string            list of hosts to scan ports (file)
   -exclude-hosts, -eh string  hosts to exclude from the scan (comma-separated)
   -exclude-file, -ef string   list of hosts to exclude from scan (file)

PORT:
   -port, -p string              ports to scan (80,443, 100-200)
   -top-ports, -tp string        top ports to scan (default 100) [full,100,1000]
   -exclude-ports, -ep string[]  ports to exclude from scan (file or comma-separated)
   -ports-file, -pf string[]     list of ports to scan (file or comma-separated)
   -port-threshold, -pts int     port threshold to skip port scan for the host
   -exclude-cdn, -ec             skip full port scans for CDN/WAF (only scan for port 80,443)
   -display-cdn, -cdn            display cdn in use

RATE-LIMIT:
   -c int                general internal worker threads (default 25)
   -rate int             packets to send per second (default 1000)
   -tw, -tx-workers int  parallel transmit workers for the fast SYN sender (default 1)

UPDATE:
   -up, -update                 update naabu to latest version
   -duc, -disable-update-check  disable automatic naabu update check

OUTPUT:
   -o, -output string                     file to write output to (optional)
   -lof, -list-output-fields              list of fields to output (comma separated)
   -eof, -exclude-output-fields string[]  exclude output fields output based on a condition
   -j, -json                              write output in JSON lines format
   -csv                                   write output in csv format
   -oX, -xml-output string                write nmap-compatible XML output to file (- for stdout)
   -oG, -grep-output string               write nmap-compatible greppable output to file (- for stdout)
   -oA, -output-all string                write json, xml and greppable output to <basename>.{json,xml,gnmap}

CONFIGURATION:
   -config string                   path to the naabu configuration file (default $HOME/.config/naabu/config.yaml)
   -scan-all-ips, -sa               scan all the IP's associated with DNS record
   -ip-version, -iv string[]        ip version to scan of hostname (4,6) - (default 4,6) (default ["4", "6"])
   -scan-type, -s string            type of port scan (SYN/CONNECT) (default "c")
   -source-ip string                source ip and port (x.x.x.x:yyy - might not work on OSX) 
   -connect-payload, -cp string     payload to send in CONNECT scans (optional)
   -interface-list, -il             list available interfaces and public ip
   -interface, -i string            network Interface to use for port scan
   -nmap                            invoke nmap scan on targets (nmap must be installed) - Deprecated
   -nmap-cli string                 nmap command to run on found results (example: -nmap-cli 'nmap -sV')
   -r string                        list of custom resolver dns resolution (comma separated or from file)
   -proxy string                    socks5 proxy (ip[:port] / fqdn[:port]
   -proxy-auth string               socks5 proxy authentication (username:password)
   -dns-order string                dns resolution order (p/l/lp/pl) (default "l")
   -sr, -system-resolver            use system DNS as fallback resolver
   -resume                          resume scan using resume.cfg
   -stream                          stream mode (disables resume, nmap, verify, retries, shuffling, etc)
   -passive                         display passive open ports using shodan internetdb api (automatically enables stream mode)
   -irt, -input-read-timeout value  timeout on input read (default 3m0s)
   -no-stdin                        Disable Stdin processing

HOST-DISCOVERY:
   -sn, -host-discovery           Perform Only Host Discovery
   -show-dead                     show hosts that did not respond to host discovery (requires host discovery)
   -Pn, -skip-host-discovery      Skip Host discovery
   -wn, -with-host-discovery      Enable Host discovery
   -ps, -probe-tcp-syn string[]   TCP SYN Ping (host discovery needs to be enabled)
   -pa, -probe-tcp-ack string[]   TCP ACK Ping (host discovery needs to be enabled)
   -pe, -probe-icmp-echo          ICMP echo request Ping (host discovery needs to be enabled)
   -pp, -probe-icmp-timestamp     ICMP timestamp request Ping (host discovery needs to be enabled)
   -pm, -probe-icmp-address-mask  ICMP address mask request Ping (host discovery needs to be enabled)
   -arp, -arp-ping                ARP ping (host discovery needs to be enabled)
   -nd, -nd-ping                  IPv6 Neighbor Discovery (host discovery needs to be enabled)
   -rev-ptr                       Reverse PTR lookup for input ips

SERVICES-DISCOVERY:
   -sD, -service-discovery  Service Discovery
   -sV, -service-version    Service Version
   -sV-fast                 only probe port-hinted services (faster)
   -sV-timeout value        timeout for service version probes (default 5s)
   -sV-workers int          number of concurrent service version workers (default 25)
   -sV-probes string        custom nmap-service-probes file path (auto-detected from local nmap install if empty)
   -uP, -udp-probes         send protocol-specific payloads on UDP scans using nmap-service-probes

OPTIMIZATION:
   -retries int                    number of retries for the port scan (default 3)
   -timeout value                  time to wait before timing out (e.g. 500ms, 2s; a bare number is milliseconds) (default 1s)
   -warm-up-time int               time in seconds between scan phases (default 2)
   -T, -timing int                 timing template, higher is faster (0-5) (default 3)
   -ping                           ping probes for verification of host
   -verify                         validate the ports again with TCP verification
   -ss, -smart-scan                predictive port scanning using port correlation model (not compatible with stream mode)
   -pt, -prediction-threshold int  minimum confidence for port predictions (0-100%) (default 20)
   -npp, -no-port-priority         disable tiered port ordering (scan the whole range in one uniform random order)
   -shard string                   distributed scan slice as index/total, 1-based (e.g. 1/4)
   -seed int                       seed for scan randomization, must match across shards (default random)

DEBUG:
   -health-check, -hc        run diagnostic check up
   -debug                    display debugging information
   -verbose, -v              display verbose output
   -no-color, -nc            disable colors in CLI output
   -silent                   display only results in output
   -version                  display version of naabu
   -stats                    display stats of the running scan (deprecated)
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (deprecated) (default 5)
   -mp, -metrics-port int    port to expose naabu metrics on (default 63636)

CLOUD:
   -auth                           configure projectdiscovery cloud (pdcp) api key (default true)
   -ac, -auth-config string        configure projectdiscovery cloud (pdcp) api key credential file
   -pd, -dashboard                 upload / view output in projectdiscovery cloud (pdcp) UI dashboard
   -tid, -team-id string           upload asset results to given team id (optional)
   -aid, -asset-id string          upload new assets to existing asset id (optional)
   -aname, -asset-name string      assets group name to set (optional)
   -pdu, -dashboard-upload string  upload naabu output file (jsonl) in projectdiscovery cloud (pdcp) UI dashboard
```


#### Real test on testfire.net

Command:

```
naabu -host testfire.net -p 80,443 -scan-type c -silent -nc -duc
```


Output (raw, exit code 0):

```
testfire.net:80
testfire.net:443
```


#### Notes and errors hit

Output (exit 0):

```
testfire.net:80
testfire.net:443
```

The connect scan (`-scan-type c`) ran as a normal user with no root and no
`libpcap-dev` installed here.

**`reconkit` runs this tool scope-mode dependently** (owner decision
2026-11-17, docs/MASTER_PLAN.md D2, superseding the 11c-G-7/12i permanent
block): with no scope file `naabu` runs like any other active tool on the
discovered hostnames; with a scope file present the engine resolves each target
itself and passes only the address(es) verified against `in_scope_cidrs`,
skipping a target whose resolution fails or resolves out of scope, and records
`blocked: no in-scope IP for any target` when nothing verifies. The manual
exists so a future session knows what the tool does and which scan reconkit asks
of it (connect scan, no root).


---

## `nmap`

- **Registry:** binary, core, active, phase 3, `stage: ports`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://nmap.org/book/man.html
- **Installed on this box:** `/usr/bin/nmap`, `Nmap version 7.991`
- **Install command:** `reconkit install nmap` (`apt install nmap`, needs sudo)
- **Multi-domain input:** **yes** - `-iL <inputfilename>`

#### Real `--help` (raw, full)

Captured with `nmap --help` (exit 0, wrote to stdout):

```
Nmap 7.991 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
  --excludefile <exclude_file>: Exclude list from file
HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
  -PS/PA/PU/PY[portlist]: TCP SYN, TCP ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS's DNS resolver
  --traceroute: Trace hop path to each host
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  --exclude-ports <port ranges>: Exclude the specified ports from scanning
  -F: Fast mode - Scan fewer ports than the default scan
  -r: Scan ports sequentially - don't randomize
  --top-ports <number>: Scan <number> most common ports
  --port-ratio <ratio>: Scan ports more common than <ratio>
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
  --version-light: Limit to most likely probes (intensity 2)
  --version-all: Try every single probe (intensity 9)
  --version-trace: Show detailed version scan activity (for debugging)
SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of
           directories, script-files or script-categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-args-file=filename: provide NSE script args in a file
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
  --script-help=<Lua scripts>: Show help about scripts.
           <Lua scripts> is a comma-separated list of script-files or
           script-categories.
OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
      probe round trip time.
  --max-retries <tries>: Caps number of port scan probe retransmissions.
  --host-timeout <time>: Give up on target after this long
  --scan-delay/--max-scan-delay <time>: Adjust delay between probes
  --min-rate <number>: Send packets no slower than <number> per second
  --max-rate <number>: Send packets no faster than <number> per second
FIREWALL/IDS EVASION AND SPOOFING:
  -f; --mtu <val>: fragment packets (optionally w/given MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  -S <IP_Address>: Spoof source address
  -e <iface>: Use specified interface
  -g/--source-port <portnum>: Use given port number
  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
  --data <hex string>: Append a custom payload to sent packets
  --data-string <string>: Append a custom ASCII string to sent packets
  --data-length <num>: Append random data to sent packets
  --ip-options <options>: Send packets with specified ip options
  --ttl <val>: Set IP time-to-live field
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
     and Grepable format, respectively, to the given filename.
  -oA <basename>: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level (use -dd or more for greater effect)
  --reason: Display the reason a port is in a particular state
  --open: Only show open (or possibly open) ports
  --packet-trace: Show all packets sent and received
  --iflist: Print host interfaces and routes (for debugging)
  --append-output: Append to rather than clobber specified output files
  --resume <filename>: Resume an aborted scan
  --noninteractive: Disable runtime interactions via keyboard
  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
  --webxml: Reference stylesheet from Nmap.Org for more portable XML
  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
MISC:
  -6: Enable IPv6 scanning
  -A: Enable OS detection, version detection, script scanning, and traceroute
  --datadir <dirname>: Specify custom Nmap data file location
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
  --privileged: Assume that the user is fully privileged
  --unprivileged: Assume the user lacks raw socket privileges
  -V: Print version number
  -h: Print this help summary page.
EXAMPLES:
  nmap -v -A scanme.nmap.org
  nmap -v -sn 192.168.0.0/16 10.0.0.0/8
  nmap -v -iR 10000 -Pn -p 80
SEE THE MAN PAGE (https://nmap.org/book/man.html) FOR MORE OPTIONS AND EXAMPLES
```


#### Real test on testfire.net

Command:

```
nmap -sV -p80,443 -T2 --noninteractive testfire.net
```


Output (raw, exit code 0):

```
Starting Nmap 7.991 ( https://nmap.org ) at 2026-11-16 08:55 -0500
Nmap scan report for testfire.net (65.61.137.117)
Host is up (3.0s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache Tomcat/Coyote JSP engine 1.1
443/tcp open  ssl/http Apache Tomcat/Coyote JSP engine 1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.89 seconds
--- stderr ---
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
```


#### Notes and errors hit

Output (exit 0, the two port lines):

```
80/tcp  open  http     Apache Tomcat/Coyote JSP engine 1.1
443/tcp open  ssl/http Apache Tomcat/Coyote JSP engine 1.1
```

`-sV` is the version detection the `ports` stage would use to raise a port's
confidence by one level. The `rate_flag` in `tools.yaml` was `-T` until
2026-11-17; the field was removed with all speed control (docs/MASTER_PLAN.md
D3), so no adapter passes `-T` any more (a bare `-T` was never valid; it needed
`-T4`).


---

## `masscan`

- **Registry:** binary, opt_in, active, phase 3, `stage: ports`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/robertdavidgraham/masscan
- **Installed on this box:** `/usr/bin/masscan`, `Masscan version 1.3.2`
- **Install command:** `reconkit install masscan` (`apt install masscan`, needs sudo)
- **Multi-domain input:** **yes** - `-iL` for a list file

#### Real `--help` (raw, full)

Captured with `masscan --help` (exit 1, wrote to stdout):

```
MASSCAN is a fast port scanner. The primary input parameters are the
IP addresses/ranges you want to scan, and the port numbers. An example
is the following, which scans the 10.x.x.x network for web servers:
 masscan 10.0.0.0/8 -p80
The program auto-detects network interface/adapter settings. If this
fails, you'll have to set these manually. The following is an
example of all the parameters that are needed:
 --adapter-ip 192.168.10.123
 --adapter-mac 00-11-22-33-44-55
 --router-mac 66-55-44-33-22-11
Parameters can be set either via the command-line or config-file. The
names are the same for both. Thus, the above adapter settings would
appear as follows in a configuration file:
 adapter-ip = 192.168.10.123
 adapter-mac = 00-11-22-33-44-55
 router-mac = 66-55-44-33-22-11
All single-dash parameters have a spelled out double-dash equivalent,
so '-p80' is the same as '--ports 80' (or 'ports = 80' in config file).
To use the config file, type:
 masscan -c <filename>
To generate a config-file from the current settings, use the --echo
option. This stops the program from actually running, and just echoes
the current configuration instead. This is a useful way to generate
your first config file, or see a list of parameters you didn't know
about. I suggest you try it now:
 masscan -p1234 --echo
```


#### Real test on testfire.net

Command:

```
masscan --echo --max-rate 100 -p1234
```


Output (raw, exit code 0):

```
seed = 4828557345408031158
rate = 100       
shard = 1/1
nocapture = servername


# TARGET SELECTION (IP, PORTS, EXCLUDES)
ports = 1234
```


#### Notes and errors hit

**No packets are sent by this test.** `--echo` prints the derived config and
exits:

```
seed = 4828557345408031158
rate = 100
shard = 1/1
nocapture = servername
```

Exit 0 here. A real scan needs root (`needs_root: true` in `tools.yaml`), and
this session never ran `sudo`, so **a real masscan scan is unverified on this
box**. `masscan --version` exits 1 while printing a valid banner (PIT-35).


---

## `rustscan`

- **Registry:** binary, core, active, phase 3, `stage: ports`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/RustScan/RustScan
- **Installed on this box:** `/home/kali/.reconkit/bin/rustscan`, `rustscan 2.3.0`
- **Install command:** `reconkit install rustscan` (pinned `github_release` 2.3.0)
- **Multi-domain input:** `-a, --addresses` takes a comma-separated list; unverified against a scan

#### Why 2.3.0 is pinned (2026-11-17)

The latest release, 2.4.1, publishes `x86_64-linux-rustscan.tar.gz.zip` - a zip
that contains a `.tar.gz` that contains the binary. `reconkit`'s extractor
unwraps exactly one archive layer (`docs/10` section on extraction), so no
`asset_pattern` alone can install it. The 2.4.1 names also use `x86_64`/
`aarch64` where `{arch}` renders `amd64`/`arm64`, so one pattern cannot cover
both architectures, and no recent release publishes a checksums asset.

The newest release whose zip holds the binary directly is 2.3.0
(`rustscan-2.3.0-x86_64-linux.zip`, member `rustscan`), so the registry pins it:

```yaml
# config.yaml: the pin lives here (docs/10: load_plans(versions=...))
tool_versions: { rustscan: "2.3.0" }

# tools.yaml
rustscan: {..., install: {method: github_release, repo: bee-san/RustScan,
           asset_pattern: "rustscan-{version}-x86_64-linux.zip",
           verify_checksums: false}, notes: "Pinned 2.3.0 ..."}
```

`verify_checksums: false` is required because 2.3.0 publishes no checksums file
(`docs/10`: `false` only for a release that publishes none), so the post-install
identity probe (`rustscan --version`) is the only verification. This is an
amd64-only pin.

**Future follow-up, not a current capability:** nested-archive extraction (unwrap
a zip/tar.gz that contains one archive member) would let the registry install
2.4.1 on amd64. It is not implemented; the pin above is the whole fix.

#### The real install, raw (2026-11-17)

```
$ reconkit install rustscan --no-color
tool      method          result     detail
rustscan  github_release  installed  /home/kali/.reconkit/bin/rustscan
exit=0

$ ~/.reconkit/bin/rustscan --version
rustscan 2.3.0
```

`reconkit doctor` then reports `rustscan` as `installed yes`, version `2.3.0`,
path `~/.reconkit/bin/rustscan`, identity `ok`. A second install is a no-op:
`already installed (2.3.0)`.


---

## `smap`

- **Registry:** binary, core, passive, phase 3, `stage: ports`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/s0md3v/Smap
- **Installed on this box:** `/home/kali/.reconkit/bin/smap`, `Smap 1.0.0-beta`
- **Install command:** `reconkit install smap` (`go install github.com/s0md3v/smap/cmd/smap@latest`)
- **Multi-domain input:** **yes** - `-iL <filename>` (or `-` for stdin)

#### Real `--help` (raw, full)

Captured with `smap -h` (exit 0, wrote to stdout):

```
Smap 1.0.0-beta
Usage: smap <targets here>
TARGET SPECIFICATION:
  Valid targets are hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, 192.168.0.1, 192.168.0.0/24, 192.168.0.10-20
  -iL <filename>: Input from list of hosts/networks. Use - as filename to use stdin input.
  --nmap: Run Nmap against the original targets using Shodan's reported port union.
  --concurrency <n>: Number of workers for target expansion and queries. Default 3.
OUTPUT:
  Nmap's normal format is written to stdout by default.
  Specify a file to write the output or use - as filename to write it to stdout (terminal).
  Ex: -oX <filename>
  -oX XML
  -oG Greppable
  -oN Nmap
  -oA All 3 above
  -oJ JSON
  -oS Smap format
  -oP ip:port pairs
  --append-output: Append to output files instead of truncating them.
  Note: With --nmap, Nmap handles its output options and writes the output directly.
```


#### Real test on testfire.net

Command:

```
smap testfire.net -oJ -
```


Output (raw, exit code 0):

```
[{"ip":"65.61.137.117","hostnames":["demo.testfire.net"],"user_hostname":"testfire.net","ports":[{"port":80,"service":"http?","service_source":"port-default","cpes":[],"protocol":"tcp","protocol_source":"compatibility-default","nmap_confidence":3,"associations":[{"cpe":"cpe:/a:oracle:jre","service":"http","confidence":"candidate"},{"cpe":"cpe:/a:apache:tomcat","service":"http","confidence":"candidate"}]},{"port":443,"service":"https?","service_source":"port-default","cpes":[],"protocol":"tcp","protocol_source":"compatibility-default","nmap_confidence":3,"associations":[{"cpe":"cpe:/a:oracle:jre","service":"http","confidence":"candidate"},{"cpe":"cpe:/a:apache:tomcat","service":"http","confidence":"candidate"}]},{"port":8080,"service":"http-proxy?","service_source":"port-default","cpes":[],"protocol":"tcp","protocol_source":"compatibility-default","nmap_confidence":3,"associations":[{"cpe":"cpe:/a:oracle:jre","service":"http","confidence":"candidate"},{"cpe":"cpe:/a:apache:tomcat","service":"http","confidence":"candidate"}]}],"tags":["cloud"],"start_time":"2026-11-16T09:09:23.857152482-05:00","end_time":"2026-11-16T09:09:23.986453883-05:00","os":{"name":"","cpes":null,"port":0},"observed_cpes":["cpe:/a:oracle:jre","cpe:/a:apache:tomcat"]}]
```


#### Notes and errors hit

Output (exit 0, truncated): `smap` reads Shodan's public data, so **no
packets go to the target**:

```json
[{"ip":"65.61.137.117","hostnames":["demo.testfire.net"],"user_hostname":"testfire.net",
  "ports":[{"port":80,"service":"http?","service_source":"port-default","cpes":[],
  "protocol":"tcp","protocol_source":"compatibility-default","nmap_confidence":3,
  "associations":[{"cpe":"cpe:/a:oracle:jre","service":"http","confidence":"candidate"},
  {"cpe":"cpe:/a:apache:tomcat","service":"http","confidence":"candidate"}]},
  {"port":443,"service":"https?","service_source":"port-default","cpes":[],"protocol":"tcp",...
```

`-oJ -` writes JSON to stdout; port 80 and 443 are both reported. Passive
ports are stored with source `smap` and confidence `LOW` until an active scan
confirms them.

